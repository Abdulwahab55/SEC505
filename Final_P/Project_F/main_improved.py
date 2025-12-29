"""
Improved Main Application with Threading and Queue Architecture
This replaces the blocking single-threaded design with a producer-consumer pattern
"""

import os
import queue
import threading
import time
import subprocess
from datetime import datetime
from proccessing_captured_data import processing
from ml_predictor import MLPredictor
from database_logger import init_database_logger, get_database_logger
import pandas as pd

# Configuration
NETWORK_INTERFACE = "eth1"  # Change this to match your network interface
CAPTURE_DURATION = 60  # seconds
ALERT_THRESHOLD = 40  # percentage
REPORT_THRESHOLD = 10  # percentage
STATIC_DIR = "../IDS/static"
REPORTS_DIR = "Reports"

# Create necessary directories
os.makedirs("Network_traffic", exist_ok=True)
os.makedirs("flow_data", exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# Thread-safe queues
capture_queue = queue.Queue(maxsize=5)  # Limit backlog
processing_queue = queue.Queue(maxsize=5)
prediction_queue = queue.Queue(maxsize=10)

# Global ML Predictor (loaded once)
ml_predictor = None
predictor_lock = threading.Lock()

# Global Database Logger
db_logger = None

# Statistics
stats = {
    "captures": 0,
    "processed": 0,
    "predictions": 0,
    "alerts": 0
}
stats_lock = threading.Lock()


def capture_worker():
    """Thread 1: Continuously capture network traffic"""
    global stats
    
    print(f"[Capture] Starting capture worker on interface {NETWORK_INTERFACE}")
    
    while True:
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"captured_{timestamp}.pcap"
            filepath = os.path.join("Network_traffic", filename)
            
            print(f"[Capture] Starting {CAPTURE_DURATION}s capture...")
            
            # Use subprocess instead of os.system for better control
            result = subprocess.run(
                ["dumpcap", "-i", NETWORK_INTERFACE, "-a", f"duration:{CAPTURE_DURATION}", 
                 "-w", filepath],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and os.path.exists(filepath):
                print(f"[Capture] Completed: {filename}")
                
                # Add to queue (blocks if queue is full)
                capture_queue.put(filepath)
                
                with stats_lock:
                    stats["captures"] += 1
            else:
                print(f"[Capture] Error: {result.stderr}")
                time.sleep(5)  # Wait before retry
                
        except Exception as e:
            print(f"[Capture] Exception: {e}")
            time.sleep(5)


def conversion_worker():
    """Thread 2: Convert PCAP files to CSV using CICFlowMeter"""
    global stats
    
    print("[Conversion] Starting conversion worker")
    
    while True:
        try:
            # Get captured file from queue (blocks until available)
            pcap_file = capture_queue.get()
            
            print(f"[Conversion] Processing {os.path.basename(pcap_file)}...")
            
            # Convert PCAP to CSV using CICFlowMeter
            result = subprocess.run(
                ["./cfm", pcap_file, "flow_data/"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                # Remove header line from CSV
                flow_files = os.listdir("flow_data")
                if flow_files:
                    latest_flow = max([os.path.join("flow_data", f) for f in flow_files],
                                     key=os.path.getctime)
                    
                    # Remove first line
                    subprocess.run(["sed", "-i", "1d", latest_flow])
                    
                    print(f"[Conversion] Completed: {os.path.basename(latest_flow)}")
                    
                    # Add to processing queue
                    processing_queue.put(latest_flow)
                else:
                    print("[Conversion] Warning: No flow file generated")
            else:
                print(f"[Conversion] Error: {result.stderr}")
            
            # Clean up PCAP file
            try:
                os.remove(pcap_file)
            except:
                pass
            
            capture_queue.task_done()
            
        except queue.Empty:
            time.sleep(1)
        except Exception as e:
            print(f"[Conversion] Exception: {e}")
            capture_queue.task_done()


def processing_worker():
    """Thread 3: Process flow data and normalize features"""
    global stats
    
    print("[Processing] Starting processing worker")
    
    while True:
        try:
            # Get flow file from queue
            flow_file = processing_queue.get()
            
            print(f"[Processing] Processing {os.path.basename(flow_file)}...")
            start_time = time.time()
            
            # Process the data
            processed_data = processing(os.path.basename(flow_file))
            
            elapsed = time.time() - start_time
            print(f"[Processing] Completed in {elapsed:.1f}s")
            
            # Add to prediction queue
            prediction_queue.put(processed_data)
            
            with stats_lock:
                stats["processed"] += 1
            
            # Clean up flow file
            try:
                os.remove(flow_file)
            except:
                pass
            
            processing_queue.task_done()
            
        except queue.Empty:
            time.sleep(1)
        except Exception as e:
            print(f"[Processing] Exception: {e}")
            processing_queue.task_done()


def prediction_worker():
    """Thread 4: Run ML predictions in parallel"""
    global stats, ml_predictor
    
    print("[Prediction] Starting prediction worker")
    
    # Load models once
    with predictor_lock:
        if ml_predictor is None:
            print("[Prediction] Loading ML models...")
            ml_predictor = MLPredictor()
            print(f"[Prediction] Loaded {len(ml_predictor.models)} models")
    
    while True:
        try:
            # Get processed data from queue
            traffic_data = prediction_queue.get()
            
            print(f"[Prediction] Analyzing {len(traffic_data)} flows...")
            start_time = time.time()
            
            # Run all predictions (fast since models are pre-loaded)
            results = ml_predictor.predict_all(traffic_data)
            
            elapsed = time.time() - start_time
            print(f"[Prediction] Completed {len(results)} predictions in {elapsed:.1f}s")
            
            # Process results
            handle_prediction_results(results, traffic_data)
            
            with stats_lock:
                stats["predictions"] += 1
            
            prediction_queue.task_done()
            
        except queue.Empty:
            time.sleep(1)
        except Exception as e:
            print(f"[Prediction] Exception: {e}")
            import traceback
            traceback.print_exc()
            prediction_queue.task_done()


def handle_prediction_results(results, traffic_data):
    """Process and save prediction results"""
    global stats, db_logger
    
    severe_attacks = {}
    
    # Collect attacks above report threshold
    for result in results:
        if "error" in result:
            continue
            
        attack_type = result["attack_type"]
        percentage = result["anomaly_percentage"]
        
        # Save visualization
        if "predictions" in result:
            ml_predictor.save_visualization(
                attack_type, 
                result["predictions"], 
                STATIC_DIR
            )
        
        # Log attack metrics to database
        if db_logger and db_logger.enabled:
            db_logger.log_attack_metrics(
                attack_type=attack_type,
                predictions_count=result.get("normal_count", 0) + result.get("anomaly_count", 0),
                normal_count=result.get("normal_count", 0),
                anomaly_count=result.get("anomaly_count", 0),
                anomaly_percentage=percentage
            )
        
        # Save detailed report if above threshold
        if percentage > REPORT_THRESHOLD:
            severe_attacks[attack_type] = percentage
            ml_predictor.save_anomaly_report(result, REPORTS_DIR)
            print(f"[Alert] {attack_type}: {percentage}% anomalous traffic detected")
            
            # Log alert to database
            if db_logger and db_logger.enabled:
                db_logger.log_alert(
                    attack_type=attack_type,
                    source_ip=result.get("source_ip"),
                    anomaly_percentage=percentage,
                    normal_count=result.get("normal_count", 0),
                    anomaly_count=result.get("anomaly_count", 0),
                    report_file=None  # Could add the CSV filename here
                )
    
    # Generate main alert if any attack is above alert threshold
    if severe_attacks:
        most_severe = max(severe_attacks, key=severe_attacks.get)
        max_percentage = severe_attacks[most_severe]
        
        if max_percentage > ALERT_THRESHOLD:
            generate_alert(most_severe, max_percentage, results)
            
            with stats_lock:
                stats["alerts"] += 1


def generate_alert(attack_type, percentage, all_results):
    """Generate alert files for the web dashboard"""
    try:
        # Find the specific result
        source_ip = "Unknown"
        for result in all_results:
            if result["attack_type"] == attack_type and "source_ip" in result:
                source_ip = result["source_ip"] or "Unknown"
                break
        
        # Load template
        template_path = f"templates/{attack_type}.txt"
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                content = f.read()
            
            # Replace placeholders
            content = content.replace("SOURCEE_IPP", str(source_ip))
            content = content.replace("PERCENTAGEE", f"{percentage}%")
            
            # Save alert
            alert_path = os.path.join(STATIC_DIR, "Attack_Details.txt")
            with open(alert_path, 'w') as f:
                f.write(content)
            
            # Copy attack image
            safe_attack_type = attack_type.replace(" ", "_").replace("/", "_")
            src_image = os.path.join(STATIC_DIR, f"{safe_attack_type}.png")
            dst_image = os.path.join(STATIC_DIR, "Attack_pic.png")
            
            if os.path.exists(src_image):
                subprocess.run(["cp", src_image, dst_image])
            
            print(f"[Alert] Generated alert for {attack_type} ({percentage}%)")
        
    except Exception as e:
        print(f"[Alert] Error generating alert: {e}")


def stats_reporter():
    """Thread 5: Periodically report statistics"""
    global db_logger
    
    while True:
        time.sleep(60)  # Report every minute
        
        with stats_lock:
            print(f"\n{'='*60}")
            print(f"System Statistics:")
            print(f"  Captures: {stats['captures']}")
            print(f"  Processed: {stats['processed']}")
            print(f"  Predictions: {stats['predictions']}")
            print(f"  Alerts: {stats['alerts']}")
            print(f"  Queue sizes: Capture={capture_queue.qsize()}, "
                  f"Processing={processing_queue.qsize()}, "
                  f"Prediction={prediction_queue.qsize()}")
            print(f"{'='*60}\n")
            
            # Log metrics to database
            if db_logger and db_logger.enabled:
                db_logger.log_system_metrics(
                    captures=stats['captures'],
                    processed=stats['processed'],
                    predictions=stats['predictions'],
                    alerts=stats['alerts'],
                    capture_queue_size=capture_queue.qsize(),
                    processing_queue_size=processing_queue.qsize(),
                    prediction_queue_size=prediction_queue.qsize()
                )


def main():
    """Main entry point - starts all worker threads"""
    global db_logger
    
    print("="*60)
    print("IDS System Starting - Multi-threaded Architecture")
    print("="*60)
    print(f"Network Interface: {NETWORK_INTERFACE}")
    print(f"Capture Duration: {CAPTURE_DURATION}s")
    print(f"Alert Threshold: {ALERT_THRESHOLD}%")
    print("="*60)
    print()
    
    # Initialize database logger
    db_logger = init_database_logger()
    
    # Create and start worker threads
    threads = [
        threading.Thread(target=capture_worker, name="Capture", daemon=True),
        threading.Thread(target=conversion_worker, name="Conversion", daemon=True),
        threading.Thread(target=processing_worker, name="Processing", daemon=True),
        threading.Thread(target=prediction_worker, name="Prediction", daemon=True),
        threading.Thread(target=stats_reporter, name="Stats", daemon=True)
    ]
    
    for thread in threads:
        thread.start()
        print(f"Started {thread.name} thread")
    
    print("\n✓ All threads started. Press Ctrl+C to stop.\n")
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        print("Final statistics:")
        with stats_lock:
            for key, value in stats.items():
                print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
