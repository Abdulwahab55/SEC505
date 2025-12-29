"""
Database Integration Module for main_improved.py
This module provides functions to store alerts and metrics in the database
"""

import os
import sys
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add IDS directory to path to import models
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'IDS'))

try:
    from models import Alert, SystemMetrics, AttackTypeMetrics, TrafficStatistics
except ImportError:
    print("Warning: Could not import database models. Database features disabled.")
    Alert = None


class DatabaseLogger:
    """Handles database operations for the IDS system"""
    
    def __init__(self, db_uri='mysql+pymysql://root:root@localhost:3306/projDB'):
        """Initialize database connection"""
        self.engine = None
        self.Session = None
        self.enabled = False
        
        try:
            self.engine = create_engine(db_uri)
            self.Session = sessionmaker(bind=self.engine)
            self.enabled = True
            print("[Database] Connected successfully")
        except Exception as e:
            print(f"[Database] Connection failed: {e}")
            print("[Database] Running without database logging")
    
    def log_alert(self, attack_type, source_ip, anomaly_percentage, 
                  normal_count, anomaly_count, report_file=None):
        """Log an alert to the database"""
        if not self.enabled or Alert is None:
            return
        
        try:
            session = self.Session()
            
            alert = Alert(
                attack_type=attack_type,
                source_ip=source_ip,
                anomaly_percentage=anomaly_percentage,
                normal_count=normal_count,
                anomaly_count=anomaly_count,
                report_file=report_file,
                timestamp=datetime.utcnow()
            )
            
            session.add(alert)
            session.commit()
            session.close()
            
            print(f"[Database] Logged alert: {attack_type} ({anomaly_percentage}%)")
            
        except Exception as e:
            print(f"[Database] Error logging alert: {e}")
    
    def log_system_metrics(self, captures, processed, predictions, alerts,
                          capture_queue_size, processing_queue_size, 
                          prediction_queue_size, processing_time_avg=None):
        """Log system metrics to the database"""
        if not self.enabled or SystemMetrics is None:
            return
        
        try:
            session = self.Session()
            
            metrics = SystemMetrics(
                captures_total=captures,
                processed_total=processed,
                predictions_total=predictions,
                alerts_total=alerts,
                capture_queue_size=capture_queue_size,
                processing_queue_size=processing_queue_size,
                prediction_queue_size=prediction_queue_size,
                processing_time_avg=processing_time_avg,
                timestamp=datetime.utcnow()
            )
            
            session.add(metrics)
            session.commit()
            session.close()
            
        except Exception as e:
            print(f"[Database] Error logging metrics: {e}")
    
    def log_attack_metrics(self, attack_type, predictions_count, 
                          normal_count, anomaly_count, anomaly_percentage):
        """Log attack type specific metrics"""
        if not self.enabled or AttackTypeMetrics is None:
            return
        
        try:
            session = self.Session()
            
            metrics = AttackTypeMetrics(
                attack_type=attack_type,
                predictions_count=predictions_count,
                normal_count=normal_count,
                anomaly_count=anomaly_count,
                anomaly_percentage=anomaly_percentage,
                timestamp=datetime.utcnow()
            )
            
            session.add(metrics)
            session.commit()
            session.close()
            
        except Exception as e:
            print(f"[Database] Error logging attack metrics: {e}")
    
    def log_traffic_statistics(self, total_flows, normal_flows, anomalous_flows,
                              top_source_ip=None, top_destination_ip=None,
                              top_protocol=None, avg_packet_size=None):
        """Log traffic statistics"""
        if not self.enabled or TrafficStatistics is None:
            return
        
        try:
            session = self.Session()
            
            stats = TrafficStatistics(
                total_flows=total_flows,
                normal_flows=normal_flows,
                anomalous_flows=anomalous_flows,
                top_source_ip=top_source_ip,
                top_destination_ip=top_destination_ip,
                top_protocol=top_protocol,
                avg_packet_size=avg_packet_size,
                timestamp=datetime.utcnow()
            )
            
            session.add(stats)
            session.commit()
            session.close()
            
        except Exception as e:
            print(f"[Database] Error logging traffic statistics: {e}")


# Global database logger instance
db_logger = None


def init_database_logger(db_uri=None):
    """Initialize the global database logger"""
    global db_logger
    
    if db_uri is None:
        # Try to load from config
        try:
            from config import Config
            db_uri = Config.SQLALCHEMY_DATABASE_URI
        except:
            db_uri = 'mysql+pymysql://root:root@localhost:3306/projDB'
    
    db_logger = DatabaseLogger(db_uri)
    return db_logger


def get_database_logger():
    """Get the global database logger instance"""
    global db_logger
    
    if db_logger is None:
        init_database_logger()
    
    return db_logger


if __name__ == "__main__":
    # Test database connection
    print("Testing database connection...")
    logger = DatabaseLogger()
    
    if logger.enabled:
        print("✓ Database connection successful")
        
        # Test logging
        print("Testing alert logging...")
        logger.log_alert(
            attack_type="Test Attack",
            source_ip="192.168.1.100",
            anomaly_percentage=50.0,
            normal_count=100,
            anomaly_count=100
        )
        print("✓ Alert logged successfully")
    else:
        print("✗ Database connection failed")
