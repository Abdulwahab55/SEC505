"""
ML Predictor Module - Loads pre-trained models and performs predictions
This replaces the individual ML_*.py files with a unified prediction system
"""

import pickle
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
from datetime import datetime

class MLPredictor:
    """Unified ML prediction class that loads and uses pre-trained models"""
    
    def __init__(self, models_dir="trained_models"):
        self.models_dir = models_dir
        self.models = {}
        self.load_all_models()
        
    def load_all_models(self):
        """Load all pre-trained models at startup"""
        model_files = {
            "Bot_Attack": "bot_model.pkl",
            "SSH-Patator": "ssh_model.pkl",
            "FTP-Patator": "ftp_model.pkl",
            "DoS GoldenEye": "dos_goldeneye_model.pkl",
            "DoS Hulk": "dos_hulk_model.pkl",
            "DoS slowloris": "dos_slowloris_model.pkl",
            "DoS Slowhttptest": "dos_slowhttptest_model.pkl",
            "Port_Scan": "portscan_model.pkl",
            "Web Attack": "web_model.pkl"
        }
        
        for attack_name, model_file in model_files.items():
            model_path = os.path.join(self.models_dir, model_file)
            try:
                with open(model_path, "rb") as f:
                    self.models[attack_name] = pickle.load(f)
                print(f"✓ Loaded {attack_name} model")
            except FileNotFoundError:
                print(f"⚠ Warning: {attack_name} model not found at {model_path}")
            except Exception as e:
                print(f"✗ Error loading {attack_name} model: {e}")
    
    def predict(self, attack_type, traffic_data):
        """
        Predict anomalies for a specific attack type
        
        Args:
            attack_type: Name of the attack type
            traffic_data: DataFrame containing network traffic features
            
        Returns:
            Dictionary with prediction results
        """
        if attack_type not in self.models:
            return {
                "attack_type": attack_type,
                "error": f"Model for {attack_type} not loaded",
                "anomaly_percentage": 0
            }
        
        try:
            model_data = self.models[attack_type]
            model = model_data["model"]
            features = model_data["features"]
            
            # Extract required features
            ct = traffic_data[features].copy()
            ct = ct.fillna(0)
            
            # Predict
            predictions = model.predict(ct)
            
            # Calculate statistics
            normal_count = np.count_nonzero(predictions == 1)
            anomaly_count = np.count_nonzero(predictions == 0)
            total = normal_count + anomaly_count
            
            anomaly_percentage = round((anomaly_count / total) * 100, 2) if total > 0 else 0
            
            # Get source IP of anomalous traffic
            source_ip = None
            anomaly_df = pd.DataFrame()
            
            if anomaly_count > 0:
                traffic_data_copy = traffic_data.copy()
                traffic_data_copy["Predicted_result"] = predictions
                anomaly_df = traffic_data_copy[traffic_data_copy["Predicted_result"] == 0]
                
                if "Source IP" in anomaly_df.columns and len(anomaly_df) > 0:
                    source_ip = anomaly_df["Source IP"].value_counts().idxmax()
            
            return {
                "attack_type": attack_type,
                "source_ip": source_ip,
                "anomaly_df": anomaly_df,
                "anomaly_percentage": anomaly_percentage,
                "normal_count": normal_count,
                "anomaly_count": anomaly_count,
                "predictions": predictions
            }
            
        except Exception as e:
            return {
                "attack_type": attack_type,
                "error": str(e),
                "anomaly_percentage": 0
            }
    
    def predict_all(self, traffic_data):
        """
        Run predictions for all loaded models
        
        Args:
            traffic_data: DataFrame containing network traffic features
            
        Returns:
            List of prediction results for each attack type
        """
        results = []
        
        for attack_type in self.models.keys():
            result = self.predict(attack_type, traffic_data)
            results.append(result)
        
        return results
    
    def save_visualization(self, attack_type, predictions, output_dir):
        """
        Generate and save visualization for predictions
        
        Args:
            attack_type: Name of the attack type
            predictions: Prediction array
            output_dir: Directory to save the plot
        """
        try:
            # Count predictions
            unique, counts = np.unique(predictions, return_counts=True)
            pred_counts = dict(zip(unique, counts))
            
            # Create bar plot
            plt.figure(figsize=(6, 5))
            categories = ['Anomaly (0)', 'Normal (1)']
            values = [pred_counts.get(0, 0), pred_counts.get(1, 0)]
            
            plt.bar(categories, values, color=['red', 'green'])
            plt.title(f'Normal and Anomaly ({attack_type}) Prediction')
            plt.ylabel('Occurrences')
            plt.xlabel('Prediction')
            plt.xticks(rotation=0)
            
            # Save plot
            safe_filename = attack_type.replace(" ", "_").replace("/", "_")
            output_path = os.path.join(output_dir, f"{safe_filename}.png")
            plt.savefig(output_path)
            plt.close()
            
        except Exception as e:
            print(f"Error saving visualization for {attack_type}: {e}")
    
    def save_anomaly_report(self, result, reports_dir):
        """
        Save detailed report of anomalous traffic
        
        Args:
            result: Prediction result dictionary
            reports_dir: Directory to save reports
        """
        try:
            if result["anomaly_percentage"] > 10 and not result["anomaly_df"].empty:
                timestamp = datetime.now().strftime('%Y_%m_%d-%I:%M:%S_%p')
                attack_type = result["attack_type"].replace(" ", "_").replace("/", "_")
                filename = f"anomaly_{attack_type}_{timestamp}.csv"
                filepath = os.path.join(reports_dir, filename)
                
                result["anomaly_df"].to_csv(filepath, encoding="utf-8", index=False)
                print(f"Saved anomaly report: {filename}")
                
        except Exception as e:
            print(f"Error saving anomaly report: {e}")


def test_predictor():
    """Test function to verify predictor works"""
    print("Testing ML Predictor...")
    
    # Create sample data
    sample_data = pd.DataFrame({
        'Destination Port': [80, 443, 22],
        'Flow Duration': [1000, 2000, 3000],
        'Total Fwd Packets': [10, 20, 30],
        'Source IP': ['192.168.1.1', '192.168.1.2', '192.168.1.3']
    })
    
    predictor = MLPredictor()
    print(f"\nLoaded {len(predictor.models)} models")
    
    if len(predictor.models) > 0:
        print("\nRunning test prediction...")
        results = predictor.predict_all(sample_data)
        for result in results:
            if "error" not in result:
                print(f"{result['attack_type']}: {result['anomaly_percentage']}% anomalous")


if __name__ == "__main__":
    test_predictor()
