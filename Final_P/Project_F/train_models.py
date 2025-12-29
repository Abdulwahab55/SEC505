"""
Model Training Script
This script trains all ML models once and saves them for later use.
Run this script when you want to retrain models with new attack datasets.
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

# Create models directory if it doesn't exist
MODEL_DIR = "trained_models"
if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)
    print(f"Created {MODEL_DIR} directory")

def train_bot_model():
    """Train and save Bot detection model"""
    print("Training Bot detection model...")
    feature_list = ["Destination Port", "Bwd Packet Length Mean", "Flow IAT Min", 
                    "Flow IAT Std", "Flow IAT Max", "Label"]
    
    df = pd.read_csv("attacks_datasets/Bot.csv", usecols=feature_list)
    df = df.fillna(0)
    
    # Convert labels to binary
    attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
    df["Label"] = attack_or_not
    
    y = df["Label"]
    X = df[feature_list[:-1]]  # Exclude Label
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=2)
    
    clf = AdaBoostClassifier()
    clf.fit(X_train, y_train)
    
    # Save model and feature list
    with open(f"{MODEL_DIR}/bot_model.pkl", "wb") as f:
        pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
    
    print(f"✓ Bot model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")

def train_ssh_model():
    """Train and save SSH-Patator detection model"""
    print("Training SSH-Patator detection model...")
    feature_list = ["Destination Port", "Flow Duration", "Total Fwd Packets", 
                    "Total Backward Packets", "Total Length of Bwd Packets", "Label"]
    
    df = pd.read_csv("attacks_datasets/SSH-Patator.csv", usecols=feature_list)
    df = df.fillna(0)
    
    attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
    df["Label"] = attack_or_not
    
    y = df["Label"]
    X = df[feature_list[:-1]]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=2)
    
    clf = AdaBoostClassifier()
    clf.fit(X_train, y_train)
    
    with open(f"{MODEL_DIR}/ssh_model.pkl", "wb") as f:
        pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
    
    print(f"✓ SSH model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")

def train_ftp_model():
    """Train and save FTP-Patator detection model"""
    print("Training FTP-Patator detection model...")
    feature_list = ["Destination Port", "Total Fwd Packets", "Bwd Packet Length Std", 
                    "Bwd Packet Length Max", "Total Length of Bwd Packets", "Label"]
    
    df = pd.read_csv("attacks_datasets/FTP-Patator.csv", usecols=feature_list)
    df = df.fillna(0)
    
    attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
    df["Label"] = attack_or_not
    
    y = df["Label"]
    X = df[feature_list[:-1]]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=2)
    
    clf = AdaBoostClassifier()
    clf.fit(X_train, y_train)
    
    with open(f"{MODEL_DIR}/ftp_model.pkl", "wb") as f:
        pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
    
    print(f"✓ FTP model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")

def train_dos_goldeneye_model():
    """Train and save DoS GoldenEye detection model"""
    print("Training DoS GoldenEye detection model...")
    feature_list = ["Flow IAT Max", "Bwd Packet Length Std", "Flow IAT Min", 
                    "Total Backward Packets", "Flow IAT Mean", "Label"]
    
    df = pd.read_csv("attacks_datasets/DOS_DDOS/DoS GoldenEye.csv", usecols=feature_list)
    df = df.fillna(0)
    
    attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
    df["Label"] = attack_or_not
    
    y = df["Label"]
    X = df[feature_list[:-1]]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=10)
    
    clf = DecisionTreeClassifier(max_depth=5, criterion="entropy")
    clf.fit(X_train, y_train)
    
    with open(f"{MODEL_DIR}/dos_goldeneye_model.pkl", "wb") as f:
        pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
    
    print(f"✓ DoS GoldenEye model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")

def train_dos_hulk_model():
    """Train and save DoS Hulk detection model"""
    print("Training DoS Hulk detection model...")
    feature_list = ["Bwd Packet Length Std", "Fwd Packet Length Std", "Fwd Packet Length Max", 
                    "Flow IAT Min", "Flow IAT Mean", "Label"]
    
    df = pd.read_csv("attacks_datasets/DOS_DDOS/DoS Hulk.csv", usecols=feature_list)
    df = df.fillna(0)
    
    attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
    df["Label"] = attack_or_not
    
    y = df["Label"]
    X = df[feature_list[:-1]]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=10)
    
    clf = DecisionTreeClassifier(max_depth=5, criterion="entropy")
    clf.fit(X_train, y_train)
    
    with open(f"{MODEL_DIR}/dos_hulk_model.pkl", "wb") as f:
        pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
    
    print(f"✓ DoS Hulk model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")

def train_dos_slowloris_model():
    """Train and save DoS Slowloris detection model"""
    print("Training DoS Slowloris detection model...")
    feature_list = ["Flow IAT Mean", "Total Length of Bwd Packets", "Bwd Packet Length Mean", 
                    "Total Fwd Packets", "Label"]
    
    df = pd.read_csv("attacks_datasets/DOS_DDOS/DoS slowloris.csv", usecols=feature_list)
    df = df.fillna(0)
    
    attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
    df["Label"] = attack_or_not
    
    y = df["Label"]
    X = df[feature_list[:-1]]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=10)
    
    clf = DecisionTreeClassifier(max_depth=5, criterion="entropy")
    clf.fit(X_train, y_train)
    
    with open(f"{MODEL_DIR}/dos_slowloris_model.pkl", "wb") as f:
        pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
    
    print(f"✓ DoS Slowloris model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")

def train_dos_slowhttptest_model():
    """Train and save DoS Slowhttptest detection model"""
    print("Training DoS Slowhttptest detection model...")
    feature_list = ["Flow IAT Mean", "Fwd Packet Length Min", "Bwd Packet Length Mean", 
                    "Total Length of Bwd Packets", "Label"]
    
    df = pd.read_csv("attacks_datasets/DOS_DDOS/DoS Slowhttptest.csv", usecols=feature_list)
    df = df.fillna(0)
    
    attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
    df["Label"] = attack_or_not
    
    y = df["Label"]
    X = df[feature_list[:-1]]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=10)
    
    clf = DecisionTreeClassifier(max_depth=5, criterion="entropy")
    clf.fit(X_train, y_train)
    
    with open(f"{MODEL_DIR}/dos_slowhttptest_model.pkl", "wb") as f:
        pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
    
    print(f"✓ DoS Slowhttptest model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")

def train_portscan_model():
    """Train and save Port Scan detection model"""
    print("Training Port Scan detection model...")
    feature_list = ["Total Length of Fwd Packets", "Flow Bytes/s", "Destination Port", 
                    "Flow Duration", "Bwd Packet Length Std", "Label"]
    
    df = pd.read_csv("attacks_datasets/PortScan.csv", usecols=feature_list)
    df = df.fillna(0)
    
    attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
    df["Label"] = attack_or_not
    
    y = df["Label"]
    X = df[feature_list[:-1]]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=2)
    
    clf = DecisionTreeClassifier(max_depth=5, criterion="entropy")
    clf.fit(X_train, y_train)
    
    with open(f"{MODEL_DIR}/portscan_model.pkl", "wb") as f:
        pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
    
    print(f"✓ Port Scan model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")

def train_web_model():
    """Train and save Web Attack detection model"""
    print("Training Web Attack detection model...")
    feature_list = ["Total Length of Fwd Packets", "Fwd Packet Length Mean", 
                    "Bwd Packet Length Mean", "Flow IAT Mean", "Flow IAT Max", "Label"]
    
    try:
        df = pd.read_csv("attacks_datasets/Web Attack.csv", usecols=feature_list)
        df = df.fillna(0)
        
        attack_or_not = [1 if i == "BENIGN" else 0 for i in df["Label"]]
        df["Label"] = attack_or_not
        
        y = df["Label"]
        X = df[feature_list[:-1]]
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=2)
        
        clf = RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1)
        clf.fit(X_train, y_train)
        
        with open(f"{MODEL_DIR}/web_model.pkl", "wb") as f:
            pickle.dump({"model": clf, "features": feature_list[:-1]}, f)
        
        print(f"✓ Web Attack model trained and saved (Accuracy: {clf.score(X_test, y_test):.2%})")
    except FileNotFoundError:
        print("⚠ Web Attack dataset not found, skipping...")

def main():
    """Train all models"""
    print("=" * 60)
    print("Starting Model Training Process")
    print("=" * 60)
    print()
    
    try:
        train_bot_model()
        train_ssh_model()
        train_ftp_model()
        train_dos_goldeneye_model()
        train_dos_hulk_model()
        train_dos_slowloris_model()
        train_dos_slowhttptest_model()
        train_portscan_model()
        train_web_model()
        
        print()
        print("=" * 60)
        print("✓ All models trained and saved successfully!")
        print(f"Models saved in: {MODEL_DIR}/")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Error during training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
