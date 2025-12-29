# 🚀 Quick Start Deployment Guide

## Step-by-Step Setup Instructions

### **1. Prerequisites**
```bash
# Make sure you have:
- Python 3.8+
- MySQL/MariaDB server
- dumpcap (part of Wireshark)
- Root/sudo access (for packet capture)
```

### **2. Install Dependencies**
```bash
cd Final_P
pip install -r requirements.txt
```

### **3. Database Setup**
```bash
# Login to MySQL
mysql -u root -p

# Create database
CREATE DATABASE projDB;
EXIT;

# Run migration script
cd IDS
python models.py
```

### **4. Configure Environment**
```bash
# Copy example environment file
cp .env.example .env

# Edit with your settings
nano .env

# Important settings to change:
# - NETWORK_INTERFACE=eth1  (change to your network interface)
# - DB_PASSWORD=your_password  (your MySQL password)
# - SECRET_KEY=generate_random_key  (generate with: python -c "import secrets; print(secrets.token_hex(32))")
```

### **5. Train ML Models (One-Time)**
```bash
cd Project_F
python train_models.py

# This will:
# - Train 9 ML models
# - Save them in trained_models/ directory
# - Take 5-10 minutes depending on your system
```

### **6. Find Your Network Interface**
```bash
# Linux:
ip link show

# Or:
ifconfig

# Common interfaces: eth0, eth1, wlan0, ens33
```

### **7. Update Network Interface**
Edit the NETWORK_INTERFACE in one of these files:
- `.env` file (preferred)
- OR `config.py`
- OR directly in `main_improved.py`

### **8. Run the System**

**Terminal 1 - ML Analyzer (needs root/sudo):**
```bash
cd Project_F
sudo python main_improved.py
```

**Terminal 2 - Web Dashboard:**
```bash
cd IDS
python app_improved.py
```

**Terminal 3 - Access Dashboard:**
```bash
# Open browser to:
http://127.0.0.1:5000

# Register an account
# Login and view dashboard
```

---

## 🎯 Quick Test (Without Real Network Capture)

If you want to test the ML models without network capture:

```bash
cd Project_F
python ml_predictor.py
```

This will verify that all models are loaded correctly.

---

## ⚠️ Common Issues & Solutions

### **Issue 1: "dumpcap: command not found"**
```bash
# Install Wireshark/dumpcap:
# Ubuntu/Debian:
sudo apt-get install wireshark

# CentOS/RHEL:
sudo yum install wireshark
```

### **Issue 2: "Permission denied" on network capture**
```bash
# Run with sudo:
sudo python main_improved.py

# Or grant capabilities:
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

### **Issue 3: "Can't find attacks_datasets"**
```bash
# Make sure you're in the Project_F directory
cd Project_F
python train_models.py
```

### **Issue 4: Database connection failed**
```bash
# Check MySQL is running:
sudo systemctl status mysql

# Start MySQL:
sudo systemctl start mysql

# Verify credentials in .env file
```

### **Issue 5: "No module named 'models'"**
```bash
# Make sure database_logger.py can find models.py
# The path is automatically handled, but verify:
cd Project_F
python -c "import sys; sys.path.append('../IDS'); from models import Alert; print('OK')"
```

---

## 📊 Monitoring the System

### **Console Output:**
```
[Capture] Starting capture worker on interface eth1
[Conversion] Starting conversion worker
[Processing] Starting processing worker
[Prediction] Starting prediction worker
[Prediction] Loaded 9 models
[Database] Connected successfully
```

### **Statistics (Every 60 seconds):**
```
============================================================
System Statistics:
  Captures: 5
  Processed: 4
  Predictions: 4
  Alerts: 2
  Queue sizes: Capture=1, Processing=0, Prediction=0
============================================================
```

### **Web Dashboard:**
- Main page: Latest alerts
- `/dashboard`: All attack visualizations
- `/alerts`: Alert history
- `/statistics`: System metrics

---

## 🔄 Comparing Old vs New System

### **Old System:**
```bash
# Terminal 1:
cd Project_F
python main.py  # Blocks for 5-10 min per cycle

# Terminal 2:
cd IDS
python app.py  # No database, only static files
```

### **New System:**
```bash
# Terminal 1:
cd Project_F
python main_improved.py  # Non-blocking, parallel processing

# Terminal 2:
cd IDS
python app_improved.py  # Full database, APIs, history
```

---

## 🎓 Architecture Overview

```
┌─────────────────────────────────────────────────┐
│              MULTI-THREADED SYSTEM              │
├─────────────────────────────────────────────────┤
│                                                 │
│  Thread 1: Capture Network (60s intervals)     │
│      ↓                                          │
│  Thread 2: Convert PCAP → CSV                  │
│      ↓                                          │
│  Thread 3: Process & Normalize Data            │
│      ↓                                          │
│  Thread 4: ML Predictions (9 models parallel)  │
│      ↓                                          │
│  ┌───────────────────────────────────┐         │
│  │  Database Logger                  │         │
│  │  - Alerts                         │         │
│  │  - Metrics                        │         │
│  │  - Statistics                     │         │
│  └───────────────────────────────────┘         │
│      ↓                                          │
│  Thread 5: Statistics Reporter                 │
│                                                 │
└─────────────────────────────────────────────────┘
              ↓
    ┌──────────────────────┐
    │   Web Dashboard      │
    │   (Flask App)        │
    │   - Real-time views  │
    │   - Alert history    │
    │   - API endpoints    │
    └──────────────────────┘
```

---

## 📁 Important Files

| File | Purpose |
|------|---------|
| `train_models.py` | Train all ML models (run once) |
| `ml_predictor.py` | Unified prediction engine |
| `main_improved.py` | Multi-threaded main app |
| `app_improved.py` | Enhanced Flask web app |
| `database_logger.py` | Database integration |
| `models.py` | Database schema |
| `config.py` | Configuration management |
| `.env` | Environment variables |

---

## ✅ Verification Checklist

Before running, verify:

- [ ] MySQL is running
- [ ] Database `projDB` exists
- [ ] Python dependencies installed
- [ ] Models trained (trained_models/ directory exists)
- [ ] Network interface configured correctly
- [ ] .env file created and configured
- [ ] Running with proper permissions (sudo for capture)

---

## 🎉 You're Ready!

If everything is set up correctly, you should see:
1. Console showing all threads starting
2. Models loading successfully
3. Database connection confirmed
4. Periodic statistics reports
5. Web dashboard accessible at http://127.0.0.1:5000

**Happy monitoring! 🛡️**
