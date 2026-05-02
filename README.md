# Real-Time Network Intrusion Detection System (NIDS) for WSN

## Overview
This project implements a hybrid Intrusion Detection System (IDS) for Wireless Sensor Networks (WSN). It detects network attacks using both rule-based (signature) and machine learning (anomaly) techniques.

## Features
- Real-time packet monitoring
- Detection of WSN attacks:
  - Sybil attack
  - Sinkhole attack
  - Selective forwarding
- Machine learning anomaly detection (Isolation Forest)
- Live attack simulation
- Interactive dashboard visualization

## Tech Stack
- Python
- Scapy
- Pandas, NumPy
- Scikit-learn
- Streamlit

## How to Run

1. Install dependencies: 
pip install -r requirements.txt

### 2. Train the model (if not already available)
python train_model.py


### 3. Start real-time detection
python realtime_detector.py


### 4. Simulate attacks (open a new terminal)
python attack_simulator.py


### 5. Launch dashboard
streamlit run dashboard.py


## Project Structure
- `realtime_detector.py` → Real-time intrusion detection system
- `attack_simulator.py` → Simulates malicious traffic
- `wsn_rules.py` → Rule-based WSN attack detection
- `dashboard.py` → Visualization dashboard
- `train_model.py` → Machine learning model training
- `packet_to_dataset.py` → Converts captured packets into dataset


## Detection Techniques

### Signature-Based Detection
Uses predefined rules to identify known attack patterns such as:
- High packet frequency → Sybil attack
- Traffic concentration → Sinkhole attack
- Irregular packet behavior → Selective forwarding

### Anomaly-Based Detection
Uses Isolation Forest to detect unusual patterns in network traffic.  
Any deviation from normal behavior is flagged as an anomaly.

## Conclusion
This project demonstrates a hybrid approach to intrusion detection in Wireless Sensor Networks by combining rule-based and machine learning techniques. It provides real-time monitoring, detection, and visualization of network threats.

