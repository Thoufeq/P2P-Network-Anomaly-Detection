---

# 🚨 P2P Network Traffic Anomaly Detection System

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-Apache-green)
![Flask](https://img.shields.io/badge/framework-Flask-lightgrey)

## 📌 Overview
Peer-to-Peer (P2P) networks play a crucial role in modern distributed systems. However, their decentralized nature introduces significant security challenges. Traditional signature-based systems often fail to catch zero-day threats or evolving malicious patterns.

This project presents an **Intelligent P2P Network Traffic Anomaly Detection System** that leverages machine learning to analyze flow-level network traffic. Instead of relying on predefined rules, the system learns the statistical "fingerprint" of normal traffic and identifies deviations that indicate malware, unauthorized access, or abnormal P2P behavior.

---

## 🎯 Objectives
* **Behavioral Detection:** Identify anomalies using ML rather than static signatures.
* **Flow-Level Analysis:** Analyze traffic via packet rates, durations, and resource usage.
* **Accessibility:** Provide a web-based interface for both single-record and batch (CSV) predictions.
* **Scalability:** Offer a modular framework that supports multiple ML algorithms.

---

## ⭐ Key Features
* **Multi-Model Support:** Choose between KNN, SVC, and Naive Bayes.
* **Data Preprocessing:** Automated feature scaling and handling of class imbalance using **SMOTE**.
* **Dual-Level Classification:**
    1.  **Traffic Anomaly:** (Normal vs. Anomalous)
    2.  **Risk Severity:** Predicting the threat level of authentication behavior.
* **Interactive Visualization:** Real-time performance metrics and results via a Flask web UI.

---

## 🧠 System Architecture

The system follows a modular pipeline to ensure data integrity and model accuracy:



1.  **Data Ingestion:** Loads CSV datasets or accepts manual user input.
2.  **Preprocessing:** Feature extraction, `StandardScaler` application, and validation.
3.  **Model Layer:** Handles training, saving, and loading of `.pkl` files.
4.  **Analysis Engine:** Executes classification and risk assessment.
5.  **Web Interface:** Renders results and evaluation metrics (Accuracy, Precision, Recall).

---

## 📂 Project Folder Structure
```text
MajorProjectCode/
│
├── app.py                 # Flask application entry point
├── main.py                # Logic orchestration
├── routes.py              # URL routing and request handling
├── ml_utils.py            # ML logic (Training, SMOTE, Scaling)
├── run3120.bat            # Windows execution script
│
├── Dataset/               # Training and testing datasets
├── models/                # Saved .pkl models and scalers
├── static/                # CSS, JS, and UI assets
├── templates/             # HTML Jinja2 templates
└── uploads/               # Directory for user-uploaded CSVs

```

---

## 🧪 Machine Learning Models Used

| Model | Use Case | Strength |
| --- | --- | --- |
| **K-Nearest Neighbors (KNN)** | Local Anomaly Detection | Excellent at finding clusters of malicious activity. |
| **Support Vector Classifier (SVC)** | Complex Traffic Patterns | Uses RBF kernels for non-linear decision boundaries. |
| **Naive Bayes** | Baseline Comparison | Fast, efficient, and requires minimal computational resources. |

---

## 📈 Dataset Description

The system utilizes flow-level statistics rather than raw packet inspection, focusing on features such as:

* **Transmission Metrics:** Packet size, flow duration, and latency.
* **System Metrics:** CPU usage, memory usage, and active connections.
* **Security Logs:** Firewall blocks, IDS alerts, and authentication failures.

---

## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone [https://github.com/Thoufeq/P2P-Network-Anomaly-Detection.git](https://github.com/Thoufeq/P2P-Network-Anomaly-Detection.git)
cd P2P-Network-Anomaly-Detection

```

### 2. Install Dependencies

```bash
pip install flask numpy pandas scikit-learn imbalanced-learn matplotlib seaborn

```

### 3. Launch the Application

**On Windows:**

```bash
run3120.bat

```

**Or via Python:**

```bash
python app.py

```

### 4. Access the UI

Open your browser and navigate to:
`http://localhost:8080/`

---

## 🔮 Future Enhancements

* **Real-time Capture:** Integration with Scapy or Wireshark for live packet sniffing.
* **Deep Learning:** Implementing LSTM or Autoencoders for time-series anomaly detection.
* **Advanced Dashboard:** Adding PowerBI-style visual analytics for network admins.

---
