import subprocess
import re
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.externals import joblib
from sklearn.svm import OneClassSVM
import numpy as np

# Configuration
RULES_FILE = "rules/macos_rules.txt"
LOG_FILE = "hid.log"
ALERT_EMAIL = "admin@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USERNAME = "username"
SMTP_PASSWORD = "password"
MALWARE_MODEL_FILE = "malware_detection_model.pkl"

# Function to send email alert
def send_alert(subject, body):
    msg = MIMEMultipart()
    msg['From'] = ALERT_EMAIL
    msg['To'] = ALERT_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    text = msg.as_string()
    server.sendmail(ALERT_EMAIL, ALERT_EMAIL, text)
    server.quit()

# Function to detect anomalies using Isolation Forest
def detect_anomalies(X):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    pca = PCA(n_components=10)  # Adjust number of components as needed
    X_pca = pca.fit_transform(X_scaled)
    clf = IsolationForest(contamination=0.05)
    clf.fit(X_pca)
    anomalies = clf.predict(X_pca)
    return anomalies

# Function to detect anomalies using One-Class SVM
def detect_anomalies_svm(X):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    pca = PCA(n_components=10)  # Adjust number of components as needed
    X_pca = pca.fit_transform(X_scaled)
    clf = OneClassSVM(nu=0.05)  # Adjust nu parameter as needed
    clf.fit(X_pca)
    anomalies = clf.predict(X_pca)
    return anomalies

# Function to detect malware using pre-trained model
def detect_malware(file_features):
    model = joblib.load(MALWARE_MODEL_FILE)
    malware_probability = model.predict_proba([file_features])[0][1]
    return malware_probability

# Function to monitor system activity
def monitor_activity():
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

    with open(RULES_FILE, 'r') as f:
        rules = f.read().splitlines()

    while True:
        # Example: Collect features for anomaly detection
        # For simplicity, we'll use a random feature vector as an example
        feature_vector = np.random.rand(1, 20)  # Example: 20-dimensional feature vector

        # Example: Detect anomalies using Isolation Forest
        anomalies_isof = detect_anomalies(feature_vector)
        # Example: Detect anomalies using One-Class SVM
        anomalies_svm = detect_anomalies_svm(feature_vector)

        # Example: If an anomaly is detected, trigger an alert
        if -1 in anomalies_isof or -1 in anomalies_svm:
            logging.warning("Anomaly detected: Possible security threat!")
            send_alert("Anomaly Detected", "Possible security threat detected!")

        # Example: Detect malware using pre-trained model
        file_features = np.random.rand(1, 50)  # Example: 50-dimensional feature vector extracted from file metadata
        malware_probability = detect_malware(file_features)
        if malware_probability > 0.5:
            logging.warning("Malware detected: Probability={}".format(malware_probability))
            send_alert("Malware Detected", "Malicious file detected (Probability={})".format(malware_probability))

        # Simulated delay for monitoring interval
        time.sleep(5)  # Adjust sleep duration as needed

if __name__ == "__main__":
    monitor_activity()
