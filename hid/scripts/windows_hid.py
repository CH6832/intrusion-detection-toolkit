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
RULES_FILE = "rules/windows_rules.txt"
LOG_FILE = "hid.log"
ALERT_EMAIL = "admin@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USERNAME = "username"
SMTP_PASSWORD = "password"
MALWARE_MODEL_FILE = "malware_detection_model.pkl"

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# UNSW-NB15: This is a publicly available dataset containing network traffic data for intrusion detection research. It includes both benign and malicious traffic samples.
# Microsoft Malware Prediction: This dataset, provided by Microsoft, contains telemetry data from Windows machines, including information about software installations, system configuration, and behavior. It's used for predicting whether a machine will be hit with malware in the future.
# Kaggle Datasets: Kaggle hosts various datasets related to cybersecurity and malware analysis. You can search for datasets related to malware detection or cybersecurity on Kaggle.
# The Malware Genome Project: This project provides a collection of malware samples categorized by families. You can use this dataset for training malware detection models.
# Contagio Mini Dump: Contagio Mini Dump is a collection of malware samples collected from various sources. It includes samples of different types of malware, which can be used for training and research purposes.
# Open Malware: This is an open repository of malware samples collected from various sources. It includes both recent and historical samples of malware.

# Load dataset (replace this with your dataset loading code)
X, y = load_dataset()

# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize classifiers
classifiers = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
    'SVM': SVC(kernel='linear'),
    'KNN': KNeighborsClassifier(n_neighbors=5)
}

best_model = None
best_accuracy = 0.0

# Train and evaluate each classifier
for name, clf in classifiers.items():
    # Train the classifier
    clf.fit(X_train, y_train)

    # Make predictions on the test set
    y_pred = clf.predict(X_test)

    # Evaluate model performance
    accuracy = accuracy_score(y_test, y_pred)
    print(f"{name} Accuracy:", accuracy)

    # Update best model if current model is better
    if accuracy > best_accuracy:
        best_model = clf
        best_accuracy = accuracy

# Serialize the best trained model
if best_model is not None:
    joblib.dump(best_model, 'malware_detection_model.pkl')
    print("Best Model saved successfully!")
else:
    print("No best model found.")



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
