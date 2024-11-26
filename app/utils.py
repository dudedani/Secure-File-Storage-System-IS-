from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import joblib
import numpy as np
from sklearn.tree import DecisionTreeClassifier


def encrypt_file(file_data):
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = file_data + b'\0' * (16 - len(file_data) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data, key

def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_file_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_file_data) + decryptor.finalize()
    return decrypted_data.rstrip(b'\0')


# Load the trained model
# model_path = os.path.join(os.path.dirname(__file__), "../malicious_file_detector.pkl")
# clf = joblib.load(model_path)

model_path = "malicious_file_detector.pkl"
print(f"DEBUG: Loading model from {model_path}")
clf = joblib.load(model_path)

# Feature Extraction Function
def extract_features(file_data):
    file_size = len(file_data)  # Size of the file
    byte_average = np.mean([b for b in file_data]) / 255  # Normalized byte average
    return [file_size, byte_average]

# Malicious File Detection Function
# def analyze_file(file_data):
#     features = extract_features(file_data)
#     prediction = clf.predict([features])[0]
#     return prediction == 1
def analyze_file(file_data):
    """
    Analyze the given file to detect if it is malicious.
    Uses the pre-trained Decision Tree Classifier.
    """
    model_path = "malicious_file_detector.pkl"
    if not os.path.exists(model_path):
        raise FileNotFoundError("Trained model not found. Train the model first.")

    clf = joblib.load(model_path)

    # Extract features from the file
    features = extract_features(file_data)
    print(f"Analyzing Features: {features}")  # Debug: Log extracted features

    # Predict if the file is malicious
    prediction = clf.predict([features])[0]
    print(f"Prediction: {'Malicious' if prediction == 1 else 'Benign'}")
    return prediction == 1  # True if malicious

