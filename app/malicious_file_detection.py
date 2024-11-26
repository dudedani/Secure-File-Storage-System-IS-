import os
import joblib
import numpy as np
from sklearn.tree import DecisionTreeClassifier
import math
print("DEBUG: analyze_file function called")

# Hardcoded Dataset for Simplicity
# Features: [file_size, byte_average, entropy]
X_train = [
    [100, 0.1, 3.5],  # Benign
    [500, 0.9, 7.0],  # Malicious
    [150, 0.2, 4.0],  # Benign
    [1000, 1.0, 6.5],  # Malicious
    [200, 0.3, 3.8],  # Benign
    [800, 0.8, 7.2],  # Malicious
]
y_train = [0, 1, 0, 1, 0, 1]  # Labels: 0 (benign), 1 (malicious)

# Train a Simple Decision Tree Classifier
clf = DecisionTreeClassifier()
clf.fit(X_train, y_train)
joblib.dump(clf, "malicious_file_detector.pkl")
print("Model trained and saved.")

#Feature Extraction Function
# def extract_features(file_data):
#     """
#     Extract features from the file data.
#     Features: [file_size, byte_average, entropy]
#     """
#     import numpy as np
#     import math

#     # Feature 1: File size
#     file_size = len(file_data)

#     # Feature 2: Byte average (normalized)
#     byte_array = np.frombuffer(file_data, dtype=np.uint8)  # Convert bytes to integers
#     byte_average = np.mean(byte_array) / 255  # Normalize to [0, 1]

#     # Feature 3: Entropy
#     histogram = np.histogram(byte_array, bins=256, range=(0, 256), density=True)[0]
#     entropy = -sum(p * math.log2(p) for p in histogram if p > 0)

#     # Log extracted features
#     print(f"Extracted Features: Size={file_size}, Avg Byte={byte_average:.2f}, Entropy={entropy:.2f}")
#     return [file_size, byte_average, entropy]


def extract_features(file_data):
    file_size = len(file_data)

    # Calculate byte average
    byte_array = np.frombuffer(file_data, dtype=np.uint8)
    byte_average = np.mean(byte_array) / 255  # Normalize byte average

    # Calculate entropy
    histogram = np.histogram(byte_array, bins=256, range=(0, 256), density=True)[0]
    entropy = -sum(p * math.log2(p) for p in histogram if p > 0)

    # Debugging: Log all features
    print(f"DEBUG: Features Extracted: [Size: {file_size}, Avg Byte: {byte_average:.2f}, Entropy: {entropy:.2f}]")

    return [file_size, byte_average, entropy]



# Malicious File Detection Function
# def analyze_file(file_data):
#     """
#     Analyze the given file to detect if it is malicious.
#     Uses the pre-trained Decision Tree Classifier.
#     """
#     # Load the trained model
#     if not os.path.exists(model_path):
#         raise FileNotFoundError("Trained model not found. Train the model first.")

#     clf = joblib.load(model_path)

#     # Extract features from the file
#     features = extract_features(file_data)
#     print(f"Analyzing Features: {features}")

#     # Predict if the file is malicious
#     prediction = clf.predict([features])[0]
#     print(f"Prediction: {'Malicious' if prediction == 1 else 'Benign'}")
#     return prediction == 1  # True if malicious

def analyze_file(file_data):
    print("DEBUG: analyze_file function called")
    model_path = "malicious_file_detector.pkl"
    clf = joblib.load(model_path)

    # Extract features
    features = extract_features(file_data)
    print(f"DEBUG: Features Passed to Model: {features}")

    # Ensure the number of features matches the model's expectation
    print(f"DEBUG: Model expects {clf.n_features_in_} features")

    # Predict using the model
    prediction = clf.predict([features])[0]
    print(f"DEBUG: Prediction Result: {'Malicious' if prediction == 1 else 'Benign'}")
    return prediction == 1


if __name__ == "__main__":
    test_data = b"Example file data for testing feature extraction."
    features = extract_features(test_data)
    print(f"Test Features: {features}")  # Should print [file_size, byte_average, entropy]
