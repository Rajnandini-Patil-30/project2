import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'nids_model.joblib')
DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'packets_with_entropy.csv') 

def train_model():
    try:
        data = pd.read_csv(DATA_PATH)  
    except FileNotFoundError:
        print(f"Error: Data file not found at {DATA_PATH}.  Make sure to run extract_features.py first.")
        return None

    features = ['entropy', 'length']  
    target = 'dpi_flag'  
    X = data[features]
    y = data[target]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)  
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy:.2f}")
    print("Classification Report:\n", classification_report(y_test, y_pred))

    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    return model 

def load_model():
    
    if not os.path.exists(MODEL_PATH):
        print(f"Warning: Model file not found at {MODEL_PATH}. Training a new model.")
        return train_model()  
    try:
        model = joblib.load(MODEL_PATH)
        print(f"Model loaded from {MODEL_PATH}")
        return model
    except Exception as e:
        print(f"Error loading the model: {e}")
        return None

def predict(model, data):
    
    try:
        input_data = pd.DataFrame([data])
        input_data = input_data[['entropy', 'length']]

        prediction = model.predict(input_data)[0]
        return prediction
    except Exception as e:
        print(f"Error during prediction: {e}")
        return None

if __name__ == '__main__':
    trained_model = train_model()
    if trained_model:
        loaded_model = load_model()
        if loaded_model:
            sample_data = {'entropy': 0.7, 'length': 120}
            prediction = predict(loaded_model, sample_data)
            print(f"Prediction for sample data: {prediction}")
