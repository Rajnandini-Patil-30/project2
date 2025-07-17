from flask import Flask, render_template, request, jsonify
import pandas as pd
import os
from model import load_model, predict  # Import the model functions
from scapy.all import * # Import Scapy

app = Flask(__name__)

# Load the ML model *once* when the app starts
model = load_model()
if model is None:
    print("Failed to load the ML model. The application may not function correctly.")
    #  Consider exiting here if the model is critical:
    #  sys.exit(1)

@app.route("/")
def home():
    try:
        logs_path = os.path.join(os.path.dirname(__file__), "data/packets_with_entropy.csv")
        logs = pd.read_csv(logs_path)
        return render_template("index.html", logs=logs.to_dict(orient="records"))
    except Exception as e:
        return f"Error loading logs: {e}"

def extract_packet_features(packet):
    """
    Extracts features from a Scapy packet object.  This function is
    identical to the one in extract_features.py.  We're including it
    here for the Flask app to use directly.
    """
    features = {}

    # Basic features (IP addresses, length)
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
    else:
        features['src_ip'] = 'Unknown'
        features['dst_ip'] = 'Unknown'

    features['length'] = len(packet)

    # Payload and Entropy
    if Raw in packet:
        payload = bytes(packet[Raw].load).decode('latin-1', errors='ignore')
        features['payload'] = payload
        features['entropy'] = calculate_entropy(payload)
    else:
        features['payload'] = ''
        features['entropy'] = 0

     # DPI
    features['dpi_flag'] = is_malicious_payload(features['payload'])
    features['protocol'] = packet. Transport_layer if packet.haslayer(TCP) or packet.haslayer(UDP) else 'Other'
    return features

def calculate_entropy(payload):
    """Calculates the entropy of a payload."""
    if not isinstance(payload, str) or not payload:
        return 0
    entropy = 0
    for x in set(payload):
        p_x = payload.count(x) / len(payload)
        entropy += -p_x * math.log2(p_x)
    return entropy

def is_malicious_payload(payload):
    """Detects malicious payloads using keyword matching."""
    suspicious_keywords = ["cmd.exe", "eval(", "malware", "virus", "trojan", "powershell"]
    if not isinstance(payload, str):
        return False
    return any(k in payload.lower() for k in suspicious_keywords)

@app.route("/analyze_packet", methods=['POST'])
def analyze_packet():
    
    try:
        
        packet_data = request.json  

        try:
            ip_packet = IP(src=packet_data['src_ip'], dst=packet_data['dst_ip'])
            raw_packet = Raw(load=packet_data['payload'])
            packet = ip_packet / raw_packet
        except Exception as e:
            return jsonify({'error': f'Error reconstructing packet: {e}', 'malicious': False, 'details': {}}), 400

        features = extract_packet_features(packet)

        if model:
            prediction = predict(model, features)
            if prediction is not None:
                malicious = bool(prediction) 
            else:
                 malicious = False
        else:
            malicious = False  

        response_data = {
            'malicious': malicious,
            'details': features,  
        }
        return jsonify(response_data), 200

    except Exception as e:
        error_message = f"Error analyzing packet: {e}"
        print(error_message)  
        return jsonify({'error': error_message, 'malicious': False, 'details': {}}), 500

if __name__ == "__main__":
    app.run(debug=True)
