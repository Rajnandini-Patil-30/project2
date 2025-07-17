import pandas as pd
import math
import os
from scapy.all import * 

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
INPUT_CSV = os.path.join(DATA_DIR, "sample_packets.csv")
OUTPUT_CSV = os.path.join(DATA_DIR, "packets_with_entropy.csv")

def calculate_entropy(payload):
    if not isinstance(payload, str) or not payload:
        return 0
    entropy = 0
    for x in set(payload):
        p_x = payload.count(x) / len(payload)
        entropy += -p_x * math.log2(p_x)
    return entropy

def is_malicious_payload(payload):
    
    suspicious_keywords = ["cmd.exe","eval(","malware","virus","trojan","powershell","SELECT","INSERT","UPDATE","DELETE","DROP","UNION",]
    if not isinstance(payload, str):
        return False
    return any(k in payload.lower() for k in suspicious_keywords)

def extract_packet_features(packet):
    
    features = {}

    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
    else:
        features['src_ip'] = 'Unknown'
        features['dst_ip'] = 'Unknown'

    features['length'] = len(packet)

    if Raw in packet:
        payload = bytes(packet[Raw].load).decode('latin-1', errors='ignore') 
        features['payload'] = payload
        features['entropy'] = calculate_entropy(payload)
    else:
        features['payload'] = ''
        features['entropy'] = 0

    features['dpi_flag'] = is_malicious_payload(features['payload'])

    features['protocol'] = packet. Transport_layer if packet.haslayer(TCP) or packet.haslayer(UDP) else 'Other'


    return features

print(f"📂 Looking for input file at: {INPUT_CSV}")
if not os.path.exists(INPUT_CSV):
    print(f"❌ Input file not found: {INPUT_CSV}")
    exit()

df = pd.read_csv(INPUT_CSV)

packets = []
for index, row in df.iterrows():
    try:
        ip_packet = IP(src=row['src_ip'], dst=row['dst_ip'])
        raw_packet = Raw(load=row['payload'])
        packet = ip_packet / raw_packet 
        packets.append(packet)
    except Exception as e:
        print(f"Error creating packet from row {index}: {e}")
        packets.append(None)  

extracted_features = []
for packet in packets:
    if packet is not None:
        extracted_features.append(extract_packet_features(packet))
    else:
        extracted_features.append({})

features_df = pd.DataFrame(extracted_features)

features_df.to_csv(OUTPUT_CSV, index=False)
print(f"✅ Extracted features and saved to: {OUTPUT_CSV}")
