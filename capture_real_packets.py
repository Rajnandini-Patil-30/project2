import os
import math
import pandas as pd
from scapy.all import sniff, IP, TCP, Raw

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
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
    suspicious_keywords = ["cmd.exe", "eval(", "malware", "virus", "trojan", "powershell"]
    if not isinstance(payload, str):
        return False
    return any(k in payload.lower() for k in suspicious_keywords)

packets_data = []

def process_packet(packet):
    if packet.haslayer(IP):
        try:
            payload = ""
            if packet.haslayer(Raw):
                payload = str(bytes(packet[Raw]))

            packet_info = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "length": len(packet),
                "payload": payload,
                "entropy": calculate_entropy(payload),
                "dpi_flag": is_malicious_payload(payload)
            }
            packets_data.append(packet_info)

            print(f"Captured: {packet_info['src_ip']} -> {packet_info['dst_ip']} | DPI: {'Suspicious' if packet_info['dpi_flag'] else 'Clean'}")

        except Exception as e:
            print(f"Error processing packet: {e}")

def start_capture(packet_count=100):
    print(f"🚀 Capturing {packet_count} packets... Press CTRL+C to stop early.")
    sniff(prn=process_packet, count=packet_count, filter="ip")

    df = pd.DataFrame(packets_data)
    os.makedirs(DATA_DIR, exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"✅ Saved captured packet data to {OUTPUT_CSV}")

if __name__ == "__main__":
    start_capture(packet_count=100)  
