from scapy.all import sniff, IP
import pandas as pd
import joblib
import time
from collections import defaultdict

# import WSN rules
from wsn_rules import detect_sybil, detect_sinkhole, detect_selective_forwarding

# load ML model
model = joblib.load("nids_model.pkl")

data = []
anomaly_counts = defaultdict(int)

protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
protocol_encoding = {"TCP": 0, "UDP": 1, "ICMP": 2}

# clear alerts file at start
open("alerts.csv", "w").close()

def process_packet(packet):

    if packet.haslayer(IP):

        protocol_num = packet[IP].proto

        if protocol_num in [1, 6, 17]:

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_length = len(packet)

            protocol = protocol_map.get(protocol_num, str(protocol_num))

            data.append([src_ip, dst_ip, protocol, packet_length])

            # keep last 200 packets
            if len(data) > 200:
                data.pop(0)

            df = pd.DataFrame(
                data,
                columns=["src_ip", "dst_ip", "protocol", "packet_length"]
            )

            # feature engineering
            df["protocol_encoded"] = df["protocol"].map(protocol_encoding)
            df["src_ip_frequency"] = df["src_ip"].map(df["src_ip"].value_counts())

            features = df[["packet_length", "protocol_encoded", "src_ip_frequency"]]

            # ML prediction
            prediction = model.predict(features.iloc[[-1]])

            # ML anomaly alert
            if prediction[0] == -1:
                anomaly_counts[src_ip] += 1

                timestamp = time.time()

                with open("alerts.csv", "a") as f:
                    print(timestamp, src_ip, packet_length, sep=",", file=f)

                if anomaly_counts[src_ip] % 5 == 1:
                    print(f"⚠ ML anomaly from IP: {src_ip}")

            # -------- WSN RULES --------
            alerts = []
            alerts += detect_sybil(df)
            alerts += detect_sinkhole(df)
            alerts += detect_selective_forwarding(df)

            for alert in alerts:
                print("⚠", alert)


print("Starting real-time detection...")
sniff(prn=process_packet, store=False)