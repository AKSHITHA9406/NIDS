from scapy.all import sniff,IP
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
import time
from collections import defaultdict
open("alerts.csv","w").close()

model=joblib.load("nids_model.pkl")

data=[]

anomaly_counts=defaultdict(int)

protocol_map={1:"ICMP",6:"TCP",17:"UDP"}
protocol_encoding={"TCP":0,"UDP":1,"ICMP":2}

def process_packet(packet):
    if packet.haslayer(IP):
        protocol_num = packet[IP].proto
        if protocol_num in [1,6,17]:
            src_ip=packet[IP].src
            dst_ip=packet[IP].dst
            packet_length=len(packet)

            protocol=protocol_map.get(protocol_num,str(protocol_num))

            data.append([src_ip,dst_ip,protocol,packet_length])
            if len(data)>200:
                data.pop(0)

            df=pd.DataFrame(data,columns=["src_ip","dst_ip","protocol","packet_length"])

            df["protocol_encoded"]=df["protocol"].map(protocol_encoding)

            df["src_ip_frequency"]=df["src_ip"].map(df["src_ip"].value_counts())

            features=df[["packet_length","protocol_encoded","src_ip_frequency"]]

            prediction=model.predict(features.iloc[[-1]])

            if prediction[0] == -1:

                anomaly_counts[src_ip] += 1
                timestamp=time.time()
                with open("alerts.csv","a") as f:
                    f.write(f"{timestamp},{src_ip},{packet_length}\n")

                if anomaly_counts[src_ip] % 10 == 1:
                    print(anomaly_counts[src_ip], "anomlies detected from IP")
                
print("strating real-time detection...")
sniff(prn=process_packet,store=False)
