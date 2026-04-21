from scapy.all import sniff,IP
import pandas as pd
import time

data=[]
protocol_map={1:"ICMP",2:"IGMP",6:"TCP",17:"UDP"}

def process_packet(packet):
    if packet.haslayer(IP):
        protocol_num = packet[IP].proto
        if protocol_num in[1,6,17]:
             timestamp=time.time()
             src_ip = packet[IP].src
             dst_ip = packet[IP].dst
             packet_length = len(packet)

       
             protocol=protocol_map.get(protocol_num,str(protocol_num))

             data.append([timestamp,src_ip,dst_ip,protocol,packet_length])
print("capturing packets")
sniff(prn=process_packet,count=300,filter="ip")
df=pd.DataFrame(data,columns=["timestamp","src_ip","dst_ip","protocol","packet_length"])
df.to_csv("network_traffic.csv",index=False)
print("dataset saved as network_traffic.csv")

