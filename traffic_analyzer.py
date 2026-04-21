import pandas as pd

df=pd.read_csv("network_traffic.csv")
print("tot captured packets:",len(df))
time_span=df["timestamp"].max() - df["timestamp"].min()
if time_span>0:
    packet_rate=len(df)/time_span
else:
    packet_rate=len(df)

print("packet rate(packets/sec):", round(packet_rate,2))

print("protocol distri:")
print(df["protocol"].value_counts())

print("top source IPs:")
print(df["src_ip"].value_counts().head())


print(".....intrusion detection check....")

if packet_rate>100:
    print("high traffic rate detected! possible anamoly")

top_ip=df["src_ip"].value_counts().idxmax()
top_ip_count=df["src_ip"].value_count().max()

if top_ip_count>len(df)*0.7:
    print("oen IP dominating traffic:",top_ip)
