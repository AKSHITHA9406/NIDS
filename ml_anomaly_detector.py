import pandas as pd 
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
df=pd.read_csv("network_traffic.csv")

encoder=LabelEncoder()
df["protocol_encoded"]=encoder.fit_transform(df["protocol"])

df["src_ip_frequency"]=df["src_ip"].map(df["src_ip"].value_counts())
features=df[["packet_length","src_ip_frequency","protocol_encoded"]]

model=IsolationForest(contamination=0.1)
model.fit(features)

df["anomaly"]=model.predict(features)
print(df)