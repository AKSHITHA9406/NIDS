import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib

df=pd.read_csv("network_traffic.csv")
encoder=LabelEncoder()
df["protocol_encoded"] = encoder.fit_transform(df["protocol"])

df["src_ip_frequency"] = df["src_ip"].map(df["src_ip"].value_counts())

features = df[[
    "packet_length", "protocol_encoded","src_ip_frequency"]]

model = IsolationForest(contamination=0.02)
model.fit(features)

joblib.dump(model,"nids_model.pkl")

print("model trained and saved successfully")
