import streamlit as st
import pandas as pd
import os

st.title("🚨 Network Intrusion Detection Dashboard")

# ----------- FILE HANDLING (IMPORTANT FIX) -----------
traffic_file = "network_traffic.csv" if os.path.exists("network_traffic.csv") else "sample_network_traffic.csv"
alerts_file = "alerts.csv" if os.path.exists("alerts.csv") else "sample_alerts.csv"

# ----------- LOAD DATA SAFELY -----------
try:
    df = pd.read_csv(traffic_file)
except:
    df = pd.DataFrame()

try:
    alerts_df = pd.read_csv(alerts_file)
except:
    alerts_df = pd.DataFrame()

# ----------- CHECK IF DATA EXISTS -----------
if df.empty:
    st.warning("No packet data found yet")
else:
    st.subheader("📊 Packet Summary")

    # Total packets
    st.write("Total Packets Captured:", len(df))

    # Protocol distribution
    st.subheader("📡 Protocol Distribution")
    st.bar_chart(df["protocol"].value_counts())

    # Top Source IPs
    st.subheader("🌐 Top Source IPs")
    st.bar_chart(df["src_ip"].value_counts().head())

# ----------- ALERTS SECTION -----------
st.subheader("⚠ Alerts")

if alerts_df.empty:
    st.write("No alerts yet")
else:
    st.dataframe(alerts_df)