import streamlit as st 
import pandas as pd
import time
st.set_page_config(page_title="NIDS Dashboard", layout="wide")
st.title("Real-Time Network Intrusion Detection System")
placeholder=st.empty()

while True:
    with placeholder.container():
        try:
            df=pd.read_csv("network_traffic.csv")
        except:
            st.warning("No packet data found yet.")
            time.sleep(3)
            st.rerun()
        st.subheader("CapturedPacket Dataset")

        col1,col2=st.columns(2)

        with col1:
            st.metric("Total Packets Captured", len(df))
        with col2:
            if "timestamp" in df.columns:
                duration=df["timestamp"].max()-df["timestamp"].min()
                if duration>0:
                    rate=round(len(df)/duration,2)
                    st.metric("Packet Rate(packets/sec)",rate)
                else:
                    st.metric("packet rate","calculatiing...")
        st.divider()
        st.subheader("Protocol Distribution")
        protocol_counts=df["protocol"].value_counts()
        st.bar_chart(protocol_counts)
        st.divider()
        st.subheader("Top Source IPs")
        top_ips = df["src_ip"].value_counts().head(10)
        st.bar_chart(top_ips)
        st.divider()
        st.subheader("Packet Length Distribution")
        st.line_chart(df["packet_length"])
        st.divider()

        st.subheader("Potentiall Large Packet Alerts")
        suspicious=df[df["packet_length"]>1500]

        if len(suspicious) > 0:
            st.error(f"{len(suspicious)} large packets detected")
            st.dataframe(suspicious.tail(10))
        else:
            st.success("No suspicious large packets detected")

        st.divider()
    
        st.subheader("Intrusion Alerts")

        try:
            alerts=pd.read_csv("alerts.csv",names=["timestamp","src_ip","packet_length"])
            st.metric("TOtal Alerts Detected",len(alerts))
            st.dataframe(alerts.tail(10))
            st.subheader("Attack Timeline")
            st.line_chart(alerts["packet_length"])
        except:
            st.success("No alerts detected yet")


        st.subheader("Packet Data Preview")
        st.dataframe(df.tail(50))
time.sleep(3)
