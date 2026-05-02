# wsn_rules.py

def detect_sybil(df):
    alerts = []
    ip_counts = df["src_ip"].value_counts()

    for ip, count in ip_counts.items():
        if count > 20:
            alerts.append(f"Sybil attack suspected from {ip}")

    return alerts


def detect_sinkhole(df):
    alerts = []

    if len(df) == 0:
        return alerts

    top_ip = df["dst_ip"].value_counts().idxmax()
    top_count = df["dst_ip"].value_counts().max()

    if top_count > len(df) * 0.6:
        alerts.append(f"Sinkhole attack suspected at {top_ip}")

    return alerts


def detect_selective_forwarding(df):
    alerts = []

    small_packets = df[df["packet_length"] < 60]

    if len(small_packets) > len(df) * 0.3:
        alerts.append("Selective forwarding attack suspected")

    return alerts