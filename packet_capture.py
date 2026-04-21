from scapy.all import sniff,IP

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        protocol=packet[IP].proto
        packet_length=len(packet)

        print(".....packet captured.....")
        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Protocol:", protocol)
        print("Packet Length:", packet_length)
        

print("starting packet capture")

sniff(prn=process_packet, count=300,filter="ip")
