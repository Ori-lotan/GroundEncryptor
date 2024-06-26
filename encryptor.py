import socket
from scapy.all import *
import keyboard

def packet_callback(packet):
    if IP in packet and packet[IP].dst == "192.0.10.1":
        print("packet summary " + packet.summary())

def main():
    sniff(prn=packet_callback)

if __name__ == '__main__':
    main()