import socket
from scapy.all import *
#192.0.1.1

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#client_socket.connect(('192.0.1.1', 8820))

send(IP(src='192.0.10.2', dst='192.0.10.1') / UDP(dport=12344, sport=12344) / Raw(load="message to ESP!"))  #.encode()

client_socket.close()