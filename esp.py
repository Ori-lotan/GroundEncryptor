import socket
from scapy.all import *
from AESCipher import AESCipher

#192.0.1.1

def encryptMessage(raw):
    aes = AESCipher('0123456789abcdef0123456789abcdef') # example -> change with diffi hellman result
    return aes.encrypt(raw)

def decryptMessage(raw):
    aes = AESCipher('0123456789abcdef0123456789abcdef') # example -> change with diffi hellman result
    return aes.decrypt(raw)   

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 8820))
packet = IP(src='192.0.10.1', dst='127.0.0.1') / UDP(dport=12345, sport=12345) / Raw(load="message from esp")
packet[Raw].load = encryptMessage(packet[Raw].load.decode())
client_socket.send(bytes(packet))


#send(IP(src='192.0.10.1', dst='192.0.10.1') / UDP(dport=12345, sport=12345) / Raw(load="abcasdfasfas"))  #.encode()

#client_socket.close()