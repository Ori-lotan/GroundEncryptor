import socket
from scapy.all import *
import keyboard
import threading
from AESCipher import AESCipher
#import bluetooth


#arp = {'IPaddressAir1':'hwaddressAir1' ESP, 'IPaddressAir2':'hwaddressAir2'} ANDROID
arp = {'192.0.10.1':'00:12:79:d2:b9:67', '10.3.0.2':'00:12:79:d2:b9:68'}

server_ip = '0.0.0.0'
server_port_ESP = 8820
server_socket_ESP = socket.socket()
server_socket_ESP.bind((server_ip, server_port_ESP))
print("Server is listening to ESP...")
server_socket_ESP.listen()
(ESP_socket, ESP_address) = server_socket_ESP.accept()
print("ESP connected")


def packet_callback(packet):
    #print("packet summary " + packet.summary())
    #print(packet.show())

    # ecrypt payload to all packets
    print(packet.show())
    packet = encrypt_payload(packet)
    print(packet.show())
    send_to_hwaddress(packet)

def modify_payload(packet):
    if Raw in packet:
        packet[Raw].load = ("modified")
    return packet

def encrypt_payload(packet):
    if Raw in packet:
        packet[Raw].load = encryptMessage(packet[Raw].load.decode())
    return packet

def decrypt_payload(packet):
    if Raw in packet:
        #breakpoint()
        packet[Raw].load = decryptMessage(packet[Raw].load)
    return packet

def send_to_hwaddress(packet):
    # ESP IP
    if packet[IP].dst == '192.0.10.1':
        ESP_socket.send(bytes(packet))
        print("sent packet to ESP")
    # Android IP   
    #elif packet[IP].dst == '10.3.0.2':
        #hwaddress = arp[packet[IP].dst]
        #print(hwaddress)
        #port_android = 12345
        
        #server_sock_android = bluetooth.BluetoothSocket( bluetooth.RFCOMM )
        #server_sock_android.bind(("",port_android))
        #server_sock_android.listen()

        #(client_sock_android, android_address) = server_sock_android.accept()
        #print("accepted android")
        #client_sock_android.send(packet)

        #client_sock.close()
        #server_sock.close()





        #bluetooth_socket = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        #bluetooth_socket.connect((hwaddress, server_port_android))
        #bluetooth_socket.sendp()

        #sock.sendp(Ether(dst='00:12:79:d2:b9:67') / IP(src=RandIP(), dst=RandIP()) / ICMP(), iface='iface')
        #send(Ether(dst = hwaddress) / IP(src=packet[IP].src, dst=packet[IP].dst) / UDP(dport=12345, sport=12345) / Raw(packet[Raw].load))
        #sock.send(Ether(dst='00:12:79:d2:b9:67') / IP(src='192.0.10.1', dst='192.0.10.1') / UDP(dport=12345, sport=12345) / Raw(load="message"))
        #sock.sendall("you've got a message from the ground encryptor".encode('utf-8'))
        
    #except OSError as err:
        #print("socket error {err}")

    #finally:
        #sock.close()


def encryptMessage(raw):
    aes = AESCipher('0123456789abcdef0123456789abcdef') # example -> change with diffi hellman result
    return aes.encrypt(raw)

def decryptMessage(raw):
    aes = AESCipher('0123456789abcdef0123456789abcdef') # example -> change with diffi hellman result
    return aes.decrypt(raw)        

def handle_info_from_ESP():
    while True:
        raw_data = ESP_socket.recv(1024)
        if not raw_data: break
        packet = IP(raw_data) # converts to scapy
        #print(packet.show())
        packet = decrypt_payload(packet)
        print(packet.show())
        send(packet)

    #ESP_socket.close()
    #print('ESP disconnected')

def handle_info_to_drone():
    sniff(filter="ip dst 192.0.10.1", prn=packet_callback)
    #ip1 = esp, ip2 = android

def main():
    # start a new thread to listen to ESP (get location)
    #, args=()
    server_thread = threading.Thread(target=handle_info_from_ESP)
    server_thread.start()
    # start a new thread to route to ESP or Android (instructions)
    router_thread = threading.Thread(target=handle_info_to_drone)
    router_thread.start()    

if __name__ == '__main__':
    main()