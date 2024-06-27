import socket
from scapy.all import *
import keyboard
import threading
from AESCipher import AESCipher
import random
#import bluetooth

def xor_strings(str1, str2):
    max_length = max(len(str1), len(str2))
    str1 = str1.ljust(max_length)
    str2 = str2.ljust(max_length)
    result = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2))
 
    return result  
    
#arp = {'IPaddressAir1':'hwaddressAir1' ESP, 'IPaddressAir2':'hwaddressAir2'} ANDROID
arp = {'192.0.10.1':'00:12:79:d2:b9:67', '10.3.0.2':'00:12:79:d2:b9:68'}

server_ip = '0.0.0.0'
server_port_ESP = 80
server_socket_ESP = socket.socket()
server_socket_ESP.bind((server_ip, server_port_ESP))
print("Server is listening to ESP...")
server_socket_ESP.listen()
(ESP_socket, ESP_address) = server_socket_ESP.accept()
print("ESP connected")


G = 3
PRIVATE_KEY = random.getrandbits(8)
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

generated_key = pow(G, PRIVATE_KEY) % P
ESP_socket.send(str(generated_key).encode())
client_generated_key = int(ESP_socket.recv(1024).decode())

secret_key = pow(client_generated_key, PRIVATE_KEY) % P
print('drone with id {} shares secret key {}'.format(1, secret_key))\

secret_key=str(secret_key)



def packet_callback(packet):
    #print("packet summary " + packet.summary())
    #print(packet.show())

    # ecrypt payload to all packets
    print(packet.show())
    packet = encrypt_payload(packet)
    #print(packet.show())
    send_to_hwaddress(packet)

def modify_payload(packet):
    if Raw in packet:
        packet[Raw].load = ("modified")
    return packet

def encrypt_payload(packet):
    if Raw in packet:
        #packet[Raw].load = encryptMessage(packet[Raw].load.decode())
        packet[Raw].load = xor_strings(secret_key, packet[Raw].load.decode())
        xor_strings(str1, str2)
    return packet

def decrypt_payload(packet):
    if Raw in packet:
        #breakpoint()
        #packet[Raw].load = decryptMessage(packet[Raw].load)
        packet[Raw].load = xor_strings(secret_key, packet[Raw].load)

    return packet

def send_to_hwaddress(packet):
    # ESP IP
    if packet[IP].dst == '192.168.163.37' and packet[IP].src != '192.168.163.84':
        ESP_socket.send(bytes(packet[Raw].load))
        #ESP_socket.send(bytes(packet))
        print("sent packet to ESP".encode())
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
        #packet = IP(raw_data) # converts to scapy
        #print(packet.show())
        #packet = decrypt_payload(packet)
        #print(packet.show())
        #send(packet)
        xor_strings(secret_key, raw_data)
        print(raw_data.decode())

    #ESP_socket.close()
    #print('ESP disconnected')

def handle_info_to_drone():
    sniff(filter="ip dst 192.168.163.37", prn=packet_callback)
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