import socket

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0003))

raw_socket.bind(('eth0',0))

try:
    while True:
        packet = raw_socket.recvfrom(65535)
        packet_content, address = packet
        print(packet_content.hex())

except KeyboardInterrupt:
    print("Sniffing stopped.") 

finally:
    raw_socket.close()