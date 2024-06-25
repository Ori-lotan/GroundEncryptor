#from scapy.all import sniff
#from scapy import packet
import socket
from scapy.all import *
import keyboard

def packet_callback(packet):
    #print("packet summary " + packet.summary())
    print(packet.show())
    packet = modify_payload(packet)
    print(packet.show())

def modify_payload(packet):
    if Raw in packet:
        packet[Raw].load = ("modified")
    return packet

def send_to_hwaddress(packet):
    try:
        address = encrypter1['HW address']
        port = 2345
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        sock.connect((arp[packet[IP].dst], port))
        #sock.sendp(Ether(dst='00:12:79:d2:b9:67') / IP(src=RandIP(), dst=RandIP()) / ICMP(), iface='iface')
        sock.sendall("message".encode('utf-8'))
    
    except OSError as err:
        print("socket error {err}")

    finally:
        sock.close()

def check_keyboard():
    if (keyboard.is_pressed('q')):
            return False
    return True        

def main():
    sniff(filter="ip dst 192.0.10.1", prn=packet_callback)    

if __name__ == '__main__':
    main()

arp_table = [{'Device': 'encrypter1',
  'Flags': '0x2',
  'HW address': '00:12:79:d2:b9:67',
  'HW type': '0x1',
  'IP address': '10.3.0.1',
  'Mask': '*'},
  {'Device': 'encrypter2',
  'Flags': '0x2',
  'HW address': '00:12:79:d2:b9:68',
  'HW type': '0x1',
  'IP address': '10.3.0.2',
  'Mask': '*'}]

  #arp = [{'10.3.0.1':'00:12:79:d2:b9:67'},
   #      {'10.3.0.2':'00:12:79:d2:b9:68'}]