#from scapy.all import sniff
from scapy.all import *
import keyboard
#from scapy import packet

def packet_callback(packet):
    print("packet summary " + packet.summary())
    #scapy_packet = IP(packet.get_payload())
    print(packet.show())
    packet = modify_payload(packet)
    print(packet.show())

def modify_payload(packet):
    if Raw in packet:
        packet[Raw].load = ("modified").encode()
    return packet

def check_keyboard():
    if (keyboard.is_pressed('q')):
            return False
    return True        

def main():
    try:
        sniffing = True;
        while sniffing:
            sniff(prn=packet_callback, stop_filter=lambda x: keyboard.is_pressed('q'))
            sniffing = check_keyboard()
            

    except KeyboardInterrupt:
        print("Sniffing stopped")        

if __name__ == '__main__':
    main()

[{'Device': 'eth0',
  'Flags': '0x2',
  'HW address': '00:12:79:d2:b9:67',
  'HW type': '0x1',
  'IP address': '10.3.0.1',
  'Mask': '*'}]

