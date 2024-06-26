import wifi
import socketpool
from random import getrandbits
 
G = 3
PRIVATE_KEY = getrandbits(8)
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
TIMEOUT = None
MAXBUF = 2048
 
SSID = 'GO AWAY'
PASSWORD = 'icbo1507'
HOST = ''
PORT = 80
 
wifi.radio.connect(SSID, PASSWORD)
print("ESP32 ip: ", wifi.radio.ipv4_address)
 
def connect_socket():
    socketpool_instance = socketpool.SocketPool(wifi.radio)
    socket = socketpool_instance.socket(socketpool_instance.AF_INET, socketpool_instance.SOCK_STREAM)
    socket.settimeout(TIMEOUT)
    socket.bind((HOST, PORT))
    socket.listen(10)
    print('Listening for connections...')
    conn, addr = socket.accept()
    print('Got connection from', addr)
 
    return conn
 
socket_connection = connect_socket()
 
client_generated_key_bytes = bytearray(MAXBUF)
socket_connection.recv_into(client_generated_key_bytes, MAXBUF)
client_generated_key = int(client_generated_key_bytes.decode().rstrip('\x00'))
 
generated_key = pow(G, PRIVATE_KEY) % P
socket_connection.send(str(generated_key).encode())
 
secret_key = pow(client_generated_key, PRIVATE_KEY) % P
print(f'drone 1 shares secret key {secret_key}')
