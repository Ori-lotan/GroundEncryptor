import os
import time
import socket
import random
from dotenv import load_dotenv

load_dotenv()

G = 3
PRIVATE_KEY = random.getrandbits(10)
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

def first_drone_encryptor(host, port):
    socketclient = socket.socket()
    socketclient.connect((host, port))

    generated_key = pow(G, PRIVATE_KEY) % P
    client_generated_key = int(socketclient.recv(1024).decode())
    socketclient.send(str(generated_key).encode())

    secret_key = pow(client_generated_key, PRIVATE_KEY) % P
    print('drone 1 shares secret key {}'.format(secret_key))

    while True:
        print('sending data to ground encryptor...')
        time.sleep(5)

if __name__ =="__main__":
    FIRST_DRONE_HOST = os.environ["first-drone-host"]
    FIRST_DRONE_PORT = int(os.environ["first-drone-port"])

    first_drone_encryptor(FIRST_DRONE_HOST, FIRST_DRONE_PORT)
