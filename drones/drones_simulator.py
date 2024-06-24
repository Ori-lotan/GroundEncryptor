import os
import time
import socket
import random
import threading
from dotenv import load_dotenv

P = int(os.environ['p-modulo'])
G = int(os.environ['g-generator'])
PRIVATE_KEY = random.getrandbits(20)

def air_encryptor_key_exchange(host, port, droneId):
    socketclient = socket.socket()
    socketclient.connect((host, port))

    generated_key = pow(G, PRIVATE_KEY) % P
    client_generated_key = int(socketclient.recv(1024).decode())
    socketclient.send(str(generated_key).encode())

    secret_key = pow(client_generated_key, PRIVATE_KEY) % P
    print('drone {} shares secret key {}'.format(droneId, secret_key))

    while True:
        print('sending data to ground encryptor...')
        time.sleep(5)

if __name__ =="__main__":
    load_dotenv()

    FIRST_DRONE_HOST = os.environ["first-drone-host"]
    FIRST_DRONE_PORT = int(os.environ["first-drone-port"])
    SECOND_DRONE_HOST = os.environ["second-drone-host"]
    SECOND_DRONE_PORT = int(os.environ["second-drone-port"])

    first_drone_thread = threading.Thread(
        target=air_encryptor_key_exchange,
        args=(FIRST_DRONE_HOST, FIRST_DRONE_PORT, 1))
    
    second_drone_thread = threading.Thread(
        target=air_encryptor_key_exchange,
        args=(SECOND_DRONE_HOST, SECOND_DRONE_PORT, 2))

    first_drone_thread.start()
    second_drone_thread.start()
