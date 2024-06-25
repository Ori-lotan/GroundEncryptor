import socket
import base64
from AESCipher import AESCipher
import rsa
import base64


def encryptMessage(raw, private_key):
    aes = AESCipher('0123456789abcdef0123456789abcdef')  # example -> change with diffi hellman result
    encrypted = aes.encrypt(raw, private_key)

    #signature = base64.b64encode(rsa.sign(encrypted, private_key, 'SHA-512'))
    #message_with_signature = encrypted + signature

    #return message_with_signature
    return encrypted

def run_client():
    # create a socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_ip = "127.0.0.1"  # replace with the server's IP address
    server_port = 8000  # replace with the server's port number
    # establish connection with server
    client.connect((server_ip, server_port))
    (public_key, private_key) = rsa.newkeys(1024)
    try:
        client.send(public_key.save_pkcs1())  # for the server to decrypt user messages
        server_key = client.recv(2048)  # used to decrypt server messages

        while True:
            # get input message from user and send it to the server
            msg = input("[CLIENT] Enter message: ")
            client.send(encryptMessage(msg, private_key))

            # receive message from the server
            response = client.recv(1024)
            response = response.decode("utf-8")

            print(f"[CLIENT] Received: {response}")
    except Exception as e:
        print(f"[CLIENT] Error: {e}")
    finally:
        # close client socket (connection to the server)
        client.close()
        print("[CLIENT] Connection to server closed")


run_client()
