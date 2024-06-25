import socket
import threading
from AESCipher import AESCipher
import rsa
import base64

def decryptMessage(message, client_key):
    aes = AESCipher('0123456789abcdef0123456789abcdef') # example -> change with diffi hellman result
    dec = aes.decrypt(message, client_key)
    return dec


def handle_client(client_socket, addr, public_key, private_key):
    try:
        client_socket.send(public_key.save_pkcs1())
        client_key = rsa.PublicKey.load_pkcs1(keyfile=client_socket.recv(1024))

        while True:

            request = client_socket.recv(1024).decode("utf-8")
            decrypted = decryptMessage(request, client_key)

            print(f"[SERVER] Received: {decrypted}")

            response = "OK"
            client_socket.send(response.encode("utf-8"))
    except Exception as e:
        print(f"[SERVER] Error when hanlding client: {e}")
        client_socket.send(f"error sending message->{e}\n closing connection".encode("utf-8"))
    finally:
        client_socket.close()
        print(f"[SERVER] Connection to client ({addr[0]}:{addr[1]}) closed")


def run_server():
    server_ip = "127.0.0.1"  # server hostname or IP address
    port = 8000  # server port number
    # create a socket object
    try:
        (public_key, private_key) = rsa.newkeys(1024)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bind the socket to the host and port
        server.bind((server_ip, port))
        # listen for incoming connections
        server.listen()

        print(f"Listening on {server_ip}:{port}")

        while True:
            # accept a client connection
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr[0]}:{addr[1]}")
            # start a new thread to handle the client
            thread = threading.Thread(target=handle_client, args=(client_socket, addr, public_key, private_key))
            thread.start()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.close()


run_server()
