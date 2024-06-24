import socket

server_port = 8820
destanation_address = '127.0.1.1'

client = socket.socket()
client.connect((destanation_address, server_port))

client.send("I am a CLIENT".encode())
from_server = client.recv(1024).decode()
print("server sent:" + from_server)

client.close()