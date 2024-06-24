import socket

server_port = 0

server_socket = socket.socket()
server_socket.bind(("0.0.0.0", server_port))
server_socket.listen()
print("Server is up and running")

while True:
    (client_socket, client_address) = server_socket.accept()
    print("client connected")
    data = client_socket.recv(1024).decode()
    if not data: break
    print("client sent: " + data)
    client_socket.send("I am sever".encode())
    
client_socket.close()
print('client disconnected')