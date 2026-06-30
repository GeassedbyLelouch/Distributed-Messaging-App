import socket

HOST = "127.0.0.1"
PORT = 5000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM):
s.connect((HOST, PORT))

message = "hello from client"
s.sendall(message.encode())

data = s.recv(1024)
print("Received", data.decode())

s.close()
