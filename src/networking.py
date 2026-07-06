import socket

HOST = "127.0.0.1"
PORT = 5000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()

print("waiting for connection...")



conn, addr = s.accept()
print("connected:", addr)

data = conn.recv(1024)
print("got:", data.decode())

conn.close()
s.close()

   
