import socket

HOST = "127.0.0.1"
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.bind((HOST, PORT))
  s.listen()
  addr, conn = s.accept()
  with conn:
    print(f"Connected by {address}")
    while True:
      data = conn.recv(1024)
      if not data:
        break
      conn.sendall(data)

   
