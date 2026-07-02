import socket
import protocol

HOST = "127.0.0.1"
PORT = 5000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

line = input("Hello! What would you like to send today?: ")

final_line = protocol.encode({
  "Hello from node": line    
})

s.sendall(final_line)

s.close()
