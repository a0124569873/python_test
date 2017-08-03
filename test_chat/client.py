import socket,sys
client_sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
client_sock.connect("/tmp/aaa")
client_sock.send("aaaa")
print client_sock.recv(100)
client_sock.close()
