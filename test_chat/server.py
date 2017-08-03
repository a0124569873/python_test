import socket,sys,threading,os
print "22222"
server_socket = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
if os.path.exists("/tmp/aaa"):
	os.unlink("/tmp/aaa")
server_socket.bind("/tmp/aaa")
server_socket.listen(1)
while 1:
	conn,addr = server_socket.accept()
	data = conn.recv(1024)
	if not data : break
	conn.send(data)
	conn.close()
server_socket.close()
