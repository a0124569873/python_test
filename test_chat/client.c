#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/un.h>

int main(){
	int sock_cli = socket(AF_UNIX,SOCK_STREAM,0);

	struct sockaddr_un servaddr;
	memset(&servaddr,0,sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	strcpy (servaddr.sun_path, "/tmp/aaa");
	connect(sock_cli,(struct sockaddr *)&servaddr,sizeof(servaddr));
	char recvbuf[50];
	// while(1){
	send(sock_cli,"aaa",sizeof("aaa"),0);
	recv(sock_cli,recvbuf,sizeof(recvbuf),0);
	fputs(recvbuf,stdout);
	// }
	close(sock_cli);
	return 0;
}