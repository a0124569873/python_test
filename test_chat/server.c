#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
	int sock_cli = socket(AF_UNIX,SOCK_STREAM,0);
	int sock_server = socket(AF_UNIX,SOCK_STREAM,0);




	struct sockaddr_un servaddr,cliaddr;
	memset(&servaddr,0,sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path,"/tmp/aaa");

	unlink("/tmp/aaa");
	bind(sock_server,(struct sockaddr *)&servaddr,sizeof(servaddr));
	listen(sock_server,5);
	char tmp[50];
	socklen_t clilen = sizeof(cliaddr);
	while(1){
		sock_cli = accept(sock_server,(struct sockaddr *)&servaddr,&clilen);
		memset(tmp,0,sizeof(tmp));
		int len = recv(sock_cli,tmp,sizeof(tmp),0);
		send(sock_cli,tmp,len,0);
		close(sock_cli);
	}
	close(sock_server);
}