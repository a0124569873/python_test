#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAXLINE 4096
#define PORT 8000
int main(int argc , char **argv)
{
	int sockfd , n , rec_len;
	char recvline[4096], sendline[4096];
	char buf[MAXLINE];
	struct sockaddr_in   server;

	if ((sockfd = socket(AF_INET , SOCK_STREAM , 0)) < 0) {
		printf("create socket error:%s(errno%d)\n",strerror(errno) , errno);
		exit(0);
	}

	memset(&server , 0 ,sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	if (inet_pton(AF_INET , "127.0.0.1" , &server.sin_addr) <= 0) {
		printf("error IP\n");
		exit(0);
	}
	if (connect(sockfd , (struct sockaddr*)&server , sizeof(server)) < 0 ) {
		printf("connect error:%s(errno:%d)\n",strerror(errno) , errno);
		exit(0);
	}

	
	while(1) {	
		printf("send msg to server: ");
		fgets(sendline , 4096 ,stdin);
		if (send (sockfd , sendline ,strlen(sendline) , 0) < 0) {
			printf("send msg error:%s(errno:%d)\n",strerror(errno) , errno);
			exit(0);
		}
		if ((rec_len = recv(sockfd, buf ,MAXLINE ,0)) == -1) {
			printf("recv error\n");
			exit(0);
		}

		buf[rec_len-1] = '\0';
		printf("Received :%s\n ",buf);
		memset(&buf, 0 , sizeof(buf));
	}
	close(sockfd);
	exit(0);
}