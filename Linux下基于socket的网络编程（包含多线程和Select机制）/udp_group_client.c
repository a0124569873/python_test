#include <sys/types.h>  
#include <sys/socket.h>  
#include <arpa/inet.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
  
#define BUFLEN 255  
  
int main(int argc, char **argv)  
{  
	struct sockaddr_in groupaddr;  

	int sockfd;  
	char recmsg[BUFLEN],sendmsg[BUFLEN];  
	unsigned int socklen;  
	int num;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
	if (sockfd < 0) {  
	    printf("socket creating error\n");  
	    exit(1);  
	}  
	socklen = sizeof(struct sockaddr_in);  

	memset(&groupaddr, 0, socklen);  
	groupaddr.sin_family = AF_INET;  
	groupaddr.sin_port = htons(8000);  
	 

	inet_pton(AF_INET,"230.1.1.78", &groupaddr.sin_addr);
	

	while(1) {  
		socklen_t  addrlen;
		addrlen=sizeof(groupaddr);
		
		printf("send msg to server: ");
		bzero(sendmsg, BUFLEN + 1);  
		if (fgets(sendmsg, BUFLEN, stdin) == (char *) EOF)  
			exit(0);  
		if (sendto(sockfd, sendmsg, strlen(sendmsg), 0, (struct sockaddr *) &groupaddr, sizeof(struct sockaddr_in)) < 0) {  
			printf("sendto error!\n");  
			exit(3);  
		}  
		if((num=recvfrom(sockfd,recmsg,BUFLEN,0,(struct sockaddr *)&groupaddr,&addrlen))== -1)
		{
			printf("recvfrom() error\n");
			exit(1);
		} 
		
		recmsg[num-1]='\0';
		printf("recvmsg:%s\n",recmsg);
	}  
}  
