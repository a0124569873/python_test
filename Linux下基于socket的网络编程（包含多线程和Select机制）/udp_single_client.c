#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
 
#define PORT 8000
#define MAXDATASIZE 100
 
int main(int argc, char *argv[])
{
    int sockfd, num;
    int maxfd = 0;
    char buf[MAXDATASIZE];
    char recvline[4096], sendline[4096];
 
    struct sockaddr_in server,backup;
    
    if ((sockfd=socket(AF_INET, SOCK_DGRAM,0))==-1)
    {
       printf("socket() error\n");
       exit(1);
    }
 
    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr= inet_addr("10.112.3.142");
    
    while (1)
    {
    		
		printf("send msg to server: ");
		fgets(sendline , 4096 ,stdin);
		sendto(sockfd, sendline,strlen(sendline),0,(struct sockaddr *)&server,sizeof(server));
		socklen_t  addrlen;
		addrlen=sizeof(server);
				
		if((num=recvfrom(sockfd,buf,MAXDATASIZE,0,(struct sockaddr *)&backup,&addrlen))== -1)
		{
			printf("recvfrom() error\n");
			exit(1);
		}
		if (addrlen != sizeof(server) ||memcmp((const void *)&server, (const void *)&backup,addrlen) != 0)
		{
			printf("Receive message from otherserver.\n");
			continue;
		}
		buf[num-1]='\0';
		printf("Server Message:%s\n",buf);
		
	}
	close(sockfd);
}

