#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<stdlib.h>
#include <sys/time.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <pthread.h>
 
#define PORT 8000
#define MAXDATASIZE 100
#define GROUP "230.1.1.78"

 
int main()
{
	int UDP_socket , TCP_socket,connect_fd;
	struct sockaddr_in server;
	struct sockaddr_in client;
	fd_set fds; 
	struct timeval timeout={3,0};
	int num;
	int maxfd = 0;
	char buf[MAXDATASIZE];
	struct ip_mreq mreq; 

 	memset(&mreq, 0, sizeof(struct ip_mreq));
	memset(&client, 0, sizeof(struct sockaddr_in));
    
	bzero(&server,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_port=htons(PORT);
	server.sin_addr.s_addr= htonl (INADDR_ANY);

	socklen_t  addrlen;
	addrlen=sizeof(server);
	
 /*********************************************UDP***********************************/
	if((UDP_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) 
	{
	   perror("Creatingsocket failed.");
	   exit(1);
	}
	
	if(bind(UDP_socket, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
	   perror("UDP_single_Bind()error.");
	   exit(1);
	}   

	if(inet_aton(GROUP, &mreq.imr_multiaddr) < 0) {
		printf("GROUP error\n");
		exit(0);
	}
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);

	if (setsockopt(UDP_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq)) == -1) {  
	    perror("setsockopt");  
	    exit(-1);  
	} 

/**********************************************TCP*************************************/
	if((TCP_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		   perror("Creatingsocket failed.");
		   exit(1);
	}
		
	if(bind(TCP_socket, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
	   perror("TCP_Bind()error.");
	   exit(1);
	}   
	
 	if ( listen(TCP_socket , 10) == -1 ){
		printf("listen socket error\n");
		exit(0);
	}
	pthread_t tcp;
	void* tcp_process(void* parm);
	while(1)  
	{
		FD_ZERO(&fds);
		FD_SET(UDP_socket,&fds);
		FD_SET(TCP_socket,&fds);
		
		if (UDP_socket > maxfd) maxfd = UDP_socket;
		if (TCP_socket > maxfd) maxfd = TCP_socket;
		maxfd += 1;
		
		switch(select(maxfd,&fds,NULL,NULL,&timeout))
		{
			case -1: exit(-1);break; 
			case 0:break; 
			default: 
			if(FD_ISSET(UDP_socket,&fds)) 
			{ 
				num =recvfrom(UDP_socket,buf,MAXDATASIZE,0,(struct sockaddr*)&client,&addrlen);                                   
				if (num < 0)
				{
					perror("recvfrom() error\n");
					exit(1);
				}
				//printf("the adress is :%s\n",inet_ntoa(client.sin_addr));
				buf[num-1] = '\0';
				printf("You got a UDP_Message :%s\n",buf); 
				sendto(UDP_socket,"Welcometo my server.\n",21,0,(struct sockaddr *)&client,sizeof(client));
			}
		
			if(FD_ISSET(TCP_socket,&fds)) {	
				if ((connect_fd = accept(TCP_socket , (struct sockaddr*)NULL , NULL)) == -1) {
					printf("accept socket error: \n");
					continue;
				} else {
					pthread_create(&tcp, NULL, tcp_process,(void *)&connect_fd);
					pthread_detach(tcp);
				}
			}
			
		}
	
	}
	close(UDP_socket);  
	close(TCP_socket);
}


void* tcp_process(void* parm)
{
	int n;
	int connect_fd =* (int *)parm;
	char buf[MAXDATASIZE];
	while(1) {
		n= recv(connect_fd , buf , MAXDATASIZE, 0);					
		if (send(connect_fd , "Hello, you are connected!\n",26 ,0) == -1)
			perror("send error");
			
		buf[n-1] = '\0';
		printf("You got a TCP_Message: %s \n",buf );	
		bzero(&buf,sizeof(buf));
	}
	close(connect_fd);
}