#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#define MAXDATASIZE 256 //
#define SERVPORT 4444  //服务器监听端口号
#define STDIN 0  //标准输入文件描述符

int main(int argc,char *argv[])
{
	char addr[30];
	int sockfd;
	struct sockaddr_in serv_addr;//Internet套接字地址结构
	char buf[MAXDATASIZE];     //用于处理输入的缓冲区
	char name[MAXDATASIZE];
	char send_str[MAXDATASIZE]; //最多发送的字符不能超过256
	int recvbytes;
	fd_set rfd_set,wfd_set,efd_set; //select()监视读、写、异常处理的文件描述符集合  
	struct timeval timeout; //本次select()的超时结束时间
	int ret; //与server连接的结果

	if(argc<2)
	{
		printf("请输入服务器IP\n");
		fgets(addr,256,stdin);
		argv[1] = (char *)malloc(sizeof(argv[1]));
		strcpy(argv[1],addr);
	}
	
	if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		perror("socker error!");
		exit(1);
	}
	//填充sockaddr结构
	bzero(&serv_addr,sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERVPORT);
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);

	if(connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(struct sockaddr))==-1)
	{
		perror("connect error!");
		exit(1);
	}
	printf("已成功连接到服务器 %s\n",inet_ntoa(serv_addr.sin_addr));
	fcntl(sockfd,F_SETFD,O_NONBLOCK);//服务器设为非阻塞
	printf("要聊天首先要输入你的名字：");
	scanf("%s",name);
	name[strlen(name)] = '\0';
	printf("%s:",name);
	fflush(stdout);
	send(sockfd,name,strlen(name),0);//发送用户名到sockfd

	while(1)
	{
		//将select()监视的读，写，异常文件描述符清除
		FD_ZERO(&rfd_set);
		FD_ZERO(&wfd_set);
		FD_ZERO(&efd_set);
		//将标准输入文件描述符加到select()监视的读文件描述符集合中
		FD_SET(STDIN,&rfd_set);
		//添加新建的描述符加到select()监视的文件描述符中
		FD_SET(sockfd,&rfd_set);
	//	FD_SET(sockfd,&wfd_set);
		FD_SET(sockfd,&efd_set);
		//设置select在被监视窗口等待的时间
		timeout.tv_sec = 10; //秒
		timeout.tv_usec = 0; //微妙
		ret = select(sockfd+1,&rfd_set,&wfd_set,&efd_set,&timeout);
		if(ret==0)
			continue;
		if(ret<0)
		{
			perror("select error!");
			exit(-1);
		}
		//判断是否已将标准输入文件描述符加到select()监视的读的文件描述符集合中
		if(FD_ISSET(STDIN,&rfd_set))
		{
			fgets(send_str,256,stdin);//读取键盘输入的内容
			send_str[strlen(send_str)-1] = '\0';
			if(strncmp("quit",send_str,4)==0)
			{
				close(sockfd);
				exit(0);
			}
			send(sockfd,send_str,strlen(send_str),0);
		}
		//判断是否已将新建的描述符加到select()监视的读的文件描述符集合中
		if(FD_ISSET(sockfd,&rfd_set))
		{
			recvbytes = recv(sockfd,buf,MAXDATASIZE,0);
			if(recvbytes==0)
			{
				close(sockfd);
				exit(0);
			}
			buf[recvbytes] = '\0';
			printf("Server: %s\n",buf);
			printf("%s: ",name);
			fflush(stdout);
		}
		//异常
		if(FD_ISSET(sockfd,&efd_set))
		{
			close(sockfd);
			exit(0);
		}
	}
	
	return 0;
}












