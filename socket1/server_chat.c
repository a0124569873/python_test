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

#define MAXDATASIZE 256 //
#define SERVPORT 4444  //服务器监听端口号
#define BACKLOG 10 //最大连接请求数
#define STDIN 0  //标准输入文件描述符

int main(void)
{
	FILE *fp;
	int sockfd,client_fd;
	int sin_size;
	struct sockaddr_in my_addr,remote_addr;//本机地址信息，客户机地址信息
	char buf[256];     //用于聊天的缓冲区
	char buff[256];			//用于输入用户名的缓冲区
	char send_str[256]; //最多发送的字符不能超过256
	int recvbytes;
	fd_set rfd_set,wfd_set,efd_set; //select()监视读、写、异常处理的文件描述符集合  
	struct timeval timeout; //本次select()的超时结束时间
	int ret; //与client连接的结果

	if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		perror("socker error!");
		exit(1);
	}
	//填充sockaddr结构
	bzero(&my_addr,sizeof(struct sockaddr_in));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(SERVPORT);
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	//解决服务器关掉，启动“Address already in use”的情况
	int on=1;
	setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));
	if(bind(sockfd,(struct sockaddr*)&my_addr,sizeof(struct sockaddr))==-1)
	{
		perror("bind error!");
		exit(1);
	}	
	if(listen(sockfd,BACKLOG)==-1)
	{
		perror("listen error!");
		exit(1);
	}
	sin_size = sizeof(struct sockaddr_in);
	if((client_fd=accept(sockfd,(struct sockaddr*)&remote_addr,&sin_size))==-1)
	{
		perror("accept error!");
		exit(1);
	}
	printf("收到一个连接来自: %s\n",inet_ntoa(remote_addr.sin_addr));
	fcntl(client_fd,F_SETFD,O_NONBLOCK);//服务器设为非阻塞
	recvbytes = recv(client_fd,buff,MAXDATASIZE,0);
	buff[recvbytes] = '\0';
	fflush(stdout);
	if((fp=fopen("name.txt","a+"))==NULL)
	{
		printf("cannot open file,exit...\n");
		return -1;
	}
	fprintf(fp,"%s\n",buff);//将用户名写入到name.txt中

	while(1)
	{
		//将select()监视的读，写，异常文件描述符清除
		FD_ZERO(&rfd_set);
		FD_ZERO(&wfd_set);
		FD_ZERO(&efd_set);
		//将标准输入文件描述符加到select()监视的读文件描述符集合中
		FD_SET(STDIN,&rfd_set);
		//添加新建的描述符加到select()监视的文件描述符中
		FD_SET(client_fd,&rfd_set);
		FD_SET(client_fd,&wfd_set);
		FD_SET(client_fd,&efd_set);
		//设置select在被监视窗口等待的时间
		timeout.tv_sec = 10; //秒
		timeout.tv_usec = 0; //微妙
		ret = select(client_fd+1,&rfd_set,&wfd_set,&efd_set,&timeout);
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
				close(client_fd);
				close(sockfd);
				exit(0);
			}
			send(client_fd,send_str,strlen(send_str),0);
		}
		//判断是否已将新建的描述符加到select()监视的读的文件描述符集合中
		if(FD_ISSET(client_fd,&rfd_set))
		{
			recvbytes = recv(client_fd,buf,MAXDATASIZE,0);
			if(recvbytes==0)
			{
				close(client_fd);
				close(sockfd);
				exit(0);
			}
			buf[recvbytes] = '\0';
			printf("%s: %s\n",buff,buf);
			printf("Server: ");
			fflush(stdout);
		}
		//异常
		if(FD_ISSET(client_fd,&efd_set))
		{
			close(client_fd);
			exit(0);
		}
	}
	
}












