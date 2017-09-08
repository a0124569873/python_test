/*
 * multi_thread_socket_server.c
 *
 *  Created on: Mar 14, 2014
 *      Author: nerohwang
 */
#include<stdlib.h>
#include<pthread.h>
#include<sys/socket.h>
#include<sys/types.h>       //pthread_t , pthread_attr_t and so on.
#include<stdio.h>
#include<netinet/in.h>      //structure sockaddr_in
#include<arpa/inet.h>       //Func : htonl; htons; ntohl; ntohs
#include<assert.h>          //Func :assert
#include<string.h>          //Func :memset
#include<unistd.h>          //Func :close,write,read
#define SOCK_PORT 9988
#define BUFFER_LENGTH 1024
#define MAX_CONN_LIMIT 512     //MAX connection limit

struct mypara
{
    int thread_id;
    char *thread_name;
};

static void Data_handle(char a[]);   //Only can be seen in the file



int main()
{

    struct mypara para;  
    para.thread_id = 1;  
    para.thread_name = "recv"; 
    pthread_t thread_id;

    pthread_create(&thread_id,NULL,(void *)(&Data_handle),&para);
    printf("gfgfdgdfg");
}

static void Data_handle(void *a)
{
    struct mypara *ps;
    ps = (* struct mypara)a;
    printf(ps->thread_id);
    printf("\n");
    pthread_exit(NULL);   //terminate calling thread!
}
