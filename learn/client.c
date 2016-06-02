/*************************************************************************
    > File Name: client.c
    > Created Time: 2016年06月02日 星期四 15时41分46秒
 ************************************************************************/

#include<stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char *argv[]){
	//socket文件描述符
	int sockfd;
	//服务器端套接口地址结构
	struct sockaddr_in saddr;
	int len;
	char buffer[BUFSIZ];

	memset(&saddr,0,sizeof(struct sockaddr_in));
	//设置为ipv4通信
	saddr.sin_family = AF_INET;
	//设置server ip
	//inet_pton(AF_INET,"127.0.0.1",&saddr.sin_addr.s_addr);
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	//设置server port
	saddr.sin_port = htons(8001);
	
	//创建socket，设置ipv4协议族,流套接字，tcp协议
	sockfd = socket(AF_INET,SOCK_STREAM,0);
	if(sockfd < 0){
		perror("socket error\n");
		return 1;
	}
	if(connect(sockfd,(struct sockaddr *)&saddr,sizeof(struct sockaddr)) != 0){
		perror("connect error\n");
		return 1;
	}
	printf("请输入要发送的信息:\n");
	gets(buffer);
	len = strlen(buffer);
	while(strcmp(buffer,"exit") != 0){
		len = send(sockfd,buffer,len,0);
		len = recv(sockfd,buffer,BUFSIZ,0);
		buffer[len] = '\0';
		printf("收到服务器消息:%s\n",buffer);
		printf("请输入要发送的信息:\n");
		gets(buffer);
		len = strlen(buffer);
	}
	//close(sockfd);
	return 0;
}
