/*************************************************************************
    > File Name: server.c
    > Created Time: 2016年06月02日 星期四 14时58分40秒
 ************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

int main(int argc,char *argv[]){
	pid_t pid;

	struct sockaddr_in client_addr;
	struct sockaddr_in server_addr;

	int listen_socketfd;
	int connected_socketfd;
	//接收到的字节数目
	int len;
	//接收字符串缓冲区
	char buffer[BUFSIZ];
	
	socklen_t sin_size = sizeof(sockaddr_in);

	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(8001);
	
	//打开socket
	listen_socketfd= socket(AF_INET,SOCK_STREAM,0);
	if(listen_socketfd < 0){
		perror("socket error\n");
		return 1;
	}
	//绑定
	if(bind(listen_socketfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr)) != 0){
		perror("bind error\n");
		return 1;
	}
	//监听，设置最大连接数为8
	listen(listen_socketfd,8);

	for(;;){
		connected_socketfd = accept(listen_socketfd,(struct sockaddr *)&client_addr,&sin_size);
		if(connected_socketfd < 0 ){
			perror("accept error\n");
			return 1;
		}
		pid = fork();
		if(pid == 0){
			close(listen_socketfd);
			while((len = recv(connected_socketfd,buffer,BUFSIZ,0))>0){
				buffer[len] = '\0';
				printf("服务器收到：%s\n",buffer);
				send(connected_socketfd,buffer,len,0);
			}
			exit(0);
		}
		close(connected_socketfd);
	}
	return 0;
}
