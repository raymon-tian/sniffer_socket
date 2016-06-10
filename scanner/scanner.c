/*************************************************************************
    > File Name: scanner.c
    > Created Time: 2016年06月10日 星期五 11时30分10秒
 ************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
//判断某一ip是否可达
int ping(char *ip){
	char cmd[128];
	char result[128];
	result[0] = '\0';
	sprintf(cmd,"ping -c 1 %s | grep ttl",ip);
	FILE *pp = popen(cmd,"r");
	fgets(result,sizeof(result),pp);
	pclose(pp);
	if(result[0] == '\0')	return 0;
	else return 1;
}
//ip字符串转换为uint32_t
uint32_t ip_to_uint32_t(const char *ip){
	return ntohl(inet_addr(ip));
}
//uint32_t转换为ip字符串
void uint32_t_to_ip(uint32_t ip_num,char *ip){
	struct in_addr inaddr;
	inaddr.s_addr = htonl(ip_num);
	strcpy(ip,inet_ntoa(inaddr));
}
//定义一次扫描所需的数据结构
typedef struct port_stage{
	//ip地址
	struct in_addr dest_ip;
	//起始端口
	unsigned short int begin_port;
	//结束端口
	unsigned short int end_port;
}port_info;

//扫描指定ip的指定port
void do_scan(struct sockaddr_in *des_add){
	int sock_fd;
	int result;
	socklen_t len;
	struct hostent *hptr;

	//printf("%s\n",inet_ntoa(des_add->sin_addr));
	if((sock_fd = socket(AF_INET,SOCK_STREAM,0)) < 0){
		perror("error: socket\n");
		return;
	}
	//设置为非阻塞模式
	int flags = fcntl(sock_fd,F_GETFL,0);
	fcntl(sock_fd,F_SETFL,flags|O_NONBLOCK);
	//建立连接
	len = sizeof(*des_add);
	result = connect(sock_fd,(struct sockaddr*)des_add,len);
	if(result && errno != EINPROGRESS){
		close(sock_fd);
		return;
	}
	if(result == 0){
		//connect连接成功，恢复套接字阻塞状态
		fcntl(sock_fd,F_SETFL,flags);
		hptr = gethostbyaddr(&(des_add->sin_addr),4,AF_INET);
		printf("ip:%s\thostname:%s\tport:%d\n",inet_ntoa(des_add->sin_addr),hptr->h_name,ntohs(des_add->sin_port));
		close(sock_fd);
		return;
	}
	//连接失败，设置等待或者超时
	fd_set rd,wd,ed;
	FD_ZERO(&rd);
	FD_SET(sock_fd,&rd);
	wd = rd;
	ed = rd;
	int maxfd = sock_fd;
	struct timeval tv = {0,3000};
	int ret = select(maxfd+1,&rd,&wd,&ed,&tv);
	int val;
	if(ret <= 0){
		close(sock_fd);
		return;
	}else{
		if(!FD_ISSET(sock_fd,&rd)&&!FD_ISSET(sock_fd,&wd)){
			close(sock_fd);
			return;
		}
		if(getsockopt(sock_fd,SOL_SOCKET,SO_ERROR,&val,&len)<0){
			close(sock_fd);
			return;
		}
		if(val!=0){
			close(sock_fd);
			return;
		}
		//connect正确返回，恢复阻塞状态
		fcntl(sock_fd,F_SETFL,flags);
		hptr = gethostbyaddr(&(des_add->sin_addr),4,AF_INET);
		//if(hptr == NULL)	printf("sfsdfsfsdff\n");
		//printf("ip:%s\thostname:%s\tport:%d\n",inet_ntoa(des_add->sin_addr),hptr->h_name,ntohs(des_add->sin_port));
		printf("ip:%s\t:%d\n",inet_ntoa(des_add->sin_addr),ntohs(des_add->sin_port));
		close(sock_fd);
	}
}
//线程函数，扫描指定ip的指定端口区间
void *scanner(void *arg){
	port_info pi;
	struct sockaddr_in des_addr;
	unsigned short int i;

	memcpy(&pi,arg,sizeof(pi));
	des_addr.sin_family = AF_INET;
	des_addr.sin_addr.s_addr = pi.dest_ip.s_addr;
	for(i=pi.begin_port;i<=pi.end_port;++i){
		//printf("%d\n",i);	
		des_addr.sin_port = htons(i);
		do_scan(&des_addr);
	}
	return NULL;
}

int main(int argc, char *argv[]){
	//目的ip
	struct in_addr dest_ip;
	pthread_t *pthreads;
	int port_len,pthread_num;
	int i;
	//扫描主机端口的最大值
	int max_port;
	uint32_t begin_ip,end_ip;

	if(argc != 9){
		printf("Usage: [-b] [begin_ip] [-e] [end_ip] [-m] [max_port] [-n] [thread_num]\n");
		exit(-1);
	}
	for(i=1;i<argc;++i){
		if(strcmp("-m",argv[i]) == 0){
			max_port = atoi(argv[i+1]);
			if(max_port<0 || max_port> 65535){
				printf("Usage:Invalid port number\n");
				exit(-1);
			}
			++i;
		}
		if(strcmp("-b",argv[i]) == 0){
			if(inet_aton(argv[i+1],&dest_ip) == 0){
				printf("Usage:Invalid ip address\n");
				exit(-1);
			}
			begin_ip = ip_to_uint32_t(argv[i+1]);
			++i;
		}
		if(strcmp("-e",argv[i]) == 0){
			if(inet_aton(argv[i+1],&dest_ip) == 0){
				printf("Usage:Invalid ip address\n");
				exit(-1);
			}
			end_ip = ip_to_uint32_t(argv[i+1]);
			++i;
		}
		if(strcmp("-n",argv[i]) == 0){
			if((pthread_num = atoi(argv[i+1])) < 0){
				printf("Usage:Invalid thread address\n");
				exit(-1);
			}
		}
	}
	
	if(max_port+1 < pthread_num){
		pthread_num = max_port+1;
	}
	i = 0;
	while((max_port+1+i) % pthread_num != 0){
		++i;
	}
	port_len = (max_port+1+i)/pthread_num;
	char ip_str[256];
	for(;begin_ip <= end_ip;++begin_ip){
		uint32_t_to_ip(begin_ip,ip_str);
		/*
		if(ping(ip_str) == 0){
			printf("%s\n",ip_str);
			continue;
		}*/
		printf("正在扫描 ... %s\n",ip_str);
		pthreads = (pthread_t *)malloc(sizeof(pthread_t)*pthread_num);
		for(i=0;i<pthread_num;++i){
			port_info pi;
			pi.dest_ip.s_addr = htonl(begin_ip);
			pi.begin_port = i*port_len;
			if(i == pthread_num -1){
				pi.end_port = max_port;
			}else{
				pi.end_port = pi.begin_port +port_len-1;
			}
			pthread_create(&pthreads[i],NULL,scanner,(void *)&pi);
			pthread_join(pthreads[i],NULL);
		}
		free(pthreads);
	}
	return 0;
}
