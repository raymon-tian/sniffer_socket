/*************************************************************************
    > File Name: scanner.c
    > Author: 161320118 wangdong
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
#include <string.h>
#define MAX 256

/*************************************工具类函数**********************************/
//通过ping判断某一ip是否可达
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
//解析一条命令
void parse(char *com,char *result[]){
	char sub[] = " ";
	char *p;
	int i=0;
	p = strtok(com,sub);
	if(!p)	return;
	result[i] = p;
	++i;
	while((p=strtok(NULL,sub))){
		result[i] = p;
		++i;	
	}
	result[i] = NULL;
}
/*************************************功能类函数及数据结构**********************************/
//定义扫描一台主机所需的数据结构
typedef struct port_stage{
	//ip地址结构
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
		if(hptr == NULL)	printf("\t\t\t\t\tip:%s\thostname:unkown\tport:%d\n",inet_ntoa(des_add->sin_addr),ntohs(des_add->sin_port));
		else	printf("\t\t\t\t\tip:%s\thostname:%s\tport:%d\n",inet_ntoa(des_add->sin_addr),hptr->h_name,ntohs(des_add->sin_port));
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

//扫描指定ip的指定port
int do_scan1(struct sockaddr_in serv_addr){
    int conn_fd;    //socket描述符
    int ret;
    socklen_t len;
    //socket
    conn_fd = socket(AF_INET,SOCK_STREAM,0);
    if(conn_fd < 0){
        perror("error:socket\n");
	return 0;
    }
    len = sizeof(serv_addr);
    //向服务器发送连接请求
    ret = connect(conn_fd,(struct sockaddr *)&serv_addr,len);
    if(ret < 0){
        if(errno == ECONNREFUSED){
            //目标端口未打开
            close(conn_fd);
            return 0;
        }else{
            //其他错误
            close(conn_fd);
            return -1;
        }
    }else if(ret == 0){
        //连接成功,说明端口已经打开
        printf("IP = %s\tPort:%d\n",inet_ntoa(serv_addr.sin_addr),ntohs(serv_addr.sin_port));
        close(conn_fd);
        return 1;
    }
    return -1;
}

//线程函数，扫描指定ip的指定端口区间（非阻塞）
void *scanner1(void *arg){
	port_info pi;
	struct sockaddr_in des_addr;
	unsigned short int i;

	memcpy(&pi,arg,sizeof(pi));
	des_addr.sin_family = AF_INET;
	des_addr.sin_addr.s_addr = pi.dest_ip.s_addr;
	for(i=pi.begin_port;i<=pi.end_port;++i){
		des_addr.sin_port = htons(i);
		do_scan1(des_addr);
	}
	return NULL;
}

//扫描一个网段
void scan_segment(char *argv[]){
	//目的ip
	struct in_addr dest_ip;
	pthread_t *pthreads;
	int port_len,pthread_num;
	int i;
	//扫描主机端口的最大值
	int max_port;
	//起始ip地址，结束ip地址
	uint32_t begin_ip,end_ip;
	int argc = 0;
	while(argv[argc])	++argc;
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
		//printf("scanning ... %s\n",ip_str);
		pthreads = (pthread_t *)malloc(sizeof(pthread_t)*pthread_num);
		port_info *pi;
		pi = (port_info *)malloc(sizeof(port_info)*pthread_num);
		for(i=0;i<pthread_num;++i){
			pi[i].dest_ip.s_addr = htonl(begin_ip);
			pi[i].begin_port = i*port_len;
			if(i == pthread_num -1){
				pi[i].end_port = max_port;
			}else{
				pi[i].end_port = pi[i].begin_port +port_len-1;
			}
			pthread_create(&pthreads[i],NULL,scanner,(void *)&pi[i]);
		}
		for(i=0;i<pthread_num;++i){
			pthread_join(pthreads[i],NULL);
		}
		free(pthreads);
		free(pi);
	}
}
//根据主机名扫描一个主机
void scan_host_by_ip(char *argv[]){
	int max_port;
	int port_len;
	struct in_addr d_ip;
	max_port = atoi(argv[1]);
	inet_aton(argv[2],&d_ip);
	port_info des;
        des.dest_ip = d_ip;
        des.begin_port = 0; //最小端口号从1开始
       	des.end_port = max_port;
        pthread_t pthread;
	pthread_create(&pthread,NULL,scanner1,(void *)&des);
	pthread_join(pthread,NULL);
}

#define MAX 255

char *cmd[MAX][MAX];
int cmd_total;

void get_sub_cmd(int loc,char *command){
	char *p;
	char sub[] = " ";
	int i = 0;
	p = strtok(command,sub);
	if(p!=NULL){
		cmd[loc][0] = p;
		++i;
	}
	while((p=strtok(NULL,sub))){
		cmd[loc][i] = p;
		++i;
	}
	cmd[loc][i] = NULL;
}
void get_cmd(char *command){
	char *p;
	char sub[] = "|";
	cmd_total = 0;
	p = strtok(command,sub);
	if(p!=NULL){
		cmd[0][0]=p;
		++cmd_total;
	}
	while((p=strtok(NULL,sub))){
		cmd[cmd_total][0]=p;
		++cmd_total;
	}
	int i;
	cmd[cmd_total][0]=NULL;
	for(i=0;i<cmd_total;++i){
		get_sub_cmd(i,cmd[i][0]);
	}
}
void print_cmd(){
	int i,j;
	for(i=0;i<cmd_total;++i){
		j=0;
		while(cmd[i][j]!=NULL){
			printf("%s\t",cmd[i][j]);
			++j;
		}
		printf("\n");
	}
}
void set_cmd(){
	int i;
	for(i=0;i<cmd_total;++i){
		cmd[i][0]=NULL;
	}
	cmd_total=0;
}
//界面展示
void display(){
	printf("   *********************************************************************************\n");
	printf("   *  1:scan a network segment in LAN                                              *\n");
	printf("   *  Usage: scan [-b] [begin_ip] [-e] [end_ip] [-m] [max_port] [-n] [thread_num]  *\n");
	printf("   *  2:scan a host by the ip in LAN                                               *\n");
	printf("   *  Usage: scan [max_port] [des_address]                                         *\n");
	printf("   *  3:exit scanner                                                               *\n");
	printf("   *********************************************************************************\n");
}

void my_system(){
	char choice;
	char com[MAX];
	char *com_parsed[MAX];
	char c;
	display();
	printf("please input one of the numbers above\n");
	c = getchar();
	getchar();
	while(1){
		if(c == '1'){
			printf("please input the command\n");
			gets(com);
			parse(com,com_parsed);
			//system("clear");
			scan_segment(com_parsed);	
		}	
		if(c == '2'){
			printf("please input the command\n");
			gets(com);
			parse(com,com_parsed);
			//system("clear");
			scan_host_by_ip(com_parsed);		
		}
		if(c == '3')	break;
		//system("pause");
		//system("clear");
		display();
		printf("please input one of the numbers above\n");
		c = getchar();
		getchar();
	}
			
}
int main(int argc, char *argv[]){
	my_system();
	return 0;
}
