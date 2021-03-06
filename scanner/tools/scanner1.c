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
 
//端口扫描程序TCP（多线程实现）
#define DEBUG 1
//错误处理函数
void my_err(const char *error_string,int line)
{
    if(error_string == NULL)
        return;
    fprintf(stderr,"line : %d\n",line);
    perror(error_string);
    exit(-1);
}
 
//定义一个端口区间的信息
typedef struct _Port{
    struct in_addr dest_ip;             //目的IP
    unsigned short int min_port;        //最小的端口号
    unsigned short int max_port;        //最大的端口号
}Port;
 
//扫描某一个IP的某一个端口
int do_scan(struct sockaddr_in serv_addr)
{
    int conn_fd;    //socket描述符
    int ret;
    socklen_t len;
    //socket
    conn_fd = socket(AF_INET,SOCK_STREAM,0);
    if(conn_fd < 0){
        my_err("socket",__LINE__);
    }
    len = sizeof(serv_addr);
    //printf("ip = %s\n",inet_ntoa(serv_addr.sin_addr));
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
        printf("Port:%d, IP = %s\n",ntohs(serv_addr.sin_port),inet_ntoa(serv_addr.sin_addr));
        close(conn_fd);
        return 1;
    }
    return -1;
}
 
//执行扫描的线程的启动函数，扫描某一个区间的端口
void *scaner(void *arg)
{
    int ret;
    unsigned short int i;       //端口号
    struct sockaddr_in serv_addr; //
    Port port; //端口区间的信息
 
    //通过参数arg传递端口信息
    memcpy(&port,arg,sizeof(Port));
    //printf("min port = %d\n",port.min_port);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = port.dest_ip.s_addr;
    //printf("ip = %s\n",inet_ntoa(serv_addr.sin_addr));
    for(i = port.min_port;i < port.max_port;i++){
        serv_addr.sin_port = htons(i);
        ret = do_scan(serv_addr);
        if(ret < 0)continue; //出错则退出进程
    }
    return NULL;
}
 
//命令行参数 -m 最大端口 -a 目标主机的IP地址  -n最大线程数
int main(int argc, char **argv) {
    pthread_t * thread; //指向所有线程的指针
    int max_port;   //最大端口号
    int thread_num; //最大线程数
    int port_len;       //区间端口的长度
    struct in_addr dest_ip; //目的主机IP
    int     i;
 
    if(argc != 7){
        printf("Usage: [-m] [max_port] [-a] [serv_address] [-n] [thread_num]\n");
        exit(-1);
    }
 
    //解析命令行参数
    for(i = 1;i < argc;i++){
        if(strcmp("-m",argv[i]) == 0){
            max_port = atoi(argv[i+1]); //端口，将字符串转换为相应的整数
            if(max_port < 0 || max_port >65535){
                printf("Usage:Ivalid max dest port\n");
                exit(-1);
            }
#ifdef DEBUG
            printf("%d\n",max_port);
#endif
            continue;
        }
 
        if(strcmp("-a",argv[i])== 0){
	
		
            if(inet_aton(argv[i+1],&dest_ip) == 0){//把字符串点分ip地址转换成网络ip地址
                printf("Usage:Ivalid dest ip\n");
                exit(-1);
            }
#ifdef DEBUG
            printf("%s\n",argv[i+1]);
#endif
            continue;
        }
 
        if(strcmp("-n",argv[i]) == 0){
            thread_num = atoi(argv[i+1]);
            if(thread_num <= 0){
                printf("Usage:Ivalid thread number\n");
                exit(-1);
            }
#ifdef DEBUG
            printf("%d\n",thread_num);
#endif
            continue;
        }
    }
    //如果输入的最大端口号小于线程数,将线程数设为最大的端口号
    if(max_port < thread_num){
        thread_num = max_port;
    }
    port_len = max_port /thread_num;    //端口区间的最大长度(每个线程处理的端口数)
    if(max_port % thread_num != 0){
        port_len++;
    }
 
    //分配处理所有线程的空间
    thread = (pthread_t *)malloc(sizeof(pthread_t)* thread_num);
    if(thread == NULL){
        my_err("malloc thread",__LINE__);
    }
    
    //创建线程，根据最大端口号和线程数分配每个线程扫描的端口区间
    for(i = 0;i <thread_num;i++){
        Port port;
	
        port.dest_ip = dest_ip;  //可以直接赋值
        //printf("ip = %s\n",inet_ntoa(port.dest_ip));
        port.min_port = i*port_len+1; //最小端口号从1开始
        if(i == thread_num -1){
            port.max_port = max_port;
        }else{
            port.max_port = port.min_port + port_len -1;
        }
        //创建线程
        if(pthread_create(&thread[i],NULL,scaner,(void *)&port) != 0)
        {
            my_err("pthread_create",__LINE__);
        }
        //主线程等待子线程结束
        pthread_join(thread[i],NULL);
    }
    if(thread){
        free(thread);
    }
    return 0;
}
