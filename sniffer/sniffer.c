/*************************************************************************
    > File Name: sniffer.c
    > Created Time: 2016年06月09日 星期四 13时13分35秒
 ************************************************************************/

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

//偏移量：从数据帧开始偏移一定距离从能到达网络层数据包头部
int offset = -1;
pcap_t * pd;

//根据数据链路层类型获取对应的偏移量
void get_offset(){
	//获取数据链路层类型
	int link_type;	
	if((link_type = pcap_datalink(pd)) < 0){
		printf("pcap_datalink() %s\n",pcap_geterr(pd));
		return;
	}
	//获取对应的偏移量
	switch(link_type){
		//BSD Loopback
		case DLT_NULL:
			offset = 4;
			break;
		//Ethernet 10/100/1000 Mbs
		case DLT_EN10MB:
			offset = 14;
			break;
		case DLT_SLIP:
		case DLT_PPP:
			offset = 24;
			break;
		//Wi-Fi 802.11
		case DLT_IEEE802_11:
			offset = 22;
			break;
		default:
			printf("Unsupported datalink (%d)\n",link_type);
			break;
	}
}

//解析数据包 参数1：标志数据包 参数2：数据包信息 参数3：整个数据包
void parse_packet(u_char *user,struct pcap_pkthdr *packetthdr,u_char *packetptr){
	struct ip *iphdr;
	struct icmphdr *icmphdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	char iphdr_info[256],src_ip[256],des_ip[256];
	unsigned short id,seq;

	//剥离数据链路层头部，解析网络层头部
	packetptr +=  offset;
	iphdr = (struct ip*)packetptr;//强制类型转换，按照ip结构类型解析数据
	strcpy(src_ip,inet_ntoa(iphdr->ip_src));
	strcpy(des_ip,inet_ntoa(iphdr->ip_dst));
	sprintf(iphdr_info,"ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
			ntohs(iphdr->ip_id),iphdr->ip_tos,iphdr->ip_ttl,
			4*iphdr->ip_hl,ntohs(iphdr->ip_len));
	//剥离网络层头部，解析传输层协议
	packetptr += 4*iphdr->ip_hl;
	switch(iphdr->ip_p){
		//TCP协议
		case IPPROTO_TCP:
			tcphdr = (struct tcphdr*)packetptr;
			printf("TCP %s:%d -> %s:%d\n",src_ip,ntohs(tcphdr->source),
					des_ip,ntohs(tcphdr->dest));
			printf("%s\n",iphdr_info);
			printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);	
			packetptr += 4*tcphdr->doff;
			break;
		//UDP协议
		case IPPROTO_UDP:
			udphdr = (struct udphdr*)packetptr;
			printf("UDP  %s:%d -> %s:%d\n", src_ip, ntohs(udphdr->source),des_ip, ntohs(udphdr->dest));
			printf("%s\n",iphdr_info);
			packetptr += 8;
			break;
		//ICMP协议
		case IPPROTO_ICMP:
			icmphdr = (struct icmphdr*)packetptr;
			printf("ICMP %s -> %s\n",src_ip,des_ip);
			printf("%s\n",iphdr_info);
			memcpy(&id,(u_char*)icmphdr+4,2);
			memcpy(&id,(u_char*)icmphdr+6,2);
			printf("Type:%d Code:%d ID:%d Seq:%d\n",icmphdr->type,icmphdr->code,ntohs(id),ntohs(seq));
			packetptr += 8;
			break;
	}
	//剥离传输层首部，解析应用层协议
	printf("%s\n",packetptr);
    printf(
        "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}
//处理结束部分
void handle(int sign){
	struct pcap_stat stats;
	if(pcap_stats(pd,&stats) >= 0){
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n\n", stats.ps_drop);
	}
	pcap_close(pd);
	exit(0);
}
int main(){

	//错误信息
	char err_buf[PCAP_ERRBUF_SIZE],*device_name;
	//过滤字符串
	char bpfstr[256] = "";
	//设置：一直抓取数据包，直到遇到错误
	int packet_num = -1;
	//pcap自动选择网络接口，eth0 wlan0
	device_name = pcap_lookupdev(err_buf);
	if(device_name){
		printf("success: have found the device %s\n",device_name);
	}else{
		printf("error: pcap_lookupdev %s\n",err_buf);
		return 0;
	}

	//打开网络设备
	if((pd = pcap_open_live(device_name,BUFSIZ,1,0,err_buf)) == NULL){
		printf("error: pcap_open_live %s\n",err_buf);
		return 0;
	}

	//获取网络设备信息：ip地址，子网掩码
	//uint32_t local_ip,local_netmask;
	bpf_u_int32 local_ip,local_netmask;
	if(pcap_lookupnet(device_name,&local_ip,&local_netmask,err_buf) < 0){
		printf("error: pcap_lookupnet %s\n",err_buf);
		return 0;
	}
	//编译过滤规则
	struct bpf_program bpf;
	if(pcap_compile(pd,&bpf,bpfstr,0,local_netmask)){
		printf("pcap_complie():	%s\n",pcap_geterr(pd));
		return 0;
	}
	//应用过滤规则
	if(pcap_setfilter(pd,&bpf) < 0){
		printf("pcap_compile(): %s\n",pcap_geterr(pd));
		return 0;
	}
	//根据数据链路层类型，获取偏移量
	get_offset();
	if(offset == -1){
		return 0;
	}
	//数据包抓取并解析
	signal(SIGINT,handle);
	signal(SIGTERM,handle);
	signal(SIGQUIT,handle);
	if(pcap_loop(pd,packet_num,(pcap_handler)parse_packet,0) < 0){
		printf("pcap_loop failed: %s\n",pcap_geterr(pd));
	}
	signal(0,handle);
	return 0;
}
