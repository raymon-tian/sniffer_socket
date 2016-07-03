#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int ip_to_uint32_t( const char *ip ){
	return ntohl( inet_addr( ip ) );
}

void uint32_t_to_ip(uint32_t ip_num, char *ip){
	struct in_addr inaddr;
	inaddr.s_addr = htonl(ip_num);
    strcpy(ip,inet_ntoa(inaddr));
}

int main(){
	char p1[] = "192.168.1.1";
	char p2[] = "255.255.255.254";
	printf("%u\t%u\n",ip_to_uint32_t(p1),ip_to_uint32_t(p2));
	uint32_t i = 3232235778;
	uint32_t_to_ip(i,p2);
	printf("%s\n",p2);
	return 0;
}
