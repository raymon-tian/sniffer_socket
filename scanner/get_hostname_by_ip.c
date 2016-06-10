#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
	char *ptr,**pptr;
	struct hostent *hptr;
	char str[32];
	char ipaddr[16];
	struct in_addr *hipaddr = (struct in_addr *)malloc(sizeof(struct in_addr));

	ptr = argv[1];
	printf("0:%s\n",ptr);
	if(!inet_aton(ptr,hipaddr))
	{
		printf("error1\n");
		return 1;
	}

	if( (hptr = gethostbyaddr(hipaddr,4,AF_INET) ) == NULL)
	{
		h_errno;
		printf("err2 %s\n",ptr);
		switch(h_errno)
		{
		case HOST_NOT_FOUND:printf("111\n");break;
//		case NO_ADDRESS:
//		case NO_DATA:printf("112\n");break;
		case NO_RECOVERY:printf("113\n");break;
		case TRY_AGAIN:printf("115\n");break;
		}
		return 1;
	}

	printf("hostname:%s\n",hptr->h_name);

	for(pptr = hptr->h_aliases; *pptr != NULL; pptr++ )
		printf("%s\n",*pptr);

	switch( hptr->h_addrtype)
	{
		case AF_INET:
		case AF_INET6:
		 	pptr = hptr->h_addr_list;
			for(;*pptr!=NULL;pptr++)
				printf("address:%s\n",inet_ntop(hptr->h_addrtype,*pptr,str,sizeof(str)));
			break;
		default:
			printf("default \n");
			break;
	}

	return 0;
}


