/*************************************************************************
    > File Name: ping.c
    > Created Time: 2016年06月10日 星期五 18时00分06秒
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(int argc,char *argv[]){
	char cmd[128];
	char result[128];
	result[0] = '\0';
	sprintf(cmd,"ping -c 1 %s | grep ttl",argv[1]);
	FILE *pp = popen(cmd,"r");
	fgets(result,sizeof(result),pp);
	pclose(pp);
	printf("%s\n",result);
	return 0;
}
