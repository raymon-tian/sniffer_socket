#include <stdio.h>
#include <string.h>

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

int main(){
	char com[100];
	int i=0;
	char *c[10];
	gets(com);
	printf("%s\n",com);
	parse(com,c);
	while(c[i]){
		printf("%s\n",c[i]);
		++i;	
	}
	return 0;
}
