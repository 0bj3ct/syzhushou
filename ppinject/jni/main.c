#include "inject.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
	int pid;
	char *param = NULL;
	int param_size = 0;
	if(argc<4)
		printf("usage:ppinject pid path func [param]\n");
	else
	{
		if(argc == 5)
			param = strlen(param)+1;
		pid = atoi(argv[1]);
		inject_remote_process(pid,argv[2],argv[3],param,param_size);
	}
	//inject_remote_process(pid,"/data/local/tmp/libppdvm.so","HookJdwpProcessRequest",NULL,NULL);
	return 0;
}
