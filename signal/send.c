#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


int main(int argc, char** argv)
{
	pid_t pid;

	if (argc > 1)
		sscanf(argv[1],"%d",&pid);
	printf("will send signal SIGUSR1 to pid %d\n", pid);
	kill(pid, SIGUSR1);
	return 0;
}
