#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

static void sighandler(int signo)
{
	if(signo == SIGINT){
		int fd_err = open("error.txt", O_WRONLY | O_CREAT, 0777);
		lseek(fd_err, 0, SEEK_END);
		write(fd_err, "Program exited because of signal SIGINT\n", 41);
		close(fd_err);
		exit(EXIT_FAILURE);
	} else if(signo == SIGUSR1){
		printf("Parent Process: %d\n", getppid());
	}
}

int main()
{
	signal(SIGINT, sighandler);
	signal(SIGUSR1, sighandler);

	while(1){
		printf("Process %d\n", getpid());
		sleep(1);
	}
	return 0;
}
