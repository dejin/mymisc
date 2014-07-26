#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/poll.h>



#include "msg.h"

#define MSG_SERVER_ID 		100
#define MSG_CLIENT_ID 		800

int main(int argc, char *argv[])
{
	int res;
	NP *client_port;
	int SID = 0;
	unsigned char buff[2048] = "hello msg";
	int num = 100;
	int i = 0;
	int send_len = 10;
	struct timespec ts, ts1;

	if (argc > 1)
		send_len = atoi(argv[1]);
	if (argc > 2)
		num = atoi(argv[2]);

	client_port = msg_open(MSG_CLIENT_ID);
	if (client_port == NULL) {
		printf("open client socket fail\n");
		return -1;
	}

	printf("test %d times will start\n", num);
	clock_gettime(CLOCK_MONOTONIC, &ts);
	for (i = 0; i < num; i++) {
		res = msg_send(client_port, MSG_SERVER_ID, buff, send_len);
		if (res != 0) {
			printf("Client msg send fail\n");
			return -1;
		} else {
			printf("Client msg send data [%d] ok\n", i*send_len);
		}

		/*res = msg_recv(client_port, &SID, buff, -1);
		if (res < 0) {
			printf("Client msg recv fail\n");
			return -1;
		}*/
	}
	clock_gettime(CLOCK_MONOTONIC, &ts1);
	printf("start time [%ld.%06ld]\n",ts.tv_sec, ts.tv_nsec/1000);
	printf("end   time [%ld.%06ld]\n",ts1.tv_sec, ts1.tv_nsec/1000);

	msg_close(client_port);
	printf("Client msg end\n");
	return 0;
}


