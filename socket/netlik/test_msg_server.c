
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
	NP *server_port;
	unsigned char buff[2048];
	int clientID = 0;
	int send_len = 100;

	if (argc > 1)
		send_len = atoi(argv[1]);

	server_port = msg_open(MSG_SERVER_ID);
	if (server_port == NULL) {
		printf("open server socket fail\n");
		return -1;
	}

	while (1) {
		printf("went to recv mesg\n");
		getchar();
		printf("recv mesg\n");
		res = msg_recv(server_port, &clientID, buff, -1);
		if (res < 0) {
			printf("Server msg recv fail\n");
			return -1;
		} else {
			printf("Server recv msg len[%d] buff[%s] CID[%d]\n",res, buff, clientID);
			/*res = msg_send(server_port, MSG_CLIENT_ID, buff, send_len);
			if (res != 0) {
				printf("Server msg send fail\n");
				return -1;
			}*/
		}
	}

	msg_close(server_port);
	return 0;
}

