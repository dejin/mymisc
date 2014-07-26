#ifndef __MSG_H__
#define __MSG_H__

#include <sys/socket.h>
#include <linux/netlink.h>


#define NETLINK_SHM_TEST_GROUP 		(0)
#define MSG_MAX_DATA_LEN		(128)


typedef struct _NETLINK_PORT {
	int socket;
	struct sockaddr_nl address;
} NP;

NP *msg_open(int ServiceID);
int msg_close(NP *port);
int msg_send(NP *port, int ServiceID, char *pMsgBuf, int MsgLen);
int msg_recv(NP *port, int *SrcServiceID, char *pMsgBuf, int TimeOutMs);


#endif
