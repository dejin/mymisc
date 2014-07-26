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

NP *msg_open(int ServiceID)
{
	int res;
	NP *port;

	port = malloc(sizeof(NP));
	if (port == NULL)
		return NULL;

  	port->socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (port->socket == -1)
	{
		printf("msg_open socket fail <errno = %d> (%s)\n", errno,
				strerror(errno));
		goto error_socket;
	}

	memset(&port->address, 0, sizeof(port->address));

	port->address.nl_family = AF_NETLINK;
	port->address.nl_pid = ServiceID;
	port->address.nl_groups = NETLINK_SHM_TEST_GROUP;

	res = bind(port->socket, (struct sockaddr*)&(port->address),
						sizeof(port->address));
	if (res == -1)
	{
		printf("msg_open bind Socket=%d <errno = %d> (%s)\n",
				port->socket, errno, strerror(errno));
		goto error_bind;
	}

	return port;

error_bind:
	close(port->socket);

error_socket:
	free(port);

   	return NULL;
}


int msg_close(NP *port)
{
	if (port == NULL) {
		printf("msg_close fail\n");
		return -1;
	}

	close(port->socket);
	free(port);

	return 0;
}


int msg_send(NP *port, int ServiceID, char *pMsgBuf, int MsgLen)
{
	int res;
	struct sockaddr_nl dst_addr;
	struct nlmsghdr *nlhdr;
	struct iovec iov;
	struct msghdr msg;

	if ((pMsgBuf == NULL) || (MsgLen > MSG_MAX_DATA_LEN) || (port == NULL)) {
		printf("msg_send parameter fail\n");
		return -1;
	}

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_pid = ServiceID;
	dst_addr.nl_groups = NETLINK_SHM_TEST_GROUP;

	nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(MsgLen));
	if ( nlhdr == NULL ) {
		printf("msg_send malloc fail\n");
		return -1;
	}
	memset(nlhdr, 0, NLMSG_SPACE(MsgLen));
	memcpy(NLMSG_DATA(nlhdr), pMsgBuf, MsgLen);
	nlhdr->nlmsg_len = NLMSG_LENGTH(MsgLen);
	nlhdr->nlmsg_pid = port->address.nl_pid;
	nlhdr->nlmsg_flags = 0;

	iov.iov_base = (void *)nlhdr;
	iov.iov_len = nlhdr->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&(dst_addr);
	msg.msg_namelen = sizeof(dst_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	res = sendmsg(port->socket, &msg, 0);
	if (res == -1) {
		free(nlhdr);
		printf("sendmsg  fail <errno = %d> (%s)",
				errno, strerror(errno));
		return -1;
	}

	free(nlhdr);

	return 0;
}



int msg_recv(NP *port, int *SrcServiceID, char *pMsgBuf, int TimeOutMs)
{
	int res;
	int MsgLen = 0;
	struct sockaddr_nl src_addr;
	struct pollfd fds[1];
	struct nlmsghdr *nlhdr;
	struct iovec iov;
	struct msghdr msg;

	if ((port == NULL) || (pMsgBuf == NULL) || (SrcServiceID == NULL)) {
		printf("msg_recv parameter fail\n");
		return -1;
	}

	if (TimeOutMs >= 0)
	{
		fds[0].fd = port->socket;
		fds[0].events = POLLIN;
		res = poll(fds, 1, TimeOutMs);
		if (res == -1)
		{
			printf("msg_recv poll fail <errno = %d> (%s)\n",
						errno, strerror(errno));
			return -1;
 		} else if (res == 0) {
 			printf("msg_recv poll timeout\n");
			return -2;
		}
	}

	nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(MSG_MAX_DATA_LEN));
	if ( nlhdr == NULL ) {
		printf("msg_recv malloc fail\n");
		return -1;
	}
	memset(nlhdr, 0, NLMSG_SPACE(MSG_MAX_DATA_LEN));
	nlhdr->nlmsg_len = NLMSG_LENGTH(MSG_MAX_DATA_LEN);

	iov.iov_base = (void *)nlhdr;
	iov.iov_len = nlhdr->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&(src_addr);
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	res = recvmsg(port->socket, &msg, (TimeOutMs >= 0 ? MSG_DONTWAIT : 0));
	if (res == -1) {
		free(nlhdr);
		printf("msg_recv fial <errno = %d> (%s)\n", errno, strerror(errno));
		return -1;
 	} else if (res > 0) {
	        MsgLen = res - NLMSG_ALIGN(NLMSG_HDRLEN);
		if ( MsgLen < 0 ) {
			free(nlhdr);
			printf("msg_recv fial MsgLen = %d ( < 0) ", MsgLen);
			return -1;
		}
		memcpy(pMsgBuf, NLMSG_DATA(nlhdr), MsgLen);
	}

	*SrcServiceID = nlhdr->nlmsg_pid;
	free(nlhdr);

	return MsgLen;
}



