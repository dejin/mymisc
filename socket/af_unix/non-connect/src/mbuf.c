/*******************************************************************************
*                Copyright 2012, MARVELL SEMICONDUCTOR, LTD.                   *
* THIS CODE CONTAINS CONFIDENTIAL INFORMATION OF MARVELL.                      *
* NO RIGHTS ARE GRANTED HEREIN UNDER ANY PATENT, MASK WORK RIGHT OR COPYRIGHT  *
* OF MARVELL OR ANY THIRD PARTY. MARVELL RESERVES THE RIGHT AT ITS SOLE        *
* DISCRETION TO REQUEST THAT THIS CODE BE IMMEDIATELY RETURNED TO MARVELL.     *
* THIS CODE IS PROVIDED "AS IS". MARVELL MAKES NO WARRANTIES, EXPRESSED,       *
* IMPLIED OR OTHERWISE, REGARDING ITS ACCURACY, COMPLETENESS OR PERFORMANCE.   *
*                                                                              *
* MARVELL COMPRISES MARVELL TECHNOLOGY GROUP LTD. (MTGL) AND ITS SUBSIDIARIES, *
* MARVELL INTERNATIONAL LTD. (MIL), MARVELL TECHNOLOGY, INC. (MTI), MARVELL    *
* SEMICONDUCTOR, INC. (MSI), MARVELL ASIA PTE LTD. (MAPL), MARVELL JAPAN K.K.  *
* (MJKK), MARVELL ISRAEL LTD. (MSIL).                                          *
*******************************************************************************/

#define LOG_TAG "MBUF"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>


#include "mbuf_api.h"
#include "ion.h"


#ifdef ANDROID
#include <cutils/log.h>
#define MBUF_ERR	ALOGE
#define MBUF_DBG	ALOGD
#else
#define MBUF_ERR
#define MBUF_DBG
#endif


#define CLIENT_NAME(name)  strcat(name, "1")


struct MV_MBUF_HANDLE_internal_s {
	int sockfd;
	int auto_name;
	int direction;
	int recv_timout;
	size_t len;
	char dst_addr[40];
};


static int socket_create(char *name)
{
	int sockfd;
	int ret;
	socklen_t len;
	struct sockaddr_un addr;

	sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		MBUF_ERR("%s line:%d open socket fail errno[%d] [%s]\n",
			__func__, __LINE__, errno, strerror(errno));
		if (errno == EMFILE || errno == ENFILE) {
			return ERR_NORES;
		} else if (errno == ENOBUFS || errno == ENOMEM) {
			return ERR_NOMEM;
		} else {
			assert(0);
		}
	}

	addr.sun_family = AF_UNIX;
	strcpy(&addr.sun_path[1], name);
	addr.sun_path[0] = 0;
	len = strlen(name) + sizeof(addr.sun_family) + 1;

	ret = bind(sockfd, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		MBUF_ERR("%s line:%d bind socket[%s] fail errno[%d] [%s]\n",
			__func__, __LINE__, name, errno, strerror(errno));
		close(sockfd);
		if (errno == EADDRINUSE) {
			return ERR_EXISTS;
		} else if (errno == ENOMEM) {
			return ERR_NOMEM;
		} else {
			assert(0);
		}
	}
	MBUF_DBG("%s line:%d socket[%s] fd[%d] ok\n",
			__func__, __LINE__, name, sockfd);
	return sockfd;
}


static int socket_recv(int fd, char *src_addr, void *buf, int bytes, int timeout)
{
	struct iovec iov[1];
	struct sockaddr_un addr;
	struct msghdr msg;
	struct pollfd fds[1];
	int ret = 0;

	if (timeout > 0)
	{
		fds[0].fd = fd;
		fds[0].events = POLLIN;
		ret = TEMP_FAILURE_RETRY(poll(fds, 1, timeout));
		if (ret == -1) {
			MBUF_ERR("%s line:%d poll fail"
				" errno[%d] [%s]\n", __func__,
				 __LINE__, errno, strerror(errno));
			assert(0);
		} else if (ret == 0) {
			/*MBUF_ERR("%s line:%d poll time out [%d]ms\n",
				__func__, __LINE__, timeout);*/
			return ERR_PEERGONE;
		}
	}

	memset(&addr, 0, sizeof(addr));

	iov[0].iov_base = buf;
	iov[0].iov_len = bytes;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = sizeof(struct sockaddr_un);
	msg.msg_name = &addr;

	ret = TEMP_FAILURE_RETRY(recvmsg(fd, &msg,
		(timeout >= 0 ? MSG_DONTWAIT : 0)));
	if (ret < 0) {
		MBUF_ERR("%s line:%d recvmsg fail errno[%d] [%s]\n",
			__func__, __LINE__, errno, strerror(errno));
		if (errno == ENOMEM) {
			return ERR_NOMEM;
		} else {
			assert(0);
		}
	}

	if (src_addr != NULL)
		strncpy(src_addr, &addr.sun_path[1], 32);

	return ret;
}


static int socket_send(int fd, char *dest_addr, void *buf, int bytes, int flag)
{
	struct iovec iov[1];
	struct sockaddr_un addr;
	struct msghdr msg;
	socklen_t len;
	int ret = 0;

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;
	addr.sun_path[0]= 0;
	strcpy(&addr.sun_path[1], dest_addr);
	len = strlen(dest_addr) + sizeof(addr.sun_family) + 1;

	iov[0].iov_base = buf;
	iov[0].iov_len = bytes;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = len;
	msg.msg_name = &addr;

	ret = TEMP_FAILURE_RETRY(sendmsg(fd, &msg,
		(flag > 0 ? MSG_DONTWAIT : 0)));
	if(ret < 0) {
		/*flag > 0 && errno == EAGAIN is try write fail*/
		if (!(flag > 0 && errno == EAGAIN))
			MBUF_ERR("%s line:%d sendmsg fail address[%s]"
				" errno[%d] [%s]\n", __func__, __LINE__,
				dest_addr, errno, strerror(errno));
		if (errno == ECONNREFUSED) {
			MBUF_ERR("ERROR: went to send data to address[%s]"
				", But [%s] socket don't exist, so connection"
				" refused\n", dest_addr, dest_addr);
			return ERR_PEERGONE;
		} else if (flag > 0 && errno == EAGAIN) {
			ret = 0; /*just for try write fail, set write 0 byte*/
		} else {
			assert(0);
		}
	}

	return ret;
}


static int socket_getautoname(char *name)
{
	#define ServiceID_DynamicApply	(0x80000000)
	struct berlin_cc_info info;
	int ionfd;
	int ret;

	ionfd = ion_get_osal_fd();
	if (ionfd < 0) {
		MBUF_ERR("%s line:%d can't open ion device\n",
			__func__, __LINE__);
		return -1;
	}

	info.m_ServiceID = ServiceID_DynamicApply;
	ret = ion_cc_reg(ionfd, &info);
	if (ret < 0) {
		MBUF_ERR("%s line:%d can't reg service ID\n",
			__func__, __LINE__);
		return -1;
	}

	sprintf(name, "%x", info.m_ServiceID);
	MBUF_DBG("%s line:%d got name %s SID[%x]\n",
			__func__, __LINE__, name, info.m_ServiceID);
	return 0;
}


static int socket_putautoname(char *name)
{
	int ionfd;
	struct berlin_cc_info info;
	int ret = 0;

	ionfd = ion_get_osal_fd();
	if (ionfd < 0) {
		MBUF_ERR("%s line:%d can't open ion device\n",
			__func__, __LINE__);
		return -1;
	}

	info.m_ServiceID = strtoul(name, NULL, 16);
	MBUF_DBG("%s line:%d put name %s SID[%x]\n",
			__func__, __LINE__, name, info.m_ServiceID);
	ret = ion_cc_free(ionfd, &info);
	if (ret < 0) {
		MBUF_ERR("%s line:%d can't reg service ID\n",
			__func__, __LINE__);
		return -1;
	}

	return 0;
}


HRESULT MV_MBUF_Create(
		size_t uSize,
		MV_MBUF_DIRECTION direction,
		MV_MBUF_HANDLE *phMbuf)
{
	int fd = 0;
	int auto_flag = 0;
	int ret = 0;

	if (phMbuf == NULL) {
		MBUF_ERR("%s line:%d bad parameter\n",
			__func__, __LINE__);
		return ERR_BADPARAM;
	}

	if (phMbuf->address[0] == '\0') {
		auto_flag = 1;
		ret = socket_getautoname(phMbuf->address);
		if (ret < 0) {
			MBUF_ERR("%s line:%d socket get auto name fail\n",
					__func__, __LINE__);
			return ERR_NORES;
		}
	} else if (strlen(phMbuf->address) >= sizeof(phMbuf->address)) {
		MBUF_ERR("%s line:%d bad parameter address len[%d]\n",
			__func__, __LINE__, strlen(phMbuf->address));
		return ERR_BADPARAM;
	}

	phMbuf->pPrivate =
		malloc(sizeof(struct MV_MBUF_HANDLE_internal_s));
	if (phMbuf->pPrivate == NULL) {
		MBUF_ERR("%s line:%d malloc fail\n",
			__func__, __LINE__);
		if (auto_flag == 1)
			socket_putautoname(phMbuf->address);
		return ERR_NOMEM;
	}

	fd = socket_create(phMbuf->address);
	if (fd < 0) {
		free(phMbuf->pPrivate);
		if (auto_flag == 1)
			socket_putautoname(phMbuf->address);
		return fd;
	}

	phMbuf->pPrivate->auto_name = auto_flag;
	phMbuf->pPrivate->len = uSize;
	phMbuf->pPrivate->sockfd = fd;
	phMbuf->pPrivate->direction = direction;
	phMbuf->pPrivate->recv_timout = 5*60*1000;
	strcpy(phMbuf->pPrivate->dst_addr, phMbuf->address);
	CLIENT_NAME(phMbuf->pPrivate->dst_addr);

	return S_OK;
}


HRESULT MV_MBUF_Destroy(
		MV_MBUF_HANDLE *phMbuf)
{
	int ret = 0;

	if (phMbuf == NULL || phMbuf->pPrivate == NULL) {
		MBUF_ERR("%s line:%d bad parameter phMbuf[%p]"
			" phMbuf->pPrivate[%p]\n", __func__,
			__LINE__, phMbuf, phMbuf->pPrivate);
		return ERR_BADPARAM;
	}

	if (phMbuf->pPrivate->auto_name == 1)
		socket_putautoname(phMbuf->address);

	ret = TEMP_FAILURE_RETRY(close(phMbuf->pPrivate->sockfd));
	if (ret != 0) {
		MBUF_ERR("%s line:%d close socket[%d] fail\n",
			__func__, __LINE__,
			phMbuf->pPrivate->sockfd);
		assert(0);
	}
	free(phMbuf->pPrivate);
	phMbuf->pPrivate = NULL;
	return S_OK;
}


HRESULT MV_MBUF_Open(
		MV_MBUF_DIRECTION direction,
		MV_MBUF_HANDLE *phMbuf)
{
	int fd;
	char tmp_addr[64];

	if (phMbuf == NULL) {
		MBUF_ERR("%s line:%d bad parameter\n",
			__func__, __LINE__);
		return ERR_BADPARAM;
	}

	if (phMbuf->address[0] == '\0' ||
		strlen(phMbuf->address) >= sizeof(phMbuf->address)) {
		MBUF_ERR("%s line:%d bad address\n",
			__func__, __LINE__);
		return ERR_NOTFOUND;
	}

	phMbuf->pPrivate =
		malloc(sizeof(struct MV_MBUF_HANDLE_internal_s));
	if (phMbuf->pPrivate == NULL) {
		MBUF_ERR("%s line:%d malloc fail\n",
			__func__, __LINE__);
		return ERR_NOMEM;
	}

	strcpy(tmp_addr, phMbuf->address);
	CLIENT_NAME(tmp_addr);
	fd = socket_create(tmp_addr);
	if (fd < 0) {
		free(phMbuf->pPrivate);
		return fd;
	}

	phMbuf->pPrivate->sockfd = fd;
	phMbuf->pPrivate->direction = direction;
	phMbuf->pPrivate->recv_timout = 5*60*1000;
	strcpy(phMbuf->pPrivate->dst_addr, phMbuf->address);
	return S_OK;
}


HRESULT MV_MBUF_Close(
		MV_MBUF_HANDLE *phMbuf)
{
	int ret = 0;

	if (phMbuf == NULL || phMbuf->pPrivate == NULL) {
		MBUF_ERR("%s line:%d bad parameter phMbuf[%p]"
			" phMbuf->pPrivate[%p]\n", __func__,
			__LINE__, phMbuf, phMbuf->pPrivate);
		return ERR_BADPARAM;
	}

	ret = TEMP_FAILURE_RETRY(close(phMbuf->pPrivate->sockfd));
	if (ret != 0) {
		MBUF_ERR("%s line:%d close socket[%d] fail\n",
			__func__, __LINE__,
			phMbuf->pPrivate->sockfd);
		assert(0);
	}

	free(phMbuf->pPrivate);
	phMbuf->pPrivate = NULL;
	return S_OK;
}


HRESULT MV_MBUF_Write(
		MV_MBUF_HANDLE *phMbuf,
		void *buf,
		size_t uNbytes)
{
	int ret = 0;

	if (phMbuf == NULL || phMbuf->pPrivate == NULL
		|| buf == NULL || uNbytes < 1) {
		MBUF_ERR("%s line:%d bad parameter phMbuf[%p]"
			" phMbuf->pPrivate[%p] buf[%p] uNbytes[%d]\n",
			__func__, __LINE__, phMbuf, phMbuf->pPrivate,
			buf, uNbytes);
		return ERR_BADPARAM;
	}

	if (phMbuf->pPrivate->direction ==
		MV_MBUF_DIRECTION_READ) {
		MBUF_ERR("%s line:%d mismatch\n",
			__func__, __LINE__);
		return ERR_MISMATCH;
	}

	ret = socket_send(phMbuf->pPrivate->sockfd,
		phMbuf->pPrivate->dst_addr, buf, uNbytes, 0);
	return (ret < 0 ? ret : S_OK);
}


HRESULT MV_MBUF_Read(
		MV_MBUF_HANDLE *phMbuf,
		void *buf,
		size_t uNbytes)
{
	int ret = 0;

	if (phMbuf == NULL || phMbuf->pPrivate == NULL
		|| buf == NULL || uNbytes < 1) {
		MBUF_ERR("%s line:%d bad parameter phMbuf[%p]"
			" phMbuf->pPrivate[%p] buf[%p] uNbytes[%d]\n",
			__func__, __LINE__, phMbuf, phMbuf->pPrivate,
			buf, uNbytes);
		return ERR_BADPARAM;
	}

	if (phMbuf->pPrivate->direction ==
		MV_MBUF_DIRECTION_WRITE) {
		MBUF_ERR("%s line:%d mismatch\n",
			__func__, __LINE__);
		return ERR_MISMATCH;
	}

	ret = socket_recv(phMbuf->pPrivate->sockfd,
			NULL, buf, uNbytes,
			phMbuf->pPrivate->recv_timout);
	return (ret < 0 ? ret : S_OK);
}


HRESULT MV_MBUF_TryWrite(
		MV_MBUF_HANDLE *phMbuf,
		void *buf,
		size_t uNbytes,
		size_t *puBytesWritten)
{
	int ret = 0;

	if (phMbuf == NULL || phMbuf->pPrivate == NULL
		|| puBytesWritten == NULL ||uNbytes < 1) {
		MBUF_ERR("%s line:%d bad parameter phMbuf[%p]"
			" phMbuf->pPrivate[%p] uNbytes[%d]"
			" puBytesWritten[%p]\n", __func__, __LINE__,
			phMbuf, phMbuf->pPrivate, uNbytes,
			puBytesWritten);
		return ERR_BADPARAM;
	}

	if (phMbuf->pPrivate->direction ==
		MV_MBUF_DIRECTION_READ) {
		MBUF_ERR("%s line:%d mismatch\n",
			__func__, __LINE__);
		return ERR_MISMATCH;
	}

	ret = socket_send(phMbuf->pPrivate->sockfd,
		phMbuf->pPrivate->dst_addr, buf, uNbytes, 1);

	if (puBytesWritten != NULL) {
		if (ret > 0)
			*puBytesWritten = ret;
		else
			*puBytesWritten = 0;
	}

	return (ret < 0 ? ret : S_OK);
}


HRESULT MV_MBUF_TryRead(
		MV_MBUF_HANDLE *phMbuf,
		void *buf,
		size_t uNbytes,
		size_t *puBytesRead)
{
	int ret = 0;

	if (phMbuf == NULL || phMbuf->pPrivate == NULL
		|| puBytesRead == NULL ||uNbytes < 1) {
		MBUF_ERR("%s line:%d bad parameter phMbuf[%p]"
			" phMbuf->pPrivate[%p] uNbytes[%d]"
			" puBytesWritten[%p]\n", __func__, __LINE__,
			phMbuf, phMbuf->pPrivate, uNbytes,
			puBytesRead);
		return ERR_BADPARAM;
	}

	if (phMbuf->pPrivate->direction ==
		MV_MBUF_DIRECTION_WRITE) {
		MBUF_ERR("%s line:%d mismatch\n",
			__func__, __LINE__);
		return ERR_MISMATCH;
	}

	ret = socket_recv(phMbuf->pPrivate->sockfd,
			NULL, buf, uNbytes, 0);

	if (puBytesRead != NULL) {
		if (ret > 0)
			*puBytesRead = ret;
		else
			*puBytesRead = 0;
	}

	return (ret < 0 ? ret : S_OK);
}



