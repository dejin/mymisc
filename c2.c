#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
 
#define PATH "/data/unixdomain"
 
int main(int argc,char *argv[])
{
    int sockfd = 0;
    struct sockaddr_un addr;
    bzero(&addr,sizeof(addr));
 
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path,PATH);
 
    sockfd = socket(AF_UNIX,SOCK_DGRAM,0);
    if(sockfd < 0)
    {
        perror("socket error");
        exit(-1);
    }
 
    while(1)
    {
        static int counter = 0;
        char send_buf[20] = "";
		struct iovec    iov[1];
		struct cmsghdr *cmmag=malloc(sizeof(struct cmsghdr)+sizeof(int));
        struct msghdr   msg;
        counter++;
        sprintf(send_buf,"Counter is %d",counter);
		#if 0
        int len = strlen(addr.sun_path)+sizeof(addr.sun_family);
        sendto(sockfd,send_buf,strlen(send_buf),0,(struct sockaddr*)&addr,len);
		#else
		msg.msg_name    = &addr;
        msg.msg_namelen = sizeof(struct sockaddr_un);

        iov[0].iov_base = send_buf;
        iov[0].iov_len  = strlen(send_buf);
        msg.msg_iov     = iov;
        msg.msg_iovlen  = 1;
		sendmsg(sockfd, &msg, 0);
		#endif
        printf("Send: %s\n",send_buf);
        getchar();
    }
    return 0;
}