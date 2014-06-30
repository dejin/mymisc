#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
 
#define PATH "/data/unixdomain"
 
int main(int argc ,char *argv[])
{
    int sockfd = 0;
    struct sockaddr_un addr;
    unlink(PATH);   
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path,PATH);
 
    unsigned int len = strlen(addr.sun_path) + sizeof(addr.sun_family);
    sockfd = socket(AF_UNIX,SOCK_DGRAM,0);
    if(sockfd < 0 )
    {
        perror("socket error");
        exit(-1);
    }
     
    if(bind(sockfd,(struct sockaddr *)&addr,len) < 0)
    {
        perror("bind error");
        close(sockfd);
        exit(-1);
    }
    printf("Bind is ok\n");
 
    while(1)
    {
        char recv_buf[20] = "";
        recvfrom(sockfd,recv_buf,sizeof(recv_buf),0,(struct sockaddr*)&addr,&len);
        printf("Recv: %s\n",recv_buf);
    }
    return 0;
}