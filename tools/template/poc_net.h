/* poc_net.h - minimal localhost TCP transport for PoC demos.
 * Length-prefixed (4-byte big-endian) byte buffers. Library-neutral. */
#ifndef POC_NET_H
#define POC_NET_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
static int pn_listen(int port){
    int s=socket(AF_INET,SOCK_STREAM,0); int yes=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons(port);
    if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");exit(2);}
    listen(s,1); return s;
}
static int pn_accept(int s){ return accept(s,NULL,NULL); }
static int pn_connect(int port){
    int s=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons(port);
    int tries=0; while(connect(s,(struct sockaddr*)&a,sizeof a)<0){ if(++tries>100){perror("connect");exit(2);} usleep(100000); }
    return s;
}
static int pn_send(int fd,const void*buf,uint32_t n){
    uint32_t net=htonl(n);
    if(write(fd,&net,4)!=4) return -1;
    return (write(fd,buf,n)==(ssize_t)n)?0:-1;
}
static int pn_recv(int fd,void*buf,uint32_t cap,uint32_t*outn){
    uint32_t net; if(read(fd,&net,4)!=4) return -1;
    uint32_t n=ntohl(net); if(n>cap) return -1;
    uint32_t got=0; while(got<n){ ssize_t r=read(fd,(char*)buf+got,n-got); if(r<=0) return -1; got+=(uint32_t)r; }
    *outn=n; return 0;
}
#endif
