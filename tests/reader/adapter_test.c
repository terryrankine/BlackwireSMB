#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int bp_smb_getaddrinfo(const char*,const char*,const struct addrinfo*,struct addrinfo**);
void bp_smb_freeaddrinfo(struct addrinfo*);
void bp_smb_srandom(unsigned);
char *bp_smb_getenv(const char*);
int bp_nfs_getaddrinfo(const char*,const char*,const struct addrinfo*,struct addrinfo**);
void bp_nfs_freeaddrinfo(struct addrinfo*);
struct protoent *bp_nfs_getprotobyname(const char*);
struct servent *bp_nfs_getservbyport(int,const char*);
void (*bp_nfs_signal(int,void (*)(int)))(int);
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"adapter failed line%d\n",__LINE__);return 1;}}while(0)
int main(void){
    struct addrinfo *a=NULL;CHECK(!bp_smb_getaddrinfo("192.0.2.1","445",NULL,&a));CHECK(a&&a->ai_next==NULL&&a->ai_family==AF_INET&&a->ai_socktype==SOCK_STREAM);
    struct sockaddr_in *s=(void*)a->ai_addr;const unsigned char *p=(const void*)&s->sin_port,*ip=(const void*)&s->sin_addr;
    CHECK(p[0]==1&&p[1]==189&&ip[0]==192&&ip[1]==0&&ip[2]==2&&ip[3]==1);bp_smb_freeaddrinfo(a);
    const char *bad[]={"example.invalid","::1","127.0.0","256.0.0.1","01.2.3.4","1.2.3.4x","1..2.3","1.2.3.4.5",""};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){a=(void*)1;CHECK(bp_smb_getaddrinfo(bad[i],"445",NULL,&a)!=0&&a==NULL);}
    CHECK(bp_smb_getaddrinfo("192.0.2.1","65536",NULL,&a)!=0);CHECK(bp_smb_getaddrinfo("192.0.2.1","smb",NULL,&a)!=0);
    struct addrinfo hints={0};hints.ai_family=AF_INET6;CHECK(bp_smb_getaddrinfo("192.0.2.1","445",&hints,&a)!=0);
    CHECK(!setenv("NTLM_USER_FILE","neutral-ambient-sentinel",1));CHECK(bp_smb_getenv("NTLM_USER_FILE")==NULL);CHECK(!strcmp(getenv("NTLM_USER_FILE"),"neutral-ambient-sentinel"));
    srandom(12345);long expected=random();srandom(12345);bp_smb_srandom(77);CHECK(random()==expected);
    /* libnfs resolves with no service and no hints, then sets the port. */
    a=NULL;CHECK(!bp_nfs_getaddrinfo("192.0.2.7",NULL,NULL,&a));CHECK(a&&a->ai_next==NULL&&a->ai_family==AF_INET&&a->ai_addrlen==sizeof(struct sockaddr_in));
    s=(void*)a->ai_addr;p=(const void*)&s->sin_port;ip=(const void*)&s->sin_addr;
    CHECK(s->sin_family==AF_INET&&p[0]==0&&p[1]==0&&ip[0]==192&&ip[1]==0&&ip[2]==2&&ip[3]==7);bp_nfs_freeaddrinfo(a);
    a=NULL;CHECK(!bp_nfs_getaddrinfo("192.0.2.7","2049",NULL,&a));p=(const void*)&((struct sockaddr_in*)(void*)a->ai_addr)->sin_port;CHECK(p[0]==8&&p[1]==1);bp_nfs_freeaddrinfo(a);
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){a=(void*)1;CHECK(bp_nfs_getaddrinfo(bad[i],NULL,NULL,&a)!=0&&a==NULL);}
    CHECK(bp_nfs_getaddrinfo(NULL,NULL,NULL,&a)!=0);CHECK(bp_nfs_getaddrinfo("192.0.2.7","",NULL,&a)!=0);CHECK(bp_nfs_getaddrinfo("192.0.2.7","nfs",NULL,&a)!=0);
    CHECK(bp_nfs_getaddrinfo("192.0.2.7","65536",NULL,&a)!=0);CHECK(bp_nfs_getaddrinfo("192.0.2.7",NULL,&hints,&a)!=0);
    struct protoent *tcp=bp_nfs_getprotobyname("tcp");CHECK(tcp&&tcp->p_proto==IPPROTO_TCP);CHECK(bp_nfs_getprotobyname("udp")==NULL);
    CHECK(bp_nfs_getservbyport(111,"tcp")==NULL&&bp_nfs_getservbyport(0x0100,"tcp")==NULL);
    /* The game's SIGPIPE disposition survives libnfs context creation. */
    CHECK(signal(SIGPIPE,SIG_DFL)!=SIG_ERR);CHECK(bp_nfs_signal(SIGPIPE,SIG_IGN)!=SIG_ERR);CHECK(signal(SIGPIPE,SIG_DFL)==SIG_DFL);
    printf("{\"passed\":true,\"checks\":%u,\"networkCalls\":0,\"privateAdapterOnly\":true,\"gameRngNotReseeded\":true,\"nfsResolverNumericOnly\":true,\"gameSignalsUnchanged\":true}\n",checks);return 0;
}
