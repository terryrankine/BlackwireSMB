/* Actual HTTP parser/header/accepted-peer route, real host TCP sockets.
 * Only the backend queue is a modeled recording seam. */
#define _DEFAULT_SOURCE 1
#include "main-under-test.h"
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
static unsigned cases,checks,claims,normal_requests;
static int observed_peer,observed_header,observed_origin;
#define C(x) do{checks++;if(!(x)){fprintf(stderr,"case%u line%u %s\n",cases,__LINE__,#x);exit(1);}}while(0)
int bw_native_backend_home_claim(struct bw_native_backend*p,const void*raw,size_t size,int peer,int header,int origin,struct bw_native_response*out){
    C(p==native_backend&&raw&&size==2&&!memcmp(raw,"{}",2));claims++;observed_peer=peer;observed_header=header;observed_origin=origin;
    const char *reply=peer&&header&&!origin?"{\"accepted\":true}":"{\"error\":\"refused\"}";out->status=peer&&header&&!origin?202:403;out->type="application/json";out->size=strlen(reply);out->bytes=malloc(out->size+1);C(out->bytes);memcpy(out->bytes,reply,out->size+1);return 0;
}
int bd_resident_handle(struct bd_resident*p,const char*m,const char*u,const void*b,size_t n,const char*t,struct bw_native_response*out){(void)p;(void)m;(void)u;(void)b;(void)n;(void)t;(void)out;normal_requests++;return 1;}
int bw_native_backend_handle_authenticated(struct bw_native_backend*p,const char*m,const char*u,const void*b,size_t n,const char*t,struct bw_native_response*out){(void)p;(void)m;(void)u;(void)b;(void)n;(void)t;normal_requests++;out->status=404;out->type="application/json";out->bytes=strdup("{}");out->size=2;return 0;}
void bw_native_response_clear(struct bw_native_response*out){free(out->bytes);memset(out,0,sizeof *out);}
void bw_native_sensitive_clear(void*p,size_t n){memset(p,0,n);}
static void exchange(const char *request,int tcp,char response[4096]){
    cases++;int client,server,listener=-1;
    if(tcp){listener=socket(AF_INET,SOCK_STREAM,0);C(listener>=0);struct sockaddr_in a={.sin_family=AF_INET,.sin_port=0,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};C(!bind(listener,(struct sockaddr*)&a,sizeof a));C(!listen(listener,1));socklen_t n=sizeof a;C(!getsockname(listener,(struct sockaddr*)&a,&n));client=socket(AF_INET,SOCK_STREAM,0);C(client>=0&&!connect(client,(struct sockaddr*)&a,sizeof a));server=accept(listener,NULL,NULL);C(server>=0);C(!close(listener));}
    else{int pair[2];C(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));client=pair[0];server=pair[1];}
    C(write(client,request,strlen(request))==(ssize_t)strlen(request));C(!shutdown(client,SHUT_WR));serve(server,"127.0.0.1");C(!close(server));size_t at=0;
    for(;;){ssize_t n=read(client,response+at,4095-at);C(n>=0);if(!n)break;at+=(size_t)n;C(at<4095);}response[at]=0;C(!close(client));
}
int main(void){
    native_backend=(struct bw_native_backend*)(uintptr_t)1;dashboard=(struct bd_resident*)(uintptr_t)2;char response[4096],request[2048];
    const char *base="POST /api/reader/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:5918\r\nContent-Type: application/json\r\nX-Blackwire-Reader: home/1\r\nContent-Length: 2\r\n";
    snprintf(request,sizeof request,"%s\r\n{}",base);exchange(request,1,response);C(strstr(response,"HTTP/1.0 202 ")&&claims==1&&observed_peer&&observed_header&&!observed_origin&&!normal_requests);C(!strstr(response,"Access-Control-Allow-Origin"));
    exchange(request,0,response);C(strstr(response," 403 ")&&claims==2&&!observed_peer); /* Host does not certify peer. */
    snprintf(request,sizeof request,"%sOrigin: http://127.0.0.1:5918\r\n\r\n{}",base);exchange(request,1,response);C(strstr(response," 403 ")&&observed_origin);
    snprintf(request,sizeof request,"%sReferer: http://example.invalid/\r\n\r\n{}",base);exchange(request,1,response);C(strstr(response," 403 ")&&observed_origin);
    snprintf(request,sizeof request,"%sX-Blackwire-Reader: home/1\r\n\r\n{}",base);exchange(request,1,response);C(strstr(response," 403 ")&&!observed_header);
    snprintf(request,sizeof request,"%s\r\n{}EXTRA",base);unsigned before=claims;exchange(request,1,response);C(strstr(response," 400 ")&&claims==before);
    snprintf(request,sizeof request,"%sContent-Length: 2\r\n\r\n{}",base);exchange(request,1,response);C(strstr(response," 400 ")&&claims==before);
    exchange("GET /api/reader/bootstrap HTTP/1.1\r\nHost:127.0.0.1\r\n\r\n",1,response);C(strstr(response," 405 ")&&claims==before);
    exchange("POST /api/reader/bootstrap HTTP/1.1\r\nHost:127.0.0.1\r\nContent-Type:text/plain\r\nX-Blackwire-Reader:home/1\r\nContent-Length:2\r\n\r\n{}",1,response);C(strstr(response," 415 ")&&claims==before);
    /* Every response carries the framing, sniffing and referrer headers. */
    exchange("GET / HTTP/1.1\r\nHost: 127.0.0.1:5918\r\n\r\n",1,response);C(strstr(response,"HTTP/1.0 200 ")&&strstr(response,"\r\nX-Frame-Options: DENY\r\n")&&strstr(response,"\r\nContent-Security-Policy: frame-ancestors 'none'\r\n")&&
        strstr(response,"\r\nX-Content-Type-Options: nosniff\r\n")&&strstr(response,"\r\nReferrer-Policy: no-referrer\r\n")&&!strstr(response,"script-src"));
    exchange("GET /missing HTTP/1.1\r\nHost: evil.invalid\r\n\r\n",1,response);C(strstr(response,"HTTP/1.0 421 ")&&strstr(response,"\r\nX-Frame-Options: DENY\r\n"));
    /* DNS rebinding: only loopback names and literal IPv4 on this port are served. */
    const char *good[]={"127.0.0.1","127.0.0.1:5918","localhost","LocalHost:5918","192.0.2.20","192.0.2.20:5918"};
    for(unsigned i=0;i<sizeof good/sizeof *good;i++){snprintf(request,sizeof request,"GET / HTTP/1.1\r\nHost: %s\r\n\r\n",good[i]);exchange(request,1,response);C(strstr(response,"HTTP/1.0 200 "));}
    const char *bad[]={"evil.invalid","evil.invalid:5918","127.0.0.1:80","127.0.0.1:","localhost.evil.invalid","localhost:59180","1.2.3.4.5","256.0.0.1","0x7f.0.0.1","127.1",":5918","[::1]:5918"};
    before=normal_requests;
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){snprintf(request,sizeof request,"GET /api/state HTTP/1.1\r\nHost: %s\r\n\r\n",bad[i]);exchange(request,1,response);C(strstr(response,"HTTP/1.0 421 ")&&normal_requests==before);}
    exchange("GET / HTTP/1.1\r\n\r\n",1,response);C(strstr(response,"HTTP/1.0 400 "));
    exchange("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.invalid\r\n\r\n",1,response);C(strstr(response,"HTTP/1.0 400 "));
    /* obs-fold continuation lines are refused, not silently skipped. */
    exchange("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Fold: a\r\n b\r\n\r\n",1,response);C(strstr(response,"HTTP/1.0 400 "));
    exchange("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\tHost: evil.invalid\r\n\r\n",1,response);C(strstr(response,"HTTP/1.0 400 "));
    exchange("GET / HTTP/1.0\r\n\r\n",1,response);C(strstr(response,"HTTP/1.0 400 ")); /* No version may omit Host. */
    exchange("GET / HTTP/1.0\r\nHost: 127.0.0.1:5918\r\n\r\n",1,response);C(strstr(response,"HTTP/1.0 200 "));
    /* Cross-origin POST is refused before any handler; absent Origin is native. */
    const char *post="POST /api/refresh HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: 2\r\n%s\r\n{}";
    const char *refused[]={"Origin: http://evil.invalid\r\n","Origin: null\r\n","Origin: https://127.0.0.1:5918\r\n","Origin: http://127.0.0.1\r\n","Origin: http://127.0.0.1:5918/\r\n","Origin: http://127.0.0.1:5918\r\nOrigin: http://127.0.0.1:5918\r\n"};
    before=normal_requests;
    for(unsigned i=0;i<sizeof refused/sizeof *refused;i++){snprintf(request,sizeof request,post,"127.0.0.1:5918",refused[i]);exchange(request,1,response);C((strstr(response,"HTTP/1.0 403 ")||(i==5&&strstr(response,"HTTP/1.0 400 ")))&&normal_requests==before);}
    exchange("POST /api/refresh HTTP/1.0\r\nContent-Type: application/json\r\nOrigin: http://127.0.0.1:5918\r\nContent-Length: 2\r\n\r\n{}",1,response);C(strstr(response,"HTTP/1.0 400 ")&&normal_requests==before);
    snprintf(request,sizeof request,post,"192.0.2.20:5918","Origin: http://192.0.2.20:5918\r\n");exchange(request,1,response);C(strstr(response,"HTTP/1.0 404 ")&&normal_requests==before+2);
    snprintf(request,sizeof request,post,"127.0.0.1:5918","Origin: HTTP://127.0.0.1:5918\r\n");exchange(request,1,response);C(strstr(response,"HTTP/1.0 404 ")&&normal_requests==before+4);
    snprintf(request,sizeof request,post,"127.0.0.1:5918","");exchange(request,1,response);C(strstr(response,"HTTP/1.0 404 ")&&normal_requests==before+6);
    /* A peer dripping bytes inside the per-read timeout is still cut off by the
     * request budget instead of holding the single-threaded listener. */
    {
        cases++;int pair[2];C(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));pid_t child=fork();C(child>=0);
        if(!child){signal(SIGPIPE,SIG_IGN);close(pair[1]);const char *drip="GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: aaaaaaaaaaaaaaaa";
            for(const char *at=drip;*at;at++){if(write(pair[0],at,1)!=1)_exit(0);struct timespec t={0,500000000};nanosleep(&t,NULL);}_exit(0);}
        C(!close(pair[0]));struct timespec began,ended;C(!clock_gettime(CLOCK_MONOTONIC,&began));
        serve(pair[1],"127.0.0.1");C(!close(pair[1]));C(!clock_gettime(CLOCK_MONOTONIC,&ended));
        double elapsed=(double)(ended.tv_sec-began.tv_sec)+(double)(ended.tv_nsec-began.tv_nsec)/1e9;C(elapsed>=4.5&&elapsed<6.5);
        C(!kill(child,SIGKILL));int status;C(waitpid(child,&status,0)==child);
    }
    printf("{\"passed\":true,\"cases\":%u,\"checks\":%u,\"actualHttpParserAndTrustedPeerRoute\":true,\"backendQueueModeled\":true,\"hostOriginAndBudgetRefusals\":true}\n",cases,checks);return 0;
}
