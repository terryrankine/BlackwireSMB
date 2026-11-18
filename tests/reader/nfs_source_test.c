/* Actual DATA/cache/source code and the real NFS reader table over an
 * explicitly modeled libnfs, not a server. Mirrors source_test.c for NFS. */
#include "reader/preload/source.h"
#include "library/reader_selection.h"
#include "library/source_binding.h"
#include "streamreader/manifest.h"
#include "streamreader/cache.h"
#include "streamreader/share_config.h"
#include "streamreader/bw_tp_error.h"
#include <nfsc/libnfs.h>
#define NFS_V3 3 /* raw protocol header values */
#define NFS_V4 4
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
static unsigned checks,cases,contexts,destroys,opens,closes,reads,mounts,lstats,fstats,services,paired,drained;
static int canceled,changed,fail_mount,stale_read,timeout_read,stale_final,timeout_final,service_fail;
static int link_named,fifo_named,cancel_after_read,version_seen;
static unsigned named_seen;
static size_t server_readmax;
static uint32_t largest_read;
static uint64_t stream_size=131079;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"check failed %s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
/* The SMB table is linked but never selected for an NFS handoff. */
#define NEVER(...) {CHECK(!"SMB call on NFS source");__VA_ARGS__}
struct smb2_context *smb2_init_context(void)NEVER(return NULL;)
void smb2_destroy_context(struct smb2_context *c)NEVER((void)c;)
void smb2_set_timeout(struct smb2_context *c,int n)NEVER((void)c;(void)n;)
void smb2_set_user(struct smb2_context *c,const char *u)NEVER((void)c;(void)u;)
void smb2_set_password(struct smb2_context *c,const char *p)NEVER((void)c;(void)p;)
void smb2_set_sign(struct smb2_context *c,int r)NEVER((void)c;(void)r;)
void smb2_set_security_mode(struct smb2_context *c,uint16_t m)NEVER((void)c;(void)m;)
int smb2_connect_share(struct smb2_context *c,const char *s,const char *h,const char *u)NEVER((void)c;(void)s;(void)h;(void)u;return -1;)
int smb2_get_nterror(struct smb2_context *c)NEVER((void)c;return 0;)
uint32_t smb2_get_max_read_size(struct smb2_context *c)NEVER((void)c;return 0;)
int smb2_stat(struct smb2_context *c,const char *p,struct smb2_stat_64 *s)NEVER((void)c;(void)p;(void)s;return -1;)
int smb2_fstat(struct smb2_context *c,struct smb2fh *h,struct smb2_stat_64 *s)NEVER((void)c;(void)h;(void)s;return -1;)
int smb2_stat_async(struct smb2_context *c,const char *p,struct smb2_stat_64 *s,smb2_command_cb cb,void *o)NEVER((void)c;(void)p;(void)s;(void)cb;(void)o;return -1;)
int smb2_fstat_async(struct smb2_context *c,struct smb2fh *h,struct smb2_stat_64 *s,smb2_command_cb cb,void *o)NEVER((void)c;(void)h;(void)s;(void)cb;(void)o;return -1;)
int smb2_get_fd(struct smb2_context *c)NEVER((void)c;return -1;)
int smb2_which_events(struct smb2_context *c)NEVER((void)c;return 0;)
int smb2_service(struct smb2_context *c,int e)NEVER((void)c;(void)e;return -1;)
struct smb2fh *smb2_open(struct smb2_context *c,const char *p,int f)NEVER((void)c;(void)p;(void)f;return NULL;)
int smb2_close(struct smb2_context *c,struct smb2fh *h)NEVER((void)c;(void)h;return -1;)
int smb2_pread(struct smb2_context *c,struct smb2fh *h,uint8_t *b,uint32_t n,uint64_t a)NEVER((void)c;(void)h;(void)b;(void)n;(void)a;return -1;)
int __wrap_clock_gettime(clockid_t clock,struct timespec *stamp){
    static uint64_t ns=1000000000u;CHECK(clock==CLOCK_MONOTONIC&&stamp);ns+=1000;
    stamp->tv_sec=(time_t)(ns/1000000000u);stamp->tv_nsec=(long)(ns%1000000000u);return 0;
}
/* libnfs model: settings recorded, two async metadata slots, open handles. */
struct nfsfh {unsigned id;struct nfsfh *next;};
struct pending {int active,kind;unsigned id;nfs_cb cb;void *opaque;};
struct nfs_context {
    int version,timeout,retrans,autoreconnect,dircache,readonly,uid,gid;size_t readmax;
    int mounted;struct nfsfh *handles;struct pending meta[2];
};
static const char *root="emulation/ps5/games/folders/Fixture Title/";
static unsigned char body(unsigned id,uint64_t at){return (unsigned char)((at*13+id*31)%251);}
static int path_id(const char *p){
    size_t n=strlen(root);unsigned id;char tail;
    if(strncmp(p,root,n)||sscanf(p+n,"stream%02u.pak%c",&id,&tail)!=1||id>=18)return -1;return (int)id;
}
static void attr_of(unsigned id,struct nfs_stat_64 *s){
    memset(s,0,sizeof *s);s->nfs_mode=S_IFREG|0444;s->nfs_size=stream_size+id;s->nfs_ino=500+id+(unsigned)changed;
    s->nfs_mtime=100;s->nfs_mtime_nsec=123456789;s->nfs_ctime=200;s->nfs_ctime_nsec=987654321;s->nfs_nlink=1;
}
struct nfs_context *nfs_init_context(void){contexts++;struct nfs_context *c=calloc(1,sizeof *c);c->version=NFS_V3;c->timeout=60000;c->retrans=2;c->autoreconnect=-1;c->dircache=1;c->readmax=1024*1024;return c;}
void nfs_destroy_context(struct nfs_context *c){
    CHECK(c);
    /* As rpc_destroy_context: every queued request completes as canceled. */
    for(unsigned i=0;i<2;i++)if(c->meta[i].active){c->meta[i].active=0;drained++;c->meta[i].cb(-EINTR,c,"Command was cancelled",c->meta[i].opaque);}
    while(c->handles){struct nfsfh *h=c->handles;c->handles=h->next;free(h);}
    destroys++;free(c);
}
int nfs_set_version(struct nfs_context *c,int v){CHECK(c&&(v==NFS_V3||v==NFS_V4));c->version=v;return 0;}
void nfs_set_timeout(struct nfs_context *c,int ms){CHECK(c);c->timeout=ms;}
void nfs_set_retrans(struct nfs_context *c,int n){CHECK(c);c->retrans=n;}
void nfs_set_autoreconnect(struct nfs_context *c,int n){CHECK(c);c->autoreconnect=n;}
void nfs_set_dircache(struct nfs_context *c,int n){CHECK(c);c->dircache=n;}
void nfs_set_readonly(struct nfs_context *c,int n){CHECK(c);c->readonly=n;}
void nfs_set_uid(struct nfs_context *c,int n){CHECK(c);c->uid=n;}
void nfs_set_gid(struct nfs_context *c,int n){CHECK(c);c->gid=n;}
void nfs_set_readmax(struct nfs_context *c,size_t n){CHECK(c);c->readmax=n;}
size_t nfs_get_readmax(struct nfs_context *c){CHECK(c&&c->mounted);return c->readmax;}
char *nfs_get_error(struct nfs_context *c){(void)c;return (char*)"";}
int nfs_mount(struct nfs_context *c,const char *server,const char *export){
    mounts++;
    /* Every failure must surface: no retransmit, no reconnect, bounded RPCs. */
    CHECK(c&&c->timeout==10000&&c->retrans==0&&c->autoreconnect==0&&c->dircache==0&&c->readonly==1);
    CHECK(c->uid==1000&&c->gid==1001&&c->readmax==128u*1024u);
    CHECK(!strcmp(server,"192.0.2.1")&&!strcmp(export,"/volume1/public"));version_seen=c->version;
    if(fail_mount)return fail_mount;
    c->mounted=1;if(server_readmax)c->readmax=server_readmax;return 0;
}
static int named(struct nfs_context *c,const char *path,struct nfs_stat_64 *s){
    CHECK(c&&c->mounted);int id=path_id(path);CHECK(id>=0);lstats++;
    if(++named_seen==2){if(stale_final)return -ESTALE;if(timeout_final)return -EINTR;}
    attr_of((unsigned)id,s);if(link_named)s->nfs_mode=S_IFLNK|0777;if(fifo_named)s->nfs_mode=S_IFIFO|0644;return 0;
}
int nfs_lstat64(struct nfs_context *c,const char *path,struct nfs_stat_64 *s){return named(c,path,s);}
int nfs_stat64(struct nfs_context *c,const char *path,struct nfs_stat_64 *s){(void)c;(void)path;(void)s;CHECK(!"stat follows links");return -1;}
int nfs_fstat64(struct nfs_context *c,struct nfsfh *h,struct nfs_stat_64 *s){CHECK(c&&h);fstats++;attr_of(h->id,s);return 0;}
static int queue(struct nfs_context *c,int kind,unsigned id,nfs_cb cb,void *opaque){
    CHECK(c&&cb&&!c->meta[kind].active);c->meta[kind]=(struct pending){1,kind,id,cb,opaque};return 0;
}
int nfs_lstat64_async(struct nfs_context *c,const char *path,nfs_cb cb,void *opaque){int id=path_id(path);CHECK(id>=0);return queue(c,0,(unsigned)id,cb,opaque);}
int nfs_fstat64_async(struct nfs_context *c,struct nfsfh *h,nfs_cb cb,void *opaque){CHECK(h);return queue(c,1,h->id,cb,opaque);}
int nfs_get_fd(struct nfs_context *c){CHECK(c);return 77;}
int nfs_which_events(struct nfs_context *c){CHECK(c);return POLLIN;}
int poll(struct pollfd *fd,nfds_t count,int timeout){CHECK(fd&&count==1&&fd->fd==77&&timeout==250);fd->revents=POLLIN;return 1;}
int nfs_service(struct nfs_context *c,int revents){
    CHECK(c&&revents==POLLIN);services++;
    if(service_fail){service_fail=0;return -1;}
    if(c->meta[0].active&&c->meta[1].active)paired++;
    for(unsigned i=0;i<2;i++){
        struct pending *r=&c->meta[i];if(!r->active)continue;r->active=0;
        struct nfs_stat_64 s;char path[256];int rc;
        if(r->kind){fstats++;attr_of(r->id,&s);rc=0;}
        else{snprintf(path,sizeof path,"%sstream%02u.pak",root,r->id);rc=named(c,path,&s);}
        r->cb(rc,c,rc?(void*)"error":(void*)&s,r->opaque);
    }return 0;
}
int nfs_open(struct nfs_context *c,const char *path,int flags,struct nfsfh **out){
    CHECK(c&&c->mounted&&out);int id=path_id(path);CHECK(id>=0);
    CHECK(flags==(O_RDONLY|O_NOFOLLOW));
    struct nfsfh *h=calloc(1,sizeof *h);h->id=(unsigned)id;h->next=c->handles;c->handles=h;opens++;*out=h;return 0;
}
int nfs_close(struct nfs_context *c,struct nfsfh *h){
    struct nfsfh **at=&c->handles;while(*at&&*at!=h)at=&(*at)->next;CHECK(*at==h);*at=h->next;free(h);closes++;return 0;
}
int nfs_pread(struct nfs_context *c,struct nfsfh *h,void *buf,size_t count,uint64_t at){
    CHECK(c&&h&&buf&&count&&count<=c->readmax&&count<=128u*1024u);reads++;
    if(count>largest_read)largest_read=(uint32_t)count;
    if(stale_read){stale_read=0;return -ESTALE;}
    if(timeout_read){timeout_read=0;return -EINTR;}
    uint64_t size=stream_size+h->id;if(at>=size)return 0;if(count>size-at)count=(size_t)(size-at);
    for(size_t i=0;i<count;i++)((unsigned char*)buf)[i]=body(h->id,at+i);
    if(cancel_after_read)canceled=1;return (int)count;
}
static int guard(void *p){CHECK(p==&canceled);return canceled;}
static void put32(unsigned char *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(i*8));}
static void put64(unsigned char *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(n>>(i*8));}
static unsigned char map[8192];static size_t map_size,selection_size;static char selection[4096];
static struct bw_reader_selection selected;
static char share[512];static size_t share_size;
static void handoff(unsigned version,const char *extra){
    share_size=(size_t)snprintf(share,sizeof share,"transport=nfs\nserver=192.0.2.1\nexport=/volume1/public\npath=emulation/ps5/games/folders\nnfs_version=%u\nuid=1000\ngid=1001\n%s",version,extra);
}
static void fixture(unsigned version){
    canceled=changed=fail_mount=stale_read=timeout_read=stale_final=timeout_final=service_fail=0;
    link_named=fifo_named=cancel_after_read=version_seen=0;named_seen=0;server_readmax=0;largest_read=0;stream_size=131079;
    handoff(version,"");
    memset(map,0,sizeof map);memcpy(map,"BWMAP002",8);put32(map+8,2);put32(map+12,32);put32(map+16,20);
    size_t pool=40+20*32,offset=0;
    for(unsigned i=0;i<20;i++){
        char path[64];if(i==0)strcpy(path,"eboot.bin");else if(i==1)strcpy(path,"local.bin");else snprintf(path,sizeof path,"stream%02u.pak",i-2);
        size_t n=strlen(path);unsigned char *row=map+40+i*32;
        put32(row,(uint32_t)offset);put32(row+4,(uint32_t)n);put32(row+8,i<2?1:2);put64(row+16,i==0?11:i==1?17:131079+i-2);put64(row+24,100);
        memcpy(map+pool+offset,path,n+1);offset+=n+1;
    }
    map_size=pool+offset;put64(map+24,offset);put64(map+32,bw_manifest_fnv1a64(map+40,map_size-40));
    struct bw_share_config cfg;CHECK(!bw_share_parse(&cfg,share,share_size));CHECK(cfg.transport==BW_SHARE_NFS);
    struct bw_source_binding b;CHECK(!bw_source_binding_resolve(&b,&cfg,"Fixture Title","PPSA09999"));
    memset(&selected,0,sizeof selected);
    strcpy(selected.source,b.source);strcpy(selected.title,b.title);strcpy(selected.game,b.game);strcpy(selected.binding_hex,b.game+10);
    memset(selected.run,'1',32);memset(selected.prepared_record_hex,'2',64);selected.eboot_size=11;selected.manifest_count=20;
    selected.manifest_hash=bw_manifest_fnv1a64(map+40,map_size-40);selected.source_kind=1;selected.source_policy=1;
    CHECK(!bw_reader_selection_serialize(&selected,selection,sizeof selection,&selection_size));bw_share_clear(&cfg);
}
static void set_stream_size(uint64_t size){
    stream_size=size;for(unsigned i=2;i<20;i++)put64(map+40+i*32+16,size+i-2);
    selected.manifest_hash=bw_manifest_fnv1a64(map+40,map_size-40);put64(map+32,selected.manifest_hash);
    CHECK(!bw_reader_selection_serialize(&selected,selection,sizeof selection,&selection_size));
}
static struct bp_source *open_source(void){struct bp_source *p=NULL;CHECK(!bp_source_open(&p,map,map_size,selection,selection_size,share,share_size,guard,&canceled));CHECK(p);return p;}
static uint32_t match(struct bp_source *p,unsigned id){char path[64];snprintf(path,sizeof path,"/app0/stream%02u.pak",id);uint32_t out=99;CHECK(bp_source_match(p,path,strlen(path),stream_size+id,&out)==1);CHECK(out==id+2);return out;}
static void failed_with(struct bp_source *p,int error,uint32_t status){
    struct bp_source_progress progress;bp_source_progress(p,&progress);
    CHECK(progress.poisoned&&progress.first_poison.valid&&progress.first_poison.error_observed&&progress.first_poison.error==error);
    CHECK(progress.first_poison.ntstatus_observed&&progress.first_poison.ntstatus==status);
}
static unsigned char large[1024u*1024u];
int main(void){
    unsigned char out[140000];struct bp_source *p;uint32_t id;unsigned before;struct bp_connect_diagnostic diagnostic;
    /* v3 cold read: one named lstat, open without following links, held
     * fstat, payload, then the paired final fence. Paths sit below nfs_path. */
    fixture(3);cases++;p=open_source();CHECK(version_seen==NFS_V3&&mounts==1);
    bp_source_connect_diagnostic(p,&diagnostic);CHECK(diagnostic.stage==BP_CONNECT_NONE&&diagnostic.options_returned==9);
    id=match(p,0);CHECK(bp_source_read(p,id,65530,out,65550)==65549);
    CHECK(lstats==2&&fstats==2&&opens==1&&paired==1);for(size_t i=0;i<65549;i++)CHECK(out[i]==body(0,65530+i));
    before=reads;CHECK(bp_source_read(p,id,65530,out,9)==9&&reads==before&&lstats==4&&fstats==4);CHECK(!bp_source_close(p));
    CHECK(closes==opens);
    fixture(4);cases++;p=open_source();CHECK(version_seen==NFS_V4);id=match(p,1);CHECK(bp_source_read(p,id,7,out,5)==5&&out[0]==body(1,7));CHECK(!bp_source_close(p));
    /* A server offering 1MiB still gets 128KiB payload calls. */
    fixture(3);cases++;set_stream_size(2u*1024u*1024u);p=open_source();id=match(p,0);before=reads;
    CHECK(bp_source_read(p,id,0,large,sizeof large)==(int64_t)sizeof large&&reads-before==8&&largest_read==128u*1024u);
    for(size_t i=0;i<sizeof large;i++)CHECK(large[i]==body(0,i));CHECK(!bp_source_close(p));
    /* A smaller negotiated maximum constrains every call. */
    fixture(3);cases++;server_readmax=32768;p=open_source();id=match(p,0);before=reads;
    CHECK(bp_source_read(p,id,0,out,131079)==131079&&reads-before==5&&largest_read==32768);CHECK(!bp_source_close(p));
    /* STALE on payload is the changed class. The context is destroyed. */
    fixture(3);cases++;p=open_source();id=match(p,0);stale_read=1;before=destroys;
    CHECK(bp_source_read(p,id,0,out,5)==-EIO&&destroys==before+1);failed_with(p,ESTALE,BW_TP_CHANGED);
    before=reads;CHECK(bp_source_read(p,id,0,out,5)==-EIO&&reads==before);CHECK(!bp_source_close(p));
    /* An RPC timeout arrives as -EINTR and is the timeout class. */
    fixture(3);cases++;p=open_source();id=match(p,0);timeout_read=1;
    CHECK(bp_source_read(p,id,0,out,5)==-EIO);failed_with(p,EINTR,BW_TP_TIMEOUT);CHECK(!bp_source_close(p));
    /* The same classes through the async final fence. */
    fixture(3);cases++;p=open_source();id=match(p,0);stale_final=1;before=destroys;
    CHECK(bp_source_read(p,id,0,out,5)==-EIO&&destroys==before+1);failed_with(p,ESTALE,BW_TP_CHANGED);CHECK(!bp_source_close(p));
    fixture(3);cases++;p=open_source();id=match(p,0);timeout_final=1;
    CHECK(bp_source_read(p,id,0,out,5)==-EIO);failed_with(p,EINTR,BW_TP_TIMEOUT);CHECK(!bp_source_close(p));
    /* Links and special files never pass the regular-file check. */
    fixture(3);cases++;p=open_source();id=match(p,0);link_named=1;before=opens;CHECK(bp_source_read(p,id,0,out,5)==-EIO&&opens==before);CHECK(!bp_source_close(p));
    fixture(3);cases++;p=open_source();id=match(p,0);fifo_named=1;before=opens;CHECK(bp_source_read(p,id,0,out,5)==-EIO&&opens==before);CHECK(!bp_source_close(p));
    /* A replaced file (new fileid) fails the next identity fence. */
    fixture(3);cases++;p=open_source();id=match(p,0);CHECK(bp_source_read(p,id,0,out,5)==5);changed=1;CHECK(bp_source_read(p,id,0,out,5)==-EIO);CHECK(!bp_source_close(p));
    fixture(3);cases++;p=open_source();id=match(p,0);cancel_after_read=1;CHECK(bp_source_read(p,id,0,out,5)==-ECANCELED);CHECK(!bp_source_close(p));
    /* A failed service with both requests queued: destroy drains both
     * borrowed destinations before the fence returns. ASan checks lifetime. */
    fixture(3);cases++;p=open_source();id=match(p,0);CHECK(bp_source_read(p,id,0,out,5)==5);service_fail=1;before=drained;
    CHECK(bp_source_read(p,id,0,out,5)==-EIO&&drained==before+2);CHECK(!bp_source_close(p));
    /* Mount refusal: share stage, raw result, errno and class recorded. */
    fixture(3);cases++;fail_mount=-EACCES;before=destroys;p=NULL;
    CHECK(!bp_source_admit(&p,map,map_size,selection,selection_size,share,share_size,guard,&canceled));CHECK(bp_source_connect(p)==-1);
    bp_source_connect_diagnostic(p,&diagnostic);
    CHECK(diagnostic.stage==BP_CONNECT_SHARE&&diagnostic.raw==-EACCES&&diagnostic.error==EACCES&&diagnostic.options_returned==9);
    CHECK(diagnostic.ntstatus_valid&&diagnostic.ntstatus==BW_TP_AUTH&&destroys==before+1);CHECK(!bp_source_close(p));
    /* Handoff refusals happen before any connection. */
    static const char *refused[]={"share=x\n","user=x\n","path2=emulation/ps5/games/images\n"};
    for(unsigned i=0;i<sizeof refused/sizeof *refused;i++){
        fixture(3);cases++;handoff(3,refused[i]);before=contexts;p=NULL;
        CHECK(bp_source_admit(&p,map,map_size,selection,selection_size,share,share_size,guard,&canceled)<0&&!p&&contexts==before);
    }
    fixture(3);cases++;share_size=(size_t)snprintf(share,sizeof share,"transport=nfs\nserver=nas.local\nexport=/volume1/public\npath=emulation/ps5/games/folders\nnfs_version=3\nuid=1000\ngid=1001\n");
    before=contexts;p=NULL;CHECK(bp_source_admit(&p,map,map_size,selection,selection_size,share,share_size,guard,&canceled)<0&&!p&&contexts==before);
    CHECK(contexts==destroys);
    printf("{\"passed\":true,\"cases\":%u,\"checks\":%u,\"transportModelOnly\":true,\"nativeReadProved\":false,\"nfsVersions\":[3,4],\"readMaximumBytes\":131072,\"staleClass\":\"changed\",\"timeoutClass\":\"timeout\"}\n",cases,checks);
    return 0;
}
