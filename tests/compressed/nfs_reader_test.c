/* SPDX-License-Identifier: GPL-3.0-or-later
 * Actual early reader, decoder, cache and NFS reader table over a local-file
 * libnfs model. The image source is the main NFS path: every game is one
 * .ffpfsc below the images root. No console or live NFS server. */
#define _POSIX_C_SOURCE 200809L
#include "reader/preload/source.h"
#include "library/reader_selection.h"
#include "library/source_binding.h"
#include "streamreader/container_source.h"
#include "streamreader/container_manifest.h"
#include "streamreader/manifest.h"
#include "streamreader/share_config.h"
#include "streamreader/bw_tp_error.h"
#include <nfsc/libnfs.h>
#define NFS_V3 3 /* raw protocol header values */
#define NFS_V4 4
static int version=NFS_V4;
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

static unsigned checks,files,ranges,contexts,destroys,preads,nstats,hstats,drained,cancellation_cases;
static int canceled,changed,stale_read,timeout_read,cancel_during_read,cancel_after_stat,fail_close;
static size_t largest;
static const char *live_image;
#define IMAGE_PATH "emulation/ps5/games/images/fixture.ffpfsc"
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"nfs-compressed-reader line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
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
struct nfsfh {int fd;};
struct pending {int active;struct nfsfh *fh;nfs_cb cb;void *opaque;};
struct nfs_context {int version,timeout,retrans,autoreconnect,dircache,readonly;size_t readmax;int mounted;struct nfsfh *fh;struct pending meta[2];};
static void attr(const struct stat *s,struct nfs_stat_64 *out){
    memset(out,0,sizeof *out);out->nfs_mode=S_IFREG|0444;out->nfs_size=(uint64_t)s->st_size;out->nfs_ino=(uint64_t)s->st_ino;
    out->nfs_mtime=(uint64_t)s->st_mtim.tv_sec+(changed?1u:0u);out->nfs_mtime_nsec=(uint64_t)s->st_mtim.tv_nsec;
    out->nfs_ctime=(uint64_t)s->st_ctim.tv_sec;out->nfs_ctime_nsec=(uint64_t)s->st_ctim.tv_nsec;out->nfs_nlink=1;
}
struct nfs_context *nfs_init_context(void){contexts++;struct nfs_context *c=calloc(1,sizeof *c);c->retrans=2;c->autoreconnect=-1;c->dircache=1;c->readmax=1u<<20;return c;}
void nfs_destroy_context(struct nfs_context *c){
    CHECK(c);
    for(unsigned i=0;i<2;i++)if(c->meta[i].active){c->meta[i].active=0;drained++;c->meta[i].cb(-EINTR,c,"Command was cancelled",c->meta[i].opaque);}
    if(c->fh){close(c->fh->fd);free(c->fh);}destroys++;free(c);
}
int nfs_set_version(struct nfs_context *c,int v){CHECK(c&&v==version);c->version=v;return 0;}
void nfs_set_timeout(struct nfs_context *c,int ms){c->timeout=ms;}
void nfs_set_retrans(struct nfs_context *c,int n){c->retrans=n;}
void nfs_set_autoreconnect(struct nfs_context *c,int n){c->autoreconnect=n;}
void nfs_set_dircache(struct nfs_context *c,int n){c->dircache=n;}
void nfs_set_readonly(struct nfs_context *c,int n){c->readonly=n;}
void nfs_set_uid(struct nfs_context *c,int n){CHECK(c&&n==1000);}
void nfs_set_gid(struct nfs_context *c,int n){CHECK(c&&n==1000);}
void nfs_set_readmax(struct nfs_context *c,size_t n){c->readmax=n;}
size_t nfs_get_readmax(struct nfs_context *c){CHECK(c&&c->mounted);return c->readmax;}
char *nfs_get_error(struct nfs_context *c){(void)c;return (char*)"";}
int nfs_mount(struct nfs_context *c,const char *server,const char *export){
    CHECK(c&&c->timeout==10000&&!c->retrans&&!c->autoreconnect&&!c->dircache&&c->readonly&&c->readmax==131072);
    CHECK(!strcmp(server,"192.168.11.186")&&!strcmp(export,"/volume1/public"));c->mounted=1;return 0;
}
static int named(struct nfs_context *c,const char *path,struct nfs_stat_64 *out){
    CHECK(c&&c->mounted&&!strcmp(path,IMAGE_PATH));nstats++;struct stat st;
    if(stat(live_image,&st))return -ENOENT;attr(&st,out);
    if(cancel_after_stat&&!--cancel_after_stat)canceled=1;return 0;
}
int nfs_lstat64(struct nfs_context *c,const char *path,struct nfs_stat_64 *out){return named(c,path,out);}
int nfs_stat64(struct nfs_context *c,const char *path,struct nfs_stat_64 *out){(void)c;(void)path;(void)out;CHECK(!"stat follows links");return -1;}
int nfs_fstat64(struct nfs_context *c,struct nfsfh *fh,struct nfs_stat_64 *out){
    CHECK(c&&fh&&fh==c->fh);hstats++;struct stat st;if(fstat(fh->fd,&st))return -EIO;attr(&st,out);return 0;
}
int nfs_lstat64_async(struct nfs_context *c,const char *path,nfs_cb cb,void *opaque){
    CHECK(c&&cb&&!c->meta[0].active&&!strcmp(path,IMAGE_PATH));c->meta[0]=(struct pending){1,NULL,cb,opaque};return 0;
}
int nfs_fstat64_async(struct nfs_context *c,struct nfsfh *fh,nfs_cb cb,void *opaque){
    CHECK(c&&cb&&fh&&!c->meta[1].active);c->meta[1]=(struct pending){1,fh,cb,opaque};return 0;
}
int nfs_get_fd(struct nfs_context *c){CHECK(c);return 77;}
int nfs_which_events(struct nfs_context *c){CHECK(c);return POLLIN;}
int poll(struct pollfd *fd,nfds_t count,int timeout){CHECK(fd&&count==1&&fd->fd==77&&timeout==250);fd->revents=POLLIN;return 1;}
int nfs_service(struct nfs_context *c,int revents){
    CHECK(c&&revents==POLLIN);
    for(unsigned i=0;i<2;i++)if(c->meta[i].active){
        struct pending *r=&c->meta[i];r->active=0;struct nfs_stat_64 s;
        int rc=i?nfs_fstat64(c,r->fh,&s):named(c,IMAGE_PATH,&s);r->cb(rc,c,rc?(void*)"error":(void*)&s,r->opaque);
    }return 0;
}
int nfs_open(struct nfs_context *c,const char *path,int flags,struct nfsfh **out){
    CHECK(c&&c->mounted&&!c->fh&&out&&!strcmp(path,IMAGE_PATH)&&flags==(O_RDONLY|O_NOFOLLOW));
    int fd=open(live_image,O_RDONLY|O_NOFOLLOW);if(fd<0)return -errno;
    c->fh=calloc(1,sizeof *c->fh);CHECK(c->fh);c->fh->fd=fd;*out=c->fh;return 0;
}
int nfs_close(struct nfs_context *c,struct nfsfh *fh){
    CHECK(c&&fh==c->fh);close(fh->fd);free(fh);c->fh=NULL;if(fail_close){fail_close=0;return -EIO;}return 0;
}
int nfs_pread(struct nfs_context *c,struct nfsfh *fh,void *out,size_t count,uint64_t at){
    CHECK(c&&fh==c->fh&&out&&count&&count<=131072);preads++;if(count>largest)largest=count;
    if(stale_read){stale_read=0;return -ESTALE;}
    if(timeout_read){timeout_read=0;return -EINTR;}
    ssize_t got=pread(fh->fd,out,count,(off_t)at);
    if(got>0&&cancel_during_read){cancel_during_read=0;canceled=1;}
    return got<0?-errno:(int)got;
}
static int guard(void *opaque){CHECK(opaque==&canceled);return canceled;}
static int exact(int fd,uint64_t at,void *out,size_t size){
    for(size_t n=0;n<size;){ssize_t got=pread(fd,(char *)out+n,size-n,(off_t)(at+n));if(got<=0)return -1;n+=(size_t)got;}return 0;}
struct original {char *path;uint64_t size;};
struct table {struct original *items;uint32_t count;size_t path_bytes;};
static int collect(void *opaque,const char *path,const struct bw_pfs_inode *node){
    struct table *p=opaque;CHECK(p->count<BW_MANIFEST_MAX_FILES&&!(node->flags&1u));
    struct original *next=realloc(p->items,(p->count+1u)*sizeof *next);CHECK(next);p->items=next;
    p->items[p->count++]=(struct original){strdup(path),node->logical_size};p->path_bytes+=strlen(path)+1;return 0;}
static int raw(void *opaque,uint64_t at,void *out,size_t size){return exact(*(int *)opaque,at,out,size);}
static int unchanged(void *opaque){(void)opaque;return 0;}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(8*i));}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(8*i));}
/* The real handoff: one export, games as images below one subfolder.
 * Byte-equal to the settings file nfs-config pins, with the version under
 * test (BW_NFS_VERSION, default 4). */
static char share[256];static size_t share_size;
static struct bp_source *open_source(const void *map,size_t map_size,const char *selection,size_t selection_size){
    struct bp_source *p=NULL;CHECK(!bp_source_open(&p,map,map_size,selection,selection_size,share,share_size,guard,&canceled));
    unsigned before=preads+nstats+hstats;CHECK(bp_source_worker_priority(p,384)==700);CHECK(before==preads+nstats+hstats);return p;}
static void failed_with(struct bp_source *p,int error,uint32_t status){
    struct bp_source_progress progress;bp_source_progress(p,&progress);
    CHECK(progress.poisoned&&progress.first_poison.valid&&progress.first_poison.error_observed&&progress.first_poison.error==error);
    CHECK(progress.first_poison.ntstatus_observed&&progress.first_poison.ntstatus==status);
}
int main(int argc,char **argv){
    CHECK(argc==4||argc==5);int refused=argc==5;live_image=argv[2];
    const char *wanted=getenv("BW_NFS_VERSION");if(wanted&&!strcmp(wanted,"3"))version=NFS_V3;else CHECK(!wanted||!strcmp(wanted,"4"));
    share_size=(size_t)snprintf(share,sizeof share,"transport=nfs\nserver=192.168.11.186\nexport=/volume1/public\npath=emulation/ps5/games/images\nnfs_version=%d\nuid=1000\ngid=1000\n",version);
    int fd=open(argv[1],O_RDONLY|O_NOFOLLOW);CHECK(fd>=0);struct stat st,live;CHECK(!fstat(fd,&st)&&!stat(live_image,&live));
    struct bw_container *image=calloc(1,sizeof *image);CHECK(image);struct bw_container_ops ops={raw,unchanged};
    CHECK(!bw_container_open(image,&ops,&fd,(uint64_t)st.st_size));struct table table={0};CHECK(!bw_container_walk(image,collect,&table,NULL));
    close(fd);free(image);CHECK(table.count>1);
    size_t pool=40u+(size_t)table.count*32u,map_size=pool+table.path_bytes,offset=0;uint8_t *map=calloc(1,map_size);CHECK(map);
    memcpy(map,BW_MANIFEST_MAGIC,8);put32(map+8,2);put32(map+12,32);put32(map+16,table.count);put64(map+24,table.path_bytes);
    struct bw_reader_selection selected={0};strcpy(selected.source,"fixture.ffpfsc");strcpy(selected.title,"PPSA09999");
    struct bw_share_config config;CHECK(!bw_share_parse(&config,share,share_size));CHECK(config.transport==BW_SHARE_NFS);
    struct bw_provider_binding binding;
    CHECK(!bw_provider_binding_init(&binding,&config,selected.source,selected.title,BW_PROVIDER_CONTAINER));bw_share_clear(&config);
    strcpy(selected.game,binding.binding.game);strcpy(selected.binding_hex,binding.binding.game+10);memset(selected.run,'1',32);memset(selected.prepared_record_hex,'2',64);
    selected.source_kind=BW_PROVIDER_CONTAINER;selected.source_policy=BW_PROVIDER_POLICY_V1;selected.manifest_count=table.count;
    uint32_t stream_id=UINT32_MAX;
    for(uint32_t i=0;i<table.count;i++){
        const struct original *row=&table.items[table.count-i-1u];size_t n=strlen(row->path);uint8_t *bytes=map+40u+(size_t)i*32u;
        int local=!strcmp(row->path,"eboot.bin");put32(bytes,(uint32_t)offset);put32(bytes+4,(uint32_t)n);put32(bytes+8,local?1:2);
        put64(bytes+16,row->size);put64(bytes+24,(uint64_t)live.st_mtim.tv_sec);memcpy(map+pool+offset,row->path,n+1);offset+=n+1;
        if(local)selected.eboot_size=row->size;else if(row->size>262144)stream_id=i;
    }
    selected.manifest_hash=bw_manifest_fnv1a64(map+40,map_size-40);put64(map+32,selected.manifest_hash);
    char selection[BW_READER_SELECTION_BYTES+1];size_t selection_size=0;CHECK(!bw_reader_selection_serialize(&selected,selection,sizeof selection,&selection_size));
    struct bp_source *source=open_source(map,map_size,selection,selection_size);struct bw_manifest manifest;CHECK(!bw_manifest_open(&manifest,map,map_size));
    uint8_t *left=malloc(BW_PFSC_MAX_READ),*right=malloc(BW_PFSC_MAX_READ);CHECK(left&&right);
    CHECK(stream_id!=UINT32_MAX);
    if(refused){
        /* A damaged or unsupported image is refused on the NFS path too. */
        CHECK(bp_source_read(source,stream_id,0,left,1)==-EIO);
        struct bp_source_progress failure;bp_source_progress(source,&failure);CHECK(failure.poisoned&&failure.first_poison.valid);
        unsigned prior=preads+nstats+hstats;CHECK(bp_source_read(source,stream_id,0,left,1)==-EIO&&preads+nstats+hstats==prior);
        CHECK(!bp_source_close(source));
    }else{
        /* Every stream file, three ranges each, against the original bytes. */
        for(uint32_t i=0;i<manifest.count;i++){
            struct bw_manifest_record row;CHECK(!bw_manifest_get(&manifest,i,&row));if(row.flags!=BW_MANIFEST_STREAM)continue;
            char path[4096],app[2048];int n=snprintf(path,sizeof path,"%s/%s",argv[3],row.path);CHECK(n>0&&(size_t)n<sizeof path);
            n=snprintf(app,sizeof app,"/app0/%s",row.path);CHECK(n>0&&(size_t)n<sizeof app);uint32_t id=UINT32_MAX;
            CHECK(bp_source_match(source,app,strlen(app),row.size,&id)==1&&id==i);
            int original=open(path,O_RDONLY|O_NOFOLLOW);CHECK(original>=0);CHECK(!fstat(original,&st)&&(uint64_t)st.st_size==row.size);
            for(unsigned span=0;span<3&&row.size;span++){
                size_t size=row.size<65536?(size_t)row.size:65536;uint64_t at=span==0?0:span==1?(row.size-size)/2:row.size-size;
                CHECK(bp_source_read(source,id,at,left,size)==(int64_t)size);CHECK(!exact(original,at,right,size)&&!memcmp(left,right,size));ranges++;
            }
            CHECK(!close(original));files++;
        }
        CHECK(largest&&largest<=131072);
        /* Cached reads keep the strict image fences, two of each kind. */
        CHECK(bp_source_read(source,stream_id,0,left,8)==8);
        unsigned before=preads,ns=nstats,hs=hstats;CHECK(bp_source_read(source,stream_id,0,left,8)==8);
        CHECK(preads==before&&nstats==ns+2&&hstats==hs+2);
        /* Cancellation during an uncached decode keeps the same mount. */
        unsigned keep_contexts=contexts,keep_destroys=destroys;struct bp_read_witness witness={0};
        cancel_during_read=1;CHECK(bp_source_read_observed(source,stream_id,131072,left,131072,&witness)==-ECANCELED&&!witness.valid&&canceled);
        canceled=0;CHECK(bp_source_read(source,stream_id,131072,left,131072)==131072&&contexts==keep_contexts&&destroys==keep_destroys);
        struct bw_manifest_record row;CHECK(!bw_manifest_get(&manifest,stream_id,&row));
        char original_path[4096];int n=snprintf(original_path,sizeof original_path,"%s/%s",argv[3],row.path);CHECK(n>0&&(size_t)n<sizeof original_path);
        int original=open(original_path,O_RDONLY|O_NOFOLLOW);CHECK(original>=0);
        CHECK(!exact(original,131072,right,131072)&&!memcmp(left,right,131072));CHECK(!close(original));cancellation_cases++;
        /* Cancellation observed at an image fence also keeps the mount. */
        cancel_after_stat=2;CHECK(bp_source_read_observed(source,stream_id,0,left,8,&witness)==-ECANCELED&&!witness.valid);
        canceled=0;CHECK(bp_source_read(source,stream_id,0,left,8)==8&&contexts==keep_contexts&&destroys==keep_destroys);cancellation_cases++;
        /* A replaced image (new mtime) is permanent. */
        changed=1;CHECK(bp_source_read(source,stream_id,0,left,8)==-EIO);changed=0;CHECK(!bp_source_close(source));
        /* STALE on a payload call is the changed class, and is permanent. */
        source=open_source(map,map_size,selection,selection_size);CHECK(bp_source_read(source,stream_id,0,left,8)==8);
        stale_read=1;before=destroys;CHECK(bp_source_read(source,stream_id,131072,left,131072)==-EIO&&destroys==before+1);
        failed_with(source,ESTALE,BW_TP_CHANGED);before=preads;CHECK(bp_source_read(source,stream_id,0,left,8)==-EIO&&preads==before);
        CHECK(!bp_source_close(source));
        /* An RPC timeout during the first image open is the timeout class. */
        source=open_source(map,map_size,selection,selection_size);timeout_read=1;
        CHECK(bp_source_read(source,stream_id,0,left,8)==-EIO);failed_with(source,EINTR,BW_TP_TIMEOUT);CHECK(!bp_source_close(source));
        /* Cancel before lazy decoder admission and during its first payload:
         * the same mount recovers and the incomplete handle is closed. */
        for(unsigned point=0;point<2;point++){
            source=open_source(map,map_size,selection,selection_size);keep_contexts=contexts;keep_destroys=destroys;
            cancel_after_stat=point==0;cancel_during_read=point==1;
            CHECK(bp_source_read_observed(source,stream_id,0,left,8,&witness)==-ECANCELED&&!witness.valid&&canceled);
            canceled=0;CHECK(bp_source_read(source,stream_id,131072,left,131072)==131072&&contexts==keep_contexts&&destroys==keep_destroys);
            original=open(original_path,O_RDONLY|O_NOFOLLOW);CHECK(original>=0);
            CHECK(!exact(original,131072,right,131072)&&!memcmp(left,right,131072));CHECK(!close(original));
            CHECK(!bp_source_close(source));cancellation_cases++;
        }
        /* A failed close of a canceled first open poisons the session. */
        source=open_source(map,map_size,selection,selection_size);cancel_during_read=fail_close=1;
        CHECK(bp_source_read_observed(source,stream_id,0,left,8,&witness)==-EIO&&canceled&&!witness.valid);
        canceled=0;before=preads;CHECK(bp_source_read(source,stream_id,0,left,8)==-EIO&&preads==before);CHECK(!bp_source_close(source));
    }
    CHECK(contexts==destroys);
    printf("{\"passed\":true,\"checks\":%u,\"filesCompared\":%u,\"rangesCompared\":%u,\"transportModelOnly\":true,\"transport\":\"nfs\",\"nfsVersion\":%d,\"largestPayloadCall\":%zu,\"contextsDestroyed\":%u,\"pendingDrained\":%u,\"cancellationRecoveryCases\":%u}\n",
           checks,files,ranges,version,largest,destroys,drained,cancellation_cases);
    for(uint32_t i=0;i<table.count;i++)free(table.items[i].path);free(table.items);free(map);free(left);free(right);return 0;
}
