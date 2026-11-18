#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "bw_transport_nfs.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <nfsc/libnfs.h>

_Static_assert(sizeof(struct nfs_stat_64)<=sizeof(struct bw_tp_stat_slot),"stat slot holds nfs_stat_64");
/* nfsdirent.type values. NFSv3 and v4 use the same numbers (NF3REG, NF4REG). */
enum {BW_NF_REG=1,BW_NF_DIR=2,BW_NF_LNK=5};

struct bw_nfs_context {
    struct nfs_context *nfs;
    char root[sizeof ((struct bw_share_config *)0)->nfs_path];
};
/* libnfs resolves absolute paths from the export root. */
static int nfs_full(const struct bw_nfs_context *c,const char *path,char *out,size_t size){
    int n=snprintf(out,size,"/%s%s%s",c->root,*c->root&&*path?"/":"",path);
    return n<0||(size_t)n>=size?-ENAMETOOLONG:0;
}
static uint32_t nfs_type(uint64_t mode){
    return S_ISREG(mode)?BW_TP_FILE:S_ISDIR(mode)?BW_TP_DIRECTORY:S_ISLNK(mode)?BW_TP_LINK:BW_TP_SPECIAL;
}
static void nfs_convert(const struct nfs_stat_64 *in,struct bw_stat *out){
    *out=(struct bw_stat){nfs_type(in->nfs_mode),0,in->nfs_ino,in->nfs_size,in->nfs_mtime,in->nfs_mtime_nsec,in->nfs_ctime,in->nfs_ctime_nsec};
}
/* lstat: a link at the leaf is reported as a link, never resolved. */
static int nfs_tp_stat(void *context,const char *path,struct bw_stat *out,struct bw_tp_stat_slot *slot){
    struct bw_nfs_context *c=context;char full[2*sizeof c->root+2];
    struct nfs_stat_64 local={0},*raw=slot?(struct nfs_stat_64 *)(void *)slot->bytes:&local;
    int result=nfs_full(c,path,full,sizeof full);if(result)return result;
    result=nfs_lstat64(c->nfs,full,raw);if(!result)nfs_convert(raw,out);return result;
}
/* O_NOFOLLOW makes libnfs refuse any link met while resolving the path. */
static void *nfs_tp_open(void *context,const char *path){
    struct bw_nfs_context *c=context;char full[2*sizeof c->root+2];struct nfsfh *fh=NULL;
    if(nfs_full(c,path,full,sizeof full)||nfs_open(c->nfs,full,O_RDONLY|O_NOFOLLOW,&fh))return NULL;
    return fh;
}
static int nfs_tp_fstat(void *context,void *file,struct bw_stat *out,struct bw_tp_stat_slot *slot){
    struct bw_nfs_context *c=context;
    struct nfs_stat_64 local={0},*raw=slot?(struct nfs_stat_64 *)(void *)slot->bytes:&local;
    int result=nfs_fstat64(c->nfs,file,raw);if(!result)nfs_convert(raw,out);return result;
}
static int nfs_tp_pread(void *context,void *file,void *buffer,uint32_t size,uint64_t offset){
    struct bw_nfs_context *c=context;return nfs_pread(c->nfs,file,buffer,size,offset);
}
static int nfs_tp_close(void *context,void *file){struct bw_nfs_context *c=context;return nfs_close(c->nfs,file);}
static uint32_t nfs_tp_max_read(void *context){
    struct bw_nfs_context *c=context;size_t maximum=nfs_get_readmax(c->nfs);
    return maximum>BW_NFS_READ_MAX?BW_NFS_READ_MAX:(uint32_t)maximum;
}
static void nfs_tp_destroy(void *context){
    struct bw_nfs_context *c=context;if(!c)return;
    if(c->nfs)nfs_destroy_context(c->nfs);memset(c,0,sizeof *c);free(c);
}
static uint32_t nfs_entry_type(uint32_t type){
    return type==BW_NF_REG?BW_TP_FILE:type==BW_NF_DIR?BW_TP_DIRECTORY:type==BW_NF_LNK?BW_TP_LINK:BW_TP_SPECIAL;
}
/* Identity only. The catalog validates each image inside the listing
 * callback, so a copy into the same folder moves its times during the read.
 * Callers that need the folder's contents unchanged (the game tree walk)
 * compare its full metadata themselves. */
static int nfs_same_directory(const struct bw_stat *a,const struct bw_stat *b){
    return a->type==BW_TP_DIRECTORY&&b->type==BW_TP_DIRECTORY&&a->ino==b->ino;
}
/* nfs_opendir follows links, so the directory is lstat'ed before and after
 * the read. A link or a different object is refused. The directory cache is
 * off, so the read is fresh. */
static int nfs_tp_list(void *context,const char *path,bw_tp_dirent_fn fn,void *opaque){
    struct bw_nfs_context *c=context;char full[2*sizeof c->root+2];struct bw_stat before,after;struct nfsdir *dir=NULL;
    int result=nfs_full(c,path,full,sizeof full);if(result)return result;
    if((result=nfs_tp_stat(c,path,&before,NULL)))return result;
    if(before.type!=BW_TP_DIRECTORY)return before.type==BW_TP_LINK?-ELOOP:-ENOTDIR;
    if((result=nfs_opendir(c->nfs,full,&dir)))return result;
    for(struct nfsdirent *e;!result&&(e=nfs_readdir(c->nfs,dir));){
        struct bw_stat entry={nfs_entry_type(e->type),0,e->inode,e->size,(uint64_t)e->mtime.tv_sec,e->mtime_nsec,
            (uint64_t)e->ctime.tv_sec,e->ctime_nsec};
        if(e->mtime.tv_sec<0||e->ctime.tv_sec<0)result=-EINVAL;
        else result=fn(opaque,e->name,&entry);
    }
    nfs_closedir(c->nfs,dir);
    if(result)return result;
    if((result=nfs_tp_stat(c,path,&after,NULL)))return result;
    return nfs_same_directory(&before,&after)?0:-ESTALE;
}
const struct bw_transport_ops bw_transport_nfs_ops={BW_TP_NFS,nfs_tp_stat,nfs_tp_open,nfs_tp_fstat,nfs_tp_pread,
    nfs_tp_close,nfs_tp_max_read,nfs_tp_destroy,nfs_tp_list};

static int nfs_fail(struct bw_tp_status *status,enum bw_tp_error error,int result){
    status->error=error;status->result=result;status->result_known=result!=0;return -1;
}
int bw_transport_nfs_connect(const struct bw_share_config *cfg,int timeout_seconds,struct bw_transport *out,struct bw_tp_status *status){
    struct bw_tp_status ignored;if(!status)status=&ignored;
    *status=(struct bw_tp_status){BW_TP_TRANSPORT,0,0,0};
    if(!out)return -1;
    *out=(struct bw_transport){&bw_transport_nfs_ops,NULL};
    if(!cfg||cfg->transport!=BW_SHARE_NFS||cfg->nfs_has_path2||timeout_seconds<1||timeout_seconds>600||
       !memchr(cfg->nfs_path,0,sizeof cfg->nfs_path)||cfg->nfs_export[0]!='/'||
       (cfg->nfs_version&&cfg->nfs_version!=3&&cfg->nfs_version!=4))return -1;
    struct bw_nfs_context *c=calloc(1,sizeof *c);if(!c)return -1;
    memcpy(c->root,cfg->nfs_path,strlen(cfg->nfs_path)+1);
    if(!(c->nfs=nfs_init_context())){free(c);return -1;}
    int result=nfs_set_version(c->nfs,cfg->nfs_version?(int)cfg->nfs_version:3);
    if(result<0){nfs_tp_destroy(c);return nfs_fail(status,BW_TP_TRANSPORT,result);}
    nfs_set_timeout(c->nfs,timeout_seconds*1000);nfs_set_retrans(c->nfs,0);nfs_set_autoreconnect(c->nfs,0);
    nfs_set_dircache(c->nfs,0);nfs_set_readonly(c->nfs,1);nfs_set_readmax(c->nfs,BW_NFS_READ_MAX);
    nfs_set_uid(c->nfs,(int)cfg->nfs_uid);nfs_set_gid(c->nfs,(int)cfg->nfs_gid);
    result=nfs_mount(c->nfs,cfg->server,cfg->nfs_export);
    if(result){nfs_tp_destroy(c);return nfs_fail(status,bw_tp_error_from_nfs(result,1),result);}
    struct bw_stat root;result=nfs_tp_stat(c,"",&root,NULL);
    if(result||root.type!=BW_TP_DIRECTORY){
        enum bw_tp_error error=result?bw_tp_error_from_nfs(result,0):BW_TP_ROOT_MISSING;
        nfs_tp_destroy(c);return nfs_fail(status,error==BW_TP_MISSING||error==BW_TP_LINKED_OR_SPECIAL?BW_TP_ROOT_MISSING:error,result);
    }
    out->context=c;status->error=BW_TP_OK;status->result=0;status->result_known=1;return 0;
}
