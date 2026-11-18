/* SPDX-License-Identifier: GPL-3.0-or-later
 * NFS reader transport over libnfs. Sync calls plus the two async metadata
 * requests the paired identity fence queues. Paths arrive relative to the
 * selected source root and are joined below nfs_path on the mounted export.
 * Settings make every failure surface: no retransmit, no reconnect, a fixed
 * RPC timeout (libnfs reports it as -EINTR) and no directory cache. */
#include "transport.h"
#include "../../streamreader/bw_tp_error.h"
#include <nfsc/libnfs.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BP_NFS_TIMEOUT_MS 10000
/* nfs_set_version() values. libnfs defines NFS_V3 and NFS_V4 only in its raw
 * protocol headers, which the reader does not include. */
#define BP_NFS_V3 3
#define BP_NFS_V4 4
/* Reader design limit. Each payload call is clamped to it, so libnfs sends
 * one READ per call and never splits it. */
#define BP_NFS_READMAX (128u*1024u)
#define BP_NFS_PATH 2400u
struct bp_nfs;
struct bp_nfs_slot {struct bp_nfs *owner;struct smb2_stat_64 *out;void *opaque;int active;};
struct bp_nfs {
    struct nfs_context *nfs;
    char root[256];
    uint32_t last;int version_failed;
    struct bp_nfs_slot slots[2]; /* 0 named, 1 held */
};
#define NFS(t) ((struct bp_nfs *)(t))
#define NFSFH(f) ((struct nfsfh *)(f))
/* libnfs returns -errno and leaves errno alone. Callers sample errno for the
 * diagnostic, so mirror the result there. */
static int classify(struct bp_nfs *n,int rc,int mounting){
    if(rc<0){n->last=(uint32_t)bw_tp_error_from_nfs(rc,mounting);errno=-rc;}
    return rc;
}
static int record(struct bp_nfs *n,int rc){return classify(n,rc,0);}
static int join(const struct bp_nfs *n,const char *path,char out[BP_NFS_PATH]){
    int len=*n->root?snprintf(out,BP_NFS_PATH,"%s/%s",n->root,path):snprintf(out,BP_NFS_PATH,"%s",path);
    return len<0||(unsigned)len>=BP_NFS_PATH?-ENAMETOOLONG:0;
}
/* Only a regular file is FILE. Links, devices, sockets and FIFOs get a type
 * no identity check accepts. */
static void to_stat(const struct nfs_stat_64 *s,struct smb2_stat_64 *st){
    memset(st,0,sizeof *st);
    uint64_t kind=s->nfs_mode&0170000u;
    st->smb2_type=kind==0100000u?SMB2_TYPE_FILE:kind==0040000u?SMB2_TYPE_DIRECTORY:kind==0120000u?SMB2_TYPE_LINK:3u;
    st->smb2_nlink=(uint32_t)s->nfs_nlink;st->smb2_ino=s->nfs_ino;st->smb2_size=s->nfs_size;
    st->smb2_atime=s->nfs_atime;st->smb2_atime_nsec=s->nfs_atime_nsec;
    st->smb2_mtime=s->nfs_mtime;st->smb2_mtime_nsec=s->nfs_mtime_nsec;
    st->smb2_ctime=s->nfs_ctime;st->smb2_ctime_nsec=s->nfs_ctime_nsec;
}
static struct bp_transport *bpn_init(void){
    struct bp_nfs *n=calloc(1,sizeof *n);if(!n)return NULL;
    n->nfs=nfs_init_context();if(!n->nfs){int error=errno;free(n);errno=error;return NULL;}
    for(unsigned i=0;i<2;i++)n->slots[i].owner=n;
    return (struct bp_transport *)n;
}
/* Each setter is counted as it returns, matching the connect diagnostic. */
static void bpn_configure(struct bp_transport *t,const struct bw_share_config *c,unsigned *returned){
    struct bp_nfs *n=NFS(t);
    n->version_failed=nfs_set_version(n->nfs,c->nfs_version==4?BP_NFS_V4:BP_NFS_V3)!=0;(*returned)++;
    nfs_set_timeout(n->nfs,BP_NFS_TIMEOUT_MS);(*returned)++;
    nfs_set_retrans(n->nfs,0);(*returned)++;
    nfs_set_autoreconnect(n->nfs,0);(*returned)++;
    nfs_set_dircache(n->nfs,0);(*returned)++;
    nfs_set_readonly(n->nfs,1);(*returned)++;
    nfs_set_uid(n->nfs,(int)c->nfs_uid);(*returned)++;
    nfs_set_gid(n->nfs,(int)c->nfs_gid);(*returned)++;
    nfs_set_readmax(n->nfs,BP_NFS_READMAX);(*returned)++;
    snprintf(n->root,sizeof n->root,"%s",c->nfs_path);
}
static int bpn_connect(struct bp_transport *t,const struct bw_share_config *c){
    struct bp_nfs *n=NFS(t);
    if(n->version_failed){n->last=BW_TP_PROTOCOL;errno=EPROTONOSUPPORT;return -EPROTONOSUPPORT;}
    return classify(n,nfs_mount(n->nfs,c->server,c->nfs_export),1);
}
static uint32_t bpn_status(struct bp_transport *t){return NFS(t)->last;}
/* Destroying the context cancels every queued request. libnfs completes
 * each one with -EINTR, so both borrowed stat destinations are released
 * before this returns. */
static void bpn_destroy(struct bp_transport *t){
    struct bp_nfs *n=NFS(t);
    nfs_destroy_context(n->nfs);n->nfs=NULL;
    for(unsigned i=0;i<2;i++)if(n->slots[i].active){
        struct bp_nfs_slot *s=&n->slots[i];s->active=0;bp_transport_metadata_done(s->opaque,-ESHUTDOWN);
    }
    memset(n->root,0,sizeof n->root);free(n);
}
static int bpn_named(struct bp_transport *t,const char *path,struct smb2_stat_64 *st){
    struct bp_nfs *n=NFS(t);char full[BP_NFS_PATH];struct nfs_stat_64 s;
    int rc=join(n,path,full);if(rc)return record(n,rc);
    rc=record(n,nfs_lstat64(n->nfs,full,&s));if(rc<0)return rc;
    to_stat(&s,st);return 0;
}
static int bpn_held(struct bp_transport *t,struct bp_file *f,struct smb2_stat_64 *st){
    struct bp_nfs *n=NFS(t);struct nfs_stat_64 s;
    int rc=record(n,nfs_fstat64(n->nfs,NFSFH(f),&s));if(rc<0)return rc;
    to_stat(&s,st);return 0;
}
/* O_NOFOLLOW makes libnfs refuse a symbolic link in the path. */
static struct bp_file *bpn_open_file(struct bp_transport *t,const char *path){
    struct bp_nfs *n=NFS(t);char full[BP_NFS_PATH];struct nfsfh *fh=NULL;
    int rc=join(n,path,full);if(rc){record(n,rc);return NULL;}
    rc=record(n,nfs_open(n->nfs,full,O_RDONLY|O_NOFOLLOW,&fh));
    if(rc<0||!fh){if(!rc)record(n,-EIO);return NULL;}
    return (struct bp_file *)fh;
}
static int bpn_close_file(struct bp_transport *t,struct bp_file *f){return record(NFS(t),nfs_close(NFS(t)->nfs,NFSFH(f)));}
static void bpn_metadata_done(int status,struct nfs_context *nfs,void *data,void *opaque){
    (void)nfs;struct bp_nfs_slot *s=opaque;
    if(!s->active)return;
    s->active=0;
    if(!status&&!data)status=-EIO;
    if(!status)to_stat(data,s->out);
    else record(s->owner,status);
    bp_transport_metadata_done(s->opaque,status);
}
static int queue(struct bp_nfs *n,unsigned at,struct smb2_stat_64 *st,void *opaque){
    struct bp_nfs_slot *s=&n->slots[at];
    if(s->active)return record(n,-EBUSY);
    s->out=st;s->opaque=opaque;s->active=1;return 0;
}
static int bpn_named_async(struct bp_transport *t,const char *path,struct smb2_stat_64 *st,void *opaque){
    struct bp_nfs *n=NFS(t);char full[BP_NFS_PATH];
    int rc=join(n,path,full);if(rc)return record(n,rc);
    if((rc=queue(n,0,st,opaque)))return rc;
    rc=nfs_lstat64_async(n->nfs,full,bpn_metadata_done,&n->slots[0]);
    if(rc<0){n->slots[0].active=0;return record(n,rc);}
    return 0;
}
static int bpn_held_async(struct bp_transport *t,struct bp_file *f,struct smb2_stat_64 *st,void *opaque){
    struct bp_nfs *n=NFS(t);
    int rc=queue(n,1,st,opaque);if(rc)return rc;
    rc=nfs_fstat64_async(n->nfs,NFSFH(f),bpn_metadata_done,&n->slots[1]);
    if(rc<0){n->slots[1].active=0;return record(n,rc);}
    return 0;
}
static int bpn_fd(struct bp_transport *t){return nfs_get_fd(NFS(t)->nfs);}
static int bpn_events(struct bp_transport *t){return nfs_which_events(NFS(t)->nfs);}
static int bpn_serve(struct bp_transport *t,int revents){
    int rc=nfs_service(NFS(t)->nfs,revents);
    if(rc<0){NFS(t)->last=BW_TP_TRANSPORT;errno=EIO;}
    return rc;
}
static int bpn_read(struct bp_transport *t,struct bp_file *f,uint8_t *out,uint32_t size,uint64_t at){
    return record(NFS(t),nfs_pread(NFS(t)->nfs,NFSFH(f),out,size,at));
}
static uint32_t bpn_max_read(struct bp_transport *t){
    size_t limit=nfs_get_readmax(NFS(t)->nfs);
    return limit>BP_NFS_READMAX?BP_NFS_READMAX:(uint32_t)limit;
}
#undef NFSFH
#undef NFS
const struct bp_transport_ops bp_nfs_ops={bpn_init,bpn_configure,bpn_connect,bpn_status,bpn_destroy,
    bpn_named,bpn_held,bpn_open_file,bpn_close_file,bpn_named_async,bpn_held_async,bpn_fd,bpn_events,bpn_serve,bpn_read,bpn_max_read};
