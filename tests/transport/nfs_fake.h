/* SPDX-License-Identifier: GPL-3.0-or-later
 * libnfs sync API fake over a local directory tree, for host tests only. The
 * fake server exports <base>/<export>. Every setting call is recorded so a
 * test can pin the connect options. Faults are injected by knobs. */
#ifndef BW_TEST_NFS_FAKE_H
#define BW_TEST_NFS_FAKE_H
#include <nfsc/libnfs.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct nfsfh {int fd,slow;};
/* Open handles are tracked: libnfs frees them with the context. */
struct nfs_context {char root[1024];int mounted,version,timeout,retrans,autoreconnect,dircache,readonly,uid,gid;size_t readmax;struct nfsfh *open[32];};
struct nfsdir {struct nfsdirent *entries,*next;};
static struct {
    char base[1024],server[64];
    int mount_result,fail_pread_at,fail_lstat,fail_fstat,stale_fstat;
    unsigned contexts,destroys,mounts,opens,closes,preads,lstats,opendirs;
    size_t server_readmax;
    struct nfs_context last;
    /* Runs on every pread: a copy job writing beside the scanned images. */
    void (*on_pread)(void);
    /* A file whose name ends with slow_name stalls its first read this long. */
    char slow_name[64];unsigned slow_ms;
} nfs_fake;

static void nfs_fake_reset(const char *base){
    memset(&nfs_fake,0,sizeof nfs_fake);snprintf(nfs_fake.base,sizeof nfs_fake.base,"%s",base);
    snprintf(nfs_fake.server,sizeof nfs_fake.server,"192.0.2.10");nfs_fake.server_readmax=1024*1024;
}
struct nfs_context *nfs_init_context(void){nfs_fake.contexts++;return calloc(1,sizeof(struct nfs_context));}
void nfs_destroy_context(struct nfs_context *n){
    nfs_fake.destroys++;nfs_fake.last=*n;
    for(unsigned i=0;i<32;i++)if(n->open[i]){close(n->open[i]->fd);free(n->open[i]);}
    free(n);
}
int nfs_set_version(struct nfs_context *n,int v){if(v!=3&&v!=4)return -EINVAL;n->version=v;return 0;}
void nfs_set_timeout(struct nfs_context *n,int ms){n->timeout=ms;}
void nfs_set_retrans(struct nfs_context *n,int r){n->retrans=r;}
void nfs_set_autoreconnect(struct nfs_context *n,int r){n->autoreconnect=r;}
void nfs_set_dircache(struct nfs_context *n,int e){n->dircache=e;}
void nfs_set_readonly(struct nfs_context *n,int r){n->readonly=r;}
void nfs_set_readmax(struct nfs_context *n,size_t m){n->readmax=m;}
size_t nfs_get_readmax(struct nfs_context *n){return n->readmax<nfs_fake.server_readmax?n->readmax:nfs_fake.server_readmax;}
void nfs_set_uid(struct nfs_context *n,int u){n->uid=u;}
void nfs_set_gid(struct nfs_context *n,int g){n->gid=g;}
char *nfs_get_error(struct nfs_context *n){(void)n;return "fake";}
int nfs_mount(struct nfs_context *n,const char *server,const char *exportname){
    nfs_fake.mounts++;nfs_fake.last=*n;
    if(nfs_fake.mount_result)return nfs_fake.mount_result;
    if(strcmp(server,nfs_fake.server))return -EIO;
    struct stat st;int k=snprintf(n->root,sizeof n->root,"%s%s",nfs_fake.base,exportname);
    if(k<0||(size_t)k>=sizeof n->root||lstat(n->root,&st)||!S_ISDIR(st.st_mode))return -ENOENT;
    n->mounted=1;return 0;
}
static int nfs_fake_path(struct nfs_context *n,const char *path,char *out,size_t size){
    if(!n->mounted||path[0]!='/')return -EINVAL;
    int k=snprintf(out,size,"%s%s",n->root,path);return k<0||(size_t)k>=size?-ENAMETOOLONG:0;
}
static void nfs_fake_stat(const struct stat *s,struct nfs_stat_64 *o){
    memset(o,0,sizeof *o);o->nfs_dev=99;o->nfs_ino=(uint64_t)s->st_ino;o->nfs_mode=(uint64_t)s->st_mode;o->nfs_nlink=(uint64_t)s->st_nlink;
    o->nfs_size=(uint64_t)s->st_size;o->nfs_mtime=(uint64_t)s->st_mtim.tv_sec;o->nfs_mtime_nsec=(uint64_t)s->st_mtim.tv_nsec;
    o->nfs_ctime=(uint64_t)s->st_ctim.tv_sec;o->nfs_ctime_nsec=(uint64_t)s->st_ctim.tv_nsec;
}
int nfs_lstat64(struct nfs_context *n,const char *path,struct nfs_stat_64 *o){
    char full[2048];struct stat s;nfs_fake.lstats++;
    if(nfs_fake.fail_lstat&&nfs_fake.lstats>=(unsigned)nfs_fake.fail_lstat)return -EINTR;
    int r=nfs_fake_path(n,path,full,sizeof full);if(r)return r;
    if(lstat(full,&s))return -errno;nfs_fake_stat(&s,o);return 0;
}
/* libnfs O_NOFOLLOW: any link met while resolving the path is -ELOOP. */
int nfs_open(struct nfs_context *n,const char *path,int flags,struct nfsfh **out){
    char full[2048];int r=nfs_fake_path(n,path,full,sizeof full);if(r)return r;
    if((flags&O_ACCMODE)!=O_RDONLY||!(flags&O_NOFOLLOW))return -EINVAL;
    size_t at=strlen(n->root);
    for(char *slash=strchr(full+at+1,'/');;slash=strchr(slash+1,'/')){
        if(slash)*slash=0;struct stat s;int bad=lstat(full,&s)?-errno:S_ISLNK(s.st_mode)?-ELOOP:0;if(slash)*slash='/';
        if(bad)return bad;
        if(!slash)break;
    }
    int fd=open(full,O_RDONLY|O_NOFOLLOW);if(fd<0)return -errno;
    struct nfsfh *f=malloc(sizeof *f);if(!f){close(fd);return -ENOMEM;}f->fd=fd;
    size_t pl=strlen(path),sl=strlen(nfs_fake.slow_name);f->slow=sl&&pl>=sl&&!strcmp(path+pl-sl,nfs_fake.slow_name);
    for(unsigned i=0;i<32;i++)if(!n->open[i]){n->open[i]=f;*out=f;nfs_fake.opens++;return 0;}
    close(fd);free(f);return -EMFILE;
}
int nfs_fstat64(struct nfs_context *n,struct nfsfh *f,struct nfs_stat_64 *o){
    (void)n;struct stat s;
    if(nfs_fake.fail_fstat)return nfs_fake.fail_fstat;
    if(fstat(f->fd,&s))return -errno;nfs_fake_stat(&s,o);
    if(nfs_fake.stale_fstat)o->nfs_mtime_nsec^=1;
    return 0;
}
int nfs_pread(struct nfs_context *n,struct nfsfh *f,void *buf,size_t count,uint64_t offset){
    nfs_fake.preads++;
    if(nfs_fake.on_pread)nfs_fake.on_pread();
    if(f->slow&&nfs_fake.slow_ms){struct timespec wait={nfs_fake.slow_ms/1000,(long)(nfs_fake.slow_ms%1000)*1000000L};nanosleep(&wait,NULL);f->slow=0;}
    if(count>nfs_get_readmax(n))return -EINVAL;
    if(nfs_fake.fail_pread_at&&nfs_fake.preads>=(unsigned)nfs_fake.fail_pread_at)return -EINTR;
    ssize_t got=pread(f->fd,buf,count,(off_t)offset);return got<0?-errno:(int)got;
}
int nfs_close(struct nfs_context *n,struct nfsfh *f){nfs_fake.closes++;for(unsigned i=0;i<32;i++)if(n->open[i]==f)n->open[i]=NULL;int r=close(f->fd);free(f);return r?-errno:0;}
static uint32_t nfs_fake_type(mode_t m){return S_ISREG(m)?1:S_ISDIR(m)?2:S_ISLNK(m)?5:S_ISFIFO(m)?7:S_ISSOCK(m)?6:S_ISCHR(m)?4:3;}
/* Like libnfs: the whole directory is read at open, including . and .. */
int nfs_opendir(struct nfs_context *n,const char *path,struct nfsdir **out){
    char full[2048];int r=nfs_fake_path(n,path,full,sizeof full);if(r)return r;nfs_fake.opendirs++;
    DIR *d=opendir(full);if(!d)return -errno;
    struct nfsdir *dir=calloc(1,sizeof *dir);if(!dir){closedir(d);return -ENOMEM;}
    struct nfsdirent **tail=&dir->entries;
    for(struct dirent *e;(e=readdir(d));){
        char child[4096];struct stat s;snprintf(child,sizeof child,"%s/%s",full,e->d_name);if(lstat(child,&s))continue;
        struct nfsdirent *x=calloc(1,sizeof *x);x->name=strdup(e->d_name);x->inode=(uint64_t)s.st_ino;x->type=nfs_fake_type(s.st_mode);
        x->mode=(uint32_t)(s.st_mode&07777);x->size=(uint64_t)s.st_size;
        x->mtime.tv_sec=s.st_mtim.tv_sec;x->mtime.tv_usec=s.st_mtim.tv_nsec/1000;x->mtime_nsec=(uint32_t)s.st_mtim.tv_nsec;
        x->ctime.tv_sec=s.st_ctim.tv_sec;x->ctime.tv_usec=s.st_ctim.tv_nsec/1000;x->ctime_nsec=(uint32_t)s.st_ctim.tv_nsec;
        *tail=x;tail=&x->next;
    }
    closedir(d);dir->next=dir->entries;*out=dir;return 0;
}
struct nfsdirent *nfs_readdir(struct nfs_context *n,struct nfsdir *dir){(void)n;struct nfsdirent *e=dir->next;if(e)dir->next=e->next;return e;}
void nfs_closedir(struct nfs_context *n,struct nfsdir *dir){
    (void)n;for(struct nfsdirent *e=dir->entries,*next;e;e=next){next=e->next;free(e->name);free(e);}free(dir);
}
#endif
