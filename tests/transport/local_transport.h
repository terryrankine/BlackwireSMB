/* SPDX-License-Identifier: GPL-3.0-or-later
 * Neutral bw_transport_ops over a local directory, for host tests only. It
 * models a server root and injects one failure on demand. Paths are
 * root-relative as on a share or export. */
#ifndef BW_TEST_LOCAL_TRANSPORT_H
#define BW_TEST_LOCAL_TRANSPORT_H
#include "streamreader/bw_transport.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct local_file {int fd;};
/* Open files are tracked so destroy frees them, as a real library frees its
 * handles with the context. */
struct local_context {char root[1024];unsigned destroyed,opens,closes,reads;int fail_read,fail_stat,fail_fstat;struct local_file *open[32];};
static int local_path(const struct local_context *c,const char *path,char *out,size_t size){
    int n=snprintf(out,size,"%s%s%s",c->root,*path?"/":"",path);return n<0||(size_t)n>=size?-ENAMETOOLONG:0;
}
static void local_convert(const struct stat *st,struct bw_stat *out){
    *out=(struct bw_stat){S_ISREG(st->st_mode)?BW_TP_FILE:S_ISDIR(st->st_mode)?BW_TP_DIRECTORY:S_ISLNK(st->st_mode)?BW_TP_LINK:BW_TP_SPECIAL,0,(uint64_t)st->st_ino,
        (uint64_t)st->st_size,(uint64_t)st->st_mtim.tv_sec,(uint64_t)st->st_mtim.tv_nsec,(uint64_t)st->st_ctim.tv_sec,(uint64_t)st->st_ctim.tv_nsec};
}
static int local_stat(void *context,const char *path,struct bw_stat *out,struct bw_tp_stat_slot *slot){
    (void)slot;struct local_context *c=context;char full[2048];struct stat st;
    if(c->fail_stat)return c->fail_stat;
    if(local_path(c,path,full,sizeof full))return -ENAMETOOLONG;
    if(lstat(full,&st))return -errno;local_convert(&st,out);return 0;
}
static void *local_open(void *context,const char *path){
    struct local_context *c=context;char full[2048];
    if(local_path(c,path,full,sizeof full))return NULL;
    int fd=open(full,O_RDONLY|O_NOFOLLOW);if(fd<0)return NULL;
    struct local_file *f=malloc(sizeof *f);if(!f){close(fd);return NULL;}f->fd=fd;c->opens++;
    for(unsigned i=0;i<32;i++)if(!c->open[i]){c->open[i]=f;return f;}
    close(fd);free(f);return NULL;
}
static int local_fstat(void *context,void *file,struct bw_stat *out,struct bw_tp_stat_slot *slot){
    (void)slot;
    struct local_context *c=context;struct local_file *f=file;struct stat st;
    if(c->fail_fstat)return c->fail_fstat;
    if(fstat(f->fd,&st))return -errno;local_convert(&st,out);return 0;
}
static int local_pread(void *context,void *file,void *buffer,uint32_t size,uint64_t offset){
    struct local_context *c=context;struct local_file *f=file;c->reads++;
    if(c->fail_read&&c->reads>=(unsigned)c->fail_read)return -EINTR;
    ssize_t got=pread(f->fd,buffer,size,(off_t)offset);return got<0?-errno:(int)got;
}
static int local_close(void *context,void *file){
    struct local_context *c=context;struct local_file *f=file;c->closes++;
    for(unsigned i=0;i<32;i++)if(c->open[i]==f)c->open[i]=NULL;
    int result=close(f->fd);free(f);return result?-errno:0;
}
static uint32_t local_max_read(void *context){(void)context;return 65536;}
static void local_destroy(void *context){
    struct local_context *c=context;c->destroyed++;
    for(unsigned i=0;i<32;i++)if(c->open[i]){close(c->open[i]->fd);free(c->open[i]);c->open[i]=NULL;}
}
#include <dirent.h>
static int local_list(void *context,const char *path,bw_tp_dirent_fn fn,void *opaque){
    struct local_context *c=context;char full[2048];struct stat st;
    if(local_path(c,path,full,sizeof full))return -ENAMETOOLONG;
    if(lstat(full,&st))return -errno;if(S_ISLNK(st.st_mode))return -ELOOP;if(!S_ISDIR(st.st_mode))return -ENOTDIR;
    DIR *d=opendir(full);if(!d)return -errno;int result=0;
    for(struct dirent *e;!result&&(e=readdir(d));){
        char child[4096];struct bw_stat entry;snprintf(child,sizeof child,"%s/%s",full,e->d_name);
        if(lstat(child,&st)){result=-errno;break;}
        local_convert(&st,&entry);result=fn(opaque,e->d_name,&entry);
    }
    closedir(d);return result;
}
static const struct bw_transport_ops local_ops={BW_TP_NFS,local_stat,local_open,local_fstat,local_pread,local_close,local_max_read,local_destroy,local_list};
#endif
