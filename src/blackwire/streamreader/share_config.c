#include "share_config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void clear(void *data,size_t size) { volatile unsigned char *p=data;while (size--) *p++=0; }
void bw_share_clear(struct bw_share_config *p) { if (p) clear(p,sizeof *p); }
static int share_same(const char *a,const char *b) {
    while (*a && *b) {
        unsigned x=(unsigned char)*a++,y=(unsigned char)*b++;
        if (x>='A' && x<='Z') x+=32;if (y>='A' && y<='Z') y+=32;
        if (x!=y) return 0;
    }
    return !*a && !*b;
}
int bw_share_select(struct bw_share_config *out,const struct bw_share_config *configured,const char *share) {
    if (!out || !configured) return -1;
    struct bw_share_config selected={0};int result=-1;
    if (configured->transport!=BW_SHARE_SMB ||
        !memchr(configured->server,0,sizeof configured->server) ||
        !memchr(configured->share,0,sizeof configured->share) ||
        !memchr(configured->share2,0,sizeof configured->share2) ||
        !memchr(configured->user,0,sizeof configured->user) ||
        !memchr(configured->password,0,sizeof configured->password) ||
        !*configured->server || !*configured->share ||
        strpbrk(configured->server,"/\\") || strpbrk(configured->share,"/\\:") ||
        strpbrk(configured->share2,"/\\:") ||
        (*configured->share2 && share_same(configured->share,configured->share2))) goto done;
    const char *chosen=share && *share?share:configured->share;
    if (strcmp(chosen,configured->share) && (!*configured->share2 || strcmp(chosen,configured->share2))) goto done;
    selected=*configured;memset(selected.share,0,sizeof selected.share);
    memcpy(selected.share,chosen,strlen(chosen)+1);memset(selected.share2,0,sizeof selected.share2);result=0;
done:
    bw_share_clear(out);if (!result) *out=selected;bw_share_clear(&selected);return result;
}
/* Components are case-sensitive names. Empty, "." and ".." components are
 * refused so a source can never escape or alias another part of the export. */
static int nfs_components(const char *s) {
    for (;;) {
        size_t n=0;
        while (s[n] && s[n]!='/') {
            unsigned char c=(unsigned char)s[n];
            if (c<32 || c==127 || c=='\\' || c==':') return -1;
            n++;
        }
        if (!n || (n==1 && s[0]=='.') || (n==2 && s[0]=='.' && s[1]=='.')) return -1;
        if (!s[n]) return 0;
        s+=n+1;
    }
}
static int nfs_export_valid(const char *s) { return s[0]=='/' && (!s[1] || !nfs_components(s+1)); }
static int nfs_path_valid(const char *s) { return !*s || (s[0]!='/' && !nfs_components(s)); }
static int nfs_config_valid(const struct bw_share_config *p) {
    const char *strings[]={p->server,p->share,p->user,p->password,p->share2,p->nfs_export,p->nfs_path,p->nfs_path2};
    const size_t sizes[]={sizeof p->server,sizeof p->share,sizeof p->user,sizeof p->password,sizeof p->share2,
        sizeof p->nfs_export,sizeof p->nfs_path,sizeof p->nfs_path2};
    for (unsigned i=0;i<8;i++) if (!memchr(strings[i],0,sizes[i])) return 0;
    if (p->transport!=BW_SHARE_NFS || !*p->server || strpbrk(p->server,"/\\") ||
        *p->share || *p->share2 || *p->user || *p->password ||
        (p->nfs_version!=3 && p->nfs_version!=4) || p->nfs_uid==UINT32_MAX || p->nfs_gid==UINT32_MAX ||
        !nfs_export_valid(p->nfs_export) || !nfs_path_valid(p->nfs_path) || p->nfs_has_path2>1 ||
        (!p->nfs_has_path2 && *p->nfs_path2)) return 0;
    if (p->nfs_has_path2 && (!nfs_path_valid(p->nfs_path2) ||
        !strcmp(p->nfs_path,p->nfs_path2))) return 0;
    for (const char *c=p->server;*c;c++) if ((unsigned char)*c<32 || *c==127) return 0;
    return 1;
}
int bw_share_select_source(struct bw_share_config *out,const struct bw_share_config *configured,const char *source) {
    if (!out || !configured) return -1;
    if (configured->transport==BW_SHARE_SMB) return bw_share_select(out,configured,source);
    struct bw_share_config selected={0};int result=-1;
    if (!nfs_config_valid(configured)) goto done;
    const char *chosen=configured->nfs_path;
    if (source && strcmp(source,configured->nfs_path)) {
        if (!configured->nfs_has_path2 || strcmp(source,configured->nfs_path2)) goto done;
        chosen=configured->nfs_path2;
    }
    selected=*configured;memset(selected.nfs_path,0,sizeof selected.nfs_path);
    memcpy(selected.nfs_path,chosen,strlen(chosen)+1);
    memset(selected.nfs_path2,0,sizeof selected.nfs_path2);selected.nfs_has_path2=0;result=0;
done:
    bw_share_clear(out);if (!result) *out=selected;bw_share_clear(&selected);return result;
}
const char *bw_share_source_name(const struct bw_share_config *p,unsigned index) {
    if (!p || index>1) return NULL;
    if (p->transport==BW_SHARE_NFS) return index?(p->nfs_has_path2?p->nfs_path2:NULL):p->nfs_path;
    if (p->transport!=BW_SHARE_SMB) return NULL;
    return index?(*p->share2?p->share2:NULL):(*p->share?p->share:NULL);
}
static int copy(char *out,size_t capacity,const char *value,size_t length) {
    if (length>=capacity) return -1;
    for (size_t i=0;i<length;i++) if ((unsigned char)value[i]<32 || value[i]==127) return -1;
    memcpy(out,value,length);out[length]=0;return 0;
}
/* Decimal 0..4294967294 without sign or leading zeros. UINT32_MAX is (uid_t)-1. */
static int id_parse(uint32_t *out,const char *value,size_t length) {
    if (!length || length>10 || (length>1 && value[0]=='0')) return -1;
    uint64_t n=0;
    for (size_t i=0;i<length;i++) {
        if (value[i]<'0' || value[i]>'9') return -1;
        n=n*10u+(uint64_t)(value[i]-'0');
    }
    if (n>=UINT32_MAX) return -1;
    *out=(uint32_t)n;return 0;
}
enum {K_SERVER=1,K_SHARE=2,K_USER=4,K_PASSWORD=8,K_PATH=16,K_SHARE2=32,
      K_TRANSPORT=64,K_EXPORT=128,K_PATH2=256,K_VERSION=512,K_UID=1024,K_GID=2048};
#define K_NFS_ONLY (K_EXPORT|K_PATH2|K_VERSION|K_UID|K_GID)
#define K_NFS_NEED (K_SERVER|K_EXPORT|K_VERSION|K_UID|K_GID)
int bw_share_parse(struct bw_share_config *out,const char *data,size_t size) {
    static const struct {const char *name;size_t size;unsigned bit;} keys[]={
        {"server",6,K_SERVER},{"share",5,K_SHARE},{"share2",6,K_SHARE2},{"user",4,K_USER},
        {"password",8,K_PASSWORD},{"path",4,K_PATH},{"transport",9,K_TRANSPORT},{"export",6,K_EXPORT},
        {"path2",5,K_PATH2},{"nfs_version",11,K_VERSION},{"uid",3,K_UID},{"gid",3,K_GID}};
    if (!out) return -1;
    bw_share_clear(out);
    if (!data || !size || size>4096 || memchr(data,0,size)) return -1;
    unsigned seen=0,nfs=0;
    for (size_t at=0;at<size;) {
        size_t end=at;while (end<size && data[end]!='\n') end++;
        size_t length=end-at;
        if (length && data[at+length-1]=='\r') length--;
        const char *line=data+at;
        size_t key=0;while (key<length && line[key]!='=') key++;
        if (key<length) {
            const char *value=line+key+1;size_t value_size=length-key-1;unsigned bit=0;
            for (unsigned i=0;i<sizeof keys/sizeof *keys;i++)
                if (key==keys[i].size && !memcmp(line,keys[i].name,key)) bit=keys[i].bit;
            if (bit & seen) goto bad;
            seen|=bit;
            switch (bit) {
                case K_SERVER: if (copy(out->server,sizeof out->server,value,value_size)) goto bad;break;
                case K_SHARE: if (copy(out->share,sizeof out->share,value,value_size)) goto bad;break;
                case K_SHARE2: if (copy(out->share2,sizeof out->share2,value,value_size)) goto bad;break;
                case K_USER: if (copy(out->user,sizeof out->user,value,value_size)) goto bad;break;
                case K_PASSWORD: if (copy(out->password,sizeof out->password,value,value_size)) goto bad;break;
                /* The meaning of path depends on transport, which may come
                 * later. SMB allows only an empty or "/" value. */
                case K_PATH: if (copy(out->nfs_path,sizeof out->nfs_path,value,value_size)) goto bad;break;
                case K_PATH2: if (copy(out->nfs_path2,sizeof out->nfs_path2,value,value_size)) goto bad;
                    out->nfs_has_path2=1;break;
                case K_EXPORT: if (copy(out->nfs_export,sizeof out->nfs_export,value,value_size)) goto bad;break;
                case K_TRANSPORT:
                    if (value_size==3 && !memcmp(value,"nfs",3)) nfs=1;
                    else if (!(value_size==3 && !memcmp(value,"smb",3))) goto bad;
                    break;
                case K_VERSION:
                    if (value_size!=1 || (value[0]!='3' && value[0]!='4')) goto bad;
                    out->nfs_version=(unsigned)(value[0]-'0');break;
                case K_UID: if (id_parse(&out->nfs_uid,value,value_size)) goto bad;break;
                case K_GID: if (id_parse(&out->nfs_gid,value,value_size)) goto bad;break;
                default: break;
            }
        }
        at=end<size?end+1:end;
    }
    if (nfs) {
        /* No share= or user= keeps older payloads from reading this as SMB. */
        if ((seen&K_NFS_NEED)!=K_NFS_NEED || (seen&(K_SHARE|K_SHARE2|K_USER|K_PASSWORD))) goto bad;
        out->transport=BW_SHARE_NFS;
        if (!nfs_config_valid(out)) goto bad;
        return 0;
    }
    if ((seen&K_NFS_ONLY) || (*out->nfs_path && strcmp(out->nfs_path,"/"))) goto bad;
    memset(out->nfs_path,0,sizeof out->nfs_path);
    if ((seen&7)!=7 || !*out->server || !*out->share ||
        strpbrk(out->server,"/\\\r\n") || strpbrk(out->share,"/\\:") ||
        strpbrk(out->share2,"/\\:") || (*out->share2 && share_same(out->share,out->share2))) goto bad;
    return 0;
bad:
    bw_share_clear(out);return -1;
}
static int config_equal(const struct bw_share_config *a,const struct bw_share_config *b) {
    return a->transport==b->transport && !strcmp(a->server,b->server) && !strcmp(a->share,b->share) &&
        !strcmp(a->share2,b->share2) && !strcmp(a->user,b->user) && !strcmp(a->password,b->password) &&
        !strcmp(a->nfs_export,b->nfs_export) && !strcmp(a->nfs_path,b->nfs_path) &&
        !strcmp(a->nfs_path2,b->nfs_path2) && a->nfs_has_path2==b->nfs_has_path2 &&
        a->nfs_version==b->nfs_version && a->nfs_uid==b->nfs_uid && a->nfs_gid==b->nfs_gid;
}
int bw_share_encode(const struct bw_share_config *c,char *out,size_t capacity,size_t *size) {
    if (!c || !out || !size || !capacity) return -1;
    *size=0;
    const char *strings[]={c->server,c->share,c->user,c->password,c->share2,c->nfs_export,c->nfs_path,c->nfs_path2};
    const size_t sizes[]={sizeof c->server,sizeof c->share,sizeof c->user,sizeof c->password,sizeof c->share2,
        sizeof c->nfs_export,sizeof c->nfs_path,sizeof c->nfs_path2};
    for (unsigned i=0;i<8;i++) if (!memchr(strings[i],0,sizes[i])) return -1;
    int n=-1;
    if (c->transport==BW_SHARE_SMB)
        /* Historical bytes. Existing installs must write back identically. */
        n=snprintf(out,capacity,"server=%s\nshare=%s\nuser=%s\npassword=%s\npath=\n%s%s%s",c->server,c->share,c->user,c->password,
            *c->share2?"share2=":"",c->share2,*c->share2?"\n":"");
    else if (c->transport==BW_SHARE_NFS)
        n=snprintf(out,capacity,"transport=nfs\nserver=%s\nexport=%s\npath=%s\n%s%s%snfs_version=%u\nuid=%lu\ngid=%lu\n",
            c->server,c->nfs_export,c->nfs_path,c->nfs_has_path2?"path2=":"",c->nfs_path2,c->nfs_has_path2?"\n":"",
            c->nfs_version,(unsigned long)c->nfs_uid,(unsigned long)c->nfs_gid);
    struct bw_share_config checked;int result=-1;
    if (n>0 && (size_t)n<capacity && !bw_share_parse(&checked,out,(size_t)n) && config_equal(c,&checked)) {*size=(size_t)n;result=0;}
    bw_share_clear(&checked);
    if (result) clear(out,capacity);
    return result;
}
static int same(const struct stat *a,const struct stat *b) {
    return S_ISREG(b->st_mode) && b->st_nlink==1 && a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
        a->st_size==b->st_size && a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
int bw_share_load(struct bw_share_config *out) {
    const char *base="/data/blackwire",*path="/data/blackwire/share.conf";
    char resolved[4096],data[4096];struct stat root,root_after,named,opened,after;
    int result=-1,fd=-1;
    if (!out) return -1;
    bw_share_clear(out);
    if (!realpath(base,resolved) || strcmp(resolved,base) || lstat(base,&root) || !S_ISDIR(root.st_mode) ||
        lstat(path,&named) || !S_ISREG(named.st_mode) || named.st_nlink!=1 || named.st_size<1 || named.st_size>4096) goto done;
    fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
    if (fd<0 || fstat(fd,&opened) || !same(&named,&opened)) goto done;
    for (size_t at=0;at<(size_t)opened.st_size;) {
        ssize_t got=read(fd,data+at,(size_t)opened.st_size-at);
        if (got<0 && errno==EINTR) continue;
        if (got<=0 || (size_t)got>(size_t)opened.st_size-at) goto done;
        at+=(size_t)got;
    }
    char extra;
    if (read(fd,&extra,1)!=0 || fstat(fd,&after) || !same(&opened,&after) || lstat(path,&after) || !same(&opened,&after) ||
        lstat(base,&root_after) || !S_ISDIR(root_after.st_mode) || root_after.st_dev!=root.st_dev || root_after.st_ino!=root.st_ino) goto done;
    result=bw_share_parse(out,data,(size_t)opened.st_size);
done:
    clear(data,sizeof data);
    if (fd>=0 && close(fd)) result=-1;
    if (result) bw_share_clear(out);
    return result;
}
