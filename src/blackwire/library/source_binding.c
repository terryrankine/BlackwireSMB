#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "source_binding.h"
#include "native_json.h"
#include "../streamreader/copy_sha256.h"
static int bounded(const char *text,size_t capacity){
    size_t n=strnlen(text,capacity);if(!n||n==capacity||!bw_json_utf8(text))return 0;
    for(size_t i=0;i<n;i++)if((unsigned char)text[i]<32||text[i]==127)return 0;return 1;
}
/* NFS source root inside the export. Empty is the export root. */
static int nfs_root(const char *text,size_t capacity){
    size_t n=strnlen(text,capacity);if(n==capacity)return 0;
    return !n||(bw_json_utf8(text)&&!bw_manifest_validate_path(text,n));
}
int bw_source_binding_init(struct bw_source_binding *out,const struct bw_share_config *connection,const char *source,const char *title){
    if(!out)return -1;memset(out,0,sizeof *out);
    if(!connection||!source||!title||!bounded(connection->server,sizeof connection->server)||strpbrk(connection->server,"/\\")||
        strnlen(source,BW_MANIFEST_MAX_PATH+1)>BW_MANIFEST_MAX_PATH||
        bw_manifest_validate_path(source,strlen(source))||strnlen(title,10)!=9||memcmp(title,"PPSA",4))return -1;
    const int nfs=connection->transport==BW_SHARE_NFS;
    if(nfs?(!bounded(connection->nfs_export,sizeof connection->nfs_export)||connection->nfs_export[0]!='/'||
            !nfs_root(connection->nfs_path,sizeof connection->nfs_path)):
        (connection->transport!=BW_SHARE_SMB||!bounded(connection->share,sizeof connection->share)||strpbrk(connection->share,"/\\:")))return -1;
    unsigned depth=1;for(const char *p=source;*p;p++)if(*p=='/'&&++depth>48)return -1;
    for(unsigned i=4;i<9;i++)if(title[i]<'0'||title[i]>'9')return -1;
    /* SMB keeps BWBIND01 byte for byte: installed games are bound by it. NFS
     * hashes its own domain, so no NFS source can collide with an SMB one.
     * Version, uid and gid are connection options, not identity. */
    const char *smb_fields[]={connection->server,connection->share,source,title};
    const char *nfs_fields[]={"nfs",connection->server,connection->nfs_export,connection->nfs_path,source,title};
    const char *const *fields=nfs?nfs_fields:smb_fields;unsigned count=nfs?6u:4u;
    struct cp_sha hash;cp_sha_init(&hash);cp_sha_update(&hash,nfs?"BWBIND02":"BWBIND01",8);
    for(unsigned i=0;i<count;i++){uint32_t n=(uint32_t)strlen(fields[i]);uint8_t length[4];for(unsigned j=0;j<4;j++)length[j]=(uint8_t)(n>>(8*j));cp_sha_update(&hash,length,4);cp_sha_update(&hash,fields[i],n);}
    cp_sha_final(&hash,out->sha256);memcpy(out->source,source,strlen(source)+1);memcpy(out->title,title,10);memcpy(out->game,title,9);out->game[9]='_';
    for(unsigned i=0;i<32;i++)snprintf(out->game+10+2*i,3,"%02x",out->sha256[i]);return 0;
}
