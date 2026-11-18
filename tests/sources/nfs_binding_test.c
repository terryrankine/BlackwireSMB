/* SPDX-License-Identifier: GPL-3.0-or-later
 * NFS source binding (BWBIND02). Prints the digests for an independent
 * Python recomputation and checks the domain separation from SMB. */
#define _DEFAULT_SOURCE 1
#include "library/source_binding.h"
#include "library/source_identity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define C(x) do { checks++;if(!(x)){fprintf(stderr,"nfs binding failure line %d: %s\n",__LINE__,#x);exit(1);} } while(0)

static struct bw_share_config nfs(const char *path){
    struct bw_share_config c={0};strcpy(c.server,"192.168.11.186");c.transport=BW_SHARE_NFS;
    strcpy(c.nfs_export,"/volume1/public");strcpy(c.nfs_path,path);c.nfs_version=3;c.nfs_uid=1000;c.nfs_gid=1000;return c;
}
int main(void){
    struct bw_share_config images=nfs("emulation/ps5/games/images"),root=nfs("");
    struct bw_source_binding a,b,c;
    C(!bw_source_binding_init(&a,&images,"Alpha.ffpfsc","PPSA09999"));
    C(!bw_source_binding_init(&b,&root,"Alpha.ffpfsc","PPSA09999"));
    C(memcmp(a.sha256,b.sha256,32));
    /* Connection options are not identity. */
    struct bw_share_config v4=images;v4.nfs_version=4;v4.nfs_uid=0;v4.nfs_gid=0;
    C(!bw_source_binding_init(&c,&v4,"Alpha.ffpfsc","PPSA09999")&&!memcmp(a.sha256,c.sha256,32));
    /* Same server, a share named like the export path: SMB stays BWBIND01. */
    struct bw_share_config smb={0};strcpy(smb.server,"192.168.11.186");strcpy(smb.share,"public");
    C(!bw_source_binding_init(&c,&smb,"Alpha.ffpfsc","PPSA09999")&&memcmp(a.sha256,c.sha256,32));
    /* Refusals: relative export, unsafe path, unknown transport. */
    struct bw_share_config bad=images;strcpy(bad.nfs_export,"volume1");C(bw_source_binding_init(&c,&bad,"Alpha.ffpfsc","PPSA09999"));
    bad=images;strcpy(bad.nfs_path,"../etc");C(bw_source_binding_init(&c,&bad,"Alpha.ffpfsc","PPSA09999"));
    bad=images;strcpy(bad.nfs_path,"a//b");C(bw_source_binding_init(&c,&bad,"Alpha.ffpfsc","PPSA09999"));
    bad=images;bad.transport=7;C(bw_source_binding_init(&c,&bad,"Alpha.ffpfsc","PPSA09999"));
    bad=images;strcpy(bad.server,"a/b");C(bw_source_binding_init(&c,&bad,"Alpha.ffpfsc","PPSA09999"));
    /* The provider select picks the configured root by its game id. */
    struct bw_provider_binding container,selected;
    C(!bw_provider_binding_init(&container,&images,"Alpha.ffpfsc","PPSA09999",BW_PROVIDER_CONTAINER));
    struct bw_share_config two=images;strcpy(two.nfs_path2,"emulation/ps5/games/folders");two.nfs_has_path2=1;
    C(!bw_provider_binding_select(&selected,&two,"Alpha.ffpfsc","PPSA09999",BW_PROVIDER_CONTAINER,container.binding.game));
    C(!memcmp(&selected,&container,sizeof selected)&&!strcmp(two.nfs_path,"emulation/ps5/games/images")&&!two.nfs_has_path2);
    printf("{\"checks\":%u,\"images\":\"",checks);for(unsigned i=0;i<32;i++)printf("%02x",a.sha256[i]);
    printf("\",\"root\":\"");for(unsigned i=0;i<32;i++)printf("%02x",b.sha256[i]);
    printf("\",\"game\":\"%s\"}\n",a.game);
    return 0;
}
