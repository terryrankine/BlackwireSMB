/* SPDX-License-Identifier: GPL-3.0-or-later
 * Fixed-input identity seals. Installed games are bound by these exact bytes,
 * so the expected digests were captured from the code before bw_stat existed. */
#define _DEFAULT_SOURCE 1
#include "library/source_catalog.h"
#include "library/source_identity.h"
#include "library/source_snapshot.h"
#include "streamreader/bw_stat_smb2.h"
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define C(x) do { checks++;if(!(x)){fprintf(stderr,"identity golden failure line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
/* The vectors stay in libsmb2 form so the boundary conversion is under test. */
static struct bw_stat converted[4];static unsigned next;
static const struct bw_stat *image(const struct smb2_stat_64 *raw){struct bw_stat *p=&converted[next++%4];bw_stat_from_smb2(p,raw);return p;}
#define IMAGE(raw) image(&(raw))
static void hex(const char *name,const uint8_t digest[32],int last){
    printf("\"%s\":\"",name);for(unsigned i=0;i<32;i++)printf("%02x",digest[i]);printf("\"%s",last?"":",");
}
/* nlink, atime and btime carry distinct values: they are not identity and must
 * not reach any seal. Every hashed field exceeds 32 bits where it can. */
static const struct smb2_stat_64 stats[]={
    {SMB2_TYPE_FILE,3,UINT64_C(0x0123456789abcdef),UINT64_C(0x000000123456789a),111,222,
     UINT64_C(1700000000),UINT64_C(123456000),UINT64_C(1700000123),UINT64_C(987654000),333,444},
    {SMB2_TYPE_DIRECTORY,1,UINT64_C(0xfedcba9876543210),0,0,0,
     UINT64_C(0x00000001ffffffff),UINT64_C(999999000),UINT64_C(0x0000000200000000),1000,0,0},
    {SMB2_TYPE_LINK,0,1,UINT64_C(0xffffffffffffffff),9,9,0,0,UINT64_MAX,UINT64_MAX,9,9}
};
int main(void){
    struct bw_share_config config={0};
    strcpy(config.server,"nas.example");strcpy(config.share,"Games");strcpy(config.user,"neutral");strcpy(config.password,"secret");
    struct bw_source_binding folder;struct bw_provider_binding provider[2];
    C(!bw_source_binding_init(&folder,&config,"Library/Neutral Game","PPSA09999"));
    C(!bw_provider_binding_init(&provider[0],&config,"Library/Neutral Game","PPSA09999",BW_PROVIDER_FOLDER));
    C(!bw_provider_binding_init(&provider[1],&config,"Library/Neutral.ffpfsc","PPSA09999",BW_PROVIDER_CONTAINER));
    C(!memcmp(provider[0].binding.sha256,folder.sha256,32)&&!strcmp(provider[0].binding.game,folder.game));
    uint8_t map[32];for(unsigned i=0;i<32;i++)map[i]=(uint8_t)(i*7+1);
    printf("{");hex("bindingFolder",folder.sha256,0);hex("bindingContainer",provider[1].binding.sha256,0);
    printf("\"gameFolder\":\"%s\",\"gameContainer\":\"%s\",",folder.game,provider[1].binding.game);
    for(unsigned i=0;i<sizeof stats/sizeof stats[0];i++){
        uint8_t digest[32],other[32];char name[48];
        struct smb2_stat_64 changed=stats[i];changed.smb2_nlink+=5;changed.smb2_atime+=5;changed.smb2_atime_nsec+=5;changed.smb2_btime+=5;changed.smb2_btime_nsec+=5;
        bw_source_catalog_image_hash(IMAGE(stats[i]),digest);bw_source_catalog_image_hash(IMAGE(changed),other);C(!memcmp(digest,other,32));
        snprintf(name,sizeof name,"catalogImage%u",i);hex(name,digest,0);
        for(unsigned k=0;k<2;k++){
            bw_provider_image_generation_stat(&provider[k],IMAGE(stats[i]),map,digest);bw_provider_image_generation_stat(&provider[k],IMAGE(changed),map,other);
            C(!memcmp(digest,other,32));snprintf(name,sizeof name,"imageGeneration%s%u",k?"Container":"Folder",i);hex(name,digest,0);
        }
        C(bw_source_catalog_image_same(IMAGE(stats[i]),IMAGE(changed))==(stats[i].smb2_type==SMB2_TYPE_FILE));
        /* The SMB form kept for the reader must give the same seal. */
        bw_provider_image_generation(&provider[1],&stats[i],map,other);bw_provider_image_generation_stat(&provider[1],IMAGE(stats[i]),map,digest);
        C(!memcmp(digest,other,32));
    }
    /* Bound snapshot: one held parent per source component, in the BWBOUND1 block. */
    struct bw_source_snapshot bound,plain;
    const struct bw_source_info root={0,UINT64_C(0x1000000001),UINT64_C(133000000000000000),UINT64_C(133000000000000001),0x10},
        boot={UINT64_C(0x100000003),UINT64_C(0x1000000002),UINT64_C(133000000012345678),UINT64_C(133000000087654321),0x20},
        sys={0,UINT64_C(0x1000000003),UINT64_C(133000000000000002),UINT64_C(133000000000000003),0x10},
        param={777,UINT64_C(0x1000000004),UINT64_C(133000000000000004),UINT64_C(133000000000000005),0x21},
        share={0,UINT64_C(0x0fffffffff),UINT64_C(132999999999999998),UINT64_C(132999999999999999),0x10},
        parent={0,UINT64_C(0x1000000000),UINT64_C(132999999999999999),UINT64_C(133000000000000000),0x30};
    C(!bw_source_snapshot_init_bound(&bound,"Library/Neutral Game",folder.game));
    bound.parents[0]=share;bound.parents[1]=parent;bound.parent_count=2;
    C(!bw_source_snapshot_add(&bound,"sce_sys/param.json",&param)&&!bw_source_snapshot_add(&bound,"",&root)&&
      !bw_source_snapshot_add(&bound,"eboot.bin",&boot)&&!bw_source_snapshot_add(&bound,"sce_sys",&sys));
    C(!bw_source_snapshot_finish(&bound)&&!bw_source_snapshot_validate(&bound));
    C(!bw_source_snapshot_init(&plain,folder.game));
    C(!bw_source_snapshot_add(&plain,"",&root)&&!bw_source_snapshot_add(&plain,"eboot.bin",&boot));
    C(!bw_source_snapshot_finish(&plain)&&!bw_source_snapshot_validate(&plain));
    hex("snapshotBound",bound.sha256,0);hex("snapshotPlain",plain.sha256,0);
    bw_source_snapshot_destroy(&bound);bw_source_snapshot_destroy(&plain);
    printf("\"checks\":%u}\n",checks);
    return 0;
}
