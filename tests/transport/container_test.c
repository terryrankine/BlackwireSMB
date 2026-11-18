/* SPDX-License-Identifier: GPL-3.0-or-later
 * The image container over a non-SMB transport: admission, generation checks,
 * reads, and the owned-transport poison contract. */
#define _DEFAULT_SOURCE 1
#include "streamreader/container_smb.h"
#include "local_transport.h"

static unsigned checks;
#define C(x) do { checks++;if(!(x)){fprintf(stderr,"container failure line %d: %s\n",__LINE__,#x);exit(1);} } while(0)

/* container_smb.c references the SMB table. No SMB call is made here. */
struct smb2_context *smb2_init_context(void){abort();}
void smb2_destroy_context(struct smb2_context *s){(void)s;abort();}
int smb2_stat(struct smb2_context *s,const char *p,struct smb2_stat_64 *o){(void)s;(void)p;(void)o;abort();}
int smb2_fstat(struct smb2_context *s,struct smb2fh *f,struct smb2_stat_64 *o){(void)s;(void)f;(void)o;abort();}
struct smb2fh *smb2_open(struct smb2_context *s,const char *p,int f){(void)s;(void)p;(void)f;abort();}
int smb2_pread(struct smb2_context *s,struct smb2fh *f,uint8_t *b,uint32_t n,uint64_t o){(void)s;(void)f;(void)b;(void)n;(void)o;abort();}
int smb2_close(struct smb2_context *s,struct smb2fh *f){(void)s;(void)f;abort();}
uint32_t smb2_get_max_read_size(struct smb2_context *s){(void)s;abort();}

static uint8_t pattern(uint64_t at){return (uint8_t)(at*29u+at/251u);}

int main(int argc,char **argv){
    C(argc==2);
    struct local_context c={0};snprintf(c.root,sizeof c.root,"%s",argv[1]);
    struct bw_transport owner={&local_ops,&c};struct bw_container_smb image;
    for(unsigned metadata=0;metadata<2;metadata++){
        C(!bw_container_open_transport(&image,&owner,"Images/Beta.ffpfsc",metadata)&&image.handle&&image.context==&c&&!image.smb);
        C(image.admitted.type==BW_TP_FILE&&image.admitted.size>48);
        char boot[64]={0};C(!bw_container_read(&image.container,"eboot.bin",0,boot,19));C(!memcmp(boot,"NFS NEUTRAL STARTUP",19));
        uint8_t *asset=malloc(65536);C(asset);
        C(!bw_container_read(&image.container,"asset.bin",4096,asset,65536));
        for(size_t i=0;i<65536;i++)C(asset[i]==pattern(4096+i));
        free(asset);
        C(image.generation_checks>0&&image.read_calls>0);
        C(!bw_container_smb_close(&image)&&!c.destroyed&&owner.context==&c);
    }
    /* A transport failure poisons the owner exactly once and drops the handle. */
    C(!bw_container_open_transport(&image,&owner,"Images/Beta.ffpfsc",0));
    c.fail_read=1;c.reads=0;char byte;
    C(bw_container_read(&image.container,"asset.bin",0,&byte,1)<0);
    C(c.destroyed==1&&!owner.context&&!image.context&&!image.handle&&image.first_failure_operation==BW_IMAGE_FAILURE_PREAD);
    C(image.first_failure_result==-EINTR&&bw_tp_error_from_nfs(image.first_failure_result,0)==BW_TP_TIMEOUT);
    C(!bw_container_smb_close(&image)&&c.destroyed==1);
    /* A poisoned owner refuses a new open. */
    C(bw_container_open_transport(&image,&owner,"Images/Beta.ffpfsc",0)==BW_PFS_ARGUMENT);
    /* A changed source is caught by the generation check without poisoning. */
    c.fail_read=0;owner.context=&c;
    C(!bw_container_open_transport(&image,&owner,"Images/Beta.ffpfsc",0));
    image.admitted.ino^=1;
    C(bw_container_read(&image.container,"eboot.bin",0,&byte,1)<0&&owner.context==&c&&c.destroyed==1);
    C(image.first_failure_operation==BW_IMAGE_FAILURE_GENERATION_METADATA);
    C(!bw_container_smb_close(&image));
    /* Missing image: a stat refusal is a transport result and poisons. */
    C(bw_container_open_transport(&image,&owner,"Images/Absent.ffpfsc",0)==BW_PFS_IO);
    C(image.first_failure_result==-ENOENT&&!owner.context&&c.destroyed==2);
    C(bw_container_open_transport(&image,NULL,"Images/Beta.ffpfsc",0)==BW_PFS_ARGUMENT);
    printf("{\"container\":%u}\n",checks);
    return 0;
}
