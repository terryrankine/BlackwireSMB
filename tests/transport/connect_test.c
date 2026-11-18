/* SPDX-License-Identifier: GPL-3.0-or-later
 * Resident SMB connect factory over a recording libsmb2 fake. Each profile
 * must set exactly the options its call sites set before the factory. */
#define _DEFAULT_SOURCE 1
#include "library/source_connect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define C(x) do { checks++;if(!(x)){fprintf(stderr,"connect failure line %d: %s\n",__LINE__,#x);exit(1);} } while(0)

struct smb2_context {int timeout,sign;uint16_t mode;char user[128],password[256];int connected;};
static int fail_init,connect_result;
static unsigned inits;
static char seen_server[128],seen_share[128],seen_user[128];
struct smb2_context *smb2_init_context(void){inits++;return fail_init?NULL:calloc(1,sizeof(struct smb2_context));}
void smb2_destroy_context(struct smb2_context *s){free(s);}
void smb2_set_timeout(struct smb2_context *s,int t){s->timeout=t;}
void smb2_set_sign(struct smb2_context *s,int v){s->sign=v;}
void smb2_set_security_mode(struct smb2_context *s,uint16_t m){s->mode=m;}
void smb2_set_user(struct smb2_context *s,const char *v){snprintf(s->user,sizeof s->user,"%s",v);}
void smb2_set_password(struct smb2_context *s,const char *v){snprintf(s->password,sizeof s->password,"%s",v);}
int smb2_connect_share(struct smb2_context *s,const char *server,const char *share,const char *user){
    snprintf(seen_server,sizeof seen_server,"%s",server);snprintf(seen_share,sizeof seen_share,"%s",share);
    snprintf(seen_user,sizeof seen_user,"%s",user);s->connected=connect_result>=0;return connect_result;
}

int main(void){
    struct bw_share_config cfg={0};strcpy(cfg.server,"192.0.2.1");strcpy(cfg.share,"Games");strcpy(cfg.user,"account");strcpy(cfg.password,"secret");
    struct smb2_context *smb=NULL;struct bw_tp_status status;
    /* Scan sites (prepare, discover) always used timeout 10 with signing enabled and required. */
    C(!bw_source_connect_smb(&cfg,BW_TP_PROFILE_SCAN,10,&smb,&status)&&smb&&smb->connected);
    C(smb->timeout==10&&smb->sign==1&&smb->mode==(SMB2_NEGOTIATE_SIGNING_ENABLED|SMB2_NEGOTIATE_SIGNING_REQUIRED));
    C(!strcmp(smb->user,"account")&&!strcmp(smb->password,"secret"));
    C(!strcmp(seen_server,"192.0.2.1")&&!strcmp(seen_share,"Games")&&!strcmp(seen_user,"account"));
    C(status.error==BW_TP_OK&&status.result_known&&!status.result&&!status.raw);
    C(!strcmp(cfg.password,"secret"));smb2_destroy_context(smb);
    /* Admission sites (launch admission, home preflight) used signing required only. */
    C(!bw_source_connect_smb(&cfg,BW_TP_PROFILE_ADMISSION,3,&smb,NULL)&&smb);
    C(smb->timeout==3&&smb->sign==1&&smb->mode==SMB2_NEGOTIATE_SIGNING_REQUIRED);smb2_destroy_context(smb);
    /* A failed connect hands the context back so the caller keeps its release order. */
    connect_result=-ETIMEDOUT;
    C(bw_source_connect_smb(&cfg,BW_TP_PROFILE_SCAN,10,&smb,&status)<0&&smb&&!smb->connected);
    C(status.error==BW_TP_TIMEOUT&&status.result==-ETIMEDOUT&&status.result_known);smb2_destroy_context(smb);
    connect_result=-EACCES;
    C(bw_source_connect_smb(&cfg,BW_TP_PROFILE_ADMISSION,10,&smb,&status)<0&&smb);
    C(status.error==BW_TP_TRANSPORT&&status.result==-EACCES&&status.result_known);smb2_destroy_context(smb);
    /* No context: nothing attempted. */
    connect_result=0;fail_init=1;unsigned before=inits;smb=(struct smb2_context *)&cfg;
    C(bw_source_connect_smb(&cfg,BW_TP_PROFILE_SCAN,10,&smb,&status)<0&&!smb&&!status.result_known&&inits==before+1);
    fail_init=0;before=inits;
    C(bw_source_connect_smb(NULL,BW_TP_PROFILE_SCAN,10,&smb,&status)<0&&!smb&&inits==before);
    C(bw_source_connect_smb(&cfg,BW_TP_PROFILE_SCAN,10,NULL,&status)<0&&inits==before);
    printf("{\"connect\":%u}\n",checks);
    return 0;
}
