#ifndef BW_SOURCE_CONNECT_H
#define BW_SOURCE_CONNECT_H
#include "../streamreader/bw_tp_error.h"
#include "../streamreader/share_config.h"
#include "source.h"
#include <time.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
/* One connect path for every resident SMB site. A profile names the security
 * options a site has always used, so moving a site here changes no option. */
enum bw_tp_profile {
    BW_TP_PROFILE_SCAN,      /* catalog and preparation: signing enabled and required */
    BW_TP_PROFILE_ADMISSION  /* launch admission and home preflight: signing required only */
};
/* Returns 0 when connected. On a failed connect the context is still returned
 * in *out, so each caller keeps its own release order (admission disconnects
 * before destroy) and reads the NT status itself where it reports one. *out is
 * NULL only when no context could be allocated, and then status->result_known
 * is 0. The caller clears the credentials in cfg, as before. */
static inline int bw_source_connect_smb(const struct bw_share_config *cfg,enum bw_tp_profile profile,int timeout_seconds,
    struct smb2_context **out,struct bw_tp_status *status){
    struct bw_tp_status ignored;if(!status)status=&ignored;
    *status=(struct bw_tp_status){BW_TP_TRANSPORT,0,0,0};
    if(!out)return -1;
    struct smb2_context *smb=cfg?smb2_init_context():NULL;*out=smb;
    if(!smb)return -1;
    smb2_set_timeout(smb,timeout_seconds);smb2_set_sign(smb,1);
    smb2_set_security_mode(smb,profile==BW_TP_PROFILE_SCAN?SMB2_NEGOTIATE_SIGNING_ENABLED|SMB2_NEGOTIATE_SIGNING_REQUIRED:SMB2_NEGOTIATE_SIGNING_REQUIRED);
    smb2_set_user(smb,cfg->user);smb2_set_password(smb,cfg->password);
    int result=smb2_connect_share(smb,cfg->server,cfg->share,cfg->user);
    status->result=result<0?result:0;status->result_known=1;
    status->error=result>=0?BW_TP_OK:result==-ETIMEDOUT?BW_TP_TIMEOUT:BW_TP_TRANSPORT;
    return result<0?-1:0;
}
/* The NFS module (source_nfs.c, bw_transport_nfs.c, libnfs) is optional in a
 * build. Host tests that never connect NFS do not link it, and then an NFS
 * configuration is refused here instead of failing to link. */
extern int bw_source_nfs_connect(struct bw_source *,const struct bw_share_config *,int,struct bw_tp_status *) __attribute__((weak));
/* Connects source to cfg's transport. SMB: exactly bw_source_connect_smb into
 * source->smb. NFS: an owned transport in source->transport, and on failure
 * no context is left. status->result_known is 0 when nothing was attempted. */
static inline int bw_source_connect(struct bw_source *source,const struct bw_share_config *cfg,enum bw_tp_profile profile,
    int timeout_seconds,struct bw_tp_status *status){
    if(cfg&&cfg->transport==BW_SHARE_NFS){
        if(status)*status=(struct bw_tp_status){BW_TP_TRANSPORT,0,0,0};
        return source&&bw_source_nfs_connect?bw_source_nfs_connect(source,cfg,timeout_seconds,status):-1;
    }
    return bw_source_connect_smb(cfg,profile,timeout_seconds,source?&source->smb:NULL,status);
}
/* Drops whichever connection the source still owns. */
static inline void bw_source_release(struct bw_source *source){
    if(source->smb){struct smb2_context *smb=source->smb;source->smb=NULL;smb2_destroy_context(smb);}
    bw_transport_poison(&source->transport);
}
#endif
