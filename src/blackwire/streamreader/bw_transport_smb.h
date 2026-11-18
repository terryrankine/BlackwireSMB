#ifndef BW_TRANSPORT_SMB_H
#define BW_TRANSPORT_SMB_H
#include "bw_transport.h"
#include "bw_stat_smb2.h"
#include <fcntl.h>
/* SMB ops: one libsmb2 sync call each, converted at this boundary only. Header
 * only, like bw_stat_smb2.h, so every unit that already links libsmb2 (or its
 * test fake) gets the table without a new object in each build. */
_Static_assert(sizeof(struct smb2_stat_64)<=sizeof(struct bw_tp_stat_slot),"stat slot holds smb2_stat_64");
static inline int bw_tp_smb_stat(void *context,const char *path,struct bw_stat *out,struct bw_tp_stat_slot *slot){
    struct smb2_stat_64 local={0},*raw=slot?(struct smb2_stat_64 *)(void *)slot->bytes:&local;
    int result=smb2_stat(context,path,raw);bw_stat_from_smb2(out,raw);return result;
}
static inline void *bw_tp_smb_open(void *context,const char *path){return smb2_open(context,path,O_RDONLY);}
static inline int bw_tp_smb_fstat(void *context,void *file,struct bw_stat *out,struct bw_tp_stat_slot *slot){
    struct smb2_stat_64 local,*raw=slot?(struct smb2_stat_64 *)(void *)slot->bytes:&local;
    int result=smb2_fstat(context,file,raw);if(!result)bw_stat_from_smb2(out,raw);return result;
}
static inline int bw_tp_smb_pread(void *context,void *file,void *buffer,uint32_t size,uint64_t offset){
    return smb2_pread(context,file,buffer,size,offset);
}
static inline int bw_tp_smb_close(void *context,void *file){return smb2_close(context,file);}
static inline uint32_t bw_tp_smb_max_read(void *context){return smb2_get_max_read_size(context);}
static inline void bw_tp_smb_destroy(void *context){smb2_destroy_context(context);}
static const struct bw_transport_ops bw_transport_smb_ops __attribute__((unused))={BW_TP_SMB,
    bw_tp_smb_stat,bw_tp_smb_open,bw_tp_smb_fstat,bw_tp_smb_pread,bw_tp_smb_close,bw_tp_smb_max_read,bw_tp_smb_destroy};
#endif
