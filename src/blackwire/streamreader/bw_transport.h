#ifndef BW_TRANSPORT_H
#define BW_TRANSPORT_H
#include <stdint.h>
#include "bw_stat.h"
#include "bw_tp_error.h"
/* Synchronous remote file primitives shared by the image container, the
 * preparation copy and the file map. The context is the library connection
 * (smb2_context or nfs_context) and a file is its open handle. Each op makes
 * exactly the library call it names, so one SMB op is one libsmb2 call. */
enum bw_tp_kind {BW_TP_SMB=1,BW_TP_NFS=2};
/* A sync stat that fails in its wait can still get a late reply written to
 * its destination, as late as the drain in destroy. A caller that destroys
 * the context after a failure passes storage that outlives that drain.
 * Big enough for struct smb2_stat_64 and struct nfs_stat_64. */
struct bw_tp_stat_slot {_Alignas(8) unsigned char bytes[160];};
struct bw_transport_ops {
    enum bw_tp_kind kind;
    /* Root-relative path. Returns 0 or the library's negative result. */
    int (*stat)(void *context,const char *path,struct bw_stat *out,struct bw_tp_stat_slot *slot);
    /* Read-only. NULL on failure. */
    void *(*open)(void *context,const char *path);
    int (*fstat)(void *context,void *file,struct bw_stat *out,struct bw_tp_stat_slot *slot);
    /* Bytes read (>0), 0 at end of file, negative on failure. */
    int (*pread)(void *context,void *file,void *buffer,uint32_t size,uint64_t offset);
    int (*close)(void *context,void *file);
    /* Largest single read the connection accepts. Zero when unknown. */
    uint32_t (*max_read)(void *context);
    /* Drains outstanding replies and frees the connection. */
    void (*destroy)(void *context);
};
/* An owned connection. A failed op that poisons it destroys the context and
 * sets context to NULL, so every holder of this record sees it gone. */
struct bw_transport {
    const struct bw_transport_ops *ops;
    void *context;
};
static inline void bw_transport_poison(struct bw_transport *owner){
    if(owner&&owner->context){void *context=owner->context;owner->context=NULL;owner->ops->destroy(context);}
}
#endif
