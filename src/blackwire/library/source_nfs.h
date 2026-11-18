#ifndef BW_SOURCE_NFS_H
#define BW_SOURCE_NFS_H
#include "source.h"
#include "../streamreader/share_config.h"
/* bw_source over a synchronous transport with a list op (NFS). Same contract
 * as the SMB source: missing, refused or linked catalog items are positive
 * results, timeouts and transport failures poison the connection and return
 * -1. Listing metadata is synthesised from the server attributes:
 *   attributes = DIR 0x10 | LINK 0x400 | SPECIAL 0x40 | FILE 0x80
 *   ticks = 116444736000000000 + sec*10^7 + nsec/100, inode = fileid.
 * Both sides of every compare come from the same server value, so compares
 * are exact. Links, devices, sockets and FIFOs are never followed. */
extern const struct bw_source_ops bw_source_nfs_ops;
/* Connects cfg (NFS, one chosen root) and gives source the owned transport.
 * The source must be zeroed apart from deadline and observer. */
int bw_source_nfs_connect(struct bw_source *source,const struct bw_share_config *cfg,int timeout_seconds,struct bw_tp_status *status);
/* Binds an already connected transport. Host tests use it with fakes. */
void bw_source_nfs_adopt(struct bw_source *source,struct bw_transport transport);
#endif
