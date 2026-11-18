#ifndef BW_TRANSPORT_NFS_H
#define BW_TRANSPORT_NFS_H
#include "bw_transport.h"
#include "share_config.h"
/* NFS ops over one mounted libnfs context. Paths are relative to the chosen
 * source root inside the export (cfg->nfs_path), like share-relative SMB
 * paths. The context uses the settings proven on the console: sync calls,
 * retrans 0 with a timeout so failures surface, no directory cache, no
 * reconnect, read-only, and reads of at most 128 KiB. */
extern const struct bw_transport_ops bw_transport_nfs_ops;
#define BW_NFS_READ_MAX (128u*1024u)
/* Mounts cfg's export and checks that the source root is a real directory.
 * On success out holds the owned context. On failure out->context is NULL and
 * status says why: ROOT_MISSING, AUTH, TIMEOUT or TRANSPORT. cfg must be an
 * NFS configuration with one chosen root (bw_share_select_source). */
int bw_transport_nfs_connect(const struct bw_share_config *cfg,int timeout_seconds,
                             struct bw_transport *out,struct bw_tp_status *status);
#endif
