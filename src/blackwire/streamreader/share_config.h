#ifndef BW_SHARE_CONFIG_H
#define BW_SHARE_CONFIG_H
#include <stddef.h>
#include <stdint.h>
#define BW_SHARE_SMB 0u
#define BW_SHARE_NFS 1u
struct bw_share_config {
    char server[128],share[128],user[128],password[256];
    char share2[128];
    /* NFS only. All zero or empty for SMB. A missing transport= key is SMB.
     * nfs_export is absolute. nfs_path and nfs_path2 are export-relative
     * source roots, where empty means the export root. nfs_has_path2 is set
     * when the path2 key is present, because an empty path2 is still a source. */
    unsigned transport;
    char nfs_export[256];
    char nfs_path[256],nfs_path2[256];
    unsigned nfs_has_path2;
    unsigned nfs_version;
    uint32_t nfs_uid,nfs_gid;
};
void bw_share_clear(struct bw_share_config *);
int bw_share_parse(struct bw_share_config *,const char *,size_t);
/* Select one configured share on the same server/account. Empty selects the
 * primary share. The returned connection contains only that share; callers
 * clear it after use. Supports out == configured. SMB only: an NFS
 * configuration is refused, so SMB-only callers never connect to it. */
int bw_share_select(struct bw_share_config *out,const struct bw_share_config *configured,const char *share);
/* Transport-neutral selection. SMB behaves as bw_share_select. NFS: NULL
 * selects source 1, otherwise the name must equal nfs_path or nfs_path2
 * exactly (case-sensitive). The result keeps only the chosen root in nfs_path.
 * Supports out == configured. */
int bw_share_select_source(struct bw_share_config *out,const struct bw_share_config *configured,const char *source);
/* Name of source 0 or 1 to pass to bw_share_select_source: share/share2 for
 * SMB, nfs_path/nfs_path2 for NFS. NULL when that source is not configured. */
const char *bw_share_source_name(const struct bw_share_config *,unsigned);
/* Canonical share.conf bytes. SMB output is the historical format, byte for
 * byte, with no transport line. The output may hold credentials; the caller
 * clears it. Returns -1 unless the bytes parse back to the same settings. */
int bw_share_encode(const struct bw_share_config *,char *,size_t,size_t *);
/* Read only the existing canonical /data/blackwire/share.conf. Credentials
 * must never enter public status/logs. The caller clears them after connecting.
 */
int bw_share_load(struct bw_share_config *);
#endif
