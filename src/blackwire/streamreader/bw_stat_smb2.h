#ifndef BW_STAT_SMB2_H
#define BW_STAT_SMB2_H
#include "bw_stat.h"
#include <time.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
_Static_assert(BW_TP_FILE==SMB2_TYPE_FILE&&BW_TP_DIRECTORY==SMB2_TYPE_DIRECTORY&&BW_TP_LINK==SMB2_TYPE_LINK,
    "bw_stat type values are hashed as the SMB2 type");
/* Verbatim copy at the libsmb2 boundary. nlink, atime and btime are not
 * identity and were never compared or hashed. */
static inline void bw_stat_from_smb2(struct bw_stat *out,const struct smb2_stat_64 *in){
    *out=(struct bw_stat){in->smb2_type,0,in->smb2_ino,in->smb2_size,in->smb2_mtime,in->smb2_mtime_nsec,in->smb2_ctime,in->smb2_ctime_nsec};
}
#endif
