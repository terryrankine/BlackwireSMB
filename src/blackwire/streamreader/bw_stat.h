#ifndef BW_STAT_H
#define BW_STAT_H
#include <stdint.h>
/* Transport-neutral identity of one remote object. The image-generation and
 * catalog seals hash type, ino, size, mtime, mtime_nsec, ctime and ctime_nsec
 * as little-endian uint64 in that order, so these values must stay equal to
 * SMB2_TYPE_FILE/DIRECTORY/LINK (checked in bw_stat_smb2.h). */
enum bw_tp_type {BW_TP_FILE=0,BW_TP_DIRECTORY=1,BW_TP_LINK=2};
/* Fields are compared exactly, never rounded. SMB *_nsec values are whole
 * microseconds times 1000 because libsmb2 converts FILETIME to timeval. */
struct bw_stat {
    uint32_t type;      /* enum bw_tp_type */
    uint32_t reserved;  /* zero; never hashed or compared */
    uint64_t ino,size;
    uint64_t mtime,mtime_nsec;
    uint64_t ctime,ctime_nsec;
};
/* Same regular file: both FILE, equal inode, size and full timestamps. */
static inline int bw_stat_same_file(const struct bw_stat *a,const struct bw_stat *b){
    return a&&b&&a->type==BW_TP_FILE&&b->type==BW_TP_FILE&&a->ino==b->ino&&a->size==b->size&&
        a->mtime==b->mtime&&a->mtime_nsec==b->mtime_nsec&&a->ctime==b->ctime&&a->ctime_nsec==b->ctime_nsec;
}
#endif
