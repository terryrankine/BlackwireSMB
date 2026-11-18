#ifndef BW_GAME_STOP_IDENTITY_H
#define BW_GAME_STOP_IDENTITY_H
#include <stddef.h>
#include <stdint.h>
#define BW_STOP_PROFILE_FW UINT32_C(0x13000040)
#define BW_STOP_PROFILE_RECORD 1096u
#define BW_STOP_PROFILE_MAX_AGE_US INT64_C(60000000)
struct bw_stop_identity { int32_t pid; int64_t start_sec,start_usec; char role[20]; };
/* One supported firmware/kinfo_proc layout. The offsets are the public BSD
 * kinfo_proc fields the gates read; only the 13.00 family is measured, so the
 * table holds a single row and BW_STOP_PROFILE_* keep its published values. */
struct bw_stop_profile { uint32_t firmware; uint32_t record; uint16_t off_pid,off_start,off_comm,off_rssize; };
/* Return the supported profile for this firmware and record size, or NULL. A
 * firmware or record outside the table refuses exactly as the old constants. */
const struct bw_stop_profile *bw_stop_profile_lookup(uint32_t firmware,size_t record);
/* Parse ONLY the empirical public prefix approved for this isolated control.
 * Nonzero return is UNKNOWN; sanitized private pointer fields are not read. */
int bw_stop_identity_parse(const void *,size_t,uint32_t,int32_t,struct bw_stop_identity *);
int bw_stop_identity_admit(const struct bw_stop_identity *,int64_t wall_us);
/* 1=same admitted generation/role, -1=UNKNOWN. Never returns positive exit. */
int bw_stop_identity_match(const struct bw_stop_identity *,const struct bw_stop_identity *);
#endif
