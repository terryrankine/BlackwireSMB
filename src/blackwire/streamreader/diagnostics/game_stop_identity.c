#include "game_stop_identity.h"
#include <string.h>
static uint32_t le32(const unsigned char *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t le64(const unsigned char *p) { return (uint64_t)le32(p)|((uint64_t)le32(p+4)<<32); }
#define ROW(fw,record,pid,start,comm,rssize) {fw,record,pid,start,comm,rssize},
static const struct bw_stop_profile profiles[] = { BW_STOP_PROFILES(ROW) };
#undef ROW
_Static_assert(sizeof profiles/sizeof profiles[0]==1,"Only the measured 13.00 profile is supported");
const struct bw_stop_profile *bw_stop_profile_lookup(uint32_t firmware,size_t record) {
    for (size_t i=0;i<sizeof profiles/sizeof profiles[0];i++)
        if (profiles[i].firmware==firmware && profiles[i].record==record) return &profiles[i];
    return NULL;
}
int bw_stop_identity_parse(const void *raw,size_t size,uint32_t firmware,int32_t pid,struct bw_stop_identity *out) {
    const struct bw_stop_profile *fw=bw_stop_profile_lookup(firmware,size);
    if (!raw || !out || !fw || pid<=1) return -1;
    const unsigned char *p=raw;
    if (le32(p)!=fw->record || le32(p+4)!=0 || le32(p+fw->off_pid)!=(uint32_t)pid || !memchr(p+fw->off_comm,0,sizeof out->role)) return -1;
    uint64_t sec=le64(p+fw->off_start),usec=le64(p+fw->off_start+8);
    if (!sec || usec>=1000000 || sec>((uint64_t)INT64_MAX-usec)/1000000) return -1;
    memset(out,0,sizeof *out); out->pid=pid; out->start_sec=(int64_t)sec; out->start_usec=(int64_t)usec;
    memcpy(out->role,p+fw->off_comm,sizeof out->role); return 0;
}
int bw_stop_identity_admit(const struct bw_stop_identity *id,int64_t wall_us) {
    if (!id || id->pid<=1 || id->start_sec<=0 || id->start_usec<0 || id->start_usec>=1000000 ||
        id->start_sec>(INT64_MAX-id->start_usec)/1000000 || memcmp(id->role,"eboot.bin",10) || wall_us<=0) return -1;
    int64_t start=id->start_sec*1000000+id->start_usec;
    return start<=wall_us && wall_us-start<=BW_STOP_PROFILE_MAX_AGE_US?0:-1;
}
int bw_stop_identity_match(const struct bw_stop_identity *expected,const struct bw_stop_identity *now) {
    if (!expected || !now || expected->pid!=now->pid || expected->start_sec!=now->start_sec ||
        expected->start_usec!=now->start_usec || memcmp(expected->role,"eboot.bin",10) || memcmp(now->role,"eboot.bin",10)) return -1;
    return 1;
}
