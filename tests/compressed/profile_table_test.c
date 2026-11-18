/* Host check for the supported firmware/profile table and its single lookup.
 * Proves the refactor keeps the old exact-match behaviour: the 13.00 row is
 * accepted at 0x13000040/1096 and every other firmware or record size refuses
 * with the same -1 the earlier inline constant comparison returned. No console
 * or kernel access; a synthetic in-memory kinfo_proc prefix drives the parser. */
#include "game_stop_identity.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int checks;
#define CHECK(cond) do{ if(!(cond)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#cond); return 1; } checks++; }while(0)

static void put32(unsigned char *p,uint32_t v){ for(int i=0;i<4;i++) p[i]=(unsigned char)(v>>(8*i)); }
static void put64(unsigned char *p,uint64_t v){ for(int i=0;i<8;i++) p[i]=(unsigned char)(v>>(8*i)); }

/* Build a well-formed 13.00 record the baseline parser accepts. */
static void record(unsigned char *p,int32_t pid){
    memset(p,0,BW_STOP_PROFILE_RECORD);
    put32(p,BW_STOP_PROFILE_RECORD);           /* ki_structsize prefix */
    put32(p+72,(uint32_t)pid);                 /* ki_pid */
    put64(p+336,1700000000u);                  /* ki_start.tv_sec */
    put64(p+344,123456u);                      /* ki_start.tv_usec */
    memcpy(p+447,"eboot.bin",10);              /* ki_comm, NUL terminated */
}

int main(void){
    const struct bw_stop_profile *row;
    /* Lookup accepts the one measured profile and reports its offsets. */
    row=bw_stop_profile_lookup(BW_STOP_PROFILE_FW,BW_STOP_PROFILE_RECORD);
    CHECK(row!=NULL);
    CHECK(row->firmware==BW_STOP_PROFILE_FW && row->record==BW_STOP_PROFILE_RECORD);
    CHECK(row->off_pid==72 && row->off_start==336 && row->off_comm==447 && row->off_rssize==264);

    /* An unmeasured firmware (12.40 family) refuses. */
    CHECK(bw_stop_profile_lookup(UINT32_C(0x12400040),BW_STOP_PROFILE_RECORD)==NULL);
    CHECK(bw_stop_profile_lookup(UINT32_C(0x12400000),BW_STOP_PROFILE_RECORD)==NULL);
    CHECK(bw_stop_profile_lookup(0,BW_STOP_PROFILE_RECORD)==NULL);

    /* A wrong record size refuses even on the supported firmware. */
    CHECK(bw_stop_profile_lookup(BW_STOP_PROFILE_FW,0)==NULL);
    CHECK(bw_stop_profile_lookup(BW_STOP_PROFILE_FW,BW_STOP_PROFILE_RECORD-1)==NULL);
    CHECK(bw_stop_profile_lookup(BW_STOP_PROFILE_FW,BW_STOP_PROFILE_RECORD+1)==NULL);

    /* The parser accepts a valid record at the supported profile. */
    unsigned char buf[BW_STOP_PROFILE_RECORD];
    struct bw_stop_identity id;
    record(buf,1234);
    CHECK(bw_stop_identity_parse(buf,sizeof buf,BW_STOP_PROFILE_FW,1234,&id)==0);
    CHECK(id.pid==1234 && id.start_sec==1700000000 && id.start_usec==123456);
    CHECK(memcmp(id.role,"eboot.bin",10)==0);

    /* Same bytes, wrong firmware: identical -1 refusal as the old constant. */
    CHECK(bw_stop_identity_parse(buf,sizeof buf,UINT32_C(0x12400040),1234,&id)==-1);
    /* Same bytes, wrong record size argument: identical -1 refusal. */
    CHECK(bw_stop_identity_parse(buf,BW_STOP_PROFILE_RECORD-1,BW_STOP_PROFILE_FW,1234,&id)==-1);
    CHECK(bw_stop_identity_parse(buf,BW_STOP_PROFILE_RECORD+1,BW_STOP_PROFILE_FW,1234,&id)==-1);

    printf("{\"passed\":true,\"checks\":%d}\n",checks);
    return 0;
}
