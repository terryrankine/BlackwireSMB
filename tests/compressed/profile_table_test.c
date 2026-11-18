/* Host check for the supported firmware/profile table and its single lookup.
 * Proves the refactor keeps the old exact-match behaviour: the 13.00 row is
 * accepted at 0x13000040/1096 and every other firmware or record size refuses
 * with the same -1 the earlier inline constant comparison returned. No console
 * or kernel access; a synthetic in-memory kinfo_proc prefix drives the parser.
 * The gate checks drive each host-buildable firmware gate with an unknown
 * firmware and with 13.00, so a refusal is shown to come from the firmware.
 * Not host-built here: local_launch.c (bd_local_state needs a full launch and
 * log fixture) and native_session_ps5.c (live sysctl and kernel firmware). */
#include "game_stop_identity.h"
#include "game_identity.h"
#include "startup_runtime_idle.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
/* Included, not linked, to reach the static package fingerprint so the 13.00
 * control is an owner the frontend gate really accepts. */
#include "frontend_identity.c"

#define UNKNOWN_FW UINT32_C(0x12500000)

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

/* Startup idle snapshot: an unknown firmware refuses before any process query. */
static uint32_t idle_fw;
static unsigned idle_queries;
static uint32_t idle_firmware(void *p){ (void)p; return idle_fw; }
static struct bw_src_process_result idle_query(void *p,void *b,size_t c){
    (void)p;(void)b;(void)c; idle_queries++; return (struct bw_src_process_result){0,1,0};
}
static int idle_current(void *p){ (void)p; return 0; }
static int idle_gate(uint32_t fw,int adopt){
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    struct bw_startup_idle_request r={(double)t.tv_sec+(double)t.tv_nsec/1e9+60,idle_current,NULL,"/nonexistent/debug.log"};
    struct bw_src_idle_ops ops={idle_firmware,idle_query,NULL};
    struct bw_stop_identity game={500,1700000000,123456,"eboot.bin"};
    idle_fw=fw; idle_queries=0;
    return adopt?bw_src_adopt_evaluate(&r,&ops,&game,"PPSA01234"):bw_src_idle_evaluate(&r,&ops);
}

/* Game identity: the process read is the first step after the firmware gate. */
static uint32_t id_fw;
static unsigned id_process;
static uint32_t id_firmware(void *p){ (void)p; return id_fw; }
static int32_t id_self(void *p){ (void)p; return 100; }
static int id_read(void *p,int32_t pid,void *raw,size_t cap,size_t *used){ (void)p;(void)pid;(void)raw;(void)cap; id_process++; *used=0; return RC_GAME_ABSENT; }
static int id_app_info(void *p,int32_t pid,uint32_t *app,char title[14]){ (void)p;(void)pid;(void)app;(void)title; return -1; }
static int id_running(void *p,uint32_t *app){ (void)p;(void)app; return -1; }
static int id_title(void *p,uint32_t app,char *t,size_t n){ (void)p;(void)app;(void)t;(void)n; return -1; }
static int64_t id_wall(void *p){ (void)p; return INT64_C(1700000000123456)+1000; }
static const struct rc_game_identity_ops id_ops={NULL,id_firmware,id_self,id_read,id_app_info,id_running,id_title,id_wall};
static struct rc_game_identity prior(uint32_t fw,const char *title){
    struct rc_game_identity g={.process={500,1700000000,123456,"eboot.bin"},.firmware=fw,.app_id=7,.admitted_wall_us=INT64_C(1700000000123456)+1000};
    memcpy(g.title,title,10); return g;
}

/* Frontend owner whose only variable is the admitted firmware. */
static int frontend_get(uint32_t fw){
    struct bd_frontend_package pkg={{16,{1}},{1,{1}},{1,{1}}};
    struct bd_frontend_owner o;
    if(bd_frontend_init_at_for_test(&o,&pkg,"/fixture/source","/fixture/registered")) return -2;
    o.admitted=1; o.original=prior(fw,BD_FRONTEND_TITLE);
    o.identity=(struct bd_frontend_identity){.pid=500,.app_id=7,.birth_sec=1700000000,.birth_usec=123456};
    memcpy(o.identity.title_id,BD_FRONTEND_TITLE,10); package_fingerprint(&o.expected,o.identity.package_fingerprint);
    struct bd_frontend_identity out; return bd_frontend_get(&o,&out);
}

static int gates(void){
    CHECK(idle_gate(UNKNOWN_FW,0)==-1 && idle_queries==0);
    CHECK(idle_gate(BW_STOP_PROFILE_FW,0)==-1 && idle_queries==1);
    CHECK(idle_gate(UNKNOWN_FW,1)==-1 && idle_queries==0);
    CHECK(idle_gate(BW_STOP_PROFILE_FW,1)==-1 && idle_queries==1);

    struct rc_game_selection sel={500,7,"PPSA01234"};
    struct rc_game_identity out,g;
    id_fw=UNKNOWN_FW; id_process=0;
    CHECK(rc_game_identity_admit_with_ops(&id_ops,&sel,&out)==RC_GAME_UNKNOWN && id_process==0);
    id_fw=BW_STOP_PROFILE_FW; id_process=0;
    CHECK(rc_game_identity_admit_with_ops(&id_ops,&sel,&out)==RC_GAME_ABSENT && id_process==2);

    /* Live firmware is 13.00, so only the retained prior firmware can refuse. */
    g=prior(UNKNOWN_FW,"PPSA01234"); id_fw=BW_STOP_PROFILE_FW; id_process=0;
    CHECK(rc_game_identity_current_with_ops(&id_ops,&g,&out)==RC_GAME_UNKNOWN && id_process==0);
    g=prior(BW_STOP_PROFILE_FW,"PPSA01234"); id_fw=BW_STOP_PROFILE_FW; id_process=0;
    CHECK(rc_game_identity_current_with_ops(&id_ops,&g,&out)==RC_GAME_ABSENT && id_process==2);

    CHECK(frontend_get(UNKNOWN_FW)==-1);
    CHECK(frontend_get(BW_STOP_PROFILE_FW)==0);
    return 0;
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

    if(gates()) return 1;
    printf("{\"passed\":true,\"checks\":%d}\n",checks);
    return 0;
}
