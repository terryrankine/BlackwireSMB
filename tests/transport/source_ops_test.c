/* SPDX-License-Identifier: GPL-3.0-or-later
 * bw_source dispatch: a NULL table reaches the SMB implementation exactly as
 * before, a table reaches only that table. */
#define _DEFAULT_SOURCE 1
#include "library/source.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks,smb_calls,ops_calls;
#define C(x) do { checks++;if(!(x)){fprintf(stderr,"source ops failure line %d: %s\n",__LINE__,#x);exit(1);} } while(0)

int bw_source_smb_snapshot_bound_policy(struct bw_source *p,const char *s,const char *g,struct bw_source_map *m,struct bw_source_snapshot *n,enum bw_source_plan_policy y){(void)p;(void)s;(void)g;(void)m;(void)n;smb_calls++;return y==BW_SOURCE_PLAN_COMPANIONS_V1?7:1;}
int bw_source_smb_snapshot_bound(struct bw_source *p,const char *s,const char *g,struct bw_source_map *m,struct bw_source_snapshot *n){(void)p;(void)s;(void)g;(void)m;(void)n;smb_calls++;return 2;}
int bw_source_smb_read(struct bw_source *p,const struct bw_source_snapshot *s,const char *a,bw_source_consume_fn f,void *o){(void)p;(void)s;(void)a;(void)f;(void)o;smb_calls++;return 3;}
int bw_source_smb_read_range(struct bw_source *p,const struct bw_source_snapshot *s,const char *a,uint64_t b,uint64_t c,bw_source_range_current_fn d,void *e,bw_source_consume_fn f,void *g){(void)p;(void)s;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;smb_calls++;return 4;}
int bw_source_smb_list(struct bw_source *p,const char *a,bw_source_visit_fn v,void *o){(void)p;(void)a;(void)v;(void)o;smb_calls++;return 5;}
int bw_source_smb_file_info(struct bw_source *p,const char *a,struct bw_source_info *i){(void)p;(void)a;(void)i;smb_calls++;return 6;}
int bw_source_smb_small_file(struct bw_source *p,const char *a,size_t n,void **b,size_t *z,struct bw_source_info *i){(void)p;(void)a;(void)n;(void)b;(void)z;(void)i;smb_calls++;return 8;}

static int o_snapshot(struct bw_source *p,const char *s,const char *g,struct bw_source_map *m,struct bw_source_snapshot *n,enum bw_source_plan_policy y){(void)p;(void)s;(void)g;(void)m;(void)n;ops_calls++;return y==BW_SOURCE_PLAN_LEGACY?11:12;}
static int o_read(struct bw_source *p,const struct bw_source_snapshot *s,const char *a,bw_source_consume_fn f,void *o){(void)p;(void)s;(void)a;(void)f;(void)o;ops_calls++;return 13;}
static int o_range(struct bw_source *p,const struct bw_source_snapshot *s,const char *a,uint64_t b,uint64_t c,bw_source_range_current_fn d,void *e,bw_source_consume_fn f,void *g){(void)p;(void)s;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;ops_calls++;return 14;}
static int o_list(struct bw_source *p,const char *a,bw_source_visit_fn v,void *o){(void)p;(void)a;(void)v;(void)o;ops_calls++;return 15;}
static int o_info(struct bw_source *p,const char *a,struct bw_source_info *i){(void)p;(void)a;(void)i;ops_calls++;return 16;}
static int o_small(struct bw_source *p,const char *a,size_t n,void **b,size_t *z,struct bw_source_info *i){(void)p;(void)a;(void)n;(void)b;(void)z;(void)i;ops_calls++;return 17;}
static const struct bw_source_ops table={o_snapshot,o_read,o_range,o_list,o_info,o_small};

int main(void){
    struct bw_source smb={0};struct bw_source_info info;void *bytes=NULL;size_t size=0;
    C(!bw_source_connected(&smb));smb.smb=(struct smb2_context *)&smb;C(bw_source_connected(&smb));
    C(bw_source_snapshot_bound_policy(&smb,"a","b",NULL,NULL,BW_SOURCE_PLAN_COMPANIONS_V1)==7);
    C(bw_source_snapshot_bound(&smb,"a","b",NULL,NULL)==2);
    C(bw_source_read(&smb,NULL,"a",NULL,NULL)==3);
    C(bw_source_read_range(&smb,NULL,"a",0,0,NULL,NULL,NULL,NULL)==4);
    C(bw_source_list(&smb,"",NULL,NULL)==5);
    C(bw_source_file_info(&smb,"a",&info)==6);
    C(bw_source_small_file(&smb,"a",1,&bytes,&size,&info)==8);
    C(smb_calls==7&&!ops_calls);
    struct bw_source other={0};other.ops=&table;int live;
    C(!bw_source_connected(&other));other.transport.context=&live;C(bw_source_connected(&other));
    other.smb=(struct smb2_context *)&other;
    C(bw_source_snapshot_bound_policy(&other,"a","b",NULL,NULL,BW_SOURCE_PLAN_COMPANIONS_V1)==12);
    C(bw_source_snapshot_bound(&other,"a","b",NULL,NULL)==11);
    C(bw_source_read(&other,NULL,"a",NULL,NULL)==13);
    C(bw_source_read_range(&other,NULL,"a",0,0,NULL,NULL,NULL,NULL)==14);
    C(bw_source_list(&other,"",NULL,NULL)==15);
    C(bw_source_file_info(&other,"a",&info)==16);
    C(bw_source_small_file(&other,"a",1,&bytes,&size,&info)==17);
    C(smb_calls==7&&ops_calls==7);
    /* The reader still names the struct by its old name. */
    struct bw_source_smb legacy={.smb=NULL,.deadline=1};C(legacy.deadline==1&&sizeof legacy==sizeof(struct bw_source));
    printf("{\"source_ops\":%u}\n",checks);
    return 0;
}
