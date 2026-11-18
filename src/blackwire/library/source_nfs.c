#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "source_nfs.h"
#include "source_directory.h"
#include "../streamreader/bw_transport_nfs.h"
#include "../streamreader/container_smb.h"
#include <errno.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NS_MAX_DEPTH 48u
#define NS_MAX_ENTRIES 262144u
#define NS_ATTR_DIRECTORY 0x10u
#define NS_ATTR_SPECIAL 0x40u
#define NS_ATTR_FILE 0x80u
#define NS_ATTR_LINK 0x400u
#define NS_ATTR_UNSAFE (NS_ATTR_LINK|NS_ATTR_SPECIAL)
#define NS_CONSUME_BYTES 65536u
#define NS_PATH (2*BW_MANIFEST_MAX_PATH+2)
_Static_assert(BW_SOURCE_SNAPSHOT_MAX_PARENTS==NS_MAX_DEPTH+1,"parent bound");

static double ns_now(void){struct timespec t;return clock_gettime(CLOCK_MONOTONIC,&t)?-1:(double)t.tv_sec+(double)t.tv_nsec/1e9;}
static void ns_progress(struct bw_source *p){
    if(!p->observe)return;
    struct bw_source_progress value=p->progress;
    value.requests=p->requests;value.entries=p->entries;value.pages=p->pages;value.source_bytes=p->content_bytes;
    value.phase_entries=p->entries-p->phase_entry_base;value.monotonic_seconds=ns_now();
    p->observe(p->observe_opaque,&value);
}
static int ns_fail(struct bw_source *p,const char *error){if(!p->error)p->error=error;return -1;}
static int ns_poison(struct bw_source *p,const char *error){ns_fail(p,error);bw_transport_poison(&p->transport);return -1;}
static int ns_live(struct bw_source *p){
    double now=ns_now();
    return !p->transport.context||now<0||now>=p->deadline?ns_fail(p,"source_scan_expired"):0;
}
/* A timeout or a transport failure leaves libnfs in an unknown state, so the
 * connection is dropped. Any other refusal keeps it. */
static int ns_fatal(int result){
    enum bw_tp_error class=bw_tp_error_from_nfs(result,0);return class==BW_TP_TIMEOUT||class==BW_TP_TRANSPORT;
}
static int ns_failed(struct bw_source *p,int result,const char *error){
    p->last_result=result;return ns_fatal(result)?ns_poison(p,error):ns_fail(p,error);
}
static uint32_t ns_attributes(uint32_t type){
    return type==BW_TP_DIRECTORY?NS_ATTR_DIRECTORY:type==BW_TP_FILE?NS_ATTR_FILE:type==BW_TP_LINK?NS_ATTR_LINK:NS_ATTR_SPECIAL;
}
static int ns_ticks(uint64_t seconds,uint64_t nanoseconds,uint64_t *out){
    const uint64_t epoch=UINT64_C(116444736000000000);
    if(nanoseconds>=1000000000u||seconds>(UINT64_MAX-epoch-nanoseconds/100)/10000000u)return -1;
    *out=epoch+seconds*10000000u+nanoseconds/100;return 0;
}
static int ns_info(const struct bw_stat *st,struct bw_source_info *out){
    *out=(struct bw_source_info){st->size,st->ino,0,0,ns_attributes(st->type)};
    return ns_ticks(st->mtime,st->mtime_nsec,&out->mtime_ticks)||ns_ticks(st->ctime,st->ctime_nsec,&out->ctime_ticks)?-EOVERFLOW:0;
}
static int ns_same(const struct bw_source_info *a,const struct bw_source_info *b){
    return a&&b&&a->size==b->size&&a->inode==b->inode&&a->mtime_ticks==b->mtime_ticks&&a->ctime_ticks==b->ctime_ticks&&a->attributes==b->attributes;
}
/* Returns 0 or the library's negative result. Never fails p itself. */
static int ns_stat(struct bw_source *p,const char *path,struct bw_source_info *out){
    struct bw_stat st;p->requests++;ns_progress(p);
    int result=p->transport.ops->stat(p->transport.context,path,&st,NULL);
    return result?result:ns_info(&st,out);
}
static int ns_fstat(struct bw_source *p,void *file,struct bw_source_info *out){
    struct bw_stat st;p->requests++;
    int result=p->transport.ops->fstat(p->transport.context,file,&st,NULL);
    return result?result:ns_info(&st,out);
}
static int ns_directory(struct bw_source *p,const char *path,struct bw_source_info *out){
    int result=ns_stat(p,path,out);if(result)return result;
    return out->attributes&NS_ATTR_UNSAFE?-ELOOP:out->attributes&NS_ATTR_DIRECTORY?0:-ENOTDIR;
}
/* Each directory from the root down to path (the leaf only when asked) must
 * be a plain directory. infos receives each one, root first. */
static int ns_parents(struct bw_source *p,const char *path,int include_leaf,struct bw_source_info *infos,unsigned *count){
    char relative[BW_MANIFEST_MAX_PATH+1];size_t size=strlen(path);*count=0;
    if(size>=sizeof relative||(size&&bw_manifest_validate_path(path,size)))return -EINVAL;
    memcpy(relative,path,size+1);
    int result=ns_directory(p,"",&infos[(*count)++]);if(result)return result;
    for(char *part=relative;*part;){
        char *slash=strchr(part,'/');if(!slash&&!include_leaf)break;
        if(*count>=NS_MAX_DEPTH+1)return -ENAMETOOLONG;
        if(slash)*slash=0;
        result=ns_directory(p,relative,&infos[(*count)++]);if(slash)*slash='/';
        if(result)return result;
        if(!slash)break;
        part=slash+1;
    }
    return 0;
}
static int ns_parents_same(struct bw_source *p,const char *path,int include_leaf,const struct bw_source_info *before,unsigned count){
    struct bw_source_info after[NS_MAX_DEPTH+1];unsigned now=0;int result=ns_parents(p,path,include_leaf,after,&now);
    if(result)return result;
    if(now!=count)return -ESTALE;
    for(unsigned i=0;i<count;i++)if(!ns_same(&before[i],&after[i]))return -ESTALE;
    return 0;
}

/* Bound snapshot: the same tree walk and seal inputs as the SMB source. */
struct ns_walk {
    struct bw_source *p;struct bw_source_plan *plan;const char *relative;unsigned depth;
    struct bw_source_snapshot *snapshot;uint32_t *entries,*directories;const char *remote;unsigned prefix_depth;
};
static int ns_walk_directory(struct ns_walk *walk);
static int ns_entry(void *opaque,const char *name,const struct bw_stat *st){
    struct ns_walk *walk=opaque;struct bw_source *p=walk->p;struct bw_source_info info;
    if(!strcmp(name,".")||!strcmp(name,".."))return 0;
    if(++*walk->entries>NS_MAX_ENTRIES||p->entries==UINT32_MAX||ns_live(p))return ns_fail(p,"source_entry_or_time_limit");
    p->entries++;
    if(bw_source_excluded(name))return 0;
    size_t length=strlen(name);
    if(!length||length>255||strchr(name,'/')||bw_manifest_validate_path(name,length))return ns_fail(p,"invalid_source_component");
    if(ns_info(st,&info))return ns_fail(p,"source_reply_bounds_or_fields_invalid");
    if(info.attributes&NS_ATTR_UNSAFE)return ns_fail(p,"source_contains_link_or_device");
    char relative[1024];int n=snprintf(relative,sizeof relative,"%s%s%s",walk->relative,*walk->relative?"/":"",name);
    if(n<0||(size_t)n>=sizeof relative)return ns_fail(p,"source_relative_path_limit");
    if(bw_manifest_validate_path(relative,(size_t)n))return ns_fail(p,"invalid_source_relative_path");
    const int directory=!!(info.attributes&NS_ATTR_DIRECTORY);
    if(bw_source_plan_node(walk->plan,relative,directory))return ns_fail(p,walk->plan->error);
    if(directory){struct ns_walk child=*walk;child.relative=relative;child.depth=walk->depth+1;return ns_walk_directory(&child);}
    if(walk->snapshot&&bw_source_snapshot_add(walk->snapshot,relative,&info))return ns_fail(p,walk->snapshot->error);
    if(bw_source_plan_add(walk->plan,relative,info.size,bw_source_unix_mtime(info.mtime_ticks))<0)
        return ns_fail(p,walk->plan->error?walk->plan->error:"invalid_source_plan");
    return 0;
}
static int ns_walk_directory(struct ns_walk *walk){
    struct bw_source *p=walk->p;char path[NS_PATH];struct bw_source_info before,after;
    if(walk->prefix_depth>NS_MAX_DEPTH||walk->depth>NS_MAX_DEPTH-walk->prefix_depth||++*walk->directories>NS_MAX_ENTRIES||
       p->directories==UINT32_MAX||ns_live(p))return ns_fail(p,"source_directory_or_time_limit");
    p->directories++;
    int n=snprintf(path,sizeof path,"%s%s%s",walk->remote,*walk->relative?"/":"",walk->relative);
    if(n<0||(size_t)n>=sizeof path)return ns_fail(p,"source_remote_path_limit");
    int result=ns_directory(p,path,&before);
    if(result)return ns_failed(p,result,result==-ELOOP||result==-ENOTDIR?"source_directory_is_linked_special_or_changed":"source_directory_open_failed");
    if(walk->depth+1>p->peak_held_pages)p->peak_held_pages=walk->depth+1;
    p->pages++;p->requests++;
    result=p->transport.ops->list(p->transport.context,path,ns_entry,walk);
    if(p->error)return -1;
    if(result)return ns_failed(p,result,"source_directory_page_failed");
    result=ns_directory(p,path,&after);
    if(result)return ns_failed(p,result,"source_directory_stat_failed");
    if(!ns_same(&before,&after))return ns_fail(p,"source_directory_changed");
    if(walk->snapshot&&bw_source_snapshot_add(walk->snapshot,walk->relative,&after))return ns_fail(p,walk->snapshot->error);
    return 0;
}
static int ns_snapshot_bound_policy(struct bw_source *p,const char *remote,const char *game,struct bw_source_map *map,
                                    struct bw_source_snapshot *snapshot,enum bw_source_plan_policy policy){
    if(!p||!map||!snapshot)return -1;
    memset(map,0,sizeof *map);
    if(bw_source_snapshot_init_bound(snapshot,remote,game))return ns_fail(p,snapshot->error);
    if(p->error||ns_live(p))return -1;
    struct bw_source_plan plan;
    if(bw_source_plan_init_policy(&plan,game,policy)){ns_fail(p,plan.error);bw_source_plan_destroy(&plan);return -1;}
    struct bw_source_info parents[NS_MAX_DEPTH+1];unsigned count=0;int result=-1;
    int status=ns_parents(p,remote,0,parents,&count);
    if(status){ns_failed(p,status,"source_collection_parent_unavailable");goto done;}
    snapshot->parent_count=count;for(unsigned i=0;i<count;i++)snapshot->parents[i]=parents[i];
    uint32_t entries=0,directories=0;
    struct ns_walk walk={p,&plan,"",0,snapshot,&entries,&directories,remote,count};
    result=ns_walk_directory(&walk);
    if(!result&&(status=ns_parents_same(p,remote,0,parents,count)))result=ns_failed(p,status,"catalog_source_parent_changed");
    if(!result&&bw_source_plan_finish(&plan,map))result=ns_fail(p,plan.error?plan.error:"source_manifest_failed");
    if(!result&&bw_source_snapshot_finish(snapshot))result=ns_fail(p,snapshot->error);
done:
    if(result)bw_source_map_destroy(map);
    bw_source_plan_destroy(&plan);
    return result;
}

/* Whole-file and range reads share one checked path: the collection parents
 * and every directory down to the file must still match the sealed snapshot,
 * and the opened file must match it before and after the reads. */
static int ns_range_current(struct bw_source *p,bw_source_range_current_fn current,void *job){
    double now=ns_now();
    if(p->error)return -1;
    if(!p->transport.context||!(p->deadline>=-DBL_MAX&&p->deadline<=DBL_MAX)||now<0||now>=p->deadline)return ns_fail(p,"source_range_expired");
    if(current&&current(job))return ns_fail(p,"source_range_job_not_current");
    return 0;
}
static int ns_held_directory(struct bw_source *p,const struct bw_source_snapshot *snapshot,const char *relative){
    char remote[NS_PATH];const struct bw_source_info *wanted=bw_source_snapshot_find(snapshot,relative);
    int n=snprintf(remote,sizeof remote,"%s%s%s",snapshot->source,*relative?"/":"",relative);
    if(n<0||(size_t)n>=sizeof remote||!wanted||!(wanted->attributes&NS_ATTR_DIRECTORY))return ns_fail(p,"source_parent_not_in_snapshot");
    struct bw_source_info info;int result=ns_directory(p,remote,&info);
    if(result)return ns_failed(p,result,"source_file_parent_changed");
    return ns_same(wanted,&info)?0:ns_fail(p,"source_file_parent_changed");
}
static int ns_held(struct bw_source *p,const struct bw_source_snapshot *snapshot,const char *path){
    if(snapshot->parent_count){
        int result=ns_parents_same(p,snapshot->source,0,snapshot->parents,snapshot->parent_count);
        if(result)return ns_failed(p,result,"source_collection_parent_changed");
    }
    char relative[BW_MANIFEST_MAX_PATH+1];size_t length=strlen(path);memcpy(relative,path,length+1);
    if(ns_held_directory(p,snapshot,""))return -1;
    for(char *slash=strchr(relative,'/');slash;slash=strchr(slash+1,'/')){
        *slash=0;int result=ns_held_directory(p,snapshot,relative);*slash='/';if(result)return -1;
    }
    return 0;
}
static int ns_read_checked(struct bw_source *p,const struct bw_source_snapshot *snapshot,const char *path,uint64_t offset,uint64_t length,
                           int range,bw_source_range_current_fn current,void *job,bw_source_consume_fn consume,void *opaque){
    size_t path_length=strnlen(path,BW_MANIFEST_MAX_PATH+1);
    if(!path_length||path_length>BW_MANIFEST_MAX_PATH||bw_manifest_validate_path(path,path_length))return ns_fail(p,range?"source_range_invalid_path":"source_file_not_in_snapshot");
    const struct bw_source_info *expected=bw_source_snapshot_find(snapshot,path);
    if(!expected||!(expected->attributes&NS_ATTR_FILE))return ns_fail(p,"source_file_not_in_snapshot");
    if(!range)length=expected->size;
    if(range&&(length>BW_SOURCE_RANGE_LIMIT||offset>expected->size||length>expected->size-offset))return ns_fail(p,"source_range_bounds");
    char remote[NS_PATH];int n=snprintf(remote,sizeof remote,"%s/%s",snapshot->source,path);
    if(n<0||(size_t)n>=sizeof remote)return ns_fail(p,"source_remote_path_limit");
    if(ns_held(p,snapshot,path))return -1;
    struct bw_source_info named,before,after;int status=ns_stat(p,remote,&named);
    if(status)return ns_failed(p,status,"source_file_open_failed");
    if(!ns_same(expected,&named))return ns_fail(p,"source_file_is_linked_special_or_changed");
    p->requests++;void *file=p->transport.ops->open(p->transport.context,remote);
    if(!file){status=ns_stat(p,remote,&named);return ns_failed(p,status?status:-EIO,"source_file_open_failed");}
    uint8_t *buffer=NULL;int result=-1;
    if((status=ns_fstat(p,file,&before))){ns_failed(p,status,"source_file_stat_failed");goto done;}
    if(!ns_same(expected,&before)){ns_fail(p,"source_file_is_linked_special_or_changed");goto done;}
    uint32_t capacity=p->transport.ops->max_read(p->transport.context);
    if(length&&(!capacity||!(buffer=malloc(capacity)))){ns_fail(p,"source_read_buffer_allocation_failed");goto done;}
    unsigned calls=0;
    for(uint64_t at=0;at<length;){
        if(range&&(ns_range_current(p,current,job)||calls++==BW_SOURCE_RANGE_MAX_READ_CALLS)){ns_fail(p,"source_range_read_call_limit");goto done;}
        if(!range&&ns_live(p))goto done;
        uint32_t want=length-at<capacity?(uint32_t)(length-at):capacity;
        p->requests++;int got=p->transport.ops->pread(p->transport.context,file,buffer,want,offset+at);
        if(got<0){ns_failed(p,got,"source_file_read_failed_or_truncated");goto done;}
        if(!got||(uint32_t)got>want){ns_fail(p,"source_file_read_failed_or_truncated");goto done;}
        if((uint64_t)got>UINT64_MAX-p->content_bytes){ns_fail(p,"source_file_content_counter_overflow");goto done;}
        p->content_bytes+=(uint64_t)got;ns_progress(p);
        for(size_t used=0;used<(size_t)got;){
            if(range?ns_range_current(p,current,job):ns_live(p))goto done;
            size_t piece=(size_t)got-used;if(piece>NS_CONSUME_BYTES)piece=NS_CONSUME_BYTES;
            if(consume(opaque,buffer+used,piece)){ns_fail(p,"source_file_consumer_failed");goto done;}
            used+=piece;
        }
        at+=(uint64_t)got;
    }
    if((status=ns_fstat(p,file,&after))){ns_failed(p,status,"source_file_stat_failed");goto done;}
    if(!ns_same(&before,&after)){ns_fail(p,"source_file_changed_while_reading");goto done;}
    result=0;
done:
    free(buffer);
    if(p->transport.context){status=p->transport.ops->close(p->transport.context,file);if(status){ns_failed(p,status,"source_file_close_failed");result=-1;}}
    if(!result&&ns_held(p,snapshot,path))result=-1;
    return result;
}
static int ns_read(struct bw_source *p,const struct bw_source_snapshot *snapshot,const char *path,bw_source_consume_fn consume,void *opaque){
    if(!p||!snapshot||!path||!consume||p->error||ns_live(p))return -1;
    return ns_read_checked(p,snapshot,path,0,0,0,NULL,NULL,consume,opaque);
}
static int ns_read_range(struct bw_source *p,const struct bw_source_snapshot *snapshot,const char *path,uint64_t offset,uint64_t length,
                         bw_source_range_current_fn current,void *job,bw_source_consume_fn consume,void *opaque){
    if(!p)return -1;
    if(!snapshot||!path||!consume||!current||p->error)return ns_fail(p,"source_range_invalid_arguments");
    if(ns_range_current(p,current,job))return -1;
    if(bw_source_snapshot_validate(snapshot)||!snapshot->parent_count)return ns_fail(p,"source_range_invalid_or_unbound_snapshot");
    uint8_t seal[32];memcpy(seal,snapshot->sha256,sizeof seal);
    int result=ns_read_checked(p,snapshot,path,offset,length,1,current,job,consume,opaque);
    if(!result&&(ns_range_current(p,current,job)||bw_source_snapshot_validate(snapshot)||memcmp(seal,snapshot->sha256,sizeof seal)))
        result=ns_fail(p,"source_range_final_snapshot_or_job_changed");
    return result;
}

/* Catalog lookups. Missing, refused, linked or changed items are positive
 * results that leave the connection and p->error untouched. */
static int ns_lookup(int result){
    switch(bw_tp_error_from_nfs(result,0)){
    case BW_TP_MISSING:return BW_SOURCE_MISSING;
    case BW_TP_DENIED:case BW_TP_UNAVAILABLE:case BW_TP_CHANGED:case BW_TP_LINKED_OR_SPECIAL:return BW_SOURCE_UNAVAILABLE;
    default:return -1;
    }
}
static int ns_catalog_file(struct bw_source *p,const char *path,int contents,size_t maximum,void **bytes,size_t *size,struct bw_source_info *info){
    if(bytes)*bytes=NULL;
    if(size)*size=0;
    if(info)memset(info,0,sizeof *info);
    if(!p||!path||!*path||!info||p->error||ns_live(p))return -1;
    if(contents&&(!bytes||!size||!maximum||maximum>BW_SOURCE_SMALL_FILE_LIMIT))return ns_fail(p,"invalid_catalog_file_limit");
    struct bw_source_info parents[NS_MAX_DEPTH+1],named,before,after;unsigned count=0;uint8_t *output=NULL;void *file=NULL;int result=-1;
    int status=ns_parents(p,path,0,parents,&count);
    if(!status)status=ns_stat(p,path,&named);
    if(status){result=ns_lookup(status);if(result<0)ns_failed(p,status,"source_file_open_failed");goto done;}
    if(!(named.attributes&NS_ATTR_FILE)){result=BW_SOURCE_UNAVAILABLE;goto done;}
    if(contents&&named.size>maximum){result=BW_SOURCE_TOO_LARGE;goto done;}
    p->requests++;file=p->transport.ops->open(p->transport.context,path);
    if(!file){status=ns_stat(p,path,&after);result=status?ns_lookup(status):BW_SOURCE_UNAVAILABLE;
        if(result<0)ns_failed(p,status,"source_file_open_failed");goto done;}
    if((status=ns_fstat(p,file,&before))){result=ns_lookup(status);if(result<0)ns_failed(p,status,"source_file_stat_failed");goto done;}
    if(!ns_same(&named,&before)){result=BW_SOURCE_UNAVAILABLE;goto done;}
    if(contents){
        output=malloc(before.size?(size_t)before.size:1);
        if(!output){ns_fail(p,"catalog_file_allocation_failed");goto done;}
        uint32_t capacity=p->transport.ops->max_read(p->transport.context);if(!capacity){ns_fail(p,"source_max_read_unavailable");goto done;}
        for(uint64_t at=0;at<before.size;){
            uint32_t want=before.size-at<capacity?(uint32_t)(before.size-at):capacity;
            p->requests++;int got=p->transport.ops->pread(p->transport.context,file,output+(size_t)at,want,at);
            if(got<0){ns_failed(p,got,"catalog_file_read_failed_or_truncated");goto done;}
            if(!got||(uint32_t)got>want){ns_fail(p,"catalog_file_read_failed_or_truncated");goto done;}
            p->content_bytes+=(uint64_t)got;at+=(uint64_t)got;
        }
    }
    if((status=ns_fstat(p,file,&after))){result=ns_lookup(status);if(result<0)ns_failed(p,status,"source_file_stat_failed");goto done;}
    if(!ns_same(&before,&after)){result=BW_SOURCE_UNAVAILABLE;goto done;}
    if((status=ns_parents_same(p,path,0,parents,count))){result=ns_lookup(status);if(result<0)ns_failed(p,status,"catalog_source_parent_changed");goto done;}
    *info=before;result=BW_SOURCE_FOUND;
done:
    if(file&&p->transport.context){status=p->transport.ops->close(p->transport.context,file);if(status){ns_failed(p,status,"source_file_close_failed");result=-1;}}
    if(result==BW_SOURCE_FOUND&&contents){*bytes=output;*size=(size_t)info->size;output=NULL;}
    if(result!=BW_SOURCE_FOUND)memset(info,0,sizeof *info);
    free(output);return result;
}
static int ns_file_info(struct bw_source *p,const char *path,struct bw_source_info *info){return ns_catalog_file(p,path,0,0,NULL,NULL,info);}
static int ns_small_file(struct bw_source *p,const char *path,size_t maximum,void **bytes,size_t *size,struct bw_source_info *info){
    return ns_catalog_file(p,path,1,maximum,bytes,size,info);
}
struct ns_listing {struct bw_source *p;bw_source_visit_fn visit;void *opaque;uint32_t count;};
static int ns_catalog_entry(void *opaque,const char *name,const struct bw_stat *st){
    struct ns_listing *list=opaque;struct bw_source_info info;
    if(!strcmp(name,".")||!strcmp(name,".."))return 0;
    if(++list->count>NS_MAX_ENTRIES||list->p->entries==UINT32_MAX||ns_live(list->p))return ns_fail(list->p,"catalog_directory_entry_limit");
    if(ns_info(st,&info))return ns_fail(list->p,"source_reply_bounds_or_fields_invalid");
    list->p->entries++;
    return list->visit(list->opaque,name,&info)?ns_fail(list->p,"catalog_directory_page_or_consumer_failed"):0;
}
static int ns_list(struct bw_source *p,const char *path,bw_source_visit_fn visit,void *opaque){
    if(!p||!path||!visit||p->error||ns_live(p))return -1;
    struct bw_source_info parents[NS_MAX_DEPTH+1];unsigned count=0;
    int status=ns_parents(p,path,1,parents,&count);
    if(status)return ns_failed(p,status,"source_directory_open_failed");
    struct ns_listing list={p,visit,opaque,0};p->pages++;p->requests++;
    status=p->transport.ops->list(p->transport.context,path,ns_catalog_entry,&list);
    if(p->error)return -1;
    if(status)return ns_failed(p,status,"catalog_directory_page_failed");
    if((status=ns_parents_same(p,path,1,parents,count)))return ns_failed(p,status,"catalog_source_parent_changed");
    return 0;
}
static int ns_open_image(struct bw_source *p,struct bw_container_smb *image,const char *path){
    return bw_container_open_transport(image,&p->transport,path,1);
}
const struct bw_source_ops bw_source_nfs_ops={ns_snapshot_bound_policy,ns_read,ns_read_range,ns_list,ns_file_info,ns_small_file,ns_open_image};

void bw_source_nfs_adopt(struct bw_source *source,struct bw_transport transport){
    source->smb=NULL;source->ops=&bw_source_nfs_ops;source->transport=transport;
}
int bw_source_nfs_connect(struct bw_source *source,const struct bw_share_config *cfg,int timeout_seconds,struct bw_tp_status *status){
    struct bw_transport transport;
    if(!source)return -1;
    int result=bw_transport_nfs_connect(cfg,timeout_seconds,&transport,status);
    bw_source_nfs_adopt(source,transport);
    return result;
}
