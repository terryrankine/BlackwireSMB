/* SPDX-License-Identifier: GPL-3.0-or-later
 * NFS for the resident, over libnfs fakes. The compressed-image path comes
 * first: connect, catalog of an images folder, cover, image reads and the
 * timeout poison. The shared neutral scenarios then run the same source
 * calls over a neutral local transport and over NFS and require equal
 * results and equal snapshot seals. */
#define _DEFAULT_SOURCE 1
#include "nfs_fake.h"
#include "local_transport.h"
#include "library/source_nfs.h"
#include "library/source_catalog.h"
#include "library/source_connect.h"
#include "streamreader/bw_transport_nfs.h"
#include "streamreader/container_smb.h"
#include <sys/time.h>
#include <time.h>

static unsigned checks;
#define C(x) do { checks++;if(!(x)){fprintf(stderr,"nfs failure line %d: %s\n",__LINE__,#x);exit(1);} } while(0)

/* SMB is linked but must never be reached on an NFS source. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#define NEVER(signature) signature{abort();}
NEVER(struct smb2_context *smb2_init_context(void))
NEVER(void smb2_destroy_context(struct smb2_context *s))
NEVER(void smb2_set_timeout(struct smb2_context *s,int t))
NEVER(void smb2_set_sign(struct smb2_context *s,int v))
NEVER(void smb2_set_security_mode(struct smb2_context *s,uint16_t m))
NEVER(void smb2_set_user(struct smb2_context *s,const char *v))
NEVER(void smb2_set_password(struct smb2_context *s,const char *v))
NEVER(int smb2_connect_share(struct smb2_context *s,const char *a,const char *b,const char *c))
NEVER(int smb2_stat(struct smb2_context *s,const char *p,struct smb2_stat_64 *o))
NEVER(int smb2_fstat(struct smb2_context *s,struct smb2fh *f,struct smb2_stat_64 *o))
NEVER(struct smb2fh *smb2_open(struct smb2_context *s,const char *p,int f))
NEVER(int smb2_pread(struct smb2_context *s,struct smb2fh *f,uint8_t *b,uint32_t n,uint64_t o))
NEVER(int smb2_close(struct smb2_context *s,struct smb2fh *f))
NEVER(uint32_t smb2_get_max_read_size(struct smb2_context *s))
NEVER(int bw_source_smb_snapshot_bound_policy(struct bw_source *p,const char *s,const char *g,struct bw_source_map *m,struct bw_source_snapshot *n,enum bw_source_plan_policy y))
NEVER(int bw_source_smb_snapshot_bound(struct bw_source *p,const char *s,const char *g,struct bw_source_map *m,struct bw_source_snapshot *n))
NEVER(int bw_source_smb_read(struct bw_source *p,const struct bw_source_snapshot *s,const char *a,bw_source_consume_fn f,void *o))
NEVER(int bw_source_smb_read_range(struct bw_source *p,const struct bw_source_snapshot *s,const char *a,uint64_t b,uint64_t c,bw_source_range_current_fn d,void *e,bw_source_consume_fn f,void *g))
NEVER(int bw_source_smb_list(struct bw_source *p,const char *a,bw_source_visit_fn v,void *o))
NEVER(int bw_source_smb_file_info(struct bw_source *p,const char *a,struct bw_source_info *i))
NEVER(int bw_source_smb_small_file(struct bw_source *p,const char *a,size_t n,void **b,size_t *z,struct bw_source_info *i))
void bw_source_smb_progress(struct bw_source *p,enum bw_source_phase a,uint32_t b,uint32_t c,uint64_t d,uint64_t e){}
#pragma clang diagnostic pop

static char base[1024];
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (double)t.tv_sec+(double)t.tv_nsec/1e9;}
static struct bw_share_config nfs_config(const char *path){
    struct bw_share_config c={0};strcpy(c.server,"192.0.2.10");c.transport=BW_SHARE_NFS;strcpy(c.nfs_export,"/volume1/public");
    strcpy(c.nfs_path,path);c.nfs_version=3;c.nfs_uid=1000;c.nfs_gid=100;return c;
}
static void nfs_source(struct bw_source *s,const char *path){
    memset(s,0,sizeof *s);s->deadline=now()+60;struct bw_share_config c=nfs_config(path);struct bw_tp_status st;
    C(!bw_source_connect(s,&c,BW_TP_PROFILE_SCAN,10,&st)&&st.error==BW_TP_OK&&bw_source_connected(s));
}
static struct bw_tp_status refused(struct bw_share_config c){
    struct bw_source s={.deadline=now()+60};struct bw_tp_status st;unsigned destroyed=nfs_fake.destroys,made=nfs_fake.contexts;
    C(bw_source_connect(&s,&c,BW_TP_PROFILE_SCAN,10,&st)<0&&!bw_source_connected(&s)&&!s.transport.context);
    C(nfs_fake.contexts-made==nfs_fake.destroys-destroyed);return st;
}
static void connect_cases(void){
    nfs_fake_reset(base);struct bw_source s;nfs_source(&s,"emulation/ps5/games/images");
    C(s.ops==&bw_source_nfs_ops&&!s.smb&&nfs_fake.mounts==1);
    const struct nfs_context *n=&nfs_fake.last;
    C(n->version==3&&n->timeout==10000&&n->retrans==0&&n->autoreconnect==0&&n->dircache==0&&n->readonly==1);
    C(n->readmax==BW_NFS_READ_MAX&&n->uid==1000&&n->gid==100);
    C(s.transport.ops->max_read(s.transport.context)==BW_NFS_READ_MAX);
    nfs_fake.server_readmax=65536;C(s.transport.ops->max_read(s.transport.context)==65536);nfs_fake.server_readmax=1024*1024;
    bw_source_release(&s);C(!bw_source_connected(&s)&&nfs_fake.destroys==1);
    struct bw_share_config c=nfs_config("emulation/ps5/games/images");c.nfs_version=4;
    C(!bw_source_connect(&s,&c,BW_TP_PROFILE_ADMISSION,3,NULL)&&nfs_fake.last.version==4&&nfs_fake.last.timeout==3000);bw_source_release(&s);
    c.nfs_version=0;C(!bw_source_connect(&s,&c,BW_TP_PROFILE_SCAN,10,NULL)&&nfs_fake.last.version==3);bw_source_release(&s);
    /* Mount and root failures carry the design's classes. */
    struct bw_tp_status st;
    nfs_fake.mount_result=-ENOENT;st=refused(nfs_config("x"));C(st.error==BW_TP_ROOT_MISSING&&st.result==-ENOENT&&st.result_known);
    nfs_fake.mount_result=-EACCES;st=refused(nfs_config("x"));C(st.error==BW_TP_AUTH);
    nfs_fake.mount_result=-EPERM;st=refused(nfs_config("x"));C(st.error==BW_TP_AUTH);
    nfs_fake.mount_result=-EINTR;st=refused(nfs_config("x"));C(st.error==BW_TP_TIMEOUT);
    nfs_fake.mount_result=-ECONNREFUSED;st=refused(nfs_config("x"));C(st.error==BW_TP_TRANSPORT);
    nfs_fake.mount_result=0;
    c=nfs_config("emulation/ps5/games/images");strcpy(c.nfs_export,"/volume9");st=refused(c);C(st.error==BW_TP_ROOT_MISSING);
    st=refused(nfs_config("emulation/ps5/games/absent"));C(st.error==BW_TP_ROOT_MISSING&&st.result==-ENOENT);
    st=refused(nfs_config("emulation/ps5/games/images/Beta.ffpfsc"));C(st.error==BW_TP_ROOT_MISSING&&!st.result);
    st=refused(nfs_config("emulation/ps5/games/linked"));C(st.error==BW_TP_ROOT_MISSING);
    c=nfs_config("emulation/ps5/games/images");strcpy(c.server,"192.0.2.99");st=refused(c);C(st.error==BW_TP_TRANSPORT&&st.result==-EIO);
    /* Not attempted: two roots, a bad version, no NFS module input. */
    c=nfs_config("emulation/ps5/games/images");c.nfs_has_path2=1;unsigned mounts=nfs_fake.mounts;st=refused(c);C(!st.result_known&&nfs_fake.mounts==mounts);
    c=nfs_config("emulation/ps5/games/images");c.nfs_version=2;st=refused(c);C(!st.result_known&&nfs_fake.mounts==mounts);
}
static const struct bw_catalog_item *find(const struct bw_source_catalog *c,const char *source){
    for(size_t i=0;i<c->count;i++)if(!strcmp(c->items[i].source,source))return &c->items[i];return NULL;
}
static const uint8_t cover_bytes[]="\x89PNG NFS NEUTRAL COVER";
static void image_cases(void){
    nfs_fake_reset(base);struct bw_source s;nfs_source(&s,"emulation/ps5/games/images");
    struct bw_source_catalog catalog;C(!bw_source_catalog_scan(&s,&catalog));
    /* The image is a game. Its sidecar hash and an in-progress copy are not. */
    C(catalog.count==2);
    const struct bw_catalog_item *beta=find(&catalog,"Beta.ffpfsc"),*linked=find(&catalog,"Linked.ffpfsc");
    C(beta&&beta->state==BW_CATALOG_CONTAINER_READY&&!strcmp(beta->title_id,"PPSA09999")&&!strcmp(beta->title,"Neutral"));
    C(beta->image.type==BW_TP_FILE&&beta->image.size==beta->container_bytes);
    C(linked&&linked->state==BW_CATALOG_BLOCKED);
    C(!find(&catalog,"Beta.ffpfsc.sha256")&&!find(&catalog,"Gamma.ffpfsc.partial")&&catalog.skipped>=2);
    void *bytes=NULL;size_t size=0;
    C(!bw_source_catalog_container_cover(&s,beta,1u<<20,&bytes,&size));
    C(size==sizeof cover_bytes-1&&!memcmp(bytes,cover_bytes,size));free(bytes);
    /* The binding the catalog gives is the NFS one. */
    struct bw_share_config c=nfs_config("emulation/ps5/games/images");struct bw_provider_binding binding;
    struct bw_catalog_item row=*beta;strcpy(row.source_share,"emulation/ps5/games/images");
    C(!bw_source_catalog_binding(&binding,&c,&row)&&binding.kind==BW_PROVIDER_CONTAINER);
    /* Image reads, then a timeout drops the connection exactly once. */
    struct bw_container_smb image;
    C(!bw_source_open_image(&s,&image,"Beta.ffpfsc")&&image.context==s.transport.context&&image.metadata_window);
    char boot[32]={0};C(!bw_container_read(&image.container,"eboot.bin",0,boot,19)&&!memcmp(boot,"NFS NEUTRAL STARTUP",19));
    unsigned destroyed=nfs_fake.destroys;nfs_fake.fail_pread_at=(int)nfs_fake.preads+1;uint8_t big[65536];
    C(bw_container_read(&image.container,"asset.bin",65536,big,sizeof big)<0);
    C(!bw_source_connected(&s)&&nfs_fake.destroys==destroyed+1&&image.first_failure_result==-EINTR);
    C(!bw_container_smb_close(&image));nfs_fake.fail_pread_at=0;
    struct bw_source_catalog none;C(bw_source_catalog_scan(&s,&none)<0);bw_source_catalog_destroy(&none);
    bw_source_catalog_destroy(&catalog);bw_source_release(&s);
    /* A stale handle during admission is a changed image, not a crash. */
    nfs_source(&s,"emulation/ps5/games/images");nfs_fake.stale_fstat=1;
    C(bw_source_open_image(&s,&image,"Beta.ffpfsc")!=0&&bw_source_connected(&s));
    C(!bw_container_smb_close(&image));nfs_fake.stale_fstat=0;bw_source_release(&s);
}

/* A copy job writing into the scanned images folder. */
static char images_dir[2048];
static unsigned copy_steps,touch_beta;
static void copy_step(void){
    char path[4096];copy_steps++;
    /* Grow the in-progress copy and move its times. */
    snprintf(path,sizeof path,"%s/Gamma.ffpfsc.partial",images_dir);FILE *f=fopen(path,"ab");C(f);fputc('x',f);C(!fclose(f));
    struct timeval times[2]={{(time_t)copy_steps,0},{(time_t)(1000+copy_steps),0}};C(!utimes(path,times));
    /* Create and remove a sibling: the folder's own mtime and ctime move. */
    snprintf(path,sizeof path,"%s/Delta.ffpfsc.partial",images_dir);
    if(copy_steps&1){f=fopen(path,"wb");C(f);C(!fclose(f));}else C(!unlink(path));
    if(touch_beta&&copy_steps==touch_beta){
        snprintf(path,sizeof path,"%s/Beta.ffpfsc",images_dir);struct stat st;C(!stat(path,&st));
        struct timeval moved[2]={{st.st_atim.tv_sec,0},{st.st_mtim.tv_sec+7,0}};C(!utimes(path,moved));
    }
}
static void copy_cases(void){
    snprintf(images_dir,sizeof images_dir,"%s/volume1/public/emulation/ps5/games/images",base);
    char partial[4096],delta[4096];snprintf(partial,sizeof partial,"%s/Gamma.ffpfsc.partial",images_dir);
    snprintf(delta,sizeof delta,"%s/Delta.ffpfsc.partial",images_dir);
    struct stat before;C(!stat(partial,&before));
    /* A growing .partial and a churning folder leave the scan ready. */
    nfs_fake_reset(base);struct bw_source s;nfs_source(&s,"emulation/ps5/games/images");
    copy_steps=0;touch_beta=0;nfs_fake.on_pread=copy_step;
    struct bw_source_catalog catalog;C(!bw_source_catalog_scan(&s,&catalog));
    struct stat after;C(!stat(partial,&after));C(copy_steps>2&&after.st_size>before.st_size);
    const struct bw_catalog_item *beta=find(&catalog,"Beta.ffpfsc");
    C(beta&&beta->state==BW_CATALOG_CONTAINER_READY&&!catalog.error&&!s.error&&bw_source_connected(&s));
    C(!find(&catalog,"Gamma.ffpfsc.partial")&&!find(&catalog,"Delta.ffpfsc.partial"));
    struct bw_catalog_item first=*beta;bw_source_catalog_destroy(&catalog);
    /* The candidate itself changing marks that row only. */
    copy_steps=0;touch_beta=2;
    C(!bw_source_catalog_scan(&s,&catalog));beta=find(&catalog,"Beta.ffpfsc");
    C(beta&&beta->state==BW_CATALOG_CONTAINER&&beta->container_error==BW_CONTAINER_STALE&&!catalog.error&&!s.error);
    C(!*beta->title_id&&find(&catalog,"Linked.ffpfsc")->state==BW_CATALOG_BLOCKED);
    bw_source_catalog_destroy(&catalog);nfs_fake.on_pread=NULL;touch_beta=0;
    if(!access(delta,F_OK))C(!unlink(delta));
    /* Fresh full scan, then an unchanged image is reused without opening it. */
    C(!bw_source_catalog_scan(&s,&catalog));first=*find(&catalog,"Beta.ffpfsc");C(first.state==BW_CATALOG_CONTAINER_READY);
    struct bw_catalog_reuse reuse={.items=catalog.items,.count=catalog.count};
    unsigned opens=nfs_fake.opens,preads=nfs_fake.preads;struct bw_source_catalog again;
    C(!bw_source_catalog_scan_reusing(&s,&reuse,&again)&&reuse.reused==1&&reuse.validated==0&&reuse.deferred==0);
    C(nfs_fake.opens==opens&&nfs_fake.preads==preads);
    beta=find(&again,"Beta.ffpfsc");C(beta&&beta->state==BW_CATALOG_CONTAINER_READY&&!memcmp(beta->image_sha256,first.image_sha256,32)&&!strcmp(beta->title_id,"PPSA09999"));
    C(bw_source_catalog_reuse_find(catalog.items,catalog.count,beta)<catalog.count);
    /* Rows of another share are never borrowed. */
    struct bw_catalog_reuse other={.items=catalog.items,.count=catalog.count,.share="elsewhere"};struct bw_source_catalog third;
    C(!bw_source_catalog_scan_reusing(&s,&other,&third)&&other.reused==0&&other.validated==1);bw_source_catalog_destroy(&third);
    /* A changed image is validated again. */
    char image[4096];snprintf(image,sizeof image,"%s/Beta.ffpfsc",images_dir);struct stat st;C(!stat(image,&st));
    struct timeval moved[2]={{st.st_atim.tv_sec,0},{st.st_mtim.tv_sec+11,0}};C(!utimes(image,moved));
    opens=nfs_fake.opens;C(!bw_source_catalog_scan_reusing(&s,&reuse,&third)&&reuse.reused==0&&reuse.validated==1&&nfs_fake.opens>opens);
    beta=find(&third,"Beta.ffpfsc");C(beta->state==BW_CATALOG_CONTAINER_READY&&memcmp(beta->image_sha256,first.image_sha256,32));
    bw_source_catalog_destroy(&third);
    /* A removed image is dropped. */
    char moved_name[4096];snprintf(moved_name,sizeof moved_name,"%s/Beta.hidden",images_dir);C(!rename(image,moved_name));
    C(!bw_source_catalog_scan_reusing(&s,&reuse,&third)&&!find(&third,"Beta.ffpfsc")&&!reuse.reused);bw_source_catalog_destroy(&third);
    C(!rename(moved_name,image));
    /* A targeted check validates only <titleId>.<ext>; others stay unchecked. */
    struct bw_catalog_reuse only={.only="PPSA00001"};opens=nfs_fake.opens;
    C(!bw_source_catalog_scan_reusing(&s,&only,&third)&&only.deferred==1&&only.validated==0&&nfs_fake.opens==opens);
    beta=find(&third,"Beta.ffpfsc");C(beta->state==BW_CATALOG_CONTAINER&&beta->container_stage==BW_CATALOG_IMAGE_NOT_CHECKED&&!beta->container_error);
    C(!strcmp(bw_source_catalog_status(beta),"container_unverified"));bw_source_catalog_destroy(&third);
    struct bw_catalog_reuse named={.only="bEtA"};
    C(!bw_source_catalog_scan_reusing(&s,&named,&third)&&named.validated==1&&find(&third,"Beta.ffpfsc")->state==BW_CATALOG_CONTAINER_READY);
    bw_source_catalog_destroy(&third);
    bw_source_catalog_destroy(&again);bw_source_catalog_destroy(&catalog);bw_source_release(&s);
}

/* Many images, one slow: the library is ready and only that one fails. */
static void slow_cases(void){
    char many[2048],path[4096],beta[4096];snprintf(many,sizeof many,"%s/volume1/public/emulation/ps5/games/many",base);
    snprintf(beta,sizeof beta,"%s/volume1/public/emulation/ps5/games/images/Beta.ffpfsc",base);
    C(!mkdir(many,0755));FILE *in=fopen(beta,"rb");C(in);static uint8_t bytes[1u<<20];size_t size=fread(bytes,1,sizeof bytes,in);C(size>0&&size<sizeof bytes&&!fclose(in));
    for(unsigned i=0;i<16;i++){
        snprintf(path,sizeof path,"%s/%s%02u.ffpfsc",many,i==9?"Slow":"Game",i);FILE *out=fopen(path,"wb");C(out);C(fwrite(bytes,1,size,out)==size&&!fclose(out));
    }
    double stall=bw_catalog_image_stall_seconds,limit=bw_catalog_image_limit_seconds,step=bw_catalog_step_seconds;
    /* Each image may stall 2 s; the slow one stalls 3 s; the whole folder
     * runs far past one image's budget, so no total budget may apply. */
    bw_catalog_image_stall_seconds=2;bw_catalog_image_limit_seconds=2.5;bw_catalog_step_seconds=2;
    nfs_fake_reset(base);snprintf(nfs_fake.slow_name,sizeof nfs_fake.slow_name,"Slow09.ffpfsc");nfs_fake.slow_ms=3000;
    struct bw_source s;nfs_source(&s,"emulation/ps5/games/many");s.deadline=now()+1;
    double started=now();struct bw_source_catalog catalog;C(!bw_source_catalog_scan(&s,&catalog));
    C(now()-started>=3&&catalog.count==16&&!catalog.error&&!s.error&&bw_source_connected(&s));
    unsigned ready=0;
    for(size_t i=0;i<catalog.count;i++){
        const struct bw_catalog_item *row=catalog.items+i;
        if(!strcmp(row->source,"Slow09.ffpfsc"))C(row->state==BW_CATALOG_CONTAINER&&row->container_error==BW_CONTAINER_CANCELED&&!*row->title_id);
        else{C(row->state==BW_CATALOG_CONTAINER_READY);ready++;}
    }
    C(ready==15);bw_source_catalog_destroy(&catalog);bw_source_release(&s);
    bw_catalog_image_stall_seconds=stall;bw_catalog_image_limit_seconds=limit;bw_catalog_step_seconds=step;
}

/* Shared neutral scenarios over any source. */
struct names {char text[4096];};
static int names_visit(void *opaque,const char *name,const struct bw_source_info *info){
    struct names *n=opaque;size_t used=strlen(n->text);
    snprintf(n->text+used,sizeof n->text-used,"%s:%x;",name,info->attributes);return 0;
}
struct sink {uint8_t *bytes;size_t size,capacity;};
static int sink_take(void *opaque,const void *bytes,size_t size){
    struct sink *s=opaque;if(s->size+size>s->capacity)return -1;memcpy(s->bytes+s->size,bytes,size);s->size+=size;return 0;
}
static int job_current(void *job){(void)job;return 0;}
static uint8_t data_byte(size_t at){return (uint8_t)(at*7u+at/253u);}
struct outcome {struct names root;uint8_t seal[32];uint32_t local,stream;size_t catalog;};
static void neutral(struct bw_source *s,struct outcome *out){
    memset(out,0,sizeof *out);struct bw_source_info info;void *bytes=NULL;size_t size=0;
    C(!bw_source_list(s,"",names_visit,&out->root));
    C(strstr(out->root.text,"Alpha:10;")&&strstr(out->root.text,"LinkedGame:400;")&&strstr(out->root.text,"Alpha.lnk:400;"));
    C(bw_source_file_info(s,"Alpha/eboot.bin",&info)==BW_SOURCE_FOUND&&info.size==4096&&info.attributes==0x80);
    C(bw_source_file_info(s,"Alpha/absent.bin",&info)==BW_SOURCE_MISSING);
    C(bw_source_file_info(s,"Alpha/data",&info)==BW_SOURCE_UNAVAILABLE);
    C(bw_source_file_info(s,"Alpha.lnk",&info)==BW_SOURCE_UNAVAILABLE);
    C(bw_source_file_info(s,"LinkedGame/eboot.bin",&info)==BW_SOURCE_UNAVAILABLE);
    C(!s->error&&bw_source_connected(s));
    C(bw_source_small_file(s,"Alpha/sce_sys/param.json",4096,&bytes,&size,&info)==BW_SOURCE_FOUND);
    C(size==info.size&&strstr((char *)bytes,"PPSA09998")&&size<4096);free(bytes);bytes=NULL;
    C(bw_source_small_file(s,"Alpha/sce_sys/param.json",4,&bytes,&size,&info)==BW_SOURCE_TOO_LARGE&&!bytes);
    struct bw_source_catalog catalog;C(!bw_source_catalog_scan(s,&catalog));out->catalog=catalog.count;
    const struct bw_catalog_item *alpha=find(&catalog,"Alpha");
    C(alpha&&alpha->state==BW_CATALOG_FOLDER&&!strcmp(alpha->title_id,"PPSA09998")&&alpha->cover);
    C(find(&catalog,"LinkedGame")->state==BW_CATALOG_BLOCKED&&find(&catalog,"Alpha.lnk")->state==BW_CATALOG_BLOCKED);
    bw_source_catalog_destroy(&catalog);
    /* Bound snapshot, whole read and exact range. */
    struct bw_source_map map;struct bw_source_snapshot snapshot={0};
    C(!bw_source_snapshot_bound_policy(s,"Alpha","PPSA09998",&map,&snapshot,BW_SOURCE_PLAN_LEGACY));
    C(snapshot.parent_count==1&&map.local_count>=2);memcpy(out->seal,snapshot.sha256,32);out->local=map.local_count;out->stream=map.stream_count;
    uint8_t *buffer=malloc(1u<<20);struct sink sink={buffer,0,1u<<20};C(buffer);
    C(!bw_source_read(s,&snapshot,"eboot.bin",sink_take,&sink)&&sink.size==4096);
    for(size_t i=0;i<4096;i++)C(buffer[i]==(uint8_t)i);
    sink.size=0;C(!bw_source_read_range(s,&snapshot,"data/a.bin",1000,300000,job_current,NULL,sink_take,&sink)&&sink.size==300000);
    for(size_t i=0;i<300000;i++)if(buffer[i]!=data_byte(1000+i)){C(0);}
    sink.size=0;C(!bw_source_read_range(s,&snapshot,"data/a.bin",400000,0,job_current,NULL,sink_take,&sink)&&!sink.size);
    C(bw_source_read_range(s,&snapshot,"data/a.bin",399999,2,job_current,NULL,sink_take,&sink)<0&&!strcmp(s->error,"source_range_bounds"));
    s->error=NULL;
    bw_source_snapshot_destroy(&snapshot);bw_source_map_destroy(&map);free(buffer);
}
/* Runs after the seals are compared: touching a file also moves its ctime. */
static void changed(struct bw_source *s,const char *folders){
    struct bw_source_map map;struct bw_source_snapshot snapshot={0};uint8_t buffer[4096];struct sink sink={buffer,0,sizeof buffer};
    C(!bw_source_snapshot_bound_policy(s,"Alpha","PPSA09998",&map,&snapshot,BW_SOURCE_PLAN_LEGACY));
    /* A changed file is refused before any byte reaches the consumer. */
    char path[2048];snprintf(path,sizeof path,"%s/Alpha/data/a.bin",folders);struct stat st;C(!stat(path,&st));
    struct timeval times[2]={{st.st_atim.tv_sec,0},{st.st_mtim.tv_sec+5,0}};C(!utimes(path,times));
    sink.size=0;C(bw_source_read(s,&snapshot,"data/a.bin",sink_take,&sink)<0&&!sink.size&&strstr(s->error,"changed"));
    C(bw_source_connected(s));s->error=NULL;
    bw_source_snapshot_destroy(&snapshot);bw_source_map_destroy(&map);
}
static void neutral_cases(void){
    char folders[2048];snprintf(folders,sizeof folders,"%s/volume1/public/emulation/ps5/games/folders",base);
    struct local_context lc={0};snprintf(lc.root,sizeof lc.root,"%s",folders);
    struct bw_source local={.deadline=now()+60};bw_source_nfs_adopt(&local,(struct bw_transport){&local_ops,&lc});
    struct outcome a,b;neutral(&local,&a);
    nfs_fake_reset(base);struct bw_source s;nfs_source(&s,"emulation/ps5/games/folders");neutral(&s,&b);
    /* Same server objects through either transport: same listing and the same seal. */
    C(!strcmp(a.root.text,b.root.text));
    C(!memcmp(a.seal,b.seal,32)&&a.local==b.local&&a.stream==b.stream&&a.catalog==b.catalog);
    changed(&s,folders);changed(&local,folders);
    bw_source_release(&s);
}
int main(int argc,char **argv){
    C(argc==2);snprintf(base,sizeof base,"%s",argv[1]);
    connect_cases();
    image_cases();
    copy_cases();
    slow_cases();
    neutral_cases();
    printf("{\"nfs\":%u}\n",checks);
    return 0;
}
