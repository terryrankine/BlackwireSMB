#ifndef BW_SOURCE_H
#define BW_SOURCE_H
#include "source_plan.h"
#include "source_snapshot.h"
#include "../streamreader/bw_transport.h"
struct smb2_context;
struct bw_container_smb;
enum bw_source_phase {
    BW_SOURCE_IDLE=0,BW_SOURCE_SCANNING,BW_SOURCE_METADATA,BW_SOURCE_HASHING,
    BW_SOURCE_RECHECKING,BW_SOURCE_VERIFIED,BW_SOURCE_PREFLIGHT,BW_SOURCE_COPYING,
    BW_SOURCE_SPARSE,BW_SOURCE_INDEXING,BW_SOURCE_INDEX_VERIFY,BW_SOURCE_MEASURING,
    BW_SOURCE_PREPARED,BW_SOURCE_ERROR,BW_SOURCE_PHASE_COUNT
};
/* Numeric progress only: no source paths, credentials, SDK objects or borrowed
 * asset buffers. Totals are zero while unknown. File/byte counters describe
 * this phase; request/entry/read counters cover the whole owned operation. */
struct bw_source_progress {
    enum bw_source_phase phase;
    uint32_t files_done,files_total,requests,entries,pages,phase_entries;
    uint64_t bytes_done,bytes_total,source_bytes;
    double monotonic_seconds;
};
typedef void (*bw_source_observer_fn)(void *,const struct bw_source_progress *);
typedef int (*bw_source_consume_fn)(void *,const void *,size_t);
/* Required, nonreentrant native job/cancellation guard: zero means current.
 * It must not call provider_current, reenter the transport or mutate the
 * borrowed snapshot. Callbacks are synchronous; deadline checks cannot preempt
 * a blocking callback. */
typedef int (*bw_source_range_current_fn)(void *);
struct bw_source;
/* One source transport. A NULL table in struct bw_source means SMB, so every
 * existing zero-initialised SMB source keeps its exact behaviour. */
struct bw_source_ops {
    int (*snapshot_bound_policy)(struct bw_source *,const char *source,const char *game,
        struct bw_source_map *,struct bw_source_snapshot *,enum bw_source_plan_policy);
    int (*read)(struct bw_source *,const struct bw_source_snapshot *,const char *,bw_source_consume_fn,void *);
    int (*read_range)(struct bw_source *,const struct bw_source_snapshot *,const char *,uint64_t,uint64_t,
        bw_source_range_current_fn,void *,bw_source_consume_fn,void *);
    int (*list)(struct bw_source *,const char *,bw_source_visit_fn,void *);
    int (*file_info)(struct bw_source *,const char *,struct bw_source_info *);
    int (*small_file)(struct bw_source *,const char *,size_t,void **,size_t *,struct bw_source_info *);
    /* Opens a compressed image with the owned metadata window, under the
     * same owned-transport contract as bw_container_smb_open_owned_metadata. */
    int (*open_image)(struct bw_source *,struct bw_container_smb *,const char *);
};
struct bw_source {
    /* SMB: the owned libsmb2 connection. NULL for other transports. */
    struct smb2_context *smb;
    double deadline;
    const char *error;
    uint32_t last_status;
    uint32_t requests,pages,directories,entries,peak_held_pages;
    uint64_t metadata_bytes;
    uint64_t content_bytes;
    bw_source_observer_fn observe;
    void *observe_opaque;
    struct bw_source_progress progress;
    uint32_t phase_entry_base;
    /* Non-SMB sources: the table and the owned connection. A failure that
     * poisons the connection sets transport.context to NULL. */
    const struct bw_source_ops *ops;
    struct bw_transport transport;
    /* Native result of the last failed transport call, for diagnostics. */
    int last_result;
};
/* The old name, kept for the in-game reader, which this change does not touch. */
#define bw_source_smb bw_source
/* True while the source still owns a live connection of either kind. */
static inline int bw_source_connected(const struct bw_source *p){return p&&(p->ops?p->transport.context!=NULL:p->smb!=NULL);}

#define BW_SOURCE_RANGE_LIMIT (16u*1024u*1024u)
#define BW_SOURCE_RANGE_MAX_READ_CALLS 4096u
enum bw_source_lookup {BW_SOURCE_FOUND=0,BW_SOURCE_MISSING=1,BW_SOURCE_UNAVAILABLE=2,BW_SOURCE_TOO_LARGE=3};
#define BW_SOURCE_SMALL_FILE_LIMIT (4u*1024u*1024u)

const char *bw_source_phase_name(enum bw_source_phase);
void bw_source_smb_progress(struct bw_source *,enum bw_source_phase,uint32_t,uint32_t,uint64_t,uint64_t);
/* SMB implementation (source_smb.c). Callers use the bw_source_* names below. */
int bw_source_smb_plan(struct bw_source *,const char *game,struct bw_source_map *);
int bw_source_smb_snapshot(struct bw_source *,const char *game,struct bw_source_map *,struct bw_source_snapshot *);
int bw_source_smb_snapshot_bound(struct bw_source *,const char *source,const char *game,struct bw_source_map *,struct bw_source_snapshot *);
int bw_source_smb_snapshot_bound_policy(struct bw_source *,const char *source,const char *game,
    struct bw_source_map *,struct bw_source_snapshot *,enum bw_source_plan_policy);
int bw_source_smb_read(struct bw_source *,const struct bw_source_snapshot *,const char *path,bw_source_consume_fn,void *);
int bw_source_smb_read_range(struct bw_source *,const struct bw_source_snapshot *,const char *,
    uint64_t offset,uint64_t length,bw_source_range_current_fn,void *job,bw_source_consume_fn,void *consumer);
int bw_source_smb_list(struct bw_source *,const char *,bw_source_visit_fn,void *);
int bw_source_smb_file_info(struct bw_source *,const char *,struct bw_source_info *);
int bw_source_smb_small_file(struct bw_source *,const char *,size_t,void **,size_t *,struct bw_source_info *);

/* Transport-neutral entry points. Contracts are those in source_smb.h. The
 * legacy unbound plan and snapshot forms exist for SMB only. */
static inline int bw_source_snapshot_bound_policy(struct bw_source *p,const char *source,const char *game,
    struct bw_source_map *map,struct bw_source_snapshot *snapshot,enum bw_source_plan_policy policy){
    return p&&p->ops?p->ops->snapshot_bound_policy(p,source,game,map,snapshot,policy):bw_source_smb_snapshot_bound_policy(p,source,game,map,snapshot,policy);
}
static inline int bw_source_snapshot_bound(struct bw_source *p,const char *source,const char *game,
    struct bw_source_map *map,struct bw_source_snapshot *snapshot){
    return p&&p->ops?p->ops->snapshot_bound_policy(p,source,game,map,snapshot,BW_SOURCE_PLAN_LEGACY):bw_source_smb_snapshot_bound(p,source,game,map,snapshot);
}
static inline int bw_source_read(struct bw_source *p,const struct bw_source_snapshot *s,const char *path,bw_source_consume_fn consume,void *opaque){
    return p&&p->ops?p->ops->read(p,s,path,consume,opaque):bw_source_smb_read(p,s,path,consume,opaque);
}
static inline int bw_source_read_range(struct bw_source *p,const struct bw_source_snapshot *s,const char *path,uint64_t offset,uint64_t length,
    bw_source_range_current_fn current,void *job,bw_source_consume_fn consume,void *consumer){
    return p&&p->ops?p->ops->read_range(p,s,path,offset,length,current,job,consume,consumer):
        bw_source_smb_read_range(p,s,path,offset,length,current,job,consume,consumer);
}
static inline int bw_source_list(struct bw_source *p,const char *path,bw_source_visit_fn visit,void *opaque){
    return p&&p->ops?p->ops->list(p,path,visit,opaque):bw_source_smb_list(p,path,visit,opaque);
}
static inline int bw_source_file_info(struct bw_source *p,const char *path,struct bw_source_info *info){
    return p&&p->ops?p->ops->file_info(p,path,info):bw_source_smb_file_info(p,path,info);
}
int bw_container_smb_open_owned_metadata(struct bw_container_smb *,struct smb2_context **,const char *);
static inline int bw_source_open_image(struct bw_source *p,struct bw_container_smb *image,const char *path){
    return p&&p->ops?p->ops->open_image(p,image,path):bw_container_smb_open_owned_metadata(image,p?&p->smb:NULL,path);
}
static inline int bw_source_small_file(struct bw_source *p,const char *path,size_t maximum,void **bytes,size_t *size,struct bw_source_info *info){
    return p&&p->ops?p->ops->small_file(p,path,maximum,bytes,size,info):bw_source_smb_small_file(p,path,maximum,bytes,size,info);
}
#endif
