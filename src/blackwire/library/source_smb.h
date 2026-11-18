#ifndef BW_SOURCE_SMB_H
#define BW_SOURCE_SMB_H
/* SMB implementation of struct bw_source. The struct, progress types and the
 * transport-neutral entry points are in source.h. */
#include "source.h"
/* Optional synchronous observer, called on the worker outside SDK callbacks.
 * It must only copy/coalesce progress; do not reenter the connection, change
 * the operation or retain the snapshot pointer. Installing it grants no write
 * or cancellation capability. It may feed a separately synchronized UI cache. */
const char *bw_source_phase_name(enum bw_source_phase);
void bw_source_smb_progress(struct bw_source *,enum bw_source_phase,uint32_t,uint32_t,uint64_t,uint64_t);
/* The caller owns a connected context, grants this scan exclusive use of it,
 * and sets a monotonic deadline. A timeout/transport failure destroys that
 * context and sets smb=NULL before stack callbacks can leave scope. */
int bw_source_smb_plan(struct bw_source *,const char *game,struct bw_source_map *);
int bw_source_smb_snapshot(struct bw_source *,const char *game,struct bw_source_map *,struct bw_source_snapshot *);
/* Full share-relative source -> independent safe console game component.
 * Holds each collection parent; both paths and parent generations are bound
 * into the sealed snapshot. This does not register or launch a title. */
int bw_source_smb_snapshot_bound(struct bw_source *,const char *source,const char *game,struct bw_source_map *,struct bw_source_snapshot *);
int bw_source_smb_snapshot_bound_policy(struct bw_source *,const char *source,const char *game,
    struct bw_source_map *,struct bw_source_snapshot *,enum bw_source_plan_policy);
/* Whole existing file, opened read-only with reparse points rejected. Holds and
 * verifies each parent. Expected metadata must come from a sealed snapshot.
 * The consumer is synchronous and borrows at most 64 KiB per call. No callback
 * is invoked until the held file matches that snapshot. */
int bw_source_smb_read(struct bw_source *,const struct bw_source_snapshot *,const char *path,bw_source_consume_fn,void *);

/* Exact protocol-sized uint64 range of an existing regular file in an owned,
 * collection-bound native snapshot. Zero length is checked (including EOF and
 * empty files); positive chunks are <=64 KiB. At most 16 MiB per call, with no
 * signed narrowing. Whole-file API semantics above are unchanged.
 * Consumer data is provisional until zero success; discard all data on -1.
 * All callbacks (current, consumer and any prior observer) must avoid source,
 * SDK and provider reentry and must not mutate source/snapshot/provider state. This API
 * does not secure hostile in-process callbacks or arbitrary invalid pointers.
 * This checks held file/parents, not siblings or the whole provider generation.
 * A future policy owner must check whole-source/job authority and cumulative
 * budgets before publication. A checksum or HOST witness is never a capability. */
int bw_source_smb_read_range(struct bw_source *,const struct bw_source_snapshot *,const char *,
    uint64_t offset,uint64_t length,bw_source_range_current_fn,void *job,bw_source_consume_fn,void *consumer);
/* Catalog-only operations. They do not grant a preparation capability or scan
 * asset trees. A missing/denied/linked item returns a positive result without
 * poisoning the connection; transport/protocol/timeout failures return -1.
 * Paths are safe share-relative UTF-8; only list() accepts the empty share root.
 * list callbacks run outside SDK callbacks and may synchronously use lookup.
 * Buffers returned by small_file() are owned by the caller and must be freed. */
int bw_source_smb_list(struct bw_source *,const char *,bw_source_visit_fn,void *);
int bw_source_smb_file_info(struct bw_source *,const char *,struct bw_source_info *);
int bw_source_smb_small_file(struct bw_source *,const char *,size_t,void **,size_t *,struct bw_source_info *);
#endif
