/* DRAFT. Design only, not compiled. Resident side (catalog, preparation,
 * admission). Reader-side transport is designed elsewhere.
 *
 * Two layers, on purpose:
 *  1. bw_transport_ops: synchronous file primitives (stat/open/fstat/pread/
 *     close/list). Replaces direct smb2_stat/smb2_open/smb2_pread/... in
 *     container_smb.c, prepare_copy.c, filemap.c remote ops, reader_source.c.
 *  2. bw_source_ops: the existing bw_source_smb_* API (scan, snapshot, read,
 *     read_range, list, file_info, small_file). SMB impl = today's
 *     source_smb.c unchanged. NFS impl = new source_nfs.c on layer 1.
 *
 * Every wait inside an implementation runs its own poll loop and calls the
 * installed bw_tp_guard between services. That is how source_smb.c works
 * today (one PDU in flight, poll 250 ms, deadline + job check). No fd/service
 * hooks leak to callers.
 */
#ifndef BW_TRANSPORT_H
#define BW_TRANSPORT_H
#include <stddef.h>
#include <stdint.h>
#include "source_directory.h" /* struct bw_source_info, bw_source_visit_fn */

enum bw_tp_kind { BW_TP_SMB = 1, BW_TP_NFS = 2 };

/* Numeric values for FILE/DIRECTORY/LINK equal SMB2_TYPE_FILE/DIRECTORY/LINK
 * (libsmb2.h:73-75). They are hashed as uint64 by the image generation
 * seals, so SMB bytes stay identical. SPECIAL = device/fifo/socket (NFS only). */
enum bw_tp_type { BW_TP_FILE = 0, BW_TP_DIRECTORY = 1, BW_TP_LINK = 2, BW_TP_SPECIAL = 3 };

/* Replaces struct smb2_stat_64 in every resident identity check:
 * source_catalog.c:35-46, source_identity.c:9-18, reader_preflight.c:13-18,
 * container_smb.c:50-55, prepare_copy.c:467-470, compressed_stream.c:13-18.
 *
 * Precision rules (fields are compared exactly, never rounded):
 *  SMB: libsmb2 converts FILETIME to timeval. *_nsec = usec * 1000, always a
 *       multiple of 1000 (libsmb2.c:334, :1864). Copied verbatim from
 *       smb2_stat_64, so hashes over (type,ino,size,mtime,mtime_nsec,ctime,
 *       ctime_nsec) are byte-identical to today.
 *  NFS: nfstime3/nfstime4 seconds + nseconds verbatim (full ns, server
 *       granularity may be 1 s or 1 ns). ino = fileid (v3 fileid3, v4
 *       fileid attr). ctime = change time (v3 ctime, v4 time_metadata).
 * listed_vs_stat compare (catalog listed_time, source_smb bs_expected):
 *  SMB: 1 us quantum (directory rows carry 100 ns ticks, QUERY_INFO usec).
 *  NFS: 100 ns quantum (both sides derived from the same ns value). */
struct bw_stat {
    uint32_t type;          /* enum bw_tp_type */
    uint32_t reserved;      /* zero; not hashed */
    uint64_t ino, size;
    uint64_t mtime, mtime_nsec;
    uint64_t ctime, ctime_nsec;
};
int bw_stat_same_file(const struct bw_stat *, const struct bw_stat *);
/* Ticks/quantum helper so the catalog and source walker stop hard coding /10. */
uint32_t bw_tp_listing_quantum_ticks(enum bw_tp_kind); /* SMB 10, NFS 1 */

/* bw_source_info (source_directory.h) stays the listing/snapshot record.
 * SMB: raw Windows attributes + FILETIME ticks (hashed in BWSRC001).
 * NFS: synthesized, deterministic:
 *   attributes = DIR 0x10 | LINK 0x400 | SPECIAL 0x40 | FILE 0x80,
 *   ticks = 116444736000000000 + sec*10^7 + nsec/100, inode = fileid.
 * Mode bits, uid, gid and nlink are NOT folded into attributes. */

/* Neutral error classes. Replaces NT status checks at source_smb.c:337-346
 * and native_backend.c:772-775. raw keeps the native code for diagnostics. */
enum bw_tp_error {
    BW_TP_OK = 0,
    BW_TP_MISSING,          /* NT 0xc0000034, 0xc000003a | NFS3ERR_NOENT, ENOENT */
    BW_TP_DENIED,           /* NT 0xc0000022 | NFS3ERR_ACCES, NFS3ERR_PERM */
    BW_TP_UNAVAILABLE,      /* NT 0xc0000043, 0xc0000103, 0xc00000ba | NFS3ERR_NOTDIR, ISDIR */
    BW_TP_CHANGED,          /* NFS3ERR_STALE / ESTALE: handle no longer names the admitted object */
    BW_TP_LINKED_OR_SPECIAL,/* reparse/device attr | NF3LNK, NF3BLK/CHR/SOCK/FIFO */
    BW_TP_TOO_LARGE,
    BW_TP_ROOT_MISSING,     /* NT 0xc00000cc bad share | MNT3ERR_NOENT, NFS4ERR_NOENT on export */
    BW_TP_AUTH,             /* NT 0xc000006d/6a/64 | MNT3ERR_ACCES, RPC AUTH_ERROR, export host ACL */
    BW_TP_TIMEOUT,          /* deadline; libnfs reports RPC timeout as -EINTR, not -ETIMEDOUT */
    BW_TP_CANCELED,         /* guard said not current */
    BW_TP_PROTOCOL,         /* reply bounds/fields invalid */
    BW_TP_TRANSPORT         /* anything else; connection is poisoned */
};
struct bw_tp_status {
    enum bw_tp_error error;
    uint32_t raw;           /* NT status (SMB) or nfsstat3/nfsstat4/mountstat3 (NFS) */
    int result;             /* negative errno from the library call, 0 if none */
    unsigned result_known;
};
const char *bw_tp_error_name(enum bw_tp_error);

/* Installed per operation. Called between every poll/service step. Nonzero
 * = stop: the implementation drains or destroys the context and returns
 * BW_TP_CANCELED or BW_TP_TIMEOUT. Must not reenter the transport. */
struct bw_tp_guard {
    double deadline;                 /* monotonic seconds */
    int (*current)(void *job);       /* may be NULL */
    void *job;
};

struct bw_transport;   /* opaque; owns smb2_context or nfs_context */
struct bw_tp_file;     /* opaque; smb2fh / held SMB file id, or nfsfh */

enum {
    BW_TP_OPEN_FILE      = 1u << 0, /* SMB FILE_NON_DIRECTORY_FILE | NFS regular only */
    BW_TP_OPEN_DIRECTORY = 1u << 1, /* SMB FILE_DIRECTORY_FILE      | NFS dir fh     */
    BW_TP_OPEN_NOFOLLOW  = 1u << 2  /* SMB FILE_OPEN_REPARSE_POINT  | NFS lookup w/o symlink follow */
};

typedef int (*bw_tp_dirent_fn)(void *, const char *name, const struct bw_source_info *);

struct bw_transport_ops {
    enum bw_tp_kind kind;
    /* Path is root-relative ("" = share/export root), '/' separated, already
     * validated by bw_manifest_validate_path. Never follows links. */
    int (*stat)(struct bw_transport *, const char *, struct bw_stat *);
    int (*open)(struct bw_transport *, const char *, unsigned flags, struct bw_tp_file **);
    int (*fstat)(struct bw_transport *, struct bw_tp_file *, struct bw_stat *);
    /* Same as fstat but in listing form (ticks + attributes) for held-parent checks. */
    int (*finfo)(struct bw_transport *, struct bw_tp_file *, struct bw_source_info *);
    /* Returns bytes read (>0), 0 at EOF, <0 on failure. size <= max_read. */
    int (*pread)(struct bw_transport *, struct bw_tp_file *, void *, uint32_t size, uint64_t offset);
    int (*close)(struct bw_transport *, struct bw_tp_file *);
    /* Whole directory, bounded (BW_SOURCE_NAME_BYTES, 262144 entries).
     * SMB: QUERY_DIRECTORY 64 KiB pages + bw_source_directory_page.
     * NFS: READDIRPLUS (v3) / READDIR with attrs (v4), cookie paged.
     * "." and ".." are filtered by the caller as today. */
    int (*list)(struct bw_transport *, struct bw_tp_file *dir, bw_tp_dirent_fn, void *);
    uint32_t (*max_read)(struct bw_transport *);
    void (*set_guard)(struct bw_transport *, const struct bw_tp_guard *);
    const struct bw_tp_status *(*last_status)(const struct bw_transport *);
    void (*destroy)(struct bw_transport *);
};

struct bw_transport {
    const struct bw_transport_ops *ops;
    void *impl;
};

/* Connect factory. Replaces the resident connect sites:
 *   native_backend.c:263-265 (prepare), native_backend.c:799-801 (discover),
 *   native_backend_home.h:69-74, native_launch_admission.c:393-398,
 *   prepare_copy.c:645-646.
 * Reader sites (native-reader.c:870-874, preload/source.c:439-446) belong
 * to the reader-boundary design.
 * Profiles reproduce today's per-site SMB options exactly. Tests assert them
 * (test_source_connect_wrapper.c:22 expects REQUIRED only). */
enum bw_tp_profile {
    BW_TP_PROFILE_SCAN,      /* timeout 10, sign 1, ENABLED|REQUIRED       */
    BW_TP_PROFILE_ADMISSION  /* caller timeout, sign 1, REQUIRED only       */
};
struct bw_share_config;
/* Reads cfg->transport. Clears no credentials (caller keeps current
 * bw_share_clear placement). On failure *out stays NULL and status is set. */
int bw_transport_connect(const struct bw_share_config *cfg, enum bw_tp_profile,
                         int timeout_seconds, struct bw_transport **out,
                         struct bw_tp_status *status);

/* Owned-transport contract, generalised from container_smb.h:47-51 and
 * source_smb.h:39-41: a timeout or transport failure destroys the context and
 * sets *owner = NULL before any caller stack buffer leaves scope. */
void bw_transport_poison(struct bw_transport **owner, enum bw_tp_error);

/* Layer 2: today's bw_source_smb_* surface behind a table. */
struct bw_source;              /* renamed bw_source_smb; holds struct bw_transport * */
struct bw_source_map;
struct bw_source_snapshot;
enum bw_source_plan_policy;
typedef int (*bw_source_consume_fn)(void *, const void *, size_t);
typedef int (*bw_source_range_current_fn)(void *);
struct bw_source_ops {
    int (*snapshot_bound_policy)(struct bw_source *, const char *source, const char *game,
                                 struct bw_source_map *, struct bw_source_snapshot *,
                                 enum bw_source_plan_policy);
    int (*read)(struct bw_source *, const struct bw_source_snapshot *, const char *,
                bw_source_consume_fn, void *);
    int (*read_range)(struct bw_source *, const struct bw_source_snapshot *, const char *,
                      uint64_t, uint64_t, bw_source_range_current_fn, void *,
                      bw_source_consume_fn, void *);
    int (*list)(struct bw_source *, const char *, bw_source_visit_fn, void *);
    int (*file_info)(struct bw_source *, const char *, struct bw_source_info *);
    int (*small_file)(struct bw_source *, const char *, size_t, void **, size_t *,
                      struct bw_source_info *);
};

/* Identity. SMB path is byte-identical to source_binding.c:17 (BWBIND01 +
 * len32le server, share, source, title). NFS gets its own domain:
 *   "BWBIND02" + len32le each of "nfs", server, export, source, title
 * nfs_version, uid and gid are connection options, not source identity:
 * excluded, so a v3 to v4 switch keeps installs bound (same server, same files).
 * game = PPSAnnnnn_<hex>; different prefix => no collision with SMB rows. */
int bw_source_binding_init_transport(void *binding_out, const struct bw_share_config *,
                                     const char *source, const char *title);
#endif
