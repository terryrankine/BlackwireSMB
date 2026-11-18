#ifndef BW_TP_ERROR_H
#define BW_TP_ERROR_H
#include <errno.h>
#include <stdint.h>
/* Transport-neutral failure classes. The resident and the in-game reader both
 * include this header, so it stays header-only with no library dependency.
 * Callers branch on the class. The native code (NT status or NFS errno) is kept
 * beside it for diagnostics only. */
enum bw_tp_error {
    BW_TP_OK=0,
    BW_TP_MISSING,           /* NT 0xc0000034, 0xc000003a | NFS ENOENT */
    BW_TP_DENIED,            /* NT 0xc0000022 | NFS EACCES, EPERM */
    BW_TP_UNAVAILABLE,       /* NT 0xc0000043, 0xc0000103, 0xc00000ba | NFS ENOTDIR, EISDIR */
    BW_TP_CHANGED,           /* NFS ESTALE: the handle no longer names the admitted object */
    BW_TP_LINKED_OR_SPECIAL, /* reparse or device attribute | NFS ELOOP, link or special type */
    BW_TP_TOO_LARGE,         /* NFS EFBIG */
    BW_TP_ROOT_MISSING,      /* NT 0xc00000cc bad share | NFS mount ENOENT */
    BW_TP_AUTH,              /* NT 0xc000006d, 0xc000006a, 0xc0000064 | NFS mount EACCES, EPERM */
    BW_TP_TIMEOUT,           /* deadline. libnfs reports an RPC timeout as -EINTR */
    BW_TP_CANCELED,          /* the job guard said not current */
    BW_TP_PROTOCOL,          /* reply bounds or fields invalid */
    BW_TP_TRANSPORT,         /* anything else. The connection is poisoned */
    BW_TP_ERROR_COUNT
};
struct bw_tp_status {
    enum bw_tp_error error;
    uint32_t raw;            /* NT status (SMB). Zero for NFS */
    int result;              /* negative errno from the library call, 0 if none */
    unsigned result_known;
};
static inline const char *bw_tp_error_name(enum bw_tp_error error){
    static const char *const names[BW_TP_ERROR_COUNT]={"ok","missing","denied","unavailable","changed",
        "linked_or_special","too_large","root_missing","auth","timeout","canceled","protocol","transport"};
    return (unsigned)error<BW_TP_ERROR_COUNT?names[error]:"unknown";
}
/* Exactly the NT codes the resident already treated as expected per-item
 * absence, refusal or sign-in failure. Every other nonzero code is TRANSPORT,
 * so no SMB failure changes class. */
static inline enum bw_tp_error bw_tp_error_from_nt(uint32_t status){
    switch(status){
    case 0:return BW_TP_OK;
    case UINT32_C(0xc0000034):case UINT32_C(0xc000003a):return BW_TP_MISSING;
    case UINT32_C(0xc0000022):return BW_TP_DENIED;
    case UINT32_C(0xc0000043):case UINT32_C(0xc0000103):case UINT32_C(0xc00000ba):return BW_TP_UNAVAILABLE;
    case UINT32_C(0xc00000cc):return BW_TP_ROOT_MISSING;
    case UINT32_C(0xc000006d):case UINT32_C(0xc000006a):case UINT32_C(0xc0000064):return BW_TP_AUTH;
    default:return BW_TP_TRANSPORT;
    }
}
/* libnfs sync calls return -errno. A refusal while mounting means the export
 * or this console is not allowed, not one file, so it gets its own class. */
static inline enum bw_tp_error bw_tp_error_from_nfs(int result,int mounting){
    if(result>=0)return BW_TP_OK;
    switch(-result){
    case ENOENT:return mounting?BW_TP_ROOT_MISSING:BW_TP_MISSING;
    case EACCES:case EPERM:return mounting?BW_TP_AUTH:BW_TP_DENIED;
    case ENOTDIR:case EISDIR:return BW_TP_UNAVAILABLE;
    case ESTALE:return BW_TP_CHANGED;
    case ELOOP:return BW_TP_LINKED_OR_SPECIAL;
    case EFBIG:return BW_TP_TOO_LARGE;
    case EINTR:case ETIMEDOUT:return BW_TP_TIMEOUT;
    default:return BW_TP_TRANSPORT;
    }
}
#endif
