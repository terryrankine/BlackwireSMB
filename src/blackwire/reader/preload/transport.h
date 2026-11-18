/* SPDX-License-Identifier: GPL-3.0-or-later
 * Private reader transport seam. One table per protocol, chosen at admission
 * from the handoff. Opaque tags keep call sites typed without spreading a
 * library's types. Metadata stays smb2_stat_64 until the reader adopts
 * bw_stat: every implementation fills type, ino, size, mtime(+nsec) and
 * ctime(+nsec), the fields identity checks and image seals read.
 * Async completions always land in bp_transport_metadata_done. */
#ifndef BW_PRELOAD_TRANSPORT_H
#define BW_PRELOAD_TRANSPORT_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include "../../streamreader/share_config.h"
struct bp_transport;struct bp_file;
struct bp_transport_ops {
    struct bp_transport *(*init)(void);
    void (*configure)(struct bp_transport *,const struct bw_share_config *,unsigned *returned);
    int (*connect)(struct bp_transport *,const struct bw_share_config *);
    /* SMB: last NT status. NFS: enum bw_tp_error class of the last failure. */
    uint32_t (*status)(struct bp_transport *);
    void (*destroy)(struct bp_transport *);
    int (*stat)(struct bp_transport *,const char *,struct smb2_stat_64 *);
    int (*fstat)(struct bp_transport *,struct bp_file *,struct smb2_stat_64 *);
    struct bp_file *(*open)(struct bp_transport *,const char *);
    int (*close)(struct bp_transport *,struct bp_file *);
    int (*stat_async)(struct bp_transport *,const char *,struct smb2_stat_64 *,void *);
    int (*fstat_async)(struct bp_transport *,struct bp_file *,struct smb2_stat_64 *,void *);
    int (*fd)(struct bp_transport *);
    int (*events)(struct bp_transport *);
    int (*service)(struct bp_transport *,int);
    int (*pread)(struct bp_transport *,struct bp_file *,uint8_t *,uint32_t,uint64_t);
    uint32_t (*max_read)(struct bp_transport *);
};
/* Defined by source.c. Records one async metadata result, never reenters. */
void bp_transport_metadata_done(void *opaque,int status);
#endif
