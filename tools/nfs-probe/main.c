/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Blackwire NFS probe. Standalone PS5 homebrew payload, NOT built or linked
 * into Blackwire. It checks that the vendored libnfs works on the console
 * against one NFS server, and measures what the NFS transport design needs:
 * the local source port libnfs binds, the server read size, directory
 * attributes, and read throughput and latency for sync and pipelined reads.
 *
 * Read only. The context is set read-only, files are opened O_RDONLY, and the
 * probe issues only MOUNT, LOOKUP, GETATTR, READDIR(PLUS), OPEN and READ. It
 * never writes to the server. It opens no LAN listener. Symbolic links are
 * never followed: only entries whose READDIRPLUS attributes say "regular file"
 * are read, and only entries that say "directory" are walked.
 *
 * Output goes to /data/blackwire-nfs-probe.txt and stdout, line by line, so a
 * hang or crash still leaves the lines written so far. Exit status is nonzero
 * if any step failed.
 *
 * Defaults are compile-time only:
 *   -DNFS_PROBE_SERVER='"192.168.11.186"'
 *   -DNFS_PROBE_EXPORT='"/volume1/public"'
 *   -DNFS_PROBE_FOLDER='"emulation/ps5"'
 */
#include <nfsc/libnfs.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef NFS_PROBE_SERVER
#define NFS_PROBE_SERVER "192.168.11.186"
#endif
#ifndef NFS_PROBE_EXPORT
#define NFS_PROBE_EXPORT "/volume1/public"
#endif
#ifndef NFS_PROBE_FOLDER
#define NFS_PROBE_FOLDER "emulation/ps5"
#endif

#define OUT_PATH "/data/blackwire-nfs-probe.txt"
#define READ_BYTES (64ull * 1024ull * 1024ull)
#define LIST_CAP 200u
#define WALK_DEPTH 3
#define WALK_CAP 4000u
/* libnfs is built without clock_gettime on this target (its configure check
 * wants the Linux-only CLOCK_MONOTONIC_COARSE), so its RPC clock is time() and
 * timeouts have whole-second granularity. 10 s is still well inside a pass. */
#define RPC_TIMEOUT_MS 10000
/* Our own bound on one read pass, so a stuck event loop cannot hang forever. */
#define PASS_DEADLINE_S 300.0
#define MAX_DEPTH_IN_FLIGHT 8
#define PATH_CAP 1024
/* nfs_set_version() values. libnfs defines NFS_V3 and NFS_V4 only in the raw
 * protocol headers (nfs/libnfs-raw-nfs.h, nfs4/libnfs-raw-nfs4.h). */
#define PROBE_NFS_V3 3
#define PROBE_NFS_V4 4

static int g_out = -1;
static int g_failed;
static unsigned g_region;

/* One line to stdout and the report file. Lines are short; a longer one is
 * cut and marked so it is never mistaken for the whole value. */
static void emit(const char *fmt, ...) {
    char line[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) { g_failed = 1; return; }
    size_t len = (size_t)n < sizeof line ? (size_t)n : sizeof line - 1;
    if ((size_t)n >= sizeof line) {
        static const char cut[] = "...[line truncated]\n";
        len = sizeof line - sizeof cut;
        memcpy(line + len, cut, sizeof cut);
        len += sizeof cut - 1;
    }
    int fds[2] = {1, g_out};
    for (int i = 0; i < 2; i++) {
        if (fds[i] < 0) continue;
        const char *p = line;
        size_t left = len;
        while (left) {
            ssize_t w = write(fds[i], p, left);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) {
                /* Losing the file copy is a failure, but keep printing to stdout. */
                g_failed = 1;
                if (fds[i] == g_out) { close(g_out); g_out = -1; }
                break;
            }
            p += w; left -= (size_t)w;
        }
    }
}

#define FAIL(...) do { g_failed = 1; emit("ERROR: " __VA_ARGS__); } while (0)

static const char *nfs_err(struct nfs_context *nfs) {
    const char *e = nfs ? nfs_get_error(nfs) : NULL;
    return (e && *e) ? e : "(no libnfs error text)";
}

static double now_s(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1.0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Names come from the server; keep the report printable. */
static void printable(char *dst, size_t cap, const char *src) {
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++)
        dst[i] = ((unsigned char)src[i] >= 32 && (unsigned char)src[i] < 127) ? src[i] : '?';
    dst[i] = 0;
}

static const char *kind(uint32_t mode) {
    switch (mode & S_IFMT) {
    case S_IFREG: return "file";
    case S_IFDIR: return "dir";
    case S_IFLNK: return "link";
    case S_IFBLK: return "blk";
    case S_IFCHR: return "chr";
    case S_IFSOCK: return "sock";
    case S_IFIFO: return "fifo";
    default: return "?";
    }
}

struct stats { unsigned n; double min, max, sum; };

static void stats_add(struct stats *s, double v) {
    if (!s->n || v < s->min) s->min = v;
    if (!s->n || v > s->max) s->max = v;
    s->sum += v;
    s->n++;
}

static void report_pass(const char *label, uint64_t bytes, double secs, const struct stats *s) {
    double mib = (double)bytes / (1024.0 * 1024.0);
    emit("  %s: %.1f MiB in %.3f s = %.2f MiB/s; %u reads, latency ms min %.3f avg %.3f max %.3f\n",
         label, mib, secs, secs > 0 ? mib / secs : 0.0, s->n,
         s->n ? s->min * 1e3 : 0.0, s->n ? s->sum / s->n * 1e3 : 0.0, s->n ? s->max * 1e3 : 0.0);
}

/* libnfs 6.0 and later treat a failed keepalive option as a fatal connect
 * error, and on FreeBSD targets it looks up the TCP level with
 * getprotobyname("tcp"). Report each piece on a scratch socket, so a mount
 * failure below can be traced to the exact option. Informational only. */
static void probe_sockopts(void) {
    emit("\n[socket options] scratch TCP socket, not connected\n");
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { FAIL("socket(AF_INET, SOCK_STREAM): %s\n", strerror(errno)); return; }
    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one) != 0)
        emit("  SO_KEEPALIVE: failed: %s\n", strerror(errno));
    else
        emit("  SO_KEEPALIVE: ok\n");
    errno = 0;
    struct protoent *p = getprotobyname("tcp");
    if (p) emit("  getprotobyname(\"tcp\"): p_proto %d\n", p->p_proto);
    else emit("  getprotobyname(\"tcp\"): NULL (errno %d %s); libnfs set_tcp_sockopt() would fail\n",
              errno, strerror(errno));
    static const struct { int opt; int val; const char *name; } opts[] = {
        {TCP_KEEPIDLE, 60, "TCP_KEEPIDLE"},
        {TCP_KEEPINTVL, 60, "TCP_KEEPINTVL"},
        {TCP_KEEPCNT, 3, "TCP_KEEPCNT"},
    };
    for (unsigned i = 0; i < sizeof opts / sizeof opts[0]; i++) {
        int v = opts[i].val;
        if (setsockopt(s, IPPROTO_TCP, opts[i].opt, &v, sizeof v) != 0)
            emit("  %s=%d at IPPROTO_TCP: failed: %s\n", opts[i].name, v, strerror(errno));
        else
            emit("  %s=%d at IPPROTO_TCP: ok\n", opts[i].name, v);
    }
    if (close(s) != 0) FAIL("close(scratch socket): %s\n", strerror(errno));
}

static void report_endpoints(struct nfs_context *nfs) {
    int fd = nfs_get_fd(nfs);
    if (fd < 0) { FAIL("nfs_get_fd: %d\n", fd); return; }
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;
    char host[INET6_ADDRSTRLEN];
    const char *what[2] = {"local", "server"};
    for (int i = 0; i < 2; i++) {
        len = sizeof ss;
        memset(&ss, 0, sizeof ss);
        int rc = i ? getpeername(fd, (struct sockaddr *)&ss, &len) : getsockname(fd, (struct sockaddr *)&ss, &len);
        if (rc != 0) { FAIL("%s address of fd %d: %s\n", i ? "getpeername" : "getsockname", fd, strerror(errno)); continue; }
        unsigned port;
        const void *addr;
        if (ss.ss_family == AF_INET) {
            const struct sockaddr_in *a = (const struct sockaddr_in *)&ss;
            port = ntohs(a->sin_port); addr = &a->sin_addr;
        } else if (ss.ss_family == AF_INET6) {
            const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)&ss;
            port = ntohs(a->sin6_port); addr = &a->sin6_addr;
        } else {
            FAIL("%s address family %d not IPv4 or IPv6\n", what[i], ss.ss_family);
            continue;
        }
        if (!inet_ntop(ss.ss_family, addr, host, sizeof host)) snprintf(host, sizeof host, "?");
        if (i)
            emit("  server endpoint: %s port %u\n", host, port);
        else
            emit("  local source: %s port %u (%s)\n", host, port,
                 port < 1024 ? "reserved range, libnfs bind to 512-1023 worked" :
                               "ephemeral, libnfs reserved-port bind fell back");
    }
}

/* List the configured folder. Returns 0 and the alphabetically first
 * directory name in game[] (empty if none), or -1 on error. */
static int list_folder(struct nfs_context *nfs, const char *path, char *game, size_t cap) {
    struct nfsdir *dir = NULL;
    game[0] = 0;
    emit("  listing %s (cap %u entries)\n", path, LIST_CAP);
    int rc = nfs_opendir(nfs, path, &dir);
    if (rc < 0) { FAIL("nfs_opendir(%s): %d (%s): %s\n", path, rc, strerror(-rc), nfs_err(nfs)); return -1; }
    unsigned total = 0, shown = 0;
    struct nfsdirent *ent;
    char name[256];
    while ((ent = nfs_readdir(nfs, dir)) != NULL) {
        if (!strcmp(ent->name, ".") || !strcmp(ent->name, "..")) continue;
        total++;
        printable(name, sizeof name, ent->name);
        if (shown < LIST_CAP) {
            emit("    %-4s %14llu  %s\n", kind(ent->mode), (unsigned long long)ent->size, name);
            shown++;
        }
        if ((ent->mode & S_IFMT) == S_IFDIR && strlen(ent->name) < cap &&
            (!game[0] || strcmp(ent->name, game) < 0))
            memcpy(game, ent->name, strlen(ent->name) + 1);
    }
    nfs_closedir(nfs, dir);
    emit("  entries: %u, shown %u\n", total, shown);
    return 0;
}

struct pick { char path[PATH_CAP]; uint64_t size; unsigned visited; int capped; };

/* Bounded walk for the largest regular file. Depth 0 is the game folder. */
static void walk(struct nfs_context *nfs, const char *path, int depth, struct pick *p) {
    struct nfsdir *dir = NULL;
    int rc = nfs_opendir(nfs, path, &dir);
    if (rc < 0) { FAIL("nfs_opendir(%s): %d (%s): %s\n", path, rc, strerror(-rc), nfs_err(nfs)); return; }
    struct nfsdirent *ent;
    char child[PATH_CAP];
    while ((ent = nfs_readdir(nfs, dir)) != NULL) {
        if (!strcmp(ent->name, ".") || !strcmp(ent->name, "..")) continue;
        if (p->visited >= WALK_CAP) { p->capped = 1; break; }
        p->visited++;
        uint32_t type = ent->mode & S_IFMT;
        if (type != S_IFREG && type != S_IFDIR) continue;
        int n = snprintf(child, sizeof child, "%s/%s", path, ent->name);
        if (n < 0 || (size_t)n >= sizeof child) {
            char shown[128];
            printable(shown, sizeof shown, ent->name);
            emit("  skipped over-long path under %s: %s\n", path, shown);
            continue;
        }
        if (type == S_IFREG && ent->size > p->size) {
            memcpy(p->path, child, (size_t)n + 1);
            p->size = ent->size;
        } else if (type == S_IFDIR && depth < WALK_DEPTH) {
            walk(nfs, child, depth + 1, p);
        }
    }
    nfs_closedir(nfs, dir);
}

/* Each pass reads a fresh 64 MiB region where the file allows, so the server
 * page cache does not flatter later passes. */
static void next_region(uint64_t size, uint64_t *off, uint64_t *len, int *reused) {
    uint64_t regions = size / READ_BYTES;
    unsigned idx = g_region++;
    if (!regions) { *off = 0; *len = size; *reused = idx > 0; return; }
    *off = (idx % regions) * READ_BYTES;
    *len = READ_BYTES;
    *reused = idx >= regions;
}

static int read_sync(struct nfs_context *nfs, struct nfsfh *fh, char *buf, size_t readmax,
                     uint64_t off, uint64_t len) {
    struct stats st = {0};
    uint64_t done = 0;
    double t0 = now_s();
    while (done < len) {
        size_t n = (len - done) < readmax ? (size_t)(len - done) : readmax;
        double t = now_s();
        int rc = nfs_pread(nfs, fh, buf, n, off + done);
        double dt = now_s() - t;
        if (rc < 0) {
            FAIL("nfs_pread(offset %llu, %zu): %d (%s): %s\n", (unsigned long long)(off + done), n,
                 rc, strerror(-rc), nfs_err(nfs));
            return -1;
        }
        if (rc == 0) {
            FAIL("nfs_pread(offset %llu, %zu): end of file before the expected size\n",
                 (unsigned long long)(off + done), n);
            return -1;
        }
        stats_add(&st, dt);
        done += (uint64_t)rc;
    }
    report_pass("sync nfs_pread", done, now_s() - t0, &st);
    return 0;
}

struct async_pass;
struct slot { struct async_pass *pass; char *buf; uint64_t off; size_t len; double t; int busy; };
struct async_pass {
    struct nfs_context *nfs;
    struct nfsfh *fh;
    uint64_t base, len, issued, done;
    size_t readmax;
    unsigned inflight;
    int error;
    struct stats st;
    struct slot slots[MAX_DEPTH_IN_FLIGHT];
};

static void async_cb(int err, struct nfs_context *nfs, void *data, void *private_data) {
    struct slot *s = private_data;
    struct async_pass *a = s->pass;
    double dt = now_s() - s->t;
    (void)nfs;
    s->busy = 0;
    a->inflight--;
    if (err < 0) {
        if (!a->error)
            FAIL("nfs_pread_async(offset %llu, %zu): %d (%s): %s\n", (unsigned long long)s->off, s->len,
                 err, strerror(-err), data ? (const char *)data : "(no error text)");
        a->error = 1;
        return;
    }
    if ((size_t)err != s->len) {
        if (!a->error)
            FAIL("nfs_pread_async(offset %llu, %zu): short read of %d bytes\n",
                 (unsigned long long)s->off, s->len, err);
        a->error = 1;
        return;
    }
    stats_add(&a->st, dt);
    a->done += (uint64_t)err;
}

static int async_issue(struct async_pass *a, struct slot *s) {
    uint64_t left = a->len - a->issued;
    s->pass = a;
    s->off = a->base + a->issued;
    s->len = left < a->readmax ? (size_t)left : a->readmax;
    s->t = now_s();
    int rc = nfs_pread_async(a->nfs, a->fh, s->buf, s->len, s->off, async_cb, s);
    if (rc < 0) {
        FAIL("nfs_pread_async queue (offset %llu, %zu): %d: %s\n", (unsigned long long)s->off, s->len,
             rc, nfs_err(a->nfs));
        a->error = 1;
        return -1;
    }
    s->busy = 1;
    a->inflight++;
    a->issued += s->len;
    return 0;
}

/* Returns 0 on success, -1 on a read error with the connection still idle,
 * -2 if requests may still be outstanding (the caller must then destroy the
 * context before freeing any buffer). */
static int read_async(struct async_pass *a, unsigned depth) {
    char label[48];
    double t0 = now_s();
    while (!a->error && (a->issued < a->len || a->inflight)) {
        for (unsigned i = 0; i < depth && !a->error && a->issued < a->len; i++)
            if (!a->slots[i].busy) async_issue(a, &a->slots[i]);
        if (!a->inflight) break;
        struct pollfd pfd = {.fd = nfs_get_fd(a->nfs), .events = (short)nfs_which_events(a->nfs)};
        int r = poll(&pfd, 1, 100);
        if (r < 0 && errno != EINTR) { FAIL("poll: %s\n", strerror(errno)); a->error = 1; break; }
        /* revents 0 still lets libnfs scan for timed-out requests. */
        if (nfs_service(a->nfs, r > 0 ? pfd.revents : 0) < 0) {
            FAIL("nfs_service: %s\n", nfs_err(a->nfs));
            a->error = 1;
            break;
        }
        if (now_s() - t0 > PASS_DEADLINE_S) {
            FAIL("async pass exceeded %.0f s with %u reads in flight\n", PASS_DEADLINE_S, a->inflight);
            a->error = 1;
            break;
        }
    }
    double secs = now_s() - t0;
    if (a->error) {
        /* Drain so buffers are not in use, bounded by the RPC timeout. */
        double d0 = now_s();
        while (a->inflight && now_s() - d0 < RPC_TIMEOUT_MS / 1000.0 + 2.0) {
            struct pollfd pfd = {.fd = nfs_get_fd(a->nfs), .events = (short)nfs_which_events(a->nfs)};
            int r = poll(&pfd, 1, 100);
            if (r < 0 && errno != EINTR) break;
            if (nfs_service(a->nfs, r > 0 ? pfd.revents : 0) < 0) break;
        }
        if (a->inflight) emit("  %u reads still outstanding after the drain; context will be destroyed\n", a->inflight);
        return a->inflight ? -2 : -1;
    }
    snprintf(label, sizeof label, "async nfs_pread_async depth %u", depth);
    report_pass(label, a->done, secs, &a->st);
    return 0;
}

static void read_file(struct nfs_context *nfs, const char *path, uint64_t size, size_t readmax,
                      char *pool, int *poisoned) {
    struct nfsfh *fh = NULL;
    int rc = nfs_open(nfs, path, O_RDONLY, &fh);
    if (rc < 0) { FAIL("nfs_open(%s, O_RDONLY): %d (%s): %s\n", path, rc, strerror(-rc), nfs_err(nfs)); return; }
    uint64_t off, len;
    int reused;

    next_region(size, &off, &len, &reused);
    emit("  region offset %llu length %llu%s\n", (unsigned long long)off, (unsigned long long)len,
         reused ? " (region read before; server cache may be warm)" : "");
    read_sync(nfs, fh, pool, readmax, off, len);

    static const unsigned depths[] = {4, 8};
    for (unsigned d = 0; d < sizeof depths / sizeof depths[0]; d++) {
        static struct async_pass a;
        memset(&a, 0, sizeof a);
        a.nfs = nfs; a.fh = fh; a.readmax = readmax;
        for (unsigned i = 0; i < MAX_DEPTH_IN_FLIGHT; i++) a.slots[i].buf = pool + (size_t)i * readmax;
        next_region(size, &a.base, &a.len, &reused);
        emit("  region offset %llu length %llu%s\n", (unsigned long long)a.base, (unsigned long long)a.len,
             reused ? " (region read before; server cache may be warm)" : "");
        if (read_async(&a, depths[d]) == -2) {
            /* nfs_close would race the outstanding reads. */
            *poisoned = 1;
            return;
        }
    }
    rc = nfs_close(nfs, fh);
    if (rc < 0) FAIL("nfs_close(%s): %d: %s\n", path, rc, nfs_err(nfs));
}

static void run_version(int version) {
    emit("\n[NFS v%d] %s:%s\n", version, NFS_PROBE_SERVER, NFS_PROBE_EXPORT);
    struct nfs_context *nfs = nfs_init_context();
    if (!nfs) { FAIL("nfs_init_context returned NULL\n"); return; }
    char *pool = NULL;
    int poisoned = 0, mounted = 0;

    int rc = nfs_set_version(nfs, version);
    if (rc < 0) { FAIL("nfs_set_version(%d): %d: %s\n", version, rc, nfs_err(nfs)); goto out; }
    /* Defaults are a hard mount that retries forever; surface failures instead. */
    nfs_set_timeout(nfs, RPC_TIMEOUT_MS);
    nfs_set_retrans(nfs, 0);
    nfs_set_autoreconnect(nfs, 0);
    nfs_set_dircache(nfs, 0);
    nfs_set_readonly(nfs, 1);
    emit("  settings: timeout %d ms, retrans 0, autoreconnect 0, dircache off, readonly\n",
         nfs_get_timeout(nfs));

    double t = now_s();
    rc = nfs_mount(nfs, NFS_PROBE_SERVER, NFS_PROBE_EXPORT);
    double dt = now_s() - t;
    if (rc < 0) {
        FAIL("nfs_mount v%d after %.3f s: %d (%s): %s\n", version, dt, rc, strerror(-rc), nfs_err(nfs));
        goto out;
    }
    mounted = 1;
    emit("  nfs_mount: ok in %.3f s, nfs_get_version %d\n", dt, nfs_get_version(nfs));
    report_endpoints(nfs);
    size_t readmax = nfs_get_readmax(nfs);
    emit("  readmax: %zu bytes\n", readmax);
    if (!readmax) { FAIL("readmax is 0\n"); goto out; }

    char folder[PATH_CAP], game[256];
    snprintf(folder, sizeof folder, "/%s", NFS_PROBE_FOLDER);
    if (list_folder(nfs, folder, game, sizeof game) < 0) goto out;
    if (!game[0]) { FAIL("no directory under %s to use as a game folder\n", folder); goto out; }

    static struct pick p;
    memset(&p, 0, sizeof p);
    char root[PATH_CAP];
    int n = snprintf(root, sizeof root, "%s/%s", folder, game);
    if (n < 0 || (size_t)n >= sizeof root) { FAIL("game folder path too long\n"); goto out; }
    char shown[PATH_CAP];
    printable(shown, sizeof shown, root);
    emit("  game folder: %s (alphabetically first directory)\n", shown);
    walk(nfs, root, 0, &p);
    emit("  walk: %u entries visited, depth limit %d%s\n", p.visited, WALK_DEPTH,
         p.capped ? ", entry cap reached" : "");
    if (!p.path[0]) { FAIL("no regular file under %s\n", shown); goto out; }
    printable(shown, sizeof shown, p.path);
    emit("  largest file: %s, %llu bytes\n", shown, (unsigned long long)p.size);

    pool = malloc(readmax * MAX_DEPTH_IN_FLIGHT);
    if (!pool) { FAIL("malloc(%zu) for read buffers\n", readmax * MAX_DEPTH_IN_FLIGHT); goto out; }
    read_file(nfs, p.path, p.size, readmax, pool, &poisoned);

out:
    if (mounted && !poisoned && version == PROBE_NFS_V3) {
        rc = nfs_umount(nfs);
        if (rc < 0) FAIL("nfs_umount: %d: %s\n", rc, nfs_err(nfs));
    }
    /* Destroy before free: outstanding reads may still target the pool. */
    nfs_destroy_context(nfs);
    free(pool);
}

int main(void) {
    g_out = open(OUT_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (g_out < 0) {
        g_failed = 1;
        fprintf(stderr, "nfs-probe: open %s: %s; stdout only\n", OUT_PATH, strerror(errno));
    }
    emit("Blackwire NFS probe\n");
    emit("read-only; no server writes; no LAN listener\n");
    emit("server %s export %s folder %s\n", NFS_PROBE_SERVER, NFS_PROBE_EXPORT, NFS_PROBE_FOLDER);
    emit("read size per pass %llu bytes, rpc timeout %d ms, pid %d uid %d gid %d\n",
         (unsigned long long)READ_BYTES, RPC_TIMEOUT_MS, (int)getpid(), (int)getuid(), (int)getgid());
    if (now_s() < 0) FAIL("clock_gettime(CLOCK_MONOTONIC): %s; timings invalid\n", strerror(errno));

    probe_sockopts();
    run_version(PROBE_NFS_V3);
    run_version(PROBE_NFS_V4);

    emit("\nresult: %s\n", g_failed ? "FAIL" : "PASS");
    if (g_out >= 0 && close(g_out) != 0) {
        fprintf(stderr, "nfs-probe: close %s: %s\n", OUT_PATH, strerror(errno));
        g_failed = 1;
    }
    return g_failed ? 1 : 0;
}
