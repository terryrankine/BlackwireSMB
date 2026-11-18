/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Blackwire firmware/profile probe. Standalone PS5 homebrew payload, NOT built
 * or linked into Blackwire. It measures the values a new firmware row in the
 * supported-profile table (src/blackwire/streamreader/diagnostics) would need,
 * so a 12.40 (or other) console can be characterised without guessing.
 *
 * Read only. It performs the same read-only KERN_PROC sysctl query the existing
 * gates use (native_session_ps5.c, startup_runtime_idle_ps5.c) and reads the
 * firmware word. It never writes kernel memory, never ptraces, never mutates a
 * process. Output goes to /data/blackwire-fw-probe.txt and, optionally, to a
 * one-shot TCP listener.
 *
 * Usage: fw-probe-fw.elf [target_pid] [tcp_port]
 *   target_pid  extra PID to dump besides this payload's own PID (default none)
 *   tcp_port    if given, also serve the report once over TCP on that port
 */
#include <ps5/kernel.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OUT_PATH "/data/blackwire-fw-probe.txt"
#define SNAP_LIMIT (16u * 1024u * 1024u)

/* The byte offsets the lifecycle gates read from each kinfo_proc record. Kept
 * here only to annotate the hexdump; the probe never relies on them being right
 * for an unmeasured firmware, which is the whole point of measuring. */
static const struct { unsigned off; unsigned len; const char *name; } fields[] = {
    {0,   4,  "ki_structsize (record size prefix)"},
    {72,  4,  "ki_pid"},
    {264, 8,  "ki_rssize"},
    {336, 8,  "ki_start.tv_sec"},
    {344, 8,  "ki_start.tv_usec"},
    {447, 20, "ki_comm"},
};

/* Growable text buffer so the same report reaches the file and the socket. */
static char *g_buf;
static size_t g_len, g_cap;
static void emit(const char *fmt, ...) {
    for (;;) {
        va_list ap; va_start(ap, fmt);
        int n = vsnprintf(g_buf + g_len, g_cap - g_len, fmt, ap);
        va_end(ap);
        if (n < 0) return;
        if ((size_t)n < g_cap - g_len) { g_len += (size_t)n; return; }
        size_t want = g_cap ? g_cap * 2 : 4096;
        while (want - g_len <= (size_t)n) want *= 2;
        char *grown = realloc(g_buf, want);
        if (!grown) return;
        g_buf = grown; g_cap = want;
    }
}

static uint32_t le32(const unsigned char *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t le64(const unsigned char *p) { return (uint64_t)le32(p)|((uint64_t)le32(p+4)<<32); }

/* Same read-only sysctl ABI the gates use. Returns the raw syscall result; on
 * the carry flag it returns a negative errno-style value. *len is updated by
 * the kernel to the bytes written (buf) or required (buf==NULL). */
static long raw_sysctl(const int *mib, unsigned n, void *buf, size_t *len) {
    register uint64_t r10 __asm__("r10") = (uintptr_t)len, r8 __asm__("r8") = 0, r9 __asm__("r9") = 0;
    uint64_t value; unsigned char carry;
    __asm__ __volatile__("syscall" : "=a"(value), "=@ccc"(carry), "+r"(r10), "+r"(r8), "+r"(r9)
        : "a"((uint64_t)SYS___sysctl), "D"((uintptr_t)mib), "S"((uint64_t)n), "d"((uintptr_t)buf) : "rcx", "r11", "memory");
    return carry ? -(long)value : (long)value;
}

static void dump_record(const unsigned char *rec, size_t size) {
    size_t show = size < 1100 ? size : 1100;
    for (size_t i = 0; i < show; i += 16) {
        emit("  %04zx:", i);
        for (size_t j = 0; j < 16 && i + j < show; j++) emit(" %02x", rec[i + j]);
        emit("\n");
    }
    emit("  annotated fields (little-endian):\n");
    for (unsigned f = 0; f < sizeof fields / sizeof fields[0]; f++) {
        unsigned off = fields[f].off, len = fields[f].len;
        if (off + len > size) { emit("    +%-3u %-34s OUT OF RANGE (record %zu bytes)\n", off, fields[f].name, size); continue; }
        if (len == 20) {
            char comm[21]; size_t k = 0;
            while (k < 20 && rec[off + k]) { comm[k] = (rec[off + k] >= 32 && rec[off + k] < 127) ? (char)rec[off + k] : '.'; k++; }
            comm[k] = 0;
            emit("    +%-3u %-34s \"%s\"\n", off, fields[f].name, comm);
        } else if (len == 8) {
            emit("    +%-3u %-34s %llu (0x%llx)\n", off, fields[f].name,
                 (unsigned long long)le64(rec + off), (unsigned long long)le64(rec + off));
        } else {
            emit("    +%-3u %-34s %u (0x%x)\n", off, fields[f].name, le32(rec + off), le32(rec + off));
        }
    }
}

/* Read one process record by PID and report its ki_structsize and offsets. */
static void probe_pid(int32_t pid, const char *label) {
    unsigned char rec[16384];
    size_t size = sizeof rec;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    long r = raw_sysctl(mib, 4, rec, &size);
    emit("\n[%s] KERN_PROC_PID pid=%d\n", label, pid);
    if (r < 0) { emit("  sysctl failed (errno-style %ld); record unavailable\n", -r); return; }
    emit("  record bytes returned: %zu\n", size);
    if (size >= 4) emit("  ki_structsize (record size) = %u\n", le32(rec));
    if (size == 0) { emit("  empty result; no such PID or no permission\n"); return; }
    dump_record(rec, size);
}

/* Report the whole-table length and how it divides by one record. */
static void probe_proc_total(void) {
    size_t size = 0;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    long r = raw_sysctl(mib, 4, NULL, &size);
    emit("\n[all] KERN_PROC_PROC total length probe\n");
    if (r < 0) { emit("  sizing sysctl failed (errno-style %ld)\n", -r); return; }
    emit("  total bytes (sizing call): %zu\n", size);
    if (size == 0 || size > SNAP_LIMIT) { emit("  implausible size; not reading rows\n"); return; }
    unsigned char *buf = malloc(size);
    if (!buf) { emit("  out of memory for %zu bytes\n", size); return; }
    size_t got = size;
    r = raw_sysctl(mib, 4, buf, &got);
    if (r < 0) { emit("  read sysctl failed (errno-style %ld)\n", -r); free(buf); return; }
    emit("  total bytes (read call): %zu\n", got);
    if (got >= 4) {
        uint32_t first = le32(buf);
        emit("  first record ki_structsize: %u\n", first);
        if (first) emit("  got / ki_structsize = %zu, remainder %zu (expect 0 for a uniform record)\n",
                        got / first, got % first);
    }
    free(buf);
}

static void build_report(int argc, char **argv) {
    uint32_t fw = kernel_get_fw_version();
    emit("Blackwire firmware/profile probe\n");
    emit("read-only; no kernel writes\n\n");
    emit("kernel_get_fw_version(): 0x%08x\n", fw);
    emit("  family word (value & 0xffff0000): 0x%08x\n", fw & 0xffff0000u);
    emit("  low word   (value & 0x0000ffff): 0x%04x\n", fw & 0x0000ffffu);
    /* sdk_ps5_ver is the SDK's own cached software version. It is not exported
     * as a public symbol by the SDK headers, so it cannot be read here without
     * SDK-internal access. See README TODO; kernel_get_fw_version() above is the
     * value the gates compare against. */
    emit("  sdk_ps5_ver: not separately exported by public SDK headers (see README)\n");

    probe_pid((int32_t)getpid(), "self");
    if (argc > 1) {
        char *end = NULL;
        long target = strtol(argv[1], &end, 0);
        if (end && !*end && target > 0 && target <= 0x7fffffff) probe_pid((int32_t)target, "arg");
        else emit("\n[arg] ignored non-PID argument: %s\n", argv[1]);
    }
    probe_proc_total();

    /* TODO (README): libkernel.sprx base address and the native_profile.c byte
     * windows are intentionally not captured here. Resolving the module base and
     * reading export bytes needs kernel read primitives whose safety on an
     * unmeasured firmware is unconfirmed, so this probe stays within the public
     * read-only sysctl surface. Capture them separately once method is proven. */
    emit("\nlibkernel.sprx export capture: skipped (see README TODO)\n");
}

static void serve_once(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) || listen(s, 1)) { close(s); return; }
    int c = accept(s, NULL, NULL);
    if (c >= 0) {
        size_t off = 0;
        while (off < g_len) {
            ssize_t w = write(c, g_buf + off, g_len - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        close(c);
    }
    close(s);
}

int main(int argc, char **argv) {
    build_report(argc, argv);
    if (g_buf) {
        int fd = open(OUT_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            size_t off = 0;
            while (off < g_len) {
                ssize_t w = write(fd, g_buf + off, g_len - off);
                if (w <= 0) break;
                off += (size_t)w;
            }
            close(fd);
        }
        write(1, g_buf, g_len);
    }
    if (argc > 2) {
        int port = (int)strtol(argv[2], NULL, 0);
        if (port > 0 && port < 65536) serve_once(port);
    }
    free(g_buf);
    return 0;
}
