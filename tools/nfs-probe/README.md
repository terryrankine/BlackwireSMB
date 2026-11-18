# Blackwire NFS probe

A standalone PS5 homebrew payload that checks the vendored libnfs on a real
console against one NFS server. It is a diagnostic tool. It is not built into
Blackwire and not referenced by `tools/build.py`.

The NFS transport design (`docs/NFS-DESIGN.md`) rests on facts that only the
console can give: whether libnfs connects at all under libSceNet, which local
port it binds, the server read size, and how fast sync and pipelined reads are.
This probe measures them before any Blackwire code depends on them.

## What it prints

Output is written to `/data/blackwire-nfs-probe.txt` and echoed to stdout, one
line at a time, so a hang still leaves the lines written so far.

- Socket options on a scratch TCP socket: `SO_KEEPALIVE`, `getprotobyname("tcp")`
  and `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`. Since libnfs 6.0 a failed
  keepalive option is a fatal connect error, and on FreeBSD targets libnfs finds
  the TCP level through `getprotobyname`. A mount failure that names keepalive
  can be traced to the exact option here.
- Then for NFS version 3, and again for version 4:
  - `nfs_mount` result and time.
  - The local source address and port of the NFS connection, and the server
    endpoint. libnfs tries a reserved port (512 to 1023) first and falls back to
    an ephemeral port without saying so. This line says which happened.
  - `nfs_get_readmax`.
  - The listing of the folder: type, size and name, capped at 200 entries.
  - The alphabetically first directory in the folder is taken as the game
    folder. The largest regular file under it is found by a walk of at most
    3 levels below it and 4000 entries.
  - 64 MiB read from that file three times: sync `nfs_pread` in `readmax`
    chunks, then `nfs_pread_async` with 4 and then 8 reads in flight. Each pass
    reports MiB/s and per-read latency min, average and max. Async latency runs
    from queueing to callback. Each pass reads a new 64 MiB region where the
    file is large enough. A reused region is marked, as the server cache may
    then be warm.
- Every failure is an `ERROR:` line with the libnfs return code and
  `nfs_get_error` text. The last line is `result: PASS` or `result: FAIL`.

## Settings

The context is set to a 10 s RPC timeout, `retrans` 0, autoreconnect 0, no
directory cache and read only. libnfs defaults to a hard mount that retries
forever, which would hide every failure.

libnfs on this target is built without `clock_gettime` (its configure check
wants the Linux-only `CLOCK_MONOTONIC_COARSE`). Its RPC clock is `time()`, so
timeouts have whole-second granularity. The probe's own timings use
`CLOCK_MONOTONIC`.

## Read-only guarantee

The probe opens files `O_RDONLY` on a context set read only. It issues only
mount, lookup, attribute, directory and read calls. It never writes to the
server. It opens no LAN listener. It never follows a symbolic link: it reads only
entries whose directory attributes say regular file and walks only entries that
say directory.

## Defaults

Compile-time only. There are no runtime arguments.

| Macro | Default |
| --- | --- |
| `NFS_PROBE_SERVER` | `"192.168.11.186"` |
| `NFS_PROBE_EXPORT` | `"/volume1/public"` |
| `NFS_PROBE_FOLDER` | `"emulation/ps5"` |

Override with, for example,
`make PROBE_DEFS='-DNFS_PROBE_SERVER=\"10.0.0.5\"'`.

## Build

Needs the public [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk),
LLVM 18 tools and CMake, the same toolchain as the main build. From this
directory:

```
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

The Makefile first builds `vendor/libnfs` as a static archive under `build/`,
with the CMake options `-DBUILD_SHARED_LIBS=OFF -DENABLE_NFS4_2=OFF
-DENABLE_TLS=OFF -DENABLE_MULTITHREADING=OFF` and the same flags that
`tools/build/deps.py` uses for libsmb2. It then links
`blackwire-nfs-probe.elf`. Deploy it with your usual payload loader, or
`make test PS5_HOST=<console-ip>` to send it through the SDK deployer.
