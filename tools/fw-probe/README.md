# Blackwire firmware/profile probe

A standalone PS5 homebrew payload that measures the values a new firmware row in
the supported-profile table would need. It is a diagnostic tool. It is not built
into Blackwire and not referenced by `tools/build.py`.

Blackwire accepts only the measured rows in `BW_STOP_PROFILES`
(`src/blackwire/streamreader/diagnostics/game_stop_identity.h`): 13.00
(`0x13000040`) and 12.40 (`0x12400009`), both with a 1096-byte kinfo_proc
record. To support another firmware, that table needs the firmware's record
size and field offsets measured on real hardware. Blackwire
itself exposes none of these values: `/health` returns only build id, reader
hash and Media status, and `/api/state` carries catalogue state, so this probe
fills the gap.

## What it prints

Output is written to `/data/blackwire-fw-probe.txt` and echoed to stdout. If a
TCP port is given it also serves the same text once over TCP.

- `kernel_get_fw_version()`, raw, plus the family word (`value & 0xffff0000`) and
  the low word (`value & 0x0000ffff`). On 12.40 the SDK switches on the family
  word and has a `0x12400000` case. The low word is not in the SDK, so this
  reports it.
- The `KERN_PROC_PID` record for this payload's own PID, and for a PID passed as
  the first argument. For each it prints `ki_structsize` (the record size) and a
  hexdump of up to 1100 bytes with the gate offsets annotated: `ki_pid` at +72,
  `ki_rssize` at +264, `ki_start.tv_sec` at +336, `ki_start.tv_usec` at +344 and
  `ki_comm` at +447. On an unmeasured firmware these annotations may land on the
  wrong bytes; comparing the annotation against the hexdump is how you find the
  real offsets.
- The `KERN_PROC_PROC` whole-table length and that length divided by the first
  record's `ki_structsize`, with the remainder. A zero remainder means a uniform
  record size.

## Read-only guarantee

The probe only reads. It issues the same read-only `KERN_PROC` sysctl the
existing gates use (`native_session_ps5.c`, `startup_runtime_idle_ps5.c`) and
reads the firmware word. It never writes kernel memory, never ptraces and never
mutates a process.

## Build

Needs the public [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) and
LLVM 18 tools, the same toolchain as the main build. From this directory:

```
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

This produces `blackwire-fw-probe.elf`. Deploy it with your usual payload loader,
or `make test PS5_HOST=<console-ip>` to send it through the SDK deployer.

## Usage

```
blackwire-fw-probe.elf [target_pid] [tcp_port]
```

- `target_pid` optional. An extra PID to dump besides this payload's own PID.
  Use the running game's PID to capture a real `eboot.bin` record.
- `tcp_port` optional. If given, the probe serves the report once over TCP on
  that port after writing the file, for consoles where reading `/data` is awkward.

## What to capture for a 12.40 entry

Run the probe on the 12.40 console, ideally with a game running, and record from
the output:

1. `kernel_get_fw_version()` raw value. This is the table `firmware` field.
2. `ki_structsize` from a process record. This is the table `record` field and
   must match `KERN_PROC_PROC total / ki_structsize` with no remainder.
3. The real offsets of `ki_pid`, `ki_start` (sec and usec), `ki_comm` and
   `ki_rssize`, read off the annotated hexdump of a known process (the probe's
   own PID is known; a running game gives a real `eboot.bin` in `ki_comm`).

Add one table row with those values. Do not add a row until all are measured.

## Measured: 12.40

One console on 12.40, read on the probe's own process (`payload.elf`), not a
game process. These values are the 12.40 table row.

| Value | Measured |
|---|---|
| `kernel_get_fw_version()` | `0x12400009` (family `0x12400000`, low word `0x0009`) |
| `ki_structsize` (record size) | 1096 (`0x448`) |
| `ki_pid` | +72 |
| `ki_rssize` | +264 |
| `ki_start.tv_sec` | +336 |
| `ki_start.tv_usec` | +344 (value below 1000000) |
| `ki_comm` | +447 (`"payload.elf"`, NUL terminated) |
| word at +4 | 0 |
| `KERN_PROC_PROC` read length | 151248 bytes = 138 x 1096, remainder 0 |

Not yet measured on 12.40: a game process record (`eboot.bin` in `ki_comm`)
and the other 12.40 low words.

## TODO: libkernel.sprx export capture

This probe does not capture the `libkernel.sprx` base address or the byte windows
in `src/blackwire/streamreader/native_profile.c`. Those are keyed to one retained
13.00 ELF (its export offsets, prefix fingerprints and AIO data offsets), and a
12.40 entry there is a separate, larger reverse-engineering task. Resolving the
module base and reading export bytes also needs kernel read primitives whose
safety on an unmeasured firmware is unconfirmed. This is left deliberately out of
scope; capture it separately once the method is proven read-only and safe.
