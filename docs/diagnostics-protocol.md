# HashLink diagnostics protocol (HLDI v2)

HLDI is an opt-in runtime diagnostics endpoint. Its one service today is the
profiler: a client starts a session and the runtime pushes the recorded data as
it drains it. HLDI does not replace or alter the HLD2/HLD3 debugger protocol.
`docs/PROFILER.md` in Haxeon describes the design behind it.

Start it with `hl --diagnostics <port> program.hl`. The listener binds to
`127.0.0.1`. `--diagnostics-public` binds every interface and requires the
`HL_DIAGNOSTICS_TOKEN` environment variable; otherwise the runtime refuses to
start the endpoint. `--diagnostics-wait` (which requires `--diagnostics`) holds
the program before its entry point until a session has started. One client is
served at a time.

## Encoding

All integers are little-endian. On connection, the runtime sends:

| Field | Size |
| --- | ---: |
| Magic (`HLDI`) | 4 |
| Protocol version (`2`) | 2 |
| Capability bits | 2 |
| HashLink version | 4 |
| Process ID | 4 |

Capability bit 0 means the profiler service is available, bit 1 that symbol
metadata is available and bit 2 that the client must authenticate first (a
token is configured and not yet presented).

Every later message in either direction has a 16-byte header:

| Field | Size |
| --- | ---: |
| Service | 1 |
| Message type | 1 |
| Flags | 2 |
| Request ID | 4 |
| Payload length | 4 |
| Reserved (zero) | 4 |

Flag bit 0 marks a response, bit 1 an error and bit 2 a frame the runtime
pushes without a request. A pushed frame has request ID 0. A request whose
payload exceeds 1 MiB ends the connection. A request the runtime cannot honor
(unknown type, wrong payload length, not authenticated, a refused start) gets
an empty response with flags 3 and the request's service, type and ID.

## Control service (0)

- Type 1, capabilities: empty request. The response is the capability mask
  (u32).
- Type 2, authenticate: the payload is the token (at most 1024 bytes). An
  exact match answers with an empty response. Until a client authenticates,
  every other request gets the error response. A runtime started without a
  token needs no authentication.

## Profiler service (2)

Requests:

| Type | Name | Payload | Response |
| ---: | --- | --- | --- |
| 1 | status | none | status |
| 4 | metadata | none | the metadata snapshot |
| 16 | start | 16 or 20 bytes, below | status |
| 17 | stop | none | status |
| 18 | pause | none | status |
| 19 | resume | none | status |

The status payload is 32 bytes: `active:u32`, `sources:u32`, `chunks:u32`,
`chunksInUse:u32`, `dataFrames:u64`, `rawBytes:u64`. `active` is 1 while a
session runs. `sources` is the last session's sources. `chunks` is the size of
the buffer pool in 256 KiB chunks and `chunksInUse` the chunks not free.
`dataFrames` and `rawBytes` count the data frames pushed in the last session
and the record bytes in them before compression.

The start payload is `sources:u32`, `sampleRate:u32`, `allocInterval:u32`,
`poolMiB:u32`, optionally followed by `flags:u32`. Flag bit 0 starts the
session paused: it is open, but records nothing until it is resumed. Source bits are 1 for instrumentation, 2 for sampling and 4 for
allocation samples. `sampleRate` applies when sampling is on and must be 1 to
100000 Hz. `allocInterval` applies when allocation samples are on: one sample
per that many allocations, up to 100000000. `poolMiB` sizes the chunk pool,
in 256 KiB chunks and at least 16; 0 means 64. The pool is kept between
sessions and replaced only by a larger one. A start is refused (error
response) while a session is active or when the pool cannot be allocated. A
bad sample rate or allocation interval is found later (see the sequence below).

Pause and resume stop and restart recording within the open session; the
program can do the same (`haxeon.ProfileRecording`). Either is refused (error
response) without a session. Whoever changes it, the runtime pushes a
`recording` frame with the new state.

A session ends on a stop request, when the program exits, or when the client
disconnects. A stop request is answered with a status response only after the
`end` frame is pushed; with no session running it just answers. When the
program exits, the runtime asks the diagnostics thread to end the session and
waits up to 5 seconds for it. If the client disconnects mid-session, recording
stops and the undelivered records are dropped.

### Session sequence

1. The client sends start. The runtime answers with a status response (type
   16, `active` 1) and the session frame.
2. The runtime pushes `session`, `metadata`, `clock` and `threads`, in that
   order, and then releases a program held by `--diagnostics-wait`.
3. While the session runs, the diagnostics thread drains about once a
   millisecond, pushing a `data` frame for each thread's new records, and
   answers requests between drains. It pushes `clock` every 100 ms, `threads`
   every 500 ms when the set of named threads changed, `stats` every second
   and `metadata` when a module is loaded or patched.
4. On stop, the runtime stops recording, drains everything, and pushes the
   last `data` frames, then `metadata` if it changed, `threads` if they
   changed, `stats`, `clock` and `end`.

If the runtime then cannot start the sampler or allocation sampling (a bad rate
or interval), it ends the session at once as it would for a stop: the client
has already received the status response, `session`, `metadata`, `clock` and
`threads`, and now receives the closing frames and `end`.

### Pushed frames

A pushed frame has service 2, flags 4 and request ID 0. The metadata frame
carries the type of its request, 4.

| Type | Name | Payload |
| ---: | --- | --- |
| 4 | metadata | the metadata snapshot (schema 4) |
| 16 | session | `version:u32, sources:u32, tickKind:u32, 0:u32, baseTicks:u64, nominalHz:u64` |
| 17 | data | `tid:u32, flags:u32, rawLength:u32, 0:u32`, then the records |
| 18 | clock | `ticks:u64, monotonicNs:u64, unixNs:u64` |
| 19 | threads | `count:u32`, then per thread `tid:u32, length:u32`, then the UTF-8 name |
| 20 | end | `dataFrames:u64, rawBytes:u64` |
| 21 | stats | `chunksInUse:u32, chunkCount:u32, stalls:u64, stallTicks:u64, rawBytes:u64, sentBytes:u64` |
| 22 | recording | `recording:u32`: 1 while the session records, 0 while it is paused |

- **session** (32 bytes). `version` is 1. `sources` echoes the request.
  `tickKind` is 1 for the TSC, 2 for `QueryPerformanceCounter`, 3 for
  nanoseconds and 4 for `CNTVCT_EL0`. `baseTicks` is the raw tick reading
  every record's ticks are relative to. `nominalHz` is an estimate of ticks
  per second; readers convert with the clock frames instead.
- **data**. `tid` is the thread that wrote the records, `rawLength` their
  length in bytes before compression. Flag bit 0 means the records are an LZ4
  block of `rawLength` bytes; the runtime compresses only when that is
  smaller, so otherwise the flag is clear and the records follow as they are.
  The frame header's length is 16 plus the bytes that follow. A frame holds
  whole records, in the order the thread wrote them. Several frames can
  carry one thread's records; they arrive in order.
- **clock** (24 bytes). `ticks` is the current tick reading relative to
  `baseTicks`; `monotonicNs` is the monotonic clock in nanoseconds and
  `unixNs` the wall clock in nanoseconds since the Unix epoch, read together.
  Readers convert record ticks to time by interpolating between these pairs.
- **threads**. Lists the threads that have a name; the main thread is named
  `main` when it has none. The frame replaces the previous list.
- **end**. The last frame of a session. `dataFrames` and `rawBytes` are the
  session's totals. Every session's records, ticks and counters start from
  zero.
- **stats**. The chunk pool state, the number of times a producer waited for a
  free chunk and the ticks it waited in all, and the bytes pushed so far
  before and after compression (`sentBytes` includes the 16-byte frame
  headers).

### Records

A data frame's records are 8-byte aligned. Word 0 of every record is
`kind << 56 | ticks`, where ticks are relative to `baseTicks`. A record is
whole in its frame. The words after word 0:

| Kind | Name | Words after word 0 |
| ---: | --- | --- |
| 0x01 | `ENTER` | function key (u64) |
| 0x02 | `EXIT` | none |
| 0x03 | `UNWIND` | count (u64): close this many of the innermost open calls |
| 0x10 | `SPAN_BEGIN` | `units:u32, encoding:u32` (0 UTF-16, 1 UTF-8), then the name padded to 8 bytes |
| 0x11 | `SPAN_END` | none |
| 0x12 | `FRAME_MARK` | frame set (u64) |
| 0x13 | `FRAME_IDLE` | frame set (u64) |
| 0x20 | `EVENT` | `id:u32, length:u32`, then the payload padded to 8 bytes |
| 0x21 | `COUNTER` | value (f64), `units:u32, encoding:u32`, then the name padded to 8 bytes |
| 0x22 | `SAMPLE` | `tid:u32, frames:u16, flags:u8, 0:u8`, then `frames` u64 program counters, leaf first |
| 0x30 | `STALL` | end ticks (u64) |

- `units` is the name's length in 16-bit units for UTF-16 and in bytes for
  UTF-8; the padded size is `units` times 2 or 1, rounded up to 8. The writer
  caps a name at 1024 units.
- `SAMPLE` carries the sampled thread's ID in the record; the frame's `tid` is
  the sampler thread that wrote it. Flag bit 0 means the world was stopped for
  a GC. A sample holds at most 65535 frames.
- `STALL` starts at word 0's ticks and ends at the end ticks: the producer
  waited that long for a free chunk.
- `EVENT` carries the runtime's profiler events (`src/profile_events.h`) and
  the events a program sends with `hl.Profile.event()`. The runtime's own
  payloads are: GC statistics (0x484C0003), five u64: allocated bytes,
  allocation count, heap bytes, collections and mark time in microseconds;
  allocation sample (0x484C0005), `requested:u64, allocated:u64,
  interval:u32, typeKind:u32, frames:u32, 0:u32` and `frames` u64 program
  counters; native symbol (0x484C0004), `pc:u64, base:u64, moduleLength:u32,
  nameLength:u32`, then the module and the name; native location (0x484C0006),
  `pc:u64, moduleBase:u64, moduleSize:u64, line:u32, fileLength:u32`, then the
  file; module loaded (0x484C0007), the module ID (u64); module revision
  (0x484C0001), the module ID (u64) and the revision (u32); recording
  (0x484C0008), u32 0 when recording pauses and 1 when it resumes. A pause is
  written before recording stops and a resume after it starts, so a reader
  closes every thread's open calls at a pause: the calls in between went
  unrecorded.

A reader keeps the open calls and spans of each thread. `EXIT` closes the
innermost call. `UNWIND` closes the `count` innermost open calls (all of them if fewer are open). `SPAN_END`
closes the innermost span. A frame set's frames run from one `FRAME_MARK` to
the next, and `FRAME_IDLE` ends the open frame.

## Symbol metadata

The snapshot is the response to a metadata request and the payload of pushed
metadata frames. It starts with `schemaVersion:u32` (4) and `moduleCount:u32`.
Each module then holds:

| Field | Size |
| --- | ---: |
| Stable process-local module ID | 8 |
| Module revision | 4 |
| Region count | 4 |
| Debug-file count | 4 |

The debug-file count is followed, for each file, by `length:u32` and that many
UTF-8 path bytes. The regions follow.

A region is `baseAddress:u64`, `size:u64`, `flags:u32`, `revision:u32`,
`functionCount:u32`, then its functions. A module has these regions, in order:

- Its original code: flags 0, revision 1.
- One region for each patch it has taken. Flag bit 0 is set. Flag bit 1 marks
  a region that has been retired, kept so stacks captured before the patch
  still resolve. `revision` is the module revision that introduced it.
- If the module is patchable, its entry stubs: flags 4, revision 0. Every
  function of a patchable module is called through a small stub that jumps to
  its current code, so a sample can stop in one. Each stub is listed as a
  function named `<function> [entry]`. Its `functionID` is the function index,
  its `offset` the index times the stub stride and its `size` the stride. It
  has no line entries.

A function is `functionID:u32`, `offset:u32`, `size:u32`, `nameLength:u32`, the
UTF-8 name, `lineEntryCount:u32` and the line entries. The function ID is the
HashLink function index. `offset` is relative to the region base. The size runs
to the next function's start, or to the end of the region for the last. Only
functions with code inside the region are listed. A sample address belongs to a
function when it falls within the region base plus the function's range.

A line entry is six u32: `startOffset`, `endOffset`, `opcodeIndex`, `opcode`,
`fileID`, `line`. The offsets are relative to the function's start and cover
the JIT code of one opcode; `fileID` indexes the module's debug files. Entries
are written in opcode order and only for opcodes that have code, a line and a
valid file. A location is the entry whose range holds the function-relative
program counter.

A client can refresh the snapshot with a metadata request at any time; the
runtime also pushes one at session start and whenever a module loads or a
revision is published. Each snapshot replaces the previous one; it includes
retired regions. A snapshot that would exceed 64 MiB fails: the request gets
the error response, and a pushed one fails the session and closes the
connection.

## Native client

`hlprof-live` is the reference client. It starts a session and writes every
pushed frame to an HLPC capture. Its `report` and `export` subcommands read
captures. Command lines are in `docs/PROFILING.md` in Haxeon.

```sh
hl --diagnostics 7000 --diagnostics-wait program.hl
hlprof-live --sources sampling --rate 500 --output capture.hlpc 7000
```

Press Ctrl-C or use `--duration SEC` to stop: the client sends a stop request
and waits up to 10 seconds for `end`.

## Capture container (HLPC)

Captures are little-endian files with a 24-byte header:

| Field | Size |
| --- | ---: |
| Magic (`HLPC`) | 4 |
| Format version (`1` or `2`) | 2 |
| Header size (`24`) | 2 |
| Flags (zero) | 4 |
| Process ID | 4 |
| Requested sample rate | 4 |
| Sources (v2) or reserved (v1) | 4 |

The rest is an append-only sequence of records: `type:u32`, `length:u32`,
`recorderNs:u64`, then `length` payload bytes. `recorderNs` is the time since
the recorder started, as the recorder measured it.

### Version 2

The recorder writes each pushed frame as it arrives, without decoding it. The
record type is the frame type, 4 and 16 to 21 (metadata, session, data, clock,
threads, end, stats), and the payload is the frame's payload. A complete
capture ends with a type 3 record: `frames:u64, bytes:u64`, the number of
frames written, `end` included, and the sum of their payload sizes. A capture without it is
partial (the recorder was killed, the connection dropped or the session did not
end), and readers recover its complete records.

To read a v2 capture, a reader makes two passes. The first takes the last
metadata snapshot, the session frame's `nominalHz`, the clock pairs in order
(the first pair's `monotonicNs` is the time origin, and a pair whose ticks do
not increase is skipped), the last threads frame and whether the type 3 record
is there. The second decodes the data frames in order, per thread, optionally
only those whose `recorderNs` falls in a window. A time is the interpolation
between the two clock pairs around its ticks, or an extrapolation from the
nearest pair; with one pair the reader uses `nominalHz`. A data frame that
fails to decompress to `rawLength` bytes, or a record that is cut short or has
an unknown kind, is skipped with a warning.

### Version 1

Version 1 captures came from the removed pull protocol. They remain readable
by `hlprof-live report` and `export`, and no tool writes them any more.
