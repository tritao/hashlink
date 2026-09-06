# HashLink diagnostics protocol (HLDI v1)

HLDI is an opt-in, loopback-only runtime diagnostics endpoint. It does not
replace or alter the HLD2/HLD3 debugger protocol.

Start it with `hl --diagnostics <port> program.hl`. Remote access should use an
authenticated tunnel or a host-provided proxy; the runtime does not expose the
listener beyond `127.0.0.1`.

## Encoding

All integers are little-endian. On connection, the runtime sends:

| Field | Size |
| --- | ---: |
| Magic (`HLDI`) | 4 |
| Protocol version (`1`) | 2 |
| Capability bits | 2 |
| HashLink version | 4 |
| Process ID | 4 |

Every subsequent request and response has a 16-byte header:

| Field | Size |
| --- | ---: |
| Service | 1 |
| Message type | 1 |
| Flags | 2 |
| Request ID | 4 |
| Payload length | 4 |
| Reserved (zero) | 4 |

Response flag bit 0 is set on responses and bit 1 reports an error. Payloads
are limited to 1 MiB; profiler reads are additionally limited to 256 KiB.

## Services

Service 0 is control. Message 1 returns a 32-bit capability mask. Bit 0 means
the profiler service is available; bit 1 means symbol metadata is available.

Service 2 is the profiler:

- Message 1, status: empty request. The response is `first:u64`, `next:u64`,
  `droppedRecords:u64`, `sampleRate:u32`, `paused:u32`.
- Message 2, configure: `sampleRate:u32`, `enabled:u32`. The response is the
  status payload. A running sampler's rate cannot yet be changed.
- Message 3, read: `cursor:u64`, `maximumBytes:u32`. The response starts with
  `nextCursor:u64`, `droppedRecords:u64`, followed by stream bytes. A cursor
  older than `first` resumes at the first retained record.
- Message 4, metadata: empty request. Returns the current module, JIT-region,
  and function-symbol snapshot described below. Clients should refresh this
  after observing a module revision change.

## Symbol metadata

The metadata payload starts with `schemaVersion:u32` (currently 2) and
`moduleCount:u32`. Each module then contains:

| Field | Size |
| --- | ---: |
| Stable process-local module ID | 8 |
| Module revision | 4 |
| Region count | 4 |
| Debug-file count | 4 |

The debug-file count is followed by `length:u32` and UTF-8 path bytes for each
file. Schema 1 omitted this field and remains supported by `hlprof-live`.

Each region contains `baseAddress:u64`, `size:u64`, `flags:u32`, and
`functionCount:u32`. Flag bit 0 identifies patch code and bit 1 identifies a
retired patch region retained for stacks captured before publication.

Each function contains `functionID:u32`, `offset:u32`, `size:u32`, followed by
`nameLength:u32` and that many UTF-8 name bytes. Schema 2 then adds
`lineEntryCount:u32`; each line entry is `jitOffset:u32`, `fileID:u32`, and
`line:u32`. Entries are ordered by JIT offset and emitted only when the source
location changes. The function ID is the stable HashLink function index. A
sample address belongs to a function when it falls within the region base plus
the function's relative range; its location is the last line entry whose JIT
offset does not exceed the function-relative program counter.

## Profiler records

The profiler uses a bounded 8 MiB rolling buffer. Eviction is record-aligned.
Each record begins with its body length:

| Field | Size |
| --- | ---: |
| Body length | 4 |
| Kind (`1` sample, `2` event) | 1 |
| Flags (sample bit 0 means GC stop-the-world) | 1 |
| Reserved | 2 |
| Timestamp (`f64` bit representation) | 8 |
| Thread ID | 4 |
| Value (frame count or event ID) | 4 |
| Payload | body length - 20 |

Sample payloads contain `frame count` unsigned 64-bit program counters. Event
payloads contain the bytes supplied to `hl.Profile.event()`. Clients resolve
program counters using the separate symbol-metadata snapshot.

## Native client

`hlprof-live` is the reference HLDI client. For example:

```sh
hl --diagnostics 7000 program.hl
hlprof-live --rate 500 --interval 1000 --top 20 \
  --output capture.hlprof 7000
```

The client fetches and periodically refreshes symbol metadata, reads samples by
cursor, and prints self and inclusive percentages. Use `--duration SEC` for a
bounded capture or Ctrl-C to stop; either path pauses the remotely controlled
sampler before disconnecting.

## Portable capture container

Files produced by `--output` use the little-endian `HLPC` format. The 24-byte
file header contains:

| Field | Size |
| --- | ---: |
| Magic (`HLPC`) | 4 |
| Format version (`1`) | 2 |
| Header size (`24`) | 2 |
| Flags | 4 |
| Process ID | 4 |
| Requested sample rate | 4 |
| Reserved | 4 |

The remainder is an append-only sequence of records. Every record starts with
`type:u32`, `payloadLength:u32`, and `elapsedNanoseconds:u64`.

- Type 1 contains an unmodified HLDI symbol-metadata payload. Multiple records
  preserve module changes during a capture.
- Type 2 contains `requestedCursor:u64`, followed by an unmodified profiler
  read response: `nextCursor:u64`, `droppedRecords:u64`, and profiler records.
- Type 3 marks a completed capture and contains `finalCursor:u64` and
  `droppedRecords:u64`.

An interrupted or failed write has no type 3 record, allowing offline readers
to distinguish a partial capture while still recovering its complete records.

Because metadata and sample chunks are preserved rather than pre-aggregated,
offline tools can reconstruct call trees, timelines, and alternative reports.

The reference client can read captures without a running HashLink process:

```sh
hlprof-live report --top 30 capture.hlprof
hlprof-live report --lines --top 30 capture.hlprof
hlprof-live export --format folded capture.hlprof > stacks.folded
hlprof-live export --format folded --lines capture.hlprof > stacks.folded
hlprof-live export --format perfetto --lines \
  --output trace.json capture.hlprof
```

`report` reconstructs metadata revisions and prints aggregate self/inclusive
costs. Folded export emits root-to-leaf stack keys and occurrence counts for
FlameGraph-compatible tools. Both modes validate cursor continuity and recover
all complete records from partial captures, reporting truncation on stderr.
With `--lines`, reports aggregate source locations and folded frames include
`file:line` annotations.

Perfetto export produces Chrome Trace Event JSON accepted by Perfetto UI. It
creates per-runtime-thread sampling events with resolved stacks, leaf source
locations, and GC stop-the-world state. Custom `hl.Profile.event()` records,
symbol refreshes, and dropped-record notifications are emitted as timeline
events on their respective categories.
