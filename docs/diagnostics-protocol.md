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

The metadata payload starts with `schemaVersion:u32` (currently 1) and
`moduleCount:u32`. Each module then contains:

| Field | Size |
| --- | ---: |
| Stable process-local module ID | 8 |
| Module revision | 4 |
| Region count | 4 |

Each region contains `baseAddress:u64`, `size:u64`, `flags:u32`, and
`functionCount:u32`. Flag bit 0 identifies patch code and bit 1 identifies a
retired patch region retained for stacks captured before publication.

Each function contains `functionID:u32`, `offset:u32`, `size:u32`, followed by
`nameLength:u32` and that many UTF-8 name bytes. The function ID is the stable
HashLink function index. A sample address belongs to a function when it falls
within the region base plus the function's relative range.

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
payloads contain the bytes supplied to `hl.Profile.event()`. Symbol and module
metadata are intentionally deferred to a later protocol capability.
