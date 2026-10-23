/*
 * pftrace - minimal streaming writer for Perfetto native-protobuf trace files.
 *
 * Self-contained C99, no dependencies besides the C library. Produces a
 * .pftrace that loads in ui.perfetto.dev and trace_processor (v58+):
 * process/thread tracks, nested slices, instants, process counters and
 * StackSample profiling samples with interned frames/callstacks.
 *
 * Not thread-safe: callers must serialize access to one pftrace*.
 * Timestamps are nanoseconds on one common clock (no clock id is written).
 * Strings are treated as UTF-8 bytes. Any allocation or write failure marks the
 * writer failed (later calls become no-ops and pftrace_close returns 0).
 */
#ifndef PFTRACE_H
#define PFTRACE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pftrace pftrace;

/* Opens path for writing. pid must be nonzero. Returns NULL on failure. */
pftrace *pftrace_open( const char *path, uint32_t pid, const char *process_name );

/* Flushes and closes; returns 1 if every write succeeded, 0 otherwise. Frees everything. */
int pftrace_close( pftrace *t );

/* Names a thread (tid nonzero). Emits its thread track descriptor the first time; a later different name re-emits the descriptor. */
void pftrace_thread( pftrace *t, uint32_t tid, const char *name );

/* Nested slices on a thread track (thread track is created on demand with name "Thread <tid>" if not named yet). */
void pftrace_slice_begin( pftrace *t, uint64_t ts_ns, uint32_t tid, const char *name, const char *category );   /* category may be NULL */
void pftrace_slice_end( pftrace *t, uint64_t ts_ns, uint32_t tid );

/* Nested slices on the thread's "Call stacks" track, a child of its thread track: call stacks laid out over time. */
void pftrace_stack_begin( pftrace *t, uint64_t ts_ns, uint32_t tid, const char *name );
void pftrace_stack_end( pftrace *t, uint64_t ts_ns, uint32_t tid );

/* Zero-duration instant event; tid==0 puts it on the process track. */
void pftrace_instant( pftrace *t, uint64_t ts_ns, uint32_t tid, const char *name );

/* Process-scoped counter track identified by name (created on first use; unit string may be NULL, e.g. "bytes", "ns"). */
void pftrace_counter( pftrace *t, uint64_t ts_ns, const char *track_name, const char *unit, double value );

/* Interned native/JIT module mapping; same (path,start) returns the same id. Ids are nonzero. */
uint64_t pftrace_mapping( pftrace *t, const char *path, uint64_t start, uint64_t end );

/* Interned frame; identical arguments return the same id. mapping_id 0 = no mapping (rel_pc ignored). source_file may be NULL
   (then line is ignored). Ids are nonzero. */
uint64_t pftrace_frame( pftrace *t, const char *function, uint64_t mapping_id, uint64_t rel_pc, const char *source_file, uint32_t line );

/* One sampled stack: frames ordered ROOT FIRST, LEAF LAST (count may be 0 -> skipped). weight_ns = time the sample stands for. */
void pftrace_sample( pftrace *t, uint64_t ts_ns, uint32_t tid, const uint64_t *frames_root_first, uint32_t count, uint64_t weight_ns );

#ifdef __cplusplus
}
#endif

#endif /* PFTRACE_H */
