/*
 * HashLink profiler recorder: per-thread lock-free buffers of pooled chunks, drained by one consumer.
 * docs/PROFILER.md in Haxeon describes the record format, the buffers and the session protocol.
 */
#ifndef HLPROF_H
#define HLPROF_H

#include "hl.h"

/* Record kinds: the top byte of each record's first word. The low 56 bits are ticks since the session's base tick. */
#define HL_PROF_ENTER 0x01
#define HL_PROF_EXIT 0x02
#define HL_PROF_UNWIND 0x03
#define HL_PROF_SPAN_BEGIN 0x10
#define HL_PROF_SPAN_END 0x11
#define HL_PROF_FRAME_MARK 0x12
#define HL_PROF_FRAME_IDLE 0x13
#define HL_PROF_EVENT 0x20
#define HL_PROF_COUNTER 0x21
#define HL_PROF_SAMPLE 0x22
#define HL_PROF_STALL 0x30

#define HL_PROF_TICK_MASK 0x00FFFFFFFFFFFFFFULL

/* Name encodings of SPAN_BEGIN and COUNTER records. */
#define HL_PROF_UTF16 0
#define HL_PROF_UTF8 1

/* Clock sources, as reported in the session frame. */
#define HL_PROF_TICKS_TSC 1
#define HL_PROF_TICKS_QPC 2
#define HL_PROF_TICKS_NS 3
#define HL_PROF_TICKS_CNTVCT 4

/* Session sources. */
#define HL_PROF_SOURCE_INSTRUMENT 1
#define HL_PROF_SOURCE_SAMPLING 2
#define HL_PROF_SOURCE_ALLOC 4

#define HL_PROF_CHUNK_SIZE (256 << 10)

typedef struct {
	int chunk_count;
	int chunks_in_use;
	unsigned long long stalls;
	unsigned long long stall_ticks;
	unsigned long long drained_bytes;
} hl_prof_stats;

/* Nonzero while a session records. Probes test it before writing anything. */
HL_API volatile int hl_prof_on;

/* The clock. hl_prof_ticks returns raw ticks; records store them relative to hl_prof_base_ticks. */
HL_API unsigned long long hl_prof_ticks( void );
HL_API int hl_prof_tick_kind( void );
HL_API unsigned long long hl_prof_nominal_hz( void );
HL_API unsigned long long hl_prof_base_ticks( void );
/* The monotonic clock in nanoseconds, for clock pairs. */
HL_API unsigned long long hl_prof_monotonic_ns( void );

/* Session control, for the consumer. start allocates the pool on first use and begins recording; stop ends recording and
   waits for records in flight, after which a final drain returns everything recorded. */
HL_API bool hl_prof_start( unsigned int pool_mib );
HL_API void hl_prof_stop( void );

/* Hands every record written since the last drain to fn, one contiguous segment of one thread's records at a time.
   Consumer thread only. Returns the number of bytes handed over. */
typedef void (*hl_prof_segment_fn)( void *context, unsigned int tid, const unsigned char *data, unsigned int length );
HL_API unsigned long long hl_prof_drain( hl_prof_segment_fn fn, void *context );
HL_API void hl_prof_get_stats( hl_prof_stats *stats );

/* The calling thread is exiting: its remaining records are drained and its state freed. */
HL_API void hl_prof_thread_exit( void );

/* Writers. Each records on the calling thread and does nothing while no session records. */
HL_API void hl_prof_enter( unsigned long long key );
HL_API void hl_prof_exit( void );
/* The calling thread's instrumentation depth (ENTER minus EXIT records over its life). A try saves it; when a throw lands
   in the catch, hl_prof_unwind writes one UNWIND record closing the calls the throw skipped (the depth beyond the saved
   one) and restores the depth. */
HL_API int hl_prof_depth( void );
HL_API void hl_prof_unwind( int depth );
HL_API void hl_prof_span_begin( const void *name, int units, int encoding );
HL_API void hl_prof_span_end( void );
HL_API void hl_prof_frame( int kind, unsigned int frame_set );
HL_API void hl_prof_counter( const void *name, int units, int encoding, double value );
HL_API void hl_prof_event( unsigned int id, const void *payload, unsigned int length );
/* A stack sample of thread tid taken at ticks (raw), frames leaf first. Written by the sampler thread. */
HL_API void hl_prof_sample( unsigned int tid, int flags, void **frames, int count, unsigned long long ticks );

#endif
