/*
 * HashLink profiler recorder. See hlprof.h, and docs/PROFILER.md in Haxeon for the design.
 *
 * Every thread writes records into its own chunk with plain stores and publishes its write position with a release store.
 * The consumer reads positions with acquire loads, so neither side takes a lock to record or drain. The only atomic
 * read-modify-write a producer makes is taking a chunk from the pool, once per HL_PROF_CHUNK_SIZE bytes.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "hlprof.h"
#include "profile_events.h"

#ifdef HL_WIN
#	undef _GUID
#	include <windows.h>
#else
#	include <pthread.h>
#	include <sched.h>
#	include <time.h>
#	include <unistd.h>
#	include <sys/mman.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#	define PROF_X86
#	ifdef _MSC_VER
#		include <intrin.h>
#	else
#		include <cpuid.h>
#		include <x86intrin.h>
#	endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#	define PROF_ARM64
#	ifdef _MSC_VER
#		include <intrin.h>
#	endif
#endif

HL_PRIM int hl_thread_id();

/* ---- atomics ---------------------------------------------------------------------------------------------------- */

#if defined(_MSC_VER) && !defined(__clang__)
#	if defined(PROF_X86)
	/* x86 orders loads and stores as acquire/release already; only the compiler must not reorder around them. */
#		define LOAD_ACQUIRE_PTR(p) prof_load_ptr((void *volatile*)(p))
#		define STORE_RELEASE_PTR(p,v) do { _ReadWriteBarrier(); *(void *volatile*)(p) = (v); } while(0)
#		define LOAD_ACQUIRE_INT(p) prof_load_int((volatile int*)(p))
#		define STORE_RELEASE_INT(p,v) do { _ReadWriteBarrier(); *(volatile int*)(p) = (v); } while(0)
static __forceinline void *prof_load_ptr( void *volatile *p ) { void *v = *p; _ReadWriteBarrier(); return v; }
static __forceinline int prof_load_int( volatile int *p ) { int v = *p; _ReadWriteBarrier(); return v; }
#	else
#		define LOAD_ACQUIRE_PTR(p) ((void*)__ldar64((unsigned __int64 volatile*)(p)))
#		define STORE_RELEASE_PTR(p,v) __stlr64((unsigned __int64 volatile*)(p),(unsigned __int64)(v))
#		define LOAD_ACQUIRE_INT(p) ((int)__ldar32((unsigned __int32 volatile*)(p)))
#		define STORE_RELEASE_INT(p,v) __stlr32((unsigned __int32 volatile*)(p),(unsigned __int32)(v))
#	endif
#	define CAS64(p,expected,desired) (_InterlockedCompareExchange64((volatile __int64*)(p),(__int64)(desired),(__int64)(expected)) == (__int64)(expected))
#	define FETCH_ADD32(p,v) _InterlockedExchangeAdd((volatile long*)(p),(long)(v))
#	define FETCH_ADD64(p,v) _InterlockedExchangeAdd64((volatile __int64*)(p),(__int64)(v))
#	define FORCE_INLINE __forceinline
#else
#	define LOAD_ACQUIRE_PTR(p) __atomic_load_n((void**)(p),__ATOMIC_ACQUIRE)
#	define STORE_RELEASE_PTR(p,v) __atomic_store_n((void**)(p),(void*)(v),__ATOMIC_RELEASE)
#	define LOAD_ACQUIRE_INT(p) __atomic_load_n((int*)(p),__ATOMIC_ACQUIRE)
#	define STORE_RELEASE_INT(p,v) __atomic_store_n((int*)(p),(v),__ATOMIC_RELEASE)
static inline bool prof_cas64( volatile unsigned long long *p, unsigned long long expected, unsigned long long desired ) {
	return __atomic_compare_exchange_n(p,&expected,desired,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
#	define CAS64(p,expected,desired) prof_cas64((p),(expected),(desired))
#	define FETCH_ADD32(p,v) __atomic_fetch_add((p),(v),__ATOMIC_RELAXED)
#	define FETCH_ADD64(p,v) __atomic_fetch_add((p),(v),__ATOMIC_RELAXED)
#	define FORCE_INLINE inline __attribute__((always_inline))
#endif

/* ---- clock ------------------------------------------------------------------------------------------------------ */

static int tick_kind;
static bool use_tsc;
static unsigned long long nominal_hz;
static unsigned long long base_ticks;
#ifdef HL_WIN
static unsigned long long qpc_frequency;
#endif

HL_PRIM unsigned long long hl_prof_monotonic_ns( void ) {
#ifdef HL_WIN
	LARGE_INTEGER counter;
	unsigned long long value;
	QueryPerformanceCounter(&counter);
	value = (unsigned long long)counter.QuadPart;
	return value / qpc_frequency * 1000000000ULL + value % qpc_frequency * 1000000000ULL / qpc_frequency;
#else
	struct timespec now;
#	ifdef CLOCK_MONOTONIC_RAW
	clock_gettime(CLOCK_MONOTONIC_RAW,&now);
#	else
	clock_gettime(CLOCK_MONOTONIC,&now);
#	endif
	return (unsigned long long)now.tv_sec * 1000000000ULL + (unsigned long long)now.tv_nsec;
#endif
}

static unsigned long long slow_ticks( void ) {
#if defined(PROF_ARM64) && defined(_MSC_VER)
	return (unsigned long long)_ReadStatusReg(ARM64_CNTVCT);
#elif defined(PROF_ARM64)
	unsigned long long value;
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
	return value;
#elif defined(HL_WIN)
	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);
	return (unsigned long long)counter.QuadPart;
#else
	return hl_prof_monotonic_ns();
#endif
}

static FORCE_INLINE unsigned long long now_ticks( void ) {
#ifdef PROF_X86
	if( use_tsc ) return __rdtsc();
#endif
	return slow_ticks();
}

HL_PRIM unsigned long long hl_prof_ticks( void ) {
	return now_ticks();
}

static bool invariant_tsc( void ) {
#if defined(PROF_X86) && defined(_MSC_VER)
	int info[4];
	__cpuid(info,0x80000000);
	if( (unsigned int)info[0] < 0x80000007 ) return false;
	__cpuid(info,0x80000007);
	return (info[3] & (1 << 8)) != 0;
#elif defined(PROF_X86)
	unsigned int a, b, c, d;
	if( __get_cpuid_max(0x80000000,NULL) < 0x80000007 ) return false;
	__get_cpuid(0x80000007,&a,&b,&c,&d);
	return (d & (1 << 8)) != 0;
#else
	return false;
#endif
}

static void clock_init( void ) {
	if( tick_kind ) return;
#ifdef HL_WIN
	{
		LARGE_INTEGER frequency;
		QueryPerformanceFrequency(&frequency);
		qpc_frequency = (unsigned long long)frequency.QuadPart;
	}
#endif
	use_tsc = invariant_tsc();
	if( use_tsc ) {
		/* Only informative: readers convert ticks with the session's clock pairs. */
		unsigned long long ns0 = hl_prof_monotonic_ns(), t0 = now_ticks(), ns1;
		do ns1 = hl_prof_monotonic_ns(); while( ns1 - ns0 < 2000000 );
		nominal_hz = (now_ticks() - t0) * 1000000000ULL / (ns1 - ns0);
		tick_kind = HL_PROF_TICKS_TSC;
	} else {
#if defined(PROF_ARM64) && defined(_MSC_VER)
		nominal_hz = (unsigned long long)_ReadStatusReg(ARM64_CNTFRQ_EL0);
		tick_kind = HL_PROF_TICKS_CNTVCT;
#elif defined(PROF_ARM64)
		__asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(nominal_hz));
		tick_kind = HL_PROF_TICKS_CNTVCT;
#elif defined(HL_WIN)
		nominal_hz = qpc_frequency;
		tick_kind = HL_PROF_TICKS_QPC;
#else
		nominal_hz = 1000000000ULL;
		tick_kind = HL_PROF_TICKS_NS;
#endif
	}
}

HL_PRIM int hl_prof_tick_kind( void ) { clock_init(); return tick_kind; }
HL_PRIM unsigned long long hl_prof_nominal_hz( void ) { clock_init(); return nominal_hz; }
HL_PRIM unsigned long long hl_prof_base_ticks( void ) { return base_ticks; }

/* ---- chunk pool ------------------------------------------------------------------------------------------------- */

typedef struct {
	volatile int finished;      // set with release once size and next are final
	unsigned int size;          // bytes written, valid once finished
	int next;                   // the chunk the thread continued in, valid once finished
	int free_next;              // free list link
} prof_chunk;

static unsigned char *pool;
static prof_chunk *chunks;
static int chunk_count;
/* The free list head: tag << 32 | (index + 1), 0 when empty. The tag changes on every push and pop, against ABA. */
static volatile unsigned long long free_head;
static volatile long chunks_free;

static FORCE_INLINE unsigned char *chunk_data( int index ) {
	return pool + (size_t)index * HL_PROF_CHUNK_SIZE;
}

static int pool_pop( void ) {
	unsigned long long head, next;
	int index;
	do {
		head = free_head;
		if( (unsigned int)head == 0 ) return -1;
		index = (int)(unsigned int)head - 1;
		next = ((head >> 32) + 1) << 32 | (unsigned int)(chunks[index].free_next + 1);
	} while( !CAS64(&free_head,head,next) );
	FETCH_ADD32(&chunks_free,-1);
	return index;
}

static void pool_push( int index ) {
	unsigned long long head, next;
	do {
		head = free_head;
		chunks[index].free_next = (int)(unsigned int)head - 1;
		next = ((head >> 32) + 1) << 32 | (unsigned int)(index + 1);
	} while( !CAS64(&free_head,head,next) );
	FETCH_ADD32(&chunks_free,1);
}

static void pool_reset( void ) {
	free_head = 0;
	chunks_free = 0;
	for(int i=chunk_count-1;i>=0;i--) {
		chunks[i].finished = 0;
		pool_push(i);
	}
}

static bool pool_allocate( unsigned int pool_mib ) {
	int count = (int)(((unsigned long long)pool_mib << 20) / HL_PROF_CHUNK_SIZE);
	if( count < 16 ) count = 16;
	if( pool && count <= chunk_count ) return true;
	/* The pool lives as long as the process, so a record still being written when a session stops lands in valid memory.
	   A bigger session replaces it while no session records. */
	if( pool ) {
#ifdef HL_WIN
		VirtualFree(pool,0,MEM_RELEASE);
#else
		munmap(pool,(size_t)chunk_count * HL_PROF_CHUNK_SIZE);
#endif
		free(chunks);
		pool = NULL;
		chunks = NULL;
		chunk_count = 0;
	}
#ifdef HL_WIN
	pool = (unsigned char*)VirtualAlloc(NULL,(size_t)count * HL_PROF_CHUNK_SIZE,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
#else
	pool = (unsigned char*)mmap(NULL,(size_t)count * HL_PROF_CHUNK_SIZE,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
	if( pool == MAP_FAILED ) pool = NULL;
#endif
	chunks = (prof_chunk*)calloc((size_t)count,sizeof(prof_chunk));
	if( pool == NULL || chunks == NULL ) {
		free(chunks);
		chunks = NULL;
		pool = NULL;
		return false;
	}
	chunk_count = count;
	return true;
}

/* ---- thread states ---------------------------------------------------------------------------------------------- */

/* Calls dropped for being short, counted per key until the thread writes them as a PROFILE_EVENT_DROPPED_CALLS event. */
#define DROPPED_SLOTS 256
#define DROPPED_PROBES 8
typedef struct {
	unsigned long long key;
	unsigned int count;
} prof_dropped;

typedef struct prof_thread prof_thread;
struct prof_thread {
	/* Written by the producer. pos is published with release; the rest is the producer's own. Records are written at cur.
	   pos lags it over held, the run of ENTER records at the end that a short exit may still take back, and catches up
	   when anything after them is kept. */
	unsigned char *volatile pos;
	unsigned char *cur;
	unsigned char *held;
	int held_recording;         // recording_changes when the held run began: a pause in between keeps it
	unsigned char *end;
	int chunk;
	unsigned int session;
	unsigned int tid;
	volatile int first_chunk;   // the session's first chunk, published before pos moves into it
	volatile int exited;
	/* ENTER records minus EXIT records over the thread's life, across sessions, so a depth saved by a try before
	   recording started still measures what a throw skipped after it started. */
	int depth;
	int dropped_used;
	prof_dropped dropped[DROPPED_SLOTS];
	char producer_padding[64];
	/* Written by the consumer. */
	int read_chunk;
	unsigned int read_offset;
	prof_thread *next;
};

static HL_THREAD_VAR prof_thread *prof_current;
static prof_thread *threads;
static unsigned int session_id;
static volatile unsigned long long stall_count;
static volatile unsigned long long stall_ticks;
static unsigned long long drained_bytes;
/* Calls shorter than this are dropped as they exit (0 keeps every call). Set from min_call_ns when a session starts. */
static unsigned int min_call_ns;
static unsigned long long min_call_ticks;
static volatile int recording_changes;

HL_PRIM volatile int hl_prof_on = 0;

#ifdef HL_WIN
static SRWLOCK registry_lock = SRWLOCK_INIT;
#	define REGISTRY_LOCK() AcquireSRWLockExclusive(&registry_lock)
#	define REGISTRY_UNLOCK() ReleaseSRWLockExclusive(&registry_lock)
#else
static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
#	define REGISTRY_LOCK() pthread_mutex_lock(&registry_lock)
#	define REGISTRY_UNLOCK() pthread_mutex_unlock(&registry_lock)
#endif

static void thread_reset( prof_thread *t ) {
	t->pos = NULL;
	t->cur = NULL;
	t->held = NULL;
	t->end = NULL;
	t->dropped_used = 0;
	memset(t->dropped,0,sizeof(t->dropped));
	t->chunk = -1;
	t->first_chunk = -1;
	t->read_chunk = -1;
	t->read_offset = 0;
	t->session = session_id;
}

/* The calling thread's state for the current session: created on the thread's first record, reset when a new session
   begins. Slow path only. */
static prof_thread *thread_state( void ) {
	prof_thread *t = prof_current;
	if( t && t->session == session_id ) return t;
	REGISTRY_LOCK();
	if( t == NULL ) {
		t = (prof_thread*)calloc(1,sizeof(prof_thread));
		if( t == NULL ) { REGISTRY_UNLOCK(); return NULL; }
		t->tid = (unsigned int)hl_thread_id();
		t->next = threads;
		threads = t;
		prof_current = t;
	}
	if( t->session != session_id ) thread_reset(t);
	REGISTRY_UNLOCK();
	return t;
}

static void yield_thread( void ) {
#ifdef HL_WIN
	SwitchToThread();
#else
	sched_yield();
#endif
}

/* Moves the thread to a fresh chunk with room for bytes. When the pool is empty the thread waits for the consumer and the
   wait is recorded as a STALL. Returns NULL when recording stopped meanwhile. */
static unsigned char *next_chunk( prof_thread *t, unsigned int bytes ) {
	unsigned long long stall_started = 0;
	unsigned char *p;
	int index = pool_pop();
	if( bytes + 16 > HL_PROF_CHUNK_SIZE ) return NULL;
	while( index < 0 ) {
		if( !hl_prof_on ) return NULL;
		if( !stall_started ) stall_started = now_ticks();
		yield_thread();
		index = pool_pop();
	}
	/* The finished chunk keeps any held ENTER records: they can no longer be taken back. */
	t->held = NULL;
	if( t->chunk >= 0 ) {
		prof_chunk *old = chunks + t->chunk;
		old->size = (unsigned int)(t->cur - chunk_data(t->chunk));
		old->next = index;
		STORE_RELEASE_INT(&old->finished,1);
	} else
		STORE_RELEASE_INT(&t->first_chunk,index);
	chunks[index].finished = 0;
	t->chunk = index;
	p = chunk_data(index);
	t->end = p + HL_PROF_CHUNK_SIZE;
	if( stall_started ) {
		unsigned long long ended = now_ticks();
		((unsigned long long*)p)[0] = ((unsigned long long)HL_PROF_STALL << 56) | ((stall_started - base_ticks) & HL_PROF_TICK_MASK);
		((unsigned long long*)p)[1] = (ended - base_ticks) & HL_PROF_TICK_MASK;
		p += 16;
		FETCH_ADD64(&stall_count,1);
		FETCH_ADD64(&stall_ticks,ended - stall_started);
	}
	t->cur = p;
	STORE_RELEASE_PTR(&t->pos,p);
	return p;
}

/* Room for a record of bytes (a multiple of 8) on the calling thread, or NULL. */
static FORCE_INLINE unsigned char *reserve( prof_thread **out, unsigned int bytes ) {
	prof_thread *t = prof_current;
	unsigned char *p;
	if( t == NULL || t->session != session_id ) {
		t = thread_state();
		if( t == NULL ) return NULL;
	}
	p = t->cur;
	/* A chunk is never filled to its last byte, so a published position always lies inside its own chunk; a position at
	   the end would equal the start of the chunk after it in the pool. */
	if( p == NULL || (size_t)(t->end - p) <= bytes ) p = next_chunk(t,bytes);
	*out = t;
	return p;
}

static FORCE_INLINE unsigned long long head( int kind ) {
	return ((unsigned long long)kind << 56) | ((now_ticks() - base_ticks) & HL_PROF_TICK_MASK);
}

/* Keeps the record at p, and with it every ENTER record held before it. */
#define COMMIT(t,p,bytes) do { (t)->cur = (p) + (bytes); (t)->held = NULL; STORE_RELEASE_PTR(&(t)->pos,(t)->cur); } while(0)

/* ---- dropped calls ---------------------------------------------------------------------------------------------- */

/* Writes the thread's dropped-call counts as one PROFILE_EVENT_DROPPED_CALLS event (entries of u64 key, u32 count, u32 0)
   and clears them. The producer calls it, or the consumer once the producer can no longer write (stop, thread exit). */
static void write_dropped( prof_thread *t ) {
	unsigned int length = (unsigned int)t->dropped_used * 16, bytes = 16 + length, n = 0;
	unsigned char *p;
	if( !t->dropped_used ) return;
	p = t->cur;
	if( p == NULL || (size_t)(t->end - p) <= bytes ) p = next_chunk(t,bytes);
	if( p != NULL ) {
		((unsigned long long*)p)[0] = head(HL_PROF_EVENT);
		((unsigned long long*)p)[1] = (unsigned long long)PROFILE_EVENT_DROPPED_CALLS | ((unsigned long long)length << 32);
		for(int i=0;i<DROPPED_SLOTS;i++) {
			prof_dropped *d = t->dropped + i;
			if( !d->key ) continue;
			((unsigned long long*)(p + 16))[n * 2] = d->key;
			((unsigned long long*)(p + 16))[n * 2 + 1] = d->count;
			n++;
		}
		COMMIT(t,p,bytes);
	}
	memset(t->dropped,0,sizeof(t->dropped));
	t->dropped_used = 0;
}

static void count_dropped( prof_thread *t, unsigned long long key ) {
	unsigned int slot = (unsigned int)((key * 0x9E3779B97F4A7C15ULL) >> 56);
	prof_dropped *free_slot = NULL;
	for(int probe=0;probe<DROPPED_PROBES;probe++) {
		prof_dropped *d = t->dropped + ((slot + probe) & (DROPPED_SLOTS - 1));
		if( d->key == key ) {
			if( ++d->count == 0xFFFFFFFFu ) write_dropped(t);
			return;
		}
		if( d->key == 0 ) { free_slot = d; break; }
	}
	if( free_slot == NULL ) {
		write_dropped(t);
		free_slot = t->dropped + slot;
	}
	free_slot->key = key;
	free_slot->count = 1;
	t->dropped_used++;
}

/* Publishes what the thread holds back and writes its dropped-call counts, once it no longer records. */
static void release_thread( prof_thread *t ) {
	write_dropped(t);
	if( t->held ) {
		t->held = NULL;
		STORE_RELEASE_PTR(&t->pos,t->cur);
	}
}

/* ---- writers ---------------------------------------------------------------------------------------------------- */

HL_PRIM void hl_prof_enter( unsigned long long key ) {
	prof_thread *t;
	unsigned char *p;
	if( !hl_prof_on || (p = reserve(&t,16)) == NULL ) return;
	((unsigned long long*)p)[0] = head(HL_PROF_ENTER);
	((unsigned long long*)p)[1] = key;
	t->depth++;
	if( min_call_ticks ) {
		/* Held back: if the call turns out short, its exit takes this record back. */
		if( t->held == NULL ) {
			t->held = p;
			t->held_recording = recording_changes;
		}
		t->cur = p + 16;
	} else
		COMMIT(t,p,16);
}

HL_PRIM void hl_prof_exit( void ) {
	prof_thread *t = prof_current;
	unsigned char *p;
	unsigned long long now;
	if( !hl_prof_on ) return;
	now = now_ticks();
	/* With a run held, the innermost open call's ENTER is its last record. A short call is dropped by taking it back. */
	if( t != NULL && t->held != NULL && t->session == session_id && t->held_recording == recording_changes ) {
		unsigned long long *enter = (unsigned long long*)(t->cur - 16);
		if( (((now - base_ticks) & HL_PROF_TICK_MASK) - (enter[0] & HL_PROF_TICK_MASK)) < min_call_ticks ) {
			unsigned long long key = enter[1];
			t->cur -= 16;
			if( t->cur == t->held ) t->held = NULL;
			t->depth--;
			count_dropped(t,key);
			return;
		}
	}
	if( (p = reserve(&t,8)) == NULL ) return;
	((unsigned long long*)p)[0] = ((unsigned long long)HL_PROF_EXIT << 56) | ((now - base_ticks) & HL_PROF_TICK_MASK);
	t->depth--;
	COMMIT(t,p,8);
}

/* ---- native call keys ----------------------------------------------------------------------------------------------
   The first time a session sees a native key it is queued, for the consumer to name (hl_profile_name_native_keys). */

#define NATIVE_KEYS (1 << 16)
#define NATIVE_PROBES 32
static volatile unsigned long long native_keys[NATIVE_KEYS];
static volatile unsigned long long native_queue[NATIVE_KEYS];
static volatile long long native_queue_head;
static long long native_queue_tail;

static void native_key_seen( unsigned long long key ) {
	unsigned int slot = (unsigned int)((key * 0x9E3779B97F4A7C15ULL) >> 48);
	for(int probe=0;probe<NATIVE_PROBES;probe++) {
		volatile unsigned long long *entry = &native_keys[(slot + probe) & (NATIVE_KEYS - 1)];
		unsigned long long current = *entry;
		if( current == key ) return;
		if( current == 0 ) {
			if( CAS64(entry,0ULL,key) ) {
				long long index = (long long)FETCH_ADD64(&native_queue_head,1);
				/* A full queue loses the key's name, not the call: the consumer is far behind. */
				if( index - native_queue_tail < NATIVE_KEYS ) native_queue[index & (NATIVE_KEYS - 1)] = key;
				return;
			}
			if( *entry == key ) return;
		}
	}
	/* The set is full around this slot: the key stays unnamed. */
}

HL_PRIM void hl_prof_enter_native( unsigned long long key ) {
	if( !hl_prof_on ) return;
	native_key_seen(key);
	hl_prof_enter(key);
}

HL_PRIM int hl_prof_native_keys_take( unsigned long long *keys, int max ) {
	int count = 0;
	while( count < max && native_queue_tail < native_queue_head ) {
		volatile unsigned long long *entry = &native_queue[native_queue_tail & (NATIVE_KEYS - 1)];
		unsigned long long key = *entry;
		/* Claimed but not stored yet. */
		if( key == 0 ) break;
		*entry = 0;
		native_queue_tail++;
		keys[count++] = key;
	}
	return count;
}

HL_PRIM void hl_prof_native_keys_reset( void ) {
	memset((void*)native_keys,0,sizeof(native_keys));
	memset((void*)native_queue,0,sizeof(native_queue));
	native_queue_head = native_queue_tail = 0;
}

HL_PRIM int hl_prof_depth( void ) {
	prof_thread *t = prof_current;
	return t ? t->depth : 0;
}

HL_PRIM void hl_prof_unwind( int depth ) {
	prof_thread *t = prof_current;
	unsigned char *p;
	int skipped;
	if( t == NULL || t->depth <= depth ) return;
	skipped = t->depth - depth;
	t->depth = depth;
	if( !hl_prof_on || (p = reserve(&t,16)) == NULL ) return;
	((unsigned long long*)p)[0] = head(HL_PROF_UNWIND);
	((unsigned long long*)p)[1] = (unsigned long long)skipped;
	COMMIT(t,p,16);
}

/* Probes the compiler inserts into instrumented Haxe functions. The key is the probe's return address: it lies in the
   calling function's code, which the symbol metadata names, and each live revision has code of its own. */
#if defined(_MSC_VER)
#	define PROF_RETURN_ADDRESS() _ReturnAddress()
#else
#	define PROF_RETURN_ADDRESS() __builtin_return_address(0)
#endif

HL_PRIM void hl_prof_call_enter( void ) {
	if( hl_prof_on ) hl_prof_enter((unsigned long long)(uintptr_t)PROF_RETURN_ADDRESS());
}

HL_PRIM void hl_prof_call_exit( void ) {
	if( hl_prof_on ) hl_prof_exit();
}

HL_PRIM int hl_prof_call_depth( void ) {
	return hl_prof_depth();
}

HL_PRIM void hl_prof_call_unwind( int depth ) {
	hl_prof_unwind(depth);
}

DEFINE_PRIM(_VOID, prof_call_enter, _NO_ARG);
DEFINE_PRIM(_VOID, prof_call_exit, _NO_ARG);
DEFINE_PRIM(_I32, prof_call_depth, _NO_ARG);
DEFINE_PRIM(_VOID, prof_call_unwind, _I32);

#define PAD8(n) (((n) + 7u) & ~7u)
#define MAX_NAME_UNITS 1024

static void write_named( int kind, const void *name, int units, int encoding, const double *value ) {
	prof_thread *t;
	unsigned char *p;
	unsigned int size, words, bytes;
	if( units < 0 ) units = 0;
	if( units > MAX_NAME_UNITS ) units = MAX_NAME_UNITS;
	size = (unsigned int)units * (encoding == HL_PROF_UTF16 ? 2u : 1u);
	words = value ? 3 : 2;
	bytes = words * 8 + PAD8(size);
	if( (p = reserve(&t,bytes)) == NULL ) return;
	((unsigned long long*)p)[0] = head(kind);
	if( value ) memcpy(p + 8,value,8);
	((unsigned long long*)p)[words - 1] = (unsigned long long)(unsigned int)units | ((unsigned long long)(unsigned int)encoding << 32);
	if( size ) memcpy(p + words * 8,name,size);
	COMMIT(t,p,bytes);
}

HL_PRIM void hl_prof_span_begin( const void *name, int units, int encoding ) {
	if( !hl_prof_on ) return;
	write_named(HL_PROF_SPAN_BEGIN,name,units,encoding,NULL);
}

HL_PRIM void hl_prof_span_end( void ) {
	prof_thread *t;
	unsigned char *p;
	if( !hl_prof_on || (p = reserve(&t,8)) == NULL ) return;
	((unsigned long long*)p)[0] = head(HL_PROF_SPAN_END);
	COMMIT(t,p,8);
}

HL_PRIM void hl_prof_frame( int kind, unsigned int frame_set ) {
	prof_thread *t;
	unsigned char *p;
	if( !hl_prof_on || (p = reserve(&t,16)) == NULL ) return;
	((unsigned long long*)p)[0] = head(kind ? HL_PROF_FRAME_IDLE : HL_PROF_FRAME_MARK);
	((unsigned long long*)p)[1] = frame_set;
	COMMIT(t,p,16);
	/* A frame's dropped calls are counted within it. */
	write_dropped(t);
}

HL_PRIM void hl_prof_counter( const void *name, int units, int encoding, double value ) {
	if( !hl_prof_on ) return;
	write_named(HL_PROF_COUNTER,name,units,encoding,&value);
}

HL_PRIM void hl_prof_event( unsigned int id, const void *payload, unsigned int length ) {
	prof_thread *t;
	unsigned char *p;
	unsigned int bytes;
	if( !hl_prof_on || length > HL_PROF_CHUNK_SIZE - 64 ) return;
	bytes = 16 + PAD8(length);
	if( (p = reserve(&t,bytes)) == NULL ) return;
	((unsigned long long*)p)[0] = head(HL_PROF_EVENT);
	((unsigned long long*)p)[1] = (unsigned long long)id | ((unsigned long long)length << 32);
	if( length ) memcpy(p + 16,payload,length);
	COMMIT(t,p,bytes);
}

HL_PRIM void hl_prof_sample( unsigned int tid, int flags, void **frames, int count, unsigned long long ticks ) {
	prof_thread *t;
	unsigned char *p;
	unsigned int bytes;
	if( !hl_prof_on || count < 0 ) return;
	if( count > 0xFFFF ) count = 0xFFFF;
	bytes = 16 + (unsigned int)count * 8;
	if( bytes > HL_PROF_CHUNK_SIZE - 64 || (p = reserve(&t,bytes)) == NULL ) return;
	((unsigned long long*)p)[0] = ((unsigned long long)HL_PROF_SAMPLE << 56) | ((ticks - base_ticks) & HL_PROF_TICK_MASK);
	((unsigned long long*)p)[1] = (unsigned long long)tid | ((unsigned long long)(unsigned int)count << 32) | ((unsigned long long)(flags & 0xFF) << 48);
	for(int i=0;i<count;i++) ((unsigned long long*)p)[2 + i] = (unsigned long long)(uintptr_t)frames[i];
	COMMIT(t,p,bytes);
}

/* ---- session ---------------------------------------------------------------------------------------------------- */

/* A session is open from hl_prof_start to hl_prof_stop; it records while hl_prof_on is set, which pausing clears. */
static volatile int session_open;
static volatile long recording_toggle;

HL_PRIM void hl_prof_set_min_call_ns( unsigned int ns ) {
	min_call_ns = ns;
}

HL_PRIM bool hl_prof_start( unsigned int pool_mib ) {
	if( session_open ) return false;
	clock_init();
	min_call_ticks = 0;
	if( min_call_ns ) {
		min_call_ticks = (unsigned long long)((double)min_call_ns * (double)nominal_hz / 1e9);
		if( min_call_ticks == 0 ) min_call_ticks = 1;
	}
	if( pool_mib == 0 ) pool_mib = 64;
	if( !pool_allocate(pool_mib) ) return false;
	REGISTRY_LOCK();
	pool_reset();
	session_id++;
	stall_count = 0;
	stall_ticks = 0;
	drained_bytes = 0;
	base_ticks = now_ticks();
	REGISTRY_UNLOCK();
	session_open = 1;
	STORE_RELEASE_INT(&hl_prof_on,1);
	return true;
}

HL_PRIM bool hl_prof_set_recording( bool on ) {
	unsigned char payload[4] = { 0, 0, 0, 0 };
	bool ok = true;
	/* One toggle at a time, so the RECORDING events alternate. */
#ifdef _MSC_VER
	while( _InterlockedCompareExchange(&recording_toggle,1,0) != 0 ) {}
#else
	while( !__sync_bool_compare_and_swap(&recording_toggle,0,1) ) {}
#endif
	if( !session_open ) ok = false;
	else if( on != (hl_prof_on != 0) ) {
		if( !on ) {
			hl_prof_event(PROFILE_EVENT_RECORDING,payload,4);
			STORE_RELEASE_INT(&hl_prof_on,0);
		} else {
			payload[0] = 1;
			STORE_RELEASE_INT(&hl_prof_on,1);
			hl_prof_event(PROFILE_EVENT_RECORDING,payload,4);
		}
		recording_changes++;
	}
	recording_toggle = 0;
	return ok;
}

HL_PRIM int hl_prof_recording_changes( void ) {
	return recording_changes;
}

HL_PRIM bool hl_prof_session_open( void ) {
	return session_open != 0;
}

/* haxeon.ProfileRecording: starts or pauses recording from the program. Returns false when no session is open. */
HL_PRIM bool hl_prof_recording_set( bool on ) {
	return hl_prof_set_recording(on);
}

HL_PRIM bool hl_prof_recording_get( void ) {
	return hl_prof_on != 0;
}

DEFINE_PRIM(_BOOL, prof_recording_set, _BOOL);
DEFINE_PRIM(_BOOL, prof_recording_get, _NO_ARG);

HL_PRIM void hl_prof_stop( void ) {
	prof_thread *t;
	if( !session_open ) return;
	session_open = 0;
	if( hl_prof_on ) {
		STORE_RELEASE_INT(&hl_prof_on,0);
		/* A producer that saw recording on may still be writing its record: give it time to publish before the final
		   drain. */
#ifdef HL_WIN
		Sleep(2);
#else
		{ struct timespec wait = { 0, 2000000 }; nanosleep(&wait,NULL); }
#endif
	}
	/* The producers no longer write: publish what they hold back, for the final drain. */
	REGISTRY_LOCK();
	for(t=threads;t;t=t->next)
		if( t->session == session_id && !t->exited ) release_thread(t);
	REGISTRY_UNLOCK();
}

/* Hands a thread's new records to fn. Consumer only, with the registry locked. */
static unsigned long long drain_thread( prof_thread *t, hl_prof_segment_fn fn, void *context ) {
	unsigned long long total = 0;
	if( t->session != session_id ) return 0;
	if( t->read_chunk < 0 ) {
		int first = LOAD_ACQUIRE_INT(&t->first_chunk);
		if( first < 0 ) return 0;
		t->read_chunk = first;
		t->read_offset = 0;
	}
	while( true ) {
		unsigned char *base = chunk_data(t->read_chunk);
		unsigned char *pos = (unsigned char*)LOAD_ACQUIRE_PTR(&t->pos);
		if( pos >= base && pos < base + HL_PROF_CHUNK_SIZE ) {
			unsigned int end = (unsigned int)(pos - base);
			if( end > t->read_offset ) {
				fn(context,t->tid,base + t->read_offset,end - t->read_offset);
				total += end - t->read_offset;
				t->read_offset = end;
			}
			return total;
		}
		/* The producer has moved on: this chunk is finished. */
		prof_chunk *c = chunks + t->read_chunk;
		if( !LOAD_ACQUIRE_INT(&c->finished) ) return total;
		if( c->size > t->read_offset ) {
			fn(context,t->tid,base + t->read_offset,c->size - t->read_offset);
			total += c->size - t->read_offset;
		}
		{
			int next = c->next;
			pool_push(t->read_chunk);
			t->read_chunk = next;
			t->read_offset = 0;
		}
	}
}

HL_PRIM unsigned long long hl_prof_drain( hl_prof_segment_fn fn, void *context ) {
	unsigned long long total = 0;
	prof_thread *t, **link;
	REGISTRY_LOCK();
	link = &threads;
	while( (t = *link) != NULL ) {
		total += drain_thread(t,fn,context);
		if( LOAD_ACQUIRE_INT(&t->exited) ) {
			/* Its last records were drained above: return its chunk and forget it. */
			if( t->session == session_id && t->chunk >= 0 ) pool_push(t->chunk);
			*link = t->next;
			free(t);
			continue;
		}
		link = &t->next;
	}
	drained_bytes += total;
	REGISTRY_UNLOCK();
	return total;
}

HL_PRIM void hl_prof_get_stats( hl_prof_stats *stats ) {
	stats->chunk_count = chunk_count;
	stats->chunks_in_use = chunk_count - (int)chunks_free;
	stats->stalls = stall_count;
	stats->stall_ticks = stall_ticks;
	stats->drained_bytes = drained_bytes;
}

HL_PRIM void hl_prof_thread_exit( void ) {
	prof_thread *t = prof_current;
	if( t == NULL ) return;
	prof_current = NULL;
	REGISTRY_LOCK();
	if( hl_prof_on && t->session == session_id ) {
		/* The consumer drains what is left, then frees it. */
		release_thread(t);
		STORE_RELEASE_INT(&t->exited,1);
	} else {
		prof_thread **link = &threads;
		while( *link && *link != t ) link = &(*link)->next;
		if( *link ) *link = t->next;
		free(t);
	}
	REGISTRY_UNLOCK();
}
