/*
 * Copyright (C)2005-2016 Haxe Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include "hl.h"
HL_API double hl_sys_time( void );
#ifdef HL_WIN
#	undef _GUID
#	include <windows.h>
#	include <intrin.h>
#else
#	include <sys/types.h>
#	include <sys/mman.h>
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#	include <pthread.h>
#	include <libkern/OSCacheControl.h>
#endif

#if defined(HL_EMSCRIPTEN)
#	include <emscripten/heap.h>
#endif

#if defined(HL_VCC)
#define DRAM_PREFETCH(addr) _mm_prefetch(p, 1)
#elif defined(HL_CLANG) || defined (HL_GCC)
#define DRAM_PREFETCH(addr) __builtin_prefetch(addr)
#elif
#define DRAM_PREFETCH(addr)
#endif

#define MZERO(ptr,size)		memset(ptr,0,size)

// GC

#define GC_PAGE_BITS	16
#define GC_PAGE_SIZE	(1 << GC_PAGE_BITS)

#ifndef HL_64
#	define gc_hash(ptr)			((unsigned int)(ptr))
#	define GC_LEVEL0_BITS		8
#	define GC_LEVEL1_BITS		8
#else
#	define GC_LEVEL0_BITS		10
#	define GC_LEVEL1_BITS		10

// we currently discard the higher bits
// we should instead have some special handling for them
// in x86-64 user space grows up to 0x8000-00000000 (16 bits base + 31 bits page id)

#ifdef HL_WIN
#	define gc_hash(ptr)			((int_val)(ptr)&0x0000000FFFFFFFFF)
#else
// Linux gives addresses using the following patterns (X=any,Y=small value - can be 0):
//		0x0000000YXXX0000
//		0x0007FY0YXXX0000
static int_val gc_hash( void *ptr ) {
	int_val v = (int_val)ptr;
	return (v ^ ((v >> 33) << 28)) & 0x0000000FFFFFFFFF;
}
#endif

#endif

#define GC_MASK_BITS		16
#define GC_GET_LEVEL1(ptr)	hl_gc_page_map[gc_hash(ptr)>>(GC_MASK_BITS+GC_LEVEL1_BITS)]
#define GC_GET_PAGE(ptr)	GC_GET_LEVEL1(ptr)[(gc_hash(ptr)>>GC_MASK_BITS)&GC_LEVEL1_MASK]
#define GC_LEVEL1_MASK		((1 << GC_LEVEL1_BITS) - 1)

#define PAGE_KIND_BITS		2
#define PAGE_KIND_MASK		((1 << PAGE_KIND_BITS) - 1)

#if defined(HL_DEBUG) && !defined(HL_CONSOLE)
#	define GC_DEBUG
#	define GC_MEMCHK
#endif

#define GC_INTERIOR_POINTERS
#define GC_PRECISE

#ifndef HL_THREADS
#	define GC_MAX_MARK_THREADS 1
#else
#	ifndef GC_MAX_MARK_THREADS
#	define GC_MAX_MARK_THREADS 4
#	endif
#endif

#define out_of_memory(reason)		hl_fatal("Out of Memory (" reason ")")

typedef struct _gc_pheader gc_pheader;

// page + private total reserved data per page
typedef void (*gc_page_iterator)( gc_pheader *, int );
// block-ptr + size
typedef void (*gc_block_iterator)( void *, int );

//#define GC_EXTERN_API

#ifdef GC_EXTERN_API
typedef void* gc_allocator_page_data;

// Initialize the allocator
void gc_allocator_init();

// Get the block size within the given page. The block validity has already been checked.
int gc_allocator_fast_block_size( gc_pheader *page, void *block );

// Get the block id within the given page, or -1 if it's an invalid ptr. The block is already checked within page bounds
int gc_allocator_get_block_id( gc_pheader *page, void *block );

// Same as get_block_id but handles interior pointers and modify the block value
int gc_allocator_get_block_id_interior( gc_pheader *page, void **block );

// Called before marking starts: should update each page "bmp" with mark_bits
void gc_allocator_before_mark( unsigned char *mark_bits );

// Called when marking ends: should call finalizers, sweep unused blocks and free empty pages
void gc_allocator_after_mark();

// Allocate a block with given size using the specified page kind.
// Returns NULL if no block could be allocated
// Sets size to really allocated size (could be larger)
// Sets size to -1 if allocation refused (required size is invalid)
void *gc_allocator_alloc( int *size, int page_kind );

// returns the number of pages allocated and private data size (global)
void gc_get_stats( int *page_count, int *private_data);
void gc_iter_pages( gc_page_iterator i );
void gc_iter_live_blocks( gc_pheader *p, gc_block_iterator i );

#else
#	include "allocator.h"
#endif

struct _gc_pheader {
	// const
	unsigned char *base;
	unsigned char *bmp;
	unsigned char *incremental_bmp;
	uint64 incremental_epoch;
	unsigned char *validation_bmp;
	unsigned int software_dirty;
	unsigned int scan_dirty_sources;
	void *scan_profile;
	gc_pheader *software_dirty_next;
	int page_size;
	int page_kind;
	gc_allocator_page_data alloc;
	gc_pheader *next_page;
#ifdef GC_DEBUG
	int page_id;
#endif
};

#ifdef HL_64
#	define INPAGE(ptr,page) ((unsigned char*)(ptr) >= (page)->base && (unsigned char*)(ptr) < (page)->base + (page)->page_size)
#else
#	define INPAGE(ptr,page) true
#endif

#define GC_PROFILE		1
#define GC_DUMP_MEM		2
#define GC_NO_THREADS	4
#define GC_FORCE_MAJOR	8
#define GC_PROFILE_MEM  16

static int gc_flags = 0;
static gc_pheader *gc_level1_null[1<<GC_LEVEL1_BITS] = {NULL};
static gc_pheader **hl_gc_page_map[1<<GC_LEVEL0_BITS] = {NULL};
static gc_pheader *gc_free_pheaders = NULL;

typedef struct _gc_owned_alloc gc_owned_alloc;
struct _gc_owned_alloc {
	void *ptr;
	void *owner;
	gc_owned_alloc *next;
};
static gc_owned_alloc *gc_owned_allocs = NULL;
/* Opt-in diagnostics: no per-phase clocks when disabled. */
static bool gc_latency_trace;
static bool gc_scan_profile_enabled;
static double gc_latency_finalizers;
// The flag is also a generated allocation guard: incremental cycles cannot use TLABs.
static uint64 gc_incremental_epoch;
static bool gc_incremental_active = false;
static bool gc_incremental_enabled = false;
// Experimental pacing controls; pressure limits retain the ordinary threshold.
static int gc_inc_start_percent = 100;
static int64 gc_inc_step_bytes = 256 << 10;
static bool gc_incremental_bitmaps = false;
static void gc_incremental_allocated(void *ptr);
static void gc_incremental_discard(void);


static gc_pheader *gc_alloc_page( int size, int kind, int block_count );
static void gc_free_page( gc_pheader *page, int block_count );
static int64 gc_total_allocated_bytes( void );

#ifndef GC_EXTERN_API
#include "allocator.c"
#endif

#if defined(HL_THREADS) && !defined(GC_EXTERN_API) && !defined(GC_DEBUG) && !defined(GC_MEMCHK)
#	define GC_TLAB
// Allocation buffers. Each thread reserves a run of consecutive free blocks of one size class and then hands them
// out without taking the global lock or touching shared counters. A slot is only written by its own thread while it
// runs, and by the collector once the thread is blocked, so no atomic is needed.
#	define GC_TLAB_SLOTS	(GC_FIXED_PARTS << PAGE_KIND_BITS)
#	define GC_TLAB_RUN		2048
#if defined(__x86_64__) || defined(_M_X64)
# define GC_ALLOC_FAST_SUPPORTED
static bool gc_alloc_fast = true;
#endif
typedef struct {
	unsigned char *cur;
	unsigned char *end;
} gc_tlab_slot;
#endif

// Publishes this thread's earlier writes before the collector can see it blocked (the collector then clears the
// thread's allocation buffers).
#if defined(__GNUC__)
#	define gc_release_fence() __atomic_thread_fence(__ATOMIC_RELEASE)
#else
#	define gc_release_fence()
#endif

static void gc_sweep_owned_allocs() {
	gc_owned_alloc **cursor = &gc_owned_allocs;
	while( *cursor ) {
		gc_owned_alloc *owned = *cursor;
		gc_pheader *page = GC_GET_PAGE(owned->ptr);
		int bid = page == NULL ? -1 : gc_allocator_get_block_id(page,owned->ptr);
		if( bid >= 0 && (page->bmp[bid>>3] & (1<<(bid&7))) != 0 ) {
			cursor = &owned->next;
			continue;
		}
		*cursor = owned->next;
		free(owned);
	}
}

static hl_threads_info gc_threads;

#if defined(__linux__) && !defined(__ANDROID__) && defined(__GNUC__)
// The VM is linked in at startup, so the cheap initial-exec TLS model applies and each allocation skips __tls_get_addr.
HL_THREAD_STATIC_VAR hl_thread_info *current_thread __attribute__((tls_model("initial-exec")));
#else
HL_THREAD_STATIC_VAR hl_thread_info *current_thread;
#endif

static struct {
	int64 total_requested;
	int64 total_allocated;
	int64 last_mark;
	int64 last_mark_allocs;
	int64 pages_total_memory;
	int64 allocation_count;
	int64 free_memory;
	int pages_count;
	int pages_allocated;
	int pages_blocks;
	int mark_bytes;
	int mark_time;
	double mark_duration_ms;
	double last_mark_ms;
	double max_mark_ms;
	int mark_count;
	int alloc_time; // only measured if gc_profile active
} gc_stats = {0};

static int64 gc_total_allocated_bytes( void ) {
	return gc_stats.total_allocated;
}

static struct {
	int64 total_allocated;
	int64 allocation_count;
	int alloc_time;
} last_profile;

#ifdef HL_WIN
#	define TIMESTAMP() ((int)GetTickCount())
#else
#	define TIMESTAMP() 0
#endif

// -------------------------  ROOTS ----------------------------------------------------------

static void ***gc_roots = NULL;
static void **gc_root_owners = NULL;
static int gc_roots_count = 0;
static int gc_roots_max = 0;
// Root addresses are indexed so temporary FFI roots do not require a linear scan on release.
static int *gc_root_buckets = NULL, *gc_root_next = NULL, *gc_root_previous = NULL;

HL_API hl_thread_info *hl_get_thread() {
	return current_thread;
}

static void gc_save_context(hl_thread_info *t, void *prev_stack ) {
	setjmp(t->gc_regs);
	// some compilers (such as clang) might push/pop some callee registers in call
	// to gc_save_context (or before) which might hold a gc value !
	// let's capture them immediately in extra per-thread data
	t->stack_cur = &prev_stack;

#	ifndef HL_DEBUG
	void* stack_cur = &t;
	// We have no guarantee prev_stack is pointer-aligned
	// All calls are passing a pointer to a bool, which is aligned on 1 byte
	// If pointer is wrongly aligned, the extra_stack_data is misaligned
	// and register pointers save in stack will not be discovered correctly by the GC
	uintptr_t aligned_prev_stack = ((uintptr_t)prev_stack) & ~(sizeof(void*) - 1);
	prev_stack = (void*)aligned_prev_stack;
	int size = (int)((char*)prev_stack - (char*)stack_cur) / sizeof(void*);
	if( size > HL_MAX_EXTRA_STACK ) hl_fatal("GC_SAVE_CONTEXT");
	t->extra_stack_size = size;
	memcpy(t->extra_stack_data, prev_stack, size*sizeof(void*));
#	endif
}

#ifndef HL_THREADS
#	define gc_global_lock(_)
#else
static void gc_global_lock( bool lock ) {
	hl_thread_info *t = current_thread;
	bool mt = (gc_flags & GC_NO_THREADS) == 0;
	if( !t && gc_threads.count == 0 ) return;
	if( lock ) {
		if( !t )
			hl_fatal("Can't lock GC in unregistered thread");
		// Another thread can only be collecting while it holds this lock, and it then needs our registers and stack
		// to scan before we block. When the lock is free nobody is: skip the context save, which is a setjmp and a
		// stack copy on every allocation. A thread that goes on to collect saves its own context in gc_stop_world.
		if( mt && !hl_mutex_try_acquire(gc_threads.global_lock) ) {
			gc_save_context(t,&lock);
			gc_release_fence();
			t->gc_blocking++;
			hl_mutex_acquire(gc_threads.global_lock);
			return;
		}
		t->gc_blocking++;
	} else {
		t->gc_blocking--;
		if( mt ) hl_mutex_release(gc_threads.global_lock);
	}
}
#endif

HL_PRIM void hl_global_lock( bool lock ) {
	if( lock )
		hl_mutex_acquire(gc_threads.exclusive_lock);
	else
		hl_mutex_release(gc_threads.exclusive_lock);
}

static unsigned int gc_root_bucket( void *r ) {
	size_t value = (size_t)r;
	value ^= value >> 16;
	value *= 2654435761u;
	value ^= value >> 16;
	return (unsigned int)value & (gc_roots_max * 2 - 1);
}

static void gc_root_link( int index ) {
	unsigned int bucket = gc_root_bucket(gc_roots[index]);
	int head = gc_root_buckets[bucket];
	gc_root_previous[index] = -1;
	gc_root_next[index] = head;
	if( head >= 0 ) gc_root_previous[head] = index;
	gc_root_buckets[bucket] = index;
}

static void gc_root_unlink( int index ) {
	int previous = gc_root_previous[index], next = gc_root_next[index];
	if( previous >= 0 ) gc_root_next[previous] = next;
	else gc_root_buckets[gc_root_bucket(gc_roots[index])] = next;
	if( next >= 0 ) gc_root_previous[next] = previous;
}

HL_API void hl_add_root_owner( void *r, void *owner ) {
	gc_global_lock(true);
	if( gc_roots_count == gc_roots_max ) {
		int nroots = gc_roots_max ? (gc_roots_max << 1) : 16;
		void ***roots = (void***)malloc(sizeof(void*)*nroots);
		void **owners = (void**)malloc(sizeof(void*)*nroots);
		int *buckets = (int*)malloc(sizeof(int)*nroots*2);
		int *next = (int*)malloc(sizeof(int)*nroots);
		int *previous = (int*)malloc(sizeof(int)*nroots);
		if( roots == NULL || owners == NULL || buckets == NULL || next == NULL || previous == NULL )
			out_of_memory("roots");
		memcpy(roots,gc_roots,sizeof(void*)*gc_roots_count);
		memcpy(owners,gc_root_owners,sizeof(void*)*gc_roots_count);
		free(gc_roots); free(gc_root_owners);
		free(gc_root_buckets); free(gc_root_next); free(gc_root_previous);
		gc_roots = roots; gc_root_owners = owners;
		gc_root_buckets = buckets; gc_root_next = next; gc_root_previous = previous;
		gc_roots_max = nroots;
		for(int i=0;i<nroots*2;i++) buckets[i] = -1;
		for(int i=0;i<gc_roots_count;i++) gc_root_link(i);
	}
	gc_roots[gc_roots_count] = (void**)r;
	gc_root_owners[gc_roots_count] = owner;
	gc_root_link(gc_roots_count++);
	gc_global_lock(false);
}

HL_PRIM void hl_add_root( void *r ) {
	hl_add_root_owner(r,NULL);
}

HL_PRIM void hl_remove_root( void *v ) {
	int found = -1;
	gc_global_lock(true);
	if( gc_roots_count > 0 ) {
		for(int i=gc_root_buckets[gc_root_bucket(v)];i>=0;i=gc_root_next[i])
			// Preserve the old reverse-array lookup for duplicate registrations.
			if( gc_roots[i] == (void**)v && i > found ) found = i;
	}
	if( found >= 0 ) {
		gc_root_unlink(found);
		int last = --gc_roots_count;
		if( found != last ) {
			gc_roots[found] = gc_roots[last];
			gc_root_owners[found] = gc_root_owners[last];
			int previous = gc_root_previous[last], next = gc_root_next[last];
			gc_root_previous[found] = previous;
			gc_root_next[found] = next;
			if( previous >= 0 ) gc_root_next[previous] = found;
			else gc_root_buckets[gc_root_bucket(gc_roots[found])] = found;
			if( next >= 0 ) gc_root_previous[next] = found;
		}
	}
	gc_global_lock(false);
}

HL_API int hl_gc_owner_root_count( void *owner ) {
	int count = 0;
	if( owner == NULL ) return 0;
	gc_global_lock(true);
	for(int i=0;i<gc_roots_count;i++)
		if( gc_root_owners[i] == owner ) count++;
	gc_global_lock(false);
	return count;
}

HL_PRIM gc_pheader *hl_gc_get_page( void *v ) {
	gc_pheader *page = GC_GET_PAGE(v);
	if( page && !INPAGE(v,page) )
		page = NULL;
	return page;
}

// -------------------------  THREADS ----------------------------------------------------------

HL_API int hl_thread_id();

HL_API void hl_register_thread( void *stack_top ) {
	if( hl_get_thread() )
		hl_fatal("Thread already registered");

	hl_thread_info *t = (hl_thread_info*)malloc(sizeof(hl_thread_info));
	memset(t, 0, sizeof(hl_thread_info));
#	ifdef GC_TLAB
	t->gc_tlab = calloc(GC_TLAB_SLOTS,sizeof(gc_tlab_slot));
	if( t->gc_tlab == NULL ) out_of_memory("thread allocation buffers");
#	endif
	t->thread_id = hl_thread_id();
	#ifdef HL_MAC
	t->mach_thread_id = mach_thread_self();
	t->pthread_id = (pthread_t)hl_thread_current();
	#endif
	t->stack_top = stack_top;
	t->flags = HL_TRACK_MASK << HL_TREAD_TRACK_SHIFT;
	current_thread = t;
	if( hl_setup.thread_registered ) hl_setup.thread_registered();
	hl_add_root(&t->exc_value);
	hl_add_root(&t->exc_handler);

	gc_global_lock(true);
	hl_thread_info **all = (hl_thread_info**)malloc(sizeof(void*) * (gc_threads.count + 1));
	memcpy(all,gc_threads.threads,sizeof(void*)*gc_threads.count);
	gc_threads.threads = all;
	all[gc_threads.count++] = t;
	gc_global_lock(false);
}

HL_API void hl_unregister_thread() {
	int i;
	hl_thread_info *t = hl_get_thread();
	if( !t )
		hl_fatal("Thread not registered");
	if( hl_setup.thread_unregistered ) hl_setup.thread_unregistered();
	hl_remove_root(&t->exc_value);
	hl_remove_root(&t->exc_handler);
	gc_global_lock(true);
	for(i=0;i<gc_threads.count;i++)
		if( gc_threads.threads[i] == t ) {
			memmove(gc_threads.threads + i, gc_threads.threads + i + 1, sizeof(void*) * (gc_threads.count - i - 1));
			gc_threads.count--;
			break;
		}
#	ifdef GC_TLAB
	free(t->gc_tlab);
#	endif
	free(t);
	current_thread = NULL;
	// don't use gc_global_lock(false)
	hl_mutex_release(gc_threads.global_lock);
}

HL_API hl_threads_info *hl_gc_threads_info() {
	return &gc_threads;
}

static void gc_stop_world( bool b ) {
#	ifdef HL_THREADS
	if( b ) {
		int i;
		// the collecting thread publishes its own context here: gc_global_lock does not on the uncontended path
		if( current_thread ) gc_save_context(current_thread,&b);
		gc_threads.stopping_world = true;
		for(i=0;i<gc_threads.count;i++) {
			hl_thread_info *t = gc_threads.threads[i];
			while( t->gc_blocking == 0 ) {}; // spinwait
		}
#		ifdef GC_TLAB
		// The blocks reserved in allocation buffers and not handed out are unmarked, so the sweep frees them. The
		// buffers must be empty before that, or they would hand out blocks the free lists have again.
		for(i=0;i<gc_threads.count;i++) {
			hl_thread_info *t = gc_threads.threads[i];
			if( t->gc_tlab ) memset(t->gc_tlab,0,GC_TLAB_SLOTS*sizeof(gc_tlab_slot));
		}
#		endif
	} else {
		// releasing global lock will release all threads
		gc_threads.stopping_world = false;
	}
#	else
	if( b ) gc_save_context(current_thread,&b);
#	endif
}

// -------------------------  ALLOCATOR ----------------------------------------------------------

#ifdef GC_DEBUG
static int PAGE_ID = 0;
#endif

HL_API void hl_gc_dump_memory( const char *filename );
static void gc_major( void );

static void *gc_will_collide( void *p, int size ) {
#	ifdef HL_64
	int i;
	for(i=0;i<size>>GC_MASK_BITS;i++) {
		void *ptr = (unsigned char*)p + (i<<GC_MASK_BITS);
		if( GC_GET_PAGE(ptr) )
			return ptr;
	}
#	endif
	return NULL;
}

static void gc_free_page_memory( void *ptr, int page_size );
static void *gc_alloc_page_memory( int size );

static gc_pheader *gc_alloc_page( int size, int kind, int block_count ) {
	unsigned char *base = (unsigned char*)gc_alloc_page_memory(size);
	if( !base ) {
		int pages = gc_stats.pages_allocated;
		gc_major();
		if( pages != gc_stats.pages_allocated )
			return gc_alloc_page(size, kind, block_count);
		// big block : report stack trace - we should manage to handle it
		if( size >= (8 << 20) ) {
			gc_global_lock(false);
			hl_error("Failed to alloc %d KB",size>>10);
		}
		if( gc_flags & GC_DUMP_MEM ) hl_gc_dump_memory("hlmemory.dump");
		out_of_memory("pages");
	}

	gc_pheader *p = gc_free_pheaders;
	if( !p ) {
		// alloc pages by chunks so we get good memory locality
		int i, count = 100;
		gc_pheader *head = (gc_pheader*)malloc(sizeof(gc_pheader)*count);
		p = head;
		for(i=1;i<count-1;i++) {
			p->next_page = head + i;
			p = p->next_page;
		}
		p->next_page = NULL;
		p = gc_free_pheaders = head;
	}
	gc_free_pheaders = p->next_page;
	memset(p,0,sizeof(gc_pheader));
	p->base = (unsigned char*)base;
	p->page_size = size;

#	ifdef HL_64
	void *ptr = gc_will_collide(p->base,size);
	if( ptr ) {
#		ifdef HL_VCC
		printf("GC Page HASH collide %IX %IX\n",(int_val)GC_GET_PAGE(ptr),(int_val)ptr);
#		else
		printf("GC Page HASH collide %lX %lX\n",(int_val)GC_GET_PAGE(ptr),(int_val)ptr);
#		endif
		return gc_alloc_page(size, kind, block_count);
	}
#endif

#	if defined(GC_DEBUG)
	memset(base,0xDD,size);
	p->page_id = PAGE_ID++;
#	else
	// prevent false positive to access invalid type
#	if !defined(HL_WIN) && !defined(HL_CONSOLE) && !defined(HL_EMSCRIPTEN)
	// Pages come straight from a fresh mapping, which the OS already zeroed.
#	else
	if( kind == MEM_KIND_DYNAMIC ) memset(base, 0, size);
#	endif
#	endif
	if( ((int_val)base) & ((1<<GC_MASK_BITS) - 1) )
		hl_fatal("Page memory is not correctly aligned");
	p->page_size = size;
	p->page_kind = kind;
	p->bmp = NULL;
	if( gc_incremental_active ) {
		p->incremental_bmp = (unsigned char*)calloc(((block_count + 7) >> 3) * 2,1);
		if( !p->incremental_bmp ) out_of_memory("incremental bitmap");
		p->bmp = p->incremental_bmp;
		p->incremental_epoch = gc_incremental_epoch;
	}

	// update stats
	gc_stats.pages_count++;
	gc_stats.pages_allocated++;
	gc_stats.pages_blocks += block_count;
	gc_stats.pages_total_memory += size;
	gc_stats.mark_bytes += (block_count + 7) >> 3;

	// register page in page map
	int i;
	for(i=0;i<size>>GC_MASK_BITS;i++) {
		void *ptr = p->base + (i<<GC_MASK_BITS);
		if( GC_GET_LEVEL1(ptr) == gc_level1_null ) {
			gc_pheader **level = (gc_pheader**)malloc(sizeof(void*) * (1<<GC_LEVEL1_BITS));
			MZERO(level,sizeof(void*) * (1<<GC_LEVEL1_BITS));
			#if defined(__GNUC__)
			__atomic_store_n(&GC_GET_LEVEL1(ptr),level,__ATOMIC_RELEASE);
#else
			GC_GET_LEVEL1(ptr) = level;
#endif
		}
		#if defined(__GNUC__)
		__atomic_store_n(&GC_GET_PAGE(ptr),p,__ATOMIC_RELEASE);
#else
		GC_GET_PAGE(ptr) = p;
#endif
	}

	return p;
}

static void gc_free_page( gc_pheader *ph, int block_count ) {
	int i;
	for(i=0;i<ph->page_size>>GC_MASK_BITS;i++) {
		void *ptr = ph->base + (i<<GC_MASK_BITS);
		GC_GET_PAGE(ptr) = NULL;
	}
	gc_stats.pages_count--;
	gc_stats.pages_blocks -= block_count;
	gc_stats.pages_total_memory -= ph->page_size;
	gc_stats.mark_bytes -= (block_count + 7) >> 3;
	gc_free_page_memory(ph->base,ph->page_size);
	free(ph->scan_profile);
	ph->scan_profile = NULL;
	free(ph->incremental_bmp);
	ph->incremental_bmp = NULL;
	ph->next_page = gc_free_pheaders;
	gc_free_pheaders = ph;
}

static void gc_check_mark();
static void (* volatile gc_profile_allocation_callback)(hl_type*,int,int,void*);

// ------------------------- ALLOCATION CENSUS ------------------------------------------
// Optional accounting of every allocation by type, plus sampled call stacks. Off unless started with hl_gc_census_start.

HL_API uchar *hl_resolve_symbol( void *addr, uchar *out, int *outSize );

#define CENSUS_FRAMES 6

typedef struct {
	hl_type *t;
	int64 count;
	int64 bytes;
} gc_census_type;

typedef struct {
	hl_type *t;
	void *frames[CENSUS_FRAMES];
	int nframes;
	int64 samples;
	int64 bytes;
} gc_census_stack;

static bool gc_census_on = false;
static int gc_census_every = 0;
static int64 gc_census_budget = 0;
static unsigned int gc_census_rng = 2463534242u;
static int64 gc_census_total = 0;
static gc_census_type *gc_census_types = NULL;
static int gc_census_type_cap = 0, gc_census_type_count = 0;
static gc_census_stack *gc_census_stacks = NULL;
static int gc_census_stack_cap = 0, gc_census_stack_count = 0;

static unsigned int gc_census_hash( void *a, void **frames, int nframes ) {
	uint64 h = ((uint64)(int_val)a) * 0x9E3779B97F4A7C15ULL;
	int i;
	for(i=0;i<nframes;i++)
		h = (h ^ (uint64)(int_val)frames[i]) * 0x100000001B3ULL;
	return (unsigned int)(h >> 32);
}

static void gc_census_grow_types( void ) {
	int cap = gc_census_type_cap ? gc_census_type_cap * 2 : 1024, i;
	gc_census_type *next = (gc_census_type*)calloc(cap,sizeof(gc_census_type));
	if( next == NULL ) return;
	for(i=0;i<gc_census_type_cap;i++) {
		gc_census_type *e = gc_census_types + i;
		unsigned int k;
		if( e->count == 0 ) continue;
		k = gc_census_hash(e->t,NULL,0) & (cap - 1);
		while( next[k].count ) k = (k + 1) & (cap - 1);
		next[k] = *e;
	}
	free(gc_census_types);
	gc_census_types = next;
	gc_census_type_cap = cap;
}

static void gc_census_count( hl_type *t, int bytes ) {
	unsigned int k;
	gc_census_total++;
	if( gc_census_type_count * 2 >= gc_census_type_cap ) gc_census_grow_types();
	if( gc_census_type_cap == 0 ) return;
	k = gc_census_hash(t,NULL,0) & (gc_census_type_cap - 1);
	while( gc_census_types[k].count && gc_census_types[k].t != t ) k = (k + 1) & (gc_census_type_cap - 1);
	if( gc_census_types[k].count == 0 ) {
		gc_census_types[k].t = t;
		gc_census_type_count++;
	}
	gc_census_types[k].count++;
	gc_census_types[k].bytes += bytes;
}

static void gc_census_grow_stacks( void ) {
	int cap = gc_census_stack_cap ? gc_census_stack_cap * 2 : 1024, i;
	gc_census_stack *next = (gc_census_stack*)calloc(cap,sizeof(gc_census_stack));
	if( next == NULL ) return;
	for(i=0;i<gc_census_stack_cap;i++) {
		gc_census_stack *e = gc_census_stacks + i;
		unsigned int k;
		if( e->samples == 0 ) continue;
		k = gc_census_hash(e->t,e->frames,e->nframes) & (cap - 1);
		while( next[k].samples ) k = (k + 1) & (cap - 1);
		next[k] = *e;
	}
	free(gc_census_stacks);
	gc_census_stacks = next;
	gc_census_stack_cap = cap;
}

static void gc_census_sample( hl_type *t, void **frames, int nframes, int weight ) {
	unsigned int k;
	if( gc_census_stack_count * 2 >= gc_census_stack_cap ) gc_census_grow_stacks();
	if( gc_census_stack_cap == 0 ) return;
	k = gc_census_hash(t,frames,nframes) & (gc_census_stack_cap - 1);
	while( gc_census_stacks[k].samples ) {
		gc_census_stack *e = &gc_census_stacks[k];
		if( e->t == t && e->nframes == nframes && memcmp(e->frames,frames,nframes*sizeof(void*)) == 0 ) break;
		k = (k + 1) & (gc_census_stack_cap - 1);
	}
	gc_census_stack *e = &gc_census_stacks[k];
	if( e->samples == 0 ) {
		e->t = t;
		e->nframes = nframes;
		memcpy(e->frames,frames,nframes*sizeof(void*));
		gc_census_stack_count++;
	}
	e->samples += weight;
	e->bytes += (int64)weight * gc_census_every;
}

HL_PRIM void hl_gc_census_reset( void ) {
	gc_global_lock(true);
	if( gc_census_types ) memset(gc_census_types,0,gc_census_type_cap*sizeof(gc_census_type));
	if( gc_census_stacks ) memset(gc_census_stacks,0,gc_census_stack_cap*sizeof(gc_census_stack));
	gc_census_type_count = gc_census_stack_count = 0;
	gc_census_total = 0;
	gc_census_budget = 0;
	gc_global_lock(false);
}

/** Starts counting every allocation by type; when `every` > 0 also samples call stacks once per `every` allocated bytes (jittered). */
HL_PRIM void hl_gc_census_start( int every ) {
	gc_global_lock(true);
	gc_census_every = every < 0 ? 0 : every;
	gc_census_on = true;
	gc_global_lock(false);
}

HL_PRIM void hl_gc_census_stop( void ) {
	gc_global_lock(true);
	gc_census_on = false;
	gc_global_lock(false);
}

static void gc_census_write_string( FILE *f, const uchar *s ) {
	fputc('"',f);
	while( s && *s ) {
		uchar c = *s++;
		if( c == '"' || c == '\\' ) { fputc('\\',f); fputc((char)c,f); }
		else if( c < 32 || c > 126 ) fputc('?',f);
		else fputc((char)c,f);
	}
	fputc('"',f);
}

static void gc_census_write_frame( FILE *f, void *addr ) {
	uchar out[512];
	int size = 512;
	uchar *name = hl_resolve_symbol(addr,out,&size);
	if( name == NULL ) {
		fprintf(f,"\"?\"");
		return;
	}
	gc_census_write_string(f,name);
}

/** Writes the census as JSON: exact per-type counts and sampled stacks (symbols resolved). Counting continues afterwards. */
HL_PRIM void hl_gc_census_dump( const char *filename ) {
	gc_census_type *types;
	gc_census_stack *stacks;
	int ntypes = 0, nstacks = 0, i, every;
	int64 total;
	FILE *f;
	gc_global_lock(true);
	types = (gc_census_type*)malloc(sizeof(gc_census_type) * (gc_census_type_count + 1));
	stacks = (gc_census_stack*)malloc(sizeof(gc_census_stack) * (gc_census_stack_count + 1));
	for(i=0;i<gc_census_type_cap;i++)
		if( gc_census_types[i].count && ntypes < gc_census_type_count ) types[ntypes++] = gc_census_types[i];
	for(i=0;i<gc_census_stack_cap;i++)
		if( gc_census_stacks[i].samples && nstacks < gc_census_stack_count ) stacks[nstacks++] = gc_census_stacks[i];
	every = gc_census_every;
	total = gc_census_total;
	gc_global_lock(false);
	f = fopen(filename,"wb");
	if( f == NULL ) {
		free(types);
		free(stacks);
		hl_error("Failed to open file");
		return;
	}
	fprintf(f,"{\"every\":%d,\"allocations\":%lld,\"types\":[",every,(long long)total);
	for(i=0;i<ntypes;i++) {
		fprintf(f,"%s{\"type\":",i ? "," : "");
		gc_census_write_string(f,types[i].t ? hl_type_str(types[i].t) : USTR("(untyped)"));
		fprintf(f,",\"count\":%lld,\"bytes\":%lld}",(long long)types[i].count,(long long)types[i].bytes);
	}
	fprintf(f,"],\"stacks\":[");
	for(i=0;i<nstacks;i++) {
		int j;
		fprintf(f,"%s{\"type\":",i ? "," : "");
		gc_census_write_string(f,stacks[i].t ? hl_type_str(stacks[i].t) : USTR("(untyped)"));
		fprintf(f,",\"samples\":%lld,\"bytes\":%lld,\"frames\":[",(long long)stacks[i].samples,(long long)stacks[i].bytes);
		for(j=0;j<stacks[i].nframes;j++) {
			if( j ) fputc(',',f);
			gc_census_write_frame(f,stacks[i].frames[j]);
		}
		fprintf(f,"]}");
	}
	fprintf(f,"]}\n");
	fclose(f);
	free(types);
	free(stacks);
}

HL_API void hl_gc_set_profile_allocation_callback( void (*callback)(hl_type*,int,int,void*) ) {
	gc_profile_allocation_callback = callback;
}

#ifndef GC_TLAB
HL_API bool hl_jit_alloc_prepare(hl_type *type, hl_jit_alloc_data *data) { (void)type; (void)data; return false; }
#endif
#ifdef GC_TLAB
#ifdef HL_TRACK_ENABLE
#define GC_TLAB_TRACK_POLICY(X) X(hl_track.flags, HL_TRACK_ALLOC, 4)
#else
#define GC_TLAB_TRACK_POLICY(X)
#endif
#define GC_TLAB_POLICY(X) \
	X(gc_flags, GC_PROFILE|GC_FORCE_MAJOR, 4) \
	X(gc_census_on, 1, 1) \
	X(gc_incremental_active, 1, 1) \
	X(gc_profile_allocation_callback, ~(uint64)0, sizeof(void*)) \
	GC_TLAB_TRACK_POLICY(X)
#define GC_TLAB_ALLOWED(value, mask, bytes) && (((uint64)(value) & (mask)) == 0)
// Shared policy for the ordinary allocator and its thin, ready-slot entry.
static HL_INLINE hl_thread_info *gc_tlab_thread( int size, int flags, void *owner ) {
	if( owner == NULL && size <= GC_SIZES[GC_FIXED_PARTS-1] && (flags & PAGE_KIND_MASK) != MEM_KIND_FINALIZER ) {
		hl_thread_info *th = current_thread;
		if( th && th->gc_tlab GC_TLAB_POLICY(GC_TLAB_ALLOWED)
		) return th;
	}
	return NULL;
}

HL_API bool hl_jit_alloc_prepare(hl_type *type, hl_jit_alloc_data *data) {
#if defined(__linux__) && defined(__x86_64__) && defined(__GNUC__) && defined(GC_TLAB)
	if(type->kind != HOBJ) return false;
	hl_runtime_obj *rt = hl_get_obj_rt(type); // Layout only: methods remain lazy.
	if(rt->nbindings || rt->size <= 0 || rt->size > GC_SIZES[GC_FIXED_PARTS-1]) return false;
	int rounded = rt->size + ((-rt->size) & (GC_ALIGN-1));
	int part = (rounded >> GC_ALIGN_BITS)-1;
	memset(data,0,sizeof(*data));
	data->type = type; data->runtime = rt; data->block = GC_SIZES[part];
	intptr_t tls = (intptr_t)((uintptr_t)&current_thread - (uintptr_t)__builtin_thread_pointer());
	if(tls < (-2147483647-1) || tls > 2147483647) return false;
	data->tls_offset = (int)tls;
	data->slot_offset = ((part << PAGE_KIND_BITS) | (rt->hasPtr ? MEM_KIND_DYNAMIC : MEM_KIND_NOPTR)) * sizeof(gc_tlab_slot);
#define GC_TLAB_GUARD(value, bits, width) \
	data->guards[data->nguards].address = (void*)&(value); \
	data->guards[data->nguards].mask = (bits); \
	data->guards[data->nguards++].bytes = (width);
	GC_TLAB_POLICY(GC_TLAB_GUARD)
	// A pending collection must force a safepoint through the existing slow path.
	GC_TLAB_GUARD(gc_threads.stopping_world,1,1)
#undef GC_TLAB_GUARD
	return true;
#else
	(void)type; (void)data;
	return false;
#endif
}

static HL_INLINE void gc_tlab_clear( unsigned char *ptr, int size, int flags, int block ) {
	if( flags & MEM_ZERO ) {
#ifdef GC_ALLOC_FAST_SUPPORTED
		if( gc_alloc_fast && block <= 5 * (int)sizeof(uintptr_t) ) {
			// The fixed classes contain at most five words. Explicit stores keep the compiler from turning a tiny loop into a memset call.
			uintptr_t *words = (uintptr_t*)ptr;
			words[0] = 0;
			if( block > (int)sizeof(uintptr_t) ) words[1] = 0;
			if( block > 2 * (int)sizeof(uintptr_t) ) words[2] = 0;
			if( block > 3 * (int)sizeof(uintptr_t) ) words[3] = 0;
			if( block > 4 * (int)sizeof(uintptr_t) ) words[4] = 0;
		} else
#endif
		{
			for(int i=0;i<block;i+=(int)sizeof(uintptr_t)) *(uintptr_t*)(ptr+i) = 0;
		}
	} else if( MEM_HAS_PTR(flags) && block != size ) {
		MZERO(ptr+size,block-size); // erase possible pointers after data
	}
}

// A small allocation out of the thread's buffer; an empty buffer is refilled under the global lock, which is also
// where the collection trigger is checked and where the reserved bytes are counted.
static void *gc_tlab_alloc( hl_thread_info *th, int size, int flags ) {
	int kind = flags & PAGE_KIND_MASK;
	int rounded = size + ((-size) & (GC_ALIGN - 1));
	int part = (rounded >> GC_ALIGN_BITS) - 1;
	int block = GC_SIZES[part];
	gc_tlab_slot *slot = (gc_tlab_slot*)th->gc_tlab + ((part << PAGE_KIND_BITS) | kind);
	if( slot->cur >= slot->end ) {
		// A buffer is refilled only once it is exactly used up (or emptied by a collection); a cursor past its end
		// means blocks were handed out that the free lists never reserved.
		if( slot->cur != slot->end )
			hl_fatal("GC allocation buffer overran its run");
		int got;
		unsigned char *run;
		gc_global_lock(true);
		gc_check_mark();
		run = (unsigned char*)gc_alloc_fixed_run(part,kind,GC_TLAB_RUN / block,&got);
		gc_stats.allocation_count += got;
		gc_stats.total_requested += (int64)got * block;
		gc_stats.total_allocated += (int64)got * block;
		slot->cur = run;
		slot->end = run + got * block;
		gc_global_lock(false);
	}
	unsigned char *ptr = slot->cur;
	slot->cur += block;
	gc_tlab_clear(ptr,size,flags,block);
	return ptr;
}
#endif

#ifdef GC_ALLOC_FAST_SUPPORTED
#if defined(HL_VCC)
# define GC_ALLOC_NOINLINE __declspec(noinline)
#elif defined(HL_GCC) || defined(HL_CLANG)
# define GC_ALLOC_NOINLINE __attribute__((noinline))
#else
# define GC_ALLOC_NOINLINE
#endif

// Keep special allocation modes and refill bookkeeping out of the small-allocation entry's stack frame.
static GC_ALLOC_NOINLINE void *gc_alloc_gen_owner_full( hl_type *t, int size, int flags, void *owner ) {
#else
void *hl_gc_alloc_gen_owner( hl_type *t, int size, int flags, void *owner ) {
#endif
	void *ptr;
	int time = 0;
	int allocated = 0;
	int census_sample = 0;
	if( size == 0 )
		return NULL;
	if( size < 0 )
		hl_error("Invalid allocation size");
#	ifdef GC_TLAB
	hl_thread_info *th = gc_tlab_thread(size,flags,owner);
	if( th ) return gc_tlab_alloc(th,size,flags);
#	endif
	gc_global_lock(true);
	gc_check_mark();
#	ifdef GC_MEMCHK
	size += HL_WSIZE;
#	endif
	if( gc_flags & GC_PROFILE ) time = TIMESTAMP();
	{
		allocated = size;
		gc_stats.allocation_count++;
		gc_stats.total_requested += size;
#		ifdef GC_PRINT_ALLOCS_SIZES
#		define MAX_WORDS 16
		static int SIZE_CATEGORIES[MAX_WORDS] = {0};
		static int LARGE_BLOCKS[33] = {0};
		int wsize = (size + sizeof(void*) - 1) & ~(sizeof(void*)-1);
		if( wsize < MAX_WORDS * sizeof(void*) )
			SIZE_CATEGORIES[wsize/sizeof(void*)]++;
		else {
			int k = 0;
			while( size > (1<<k) && k < 20 ) {
				k++;
			}
			LARGE_BLOCKS[k]++;
		}
		if( (gc_stats.allocation_count & 0xFFFF) == 0 ) {
			int i;
			for(i=0;i<MAX_WORDS;i++)
				if( SIZE_CATEGORIES[i] )
					printf("%d=%.1f ",i*sizeof(void*),(SIZE_CATEGORIES[i] * 100.) / gc_stats.allocation_count);
			for(i=0;i<33;i++)
				if( LARGE_BLOCKS[i] )
					printf("%d=%.2f ",1<<i,(LARGE_BLOCKS[i] * 100.) / gc_stats.allocation_count);
			printf("%d\n",gc_stats.allocation_count);
		}
#		endif
		ptr = gc_allocator_alloc(&allocated,flags & PAGE_KIND_MASK);
		if( ptr == NULL ) {
			if( allocated < 0 ) {
				gc_global_lock(false);
				hl_error("Required memory allocation too big");
			}
			hl_fatal("TODO");
		}
		gc_stats.total_allocated += allocated;
		if( gc_census_on ) {
			gc_census_count(t,allocated);
			if( gc_census_every > 0 ) {
				// sample by allocated bytes with a jittered interval so periodic allocation patterns cannot alias
				gc_census_budget -= allocated;
				while( gc_census_budget <= 0 ) {
					gc_census_rng ^= gc_census_rng << 13;
					gc_census_rng ^= gc_census_rng >> 17;
					gc_census_rng ^= gc_census_rng << 5;
					gc_census_budget += gc_census_every / 2 + (gc_census_rng % (unsigned int)gc_census_every) + 1;
					census_sample++;
				}
			}
		}
	}
	if( gc_flags & GC_PROFILE ) gc_stats.alloc_time += TIMESTAMP() - time;
#	ifdef GC_DEBUG
	memset(ptr,0xCD,allocated);
#	endif
	if( flags & MEM_ZERO )
		MZERO(ptr,allocated);
	else if( MEM_HAS_PTR(flags) && allocated != size )
		MZERO((char*)ptr+size,allocated-size); // erase possible pointers after data
#	ifdef GC_MEMCHK
	memset((char*)ptr+(allocated - HL_WSIZE),0xEE,HL_WSIZE);
#	endif
	if( owner != NULL ) {
		gc_owned_alloc *owned = (gc_owned_alloc*)malloc(sizeof(gc_owned_alloc));
		if( owned == NULL ) out_of_memory("allocation owner");
		owned->ptr = ptr;
		owned->owner = owner;
		owned->next = gc_owned_allocs;
		gc_owned_allocs = owned;
	}
	if( gc_incremental_active ) gc_incremental_allocated(ptr);
	gc_global_lock(false);
	if( census_sample && hl_get_thread() != NULL ) {
		void *frames[CENSUS_FRAMES + 4];
		int n = hl_setup.capture_stack ? hl_setup.capture_stack(frames,CENSUS_FRAMES + 4) : 0;
		int skip = 0;
		if( n - skip > CENSUS_FRAMES ) n = skip + CENSUS_FRAMES;
		gc_global_lock(true);
		if( gc_census_on ) gc_census_sample(t,frames + skip,n - skip,census_sample);
		gc_global_lock(false);
	}
	void (*allocation_callback)(hl_type*,int,int,void*) = gc_profile_allocation_callback;
	if( allocation_callback ) {
#ifdef HL_WIN
		allocation_callback(t,size,allocated,_ReturnAddress());
#else
		allocation_callback(t,size,allocated,__builtin_return_address(0));
#endif
	}
	hl_track_call(HL_TRACK_ALLOC, on_alloc(t,size,flags,ptr));
	return ptr;
}

#ifdef GC_ALLOC_FAST_SUPPORTED
void *hl_gc_alloc_gen_owner( hl_type *t, int size, int flags, void *owner ) {
	if( gc_alloc_fast && size > 0 ) {
		hl_thread_info *th = gc_tlab_thread(size,flags,owner);
		if( th ) {
			int kind = flags & PAGE_KIND_MASK;
			int rounded = size + ((-size) & (GC_ALIGN - 1));
			int part = (rounded >> GC_ALIGN_BITS) - 1;
			int block = GC_SIZES[part];
			gc_tlab_slot *slot = (gc_tlab_slot*)th->gc_tlab + ((part << PAGE_KIND_BITS) | kind);
			unsigned char *ptr = slot->cur;
			if( ptr < slot->end ) {
				slot->cur = ptr + block;
				gc_tlab_clear(ptr,size,flags,block);
				return ptr;
			}
		}
	}
	// Empty runs, profiling/census/tracking, ownership, finalizers and invalid sizes use the full path.
	return gc_alloc_gen_owner_full(t,size,flags,owner);
}

#endif

void *hl_gc_alloc_gen( hl_type *t, int size, int flags ) {
	return hl_gc_alloc_gen_owner(t,size,flags,t == NULL ? NULL : t->gc_owner);
}

// -------------------------  MARKING ----------------------------------------------------------

typedef struct {
	void **cur;
	void **end;
	int size;
} gc_mstack;

typedef struct {
	gc_mstack stack;
	hl_semaphore *ready;
	int mark_count;
	hl_thread *tid;
} gc_mthread;

static float gc_mark_threshold = 0.2f;

// A major collection also waits for at least this much allocation, so a small live heap is not re-marked after every
// few megabytes of garbage. Large heaps are unaffected: 20% of them is already above it.
static int64 gc_min_trigger_bytes = 64 << 20;
static int mark_size = 0;
static unsigned char *mark_data = NULL;
static gc_mstack global_mark_stack = {0};
static int gc_mark_threads = GC_MAX_MARK_THREADS;
static gc_mthread mark_threads[GC_MAX_MARK_THREADS] = {0};
static unsigned char mark_threads_active = 0;
static hl_semaphore *mark_threads_done;

#define GC_STACK_BEGIN(st) register void **__current_stack = (st)->cur; gc_mstack *__current_mstack = st;
#define GC_STACK_END() __current_mstack->cur = __current_stack;
#define GC_STACK_RESUME() __current_stack = __current_mstack->cur;
#define GC_STACK_COUNT(st) ((st)->size - ((st)->end - (st)->cur) - 1)

#define GC_PUSH_GEN(ptr,page) \
	if( MEM_HAS_PTR((page)->page_kind) ) { \
		if( __current_stack == __current_mstack->end ) { __current_mstack->cur = __current_stack; __current_stack = hl_gc_mark_grow(__current_mstack); } \
		*__current_stack++ = ptr; \
	}

#ifdef HL_THREADS
#	define GC_THREADS 1
#else
#	define GC_THREADS 0
#endif

HL_PRIM void **hl_gc_mark_grow( gc_mstack *stack ) {
	int nsize = stack->size ? (((stack->size * 3) >> 1) & ~1) : 256;
	void **nstack = (void**)malloc(sizeof(void**) * nsize);
	void **base_stack = stack->end - stack->size;
	int avail = (int)(stack->cur - base_stack);
	if( nstack == NULL ) {
		out_of_memory("markstack");
		return NULL;
	}
	memcpy(nstack, base_stack, avail * sizeof(void*));
	free(base_stack);
	stack->size = nsize;
	stack->end = nstack + nsize;
	stack->cur = nstack + avail;
	if( avail == 0 )
		*stack->cur++ = 0;
	return stack->cur;
}

static bool atomic_bit_unset( unsigned char *addr, unsigned char bitmask ) {
	if( GC_MAX_MARK_THREADS <= 1 ) {
		unsigned char v = *addr;
		bool b = (v & bitmask) != 0;
		if( b ) *addr = v & ~bitmask;
		return b;
	}
#	if defined(HL_VCC)
	return ((unsigned)InterlockedAnd8((char*)addr,(char)~bitmask) & bitmask) != 0;
#	elif defined(HL_CLANG) || defined(HL_GCC)
	return (__sync_fetch_and_and(addr,~bitmask) & bitmask) != 0;
#	else
	hl_fatal("Not implemented");
	return false;
#	endif
}

// Stop-the-world marking with one worker has no competing bitmap writers.
// Keep other configurations on their existing atomic path until validated there.
#if defined(__linux__) && defined(__x86_64__) && defined(__GNUC__)
static bool gc_mark_serial = false;
#define GC_SERIAL_MARK (gc_mark_serial && gc_mark_threads == 1)
#else
#define GC_SERIAL_MARK false
#endif

static bool atomic_bit_set( unsigned char *addr, unsigned char bitmask ) {
	if( GC_MAX_MARK_THREADS <= 1 || GC_SERIAL_MARK ) {
		unsigned char v = *addr;
		bool b = (v & bitmask) == 0;
		if( b ) *addr = v | bitmask;
		return b;
	}
#	if defined(HL_VCC)
	return ((unsigned)InterlockedOr8((char*)addr,(char)bitmask) & bitmask) == 0;
#	elif defined(HL_CLANG) || defined(HL_GCC)
	return (__sync_fetch_and_or(addr,bitmask) & bitmask) == 0;
#	else
	hl_fatal("Not implemented");
	return false;
#	endif
}

static void gc_dispatch_mark( gc_mstack *st, bool all ) {
	int nthreads = 0;
	int i;
	if( mark_threads_active == (1<<gc_mark_threads) - 1 )
		return;
	for(i=0;i<gc_mark_threads;i++)
		if( (mark_threads_active&(1<<i)) == 0 )
			nthreads++;
	if( nthreads == 0 )
		return;
	int count = all ? (GC_STACK_COUNT(st) + nthreads - 1) / nthreads : GC_STACK_COUNT(st) / (nthreads + 1);
	if( count == 0 )
		return;
	for(i=0;i<gc_mark_threads;i++) {
		gc_mthread *t = &mark_threads[i];
		if( !atomic_bit_set(&mark_threads_active,1<<i) )
			continue;
		int push = GC_STACK_COUNT(st);
		if( push > count ) push = count;
		while( t->stack.size <= push )
			hl_gc_mark_grow(&t->stack);
		if( GC_STACK_COUNT(&t->stack) != 0 )
			hl_fatal("assert");
		st->cur -= push;
		memcpy(t->stack.cur, st->cur, push * sizeof(void*));
		t->stack.cur += push;
		if( !all )
			hl_semaphore_release(t->ready);
	}
	if( all ) {
		if( nthreads != gc_mark_threads ) hl_fatal("assert");
		for(i=0;i<gc_mark_threads;i++) {
			gc_mthread *t = &mark_threads[i];
			hl_semaphore_release(t->ready);
		}
	}
}

#define REGULAR_BITS 16

static int gc_flush_mark( gc_mstack *stack ) {
	GC_STACK_BEGIN(stack);
	if( !__current_stack ) return 0;
	int count = 0;
	int regular_mask = 1 << REGULAR_BITS;
	while( true ) {
		void **block = (void**)*--__current_stack;
		gc_pheader *page = GC_GET_PAGE(block);
		unsigned int *mark_bits = NULL;
		int pos = 0, nwords;
#		ifdef GC_DEBUG
		vdynamic *ptr = (vdynamic*)block;
		ptr += 0; // prevent unreferenced warning
#		endif
		if( !block ) {
			__current_stack++;
			break;
		}
		if( (count++ & (1 << REGULAR_BITS)) != regular_mask && GC_MAX_MARK_THREADS > 1 && gc_mark_threads > 1 ) {
			regular_mask = regular_mask ? 0 : 1 << REGULAR_BITS;
			GC_STACK_END();
			gc_dispatch_mark(stack,false);
			GC_STACK_RESUME();
		}
		int size = gc_allocator_fast_block_size(page, block);
#		ifdef GC_DEBUG
		if( size <= 0 ) hl_fatal("assert");
#		endif
		nwords = size / HL_WSIZE;
#		ifdef GC_PRECISE
		if( page->page_kind == MEM_KIND_DYNAMIC ) {
			hl_type *t = *(hl_type**)block;
#			ifdef GC_DEBUG
#				ifdef HL_64
				if( (int_val)t == 0xDDDDDDDDDDDDDDDD ) continue;
#				else
				if( (int_val)t == 0xDDDDDDDD ) continue;
#				endif
#			endif
			if( !t )
				continue; // skip not allocated block
			if( t->mark_bits && t->kind != HFUN ) {
				mark_bits = t->mark_bits;
				if( t->kind == HENUM ) {
					mark_bits += ((venum*)block)->index;
					block += 2;
					nwords -= 2;
				} else {
					block++;
					pos++;
				}
			}
		}
#		endif
		while( pos < nwords ) {
			void *p;
			if( mark_bits && (mark_bits[pos >> 5] & (1 << (pos&31))) == 0 ) {
				pos++;
				block++;
				continue;
			}
			p = *block++;
			pos++;
			if( !p ) continue;
			page = GC_GET_PAGE(p);
			if( !page || !INPAGE(p,page) ) continue;
			int bid = gc_allocator_get_block_id(page,p);
			if( bid >= 0 && atomic_bit_set(&page->bmp[bid>>3],1<<(bid&7)) ) {
				if( MEM_HAS_PTR(page->page_kind) ) DRAM_PREFETCH(p);
				GC_PUSH_GEN(p,page);
			}
		}
	}
	GC_STACK_END();
	return count;
}

ASAN_DISABLE
static void gc_mark_stack( void *start, void *end ) {
	GC_STACK_BEGIN(&global_mark_stack);
	void **stack_head = (void**)start;
	while( stack_head < (void**)end ) {
		void *p = *stack_head++;
		gc_pheader *page = GC_GET_PAGE(p);
		if( !page || !INPAGE(p,page) ) continue;
#		ifdef GC_INTERIOR_POINTERS
		int bid = gc_allocator_get_block_interior(page, &p);
#		else
		int bid = gc_allocator_get_block_id(page, p);
#		endif
		if( bid >= 0 && (page->bmp[bid>>3] & (1<<(bid&7))) == 0 ) {
			page->bmp[bid>>3] |= 1<<(bid&7);
			GC_PUSH_GEN(p,page);
		}
	}
	GC_STACK_END();
}

#include "gc_incremental.c"

static void gc_mark() {
	gc_incremental_discard();
	GC_STACK_BEGIN(&global_mark_stack);
	int mark_bytes = gc_stats.mark_bytes;
	int i;
	// prepare mark bits
	if( mark_bytes > mark_size ) {
		gc_free_page_memory(mark_data, mark_size);
		if( mark_size == 0 ) mark_size = GC_PAGE_SIZE;
		while( mark_size < mark_bytes )
			mark_size <<= 1;
		mark_data = gc_alloc_page_memory(mark_size);
		if( mark_data == NULL ) out_of_memory("markbits");
	}
	MZERO(mark_data,mark_bytes);
	gc_allocator_before_mark(mark_data);
	// push roots
	for(i=0;i<gc_roots_count;i++) {
		void *p = *gc_roots[i];
		gc_pheader *page;
		if( !p ) continue;
		page = GC_GET_PAGE(p);
		if( !page || !INPAGE(p,page) ) continue; // the value was set to a not gc allocated ptr
		int bid = gc_allocator_get_block_id(page, p);
		if( bid >= 0 && (page->bmp[bid>>3] & (1<<(bid&7))) == 0 ) {
			page->bmp[bid>>3] |= 1<<(bid&7);
			GC_PUSH_GEN(p,page);
		}
	}

	GC_STACK_END();

	// scan threads stacks & registers
	for(i=0;i<gc_threads.count;i++) {
		hl_thread_info *t = gc_threads.threads[i];
		gc_mark_stack(t->stack_cur,t->stack_top);
		gc_mark_stack(&t->gc_regs,(void**)&t->gc_regs + (sizeof(jmp_buf) / sizeof(void*) - 1));
		gc_mark_stack(&t->extra_stack_data,(void**)&t->extra_stack_data + t->extra_stack_size);
	}

	gc_mstack *st = &global_mark_stack;
	if( gc_mark_threads <= 1 )
		gc_flush_mark(st);
	else {
		gc_dispatch_mark(st, true);
		if( GC_STACK_COUNT(st) > 0 )
			hl_fatal("assert");
		// wait threads to finish
		while( mark_threads_active )
			hl_semaphore_acquire(mark_threads_done);
		for(i=0;i<gc_mark_threads;i++) {
			gc_mthread *t = &mark_threads[i];
			if( GC_STACK_COUNT(&t->stack) > 0 )
				hl_fatal("assert");
		}
	}
	gc_sweep_owned_allocs();
	gc_allocator_after_mark();
}

static void count_free_memory( gc_pheader *page, int size ) {
	gc_stats.free_memory += gc_free_memory(page);
}

static void gc_major() {

	if( gc_flags & GC_PROFILE_MEM ) {
		double gc_mem = gc_stats.mark_bytes;
		int i;
		gc_mem += gc_allocator_private_memory();
		gc_mem += global_mark_stack.size * sizeof(void*);
		for(i=0;i<gc_mark_threads;i++) {
			gc_mthread *t = &mark_threads[i];
			gc_mem += t->stack.size * sizeof(void*);
		}
		int pages = gc_stats.pages_count;
		gc_pheader *p = gc_free_pheaders;
		while( p ) {
			pages++;
			p = p->next_page;
		}
		gc_mem += sizeof(gc_pheader) * pages;
		gc_mem += sizeof(void*) * gc_roots_max;
		gc_mem += (sizeof(void*) + sizeof(hl_thread_info)) * gc_threads.count;
		for(i=0;i<(1<<GC_LEVEL0_BITS);i++) {
			void *v = hl_gc_page_map[i];
			if( v != gc_level1_null )
				gc_mem += sizeof(void*) * (1<<GC_LEVEL1_BITS);
		}
		gc_mem += gc_stats.pages_total_memory;
		gc_stats.free_memory = 0;
		gc_iter_pages(count_free_memory);
		printf("GC-PROFILE-MEM %.2fMB total, %.2f%% free %.2f%% gc\n", gc_mem / (1024.0 * 1024.0), (gc_stats.free_memory * 100.0 / gc_mem), (gc_mem - gc_stats.pages_total_memory) * 100.0 / gc_mem);
	}

	int time = TIMESTAMP(), dt;
	double mark_started = hl_sys_time();
	gc_stats.last_mark = gc_stats.total_allocated;
	gc_stats.last_mark_allocs = gc_stats.allocation_count;
	gc_stop_world(true);
	gc_mark();
	gc_stop_world(false);
	dt = TIMESTAMP() - time;
	gc_stats.mark_count++;
	gc_stats.mark_time += dt;
	double mark_ms = (hl_sys_time() - mark_started) * 1000.0;
	gc_stats.mark_duration_ms += mark_ms;
	gc_stats.last_mark_ms = mark_ms;
	if( mark_ms > gc_stats.max_mark_ms ) gc_stats.max_mark_ms = mark_ms;
	if( gc_flags & GC_PROFILE ) {
		printf("GC-PROFILE %d\n\tmark-time %.3g\n\talloc-time %.3g\n\ttotal-mark-time %.3g\n\ttotal-alloc-time %.3g\n\tallocated %d (%dKB)\n",
			gc_stats.mark_count,
			dt/1000.,
			(gc_stats.alloc_time - last_profile.alloc_time)/1000.,
			gc_stats.mark_time/1000.,
			gc_stats.alloc_time/1000.,
			(int)(gc_stats.allocation_count - last_profile.allocation_count),
			(int)((gc_stats.total_allocated - last_profile.total_allocated)>>10)
		);
		last_profile.allocation_count = gc_stats.allocation_count;
		last_profile.alloc_time = gc_stats.alloc_time;
		last_profile.total_allocated = gc_stats.total_allocated;
	}
}

HL_API void hl_gc_major() {
	gc_global_lock(true);
	gc_major();
	gc_global_lock(false);
}

HL_API int hl_gc_owner_live_count( void *owner ) {
	int count = 0;
	if( owner == NULL ) return 0;
	gc_global_lock(true);
	gc_major();
	for(gc_owned_alloc *owned=gc_owned_allocs;owned;owned=owned->next)
		if( owned->owner == owner ) count++;
	gc_global_lock(false);
	return count;
}

HL_API bool hl_is_gc_ptr( void *ptr ) {
	gc_pheader *page = GC_GET_PAGE(ptr);
	if( !page || !INPAGE(ptr,page) ) return false;
	int bid = gc_allocator_get_block_id(page, ptr);
	if( bid < 0 ) return false;
	//if( page->bmp && page->next_block == page->first_block && (page->bmp[bid>>3]&(1<<(bid&7))) == 0 ) return false;
	return true;
}

HL_API int hl_gc_get_memsize( void *ptr ) {
	gc_pheader *page = GC_GET_PAGE(ptr);
	if( !page || !INPAGE(ptr,page) ) return -1;
	return gc_allocator_fast_block_size(page,ptr);
}


static bool gc_is_active = true;

static void gc_check_mark() {
	int64 m = gc_stats.total_allocated - gc_stats.last_mark;
	int64 b = gc_stats.allocation_count - gc_stats.last_mark_allocs;
	int64 bytes_limit = (int64)(gc_stats.pages_total_memory * gc_mark_threshold);
	int64 blocks_limit = (int64)(gc_stats.pages_blocks * gc_mark_threshold);
	if( bytes_limit < gc_min_trigger_bytes ) bytes_limit = gc_min_trigger_bytes;
	// the same floor for the block count, assuming the smallest blocks are 16 bytes
	if( blocks_limit < gc_min_trigger_bytes / 16 ) blocks_limit = gc_min_trigger_bytes / 16;
	int64 start_bytes = bytes_limit, start_blocks = blocks_limit;
	if( gc_incremental_enabled && gc_inc_start_percent != 100 && gc_write_tracking.supported() ) {
		start_bytes = (int64)(bytes_limit * (gc_inc_start_percent / 100.0));
		start_blocks = (int64)(blocks_limit * (gc_inc_start_percent / 100.0));
	}
	if( gc_is_active && (gc_incremental_active || gc_inc_reclaiming || m > start_bytes || b > start_blocks || (gc_flags & GC_FORCE_MAJOR)) ) {
		// A mutator that outruns marking must eventually reclaim, even during continuous animation.
		if( (gc_incremental_enabled || gc_incremental_active || gc_inc_reclaiming) && !(gc_flags & GC_FORCE_MAJOR) && m <= bytes_limit * 4 ) {
			if( (!gc_incremental_active && !gc_inc_reclaiming) || gc_stats.total_allocated - gc_inc_last_step_bytes >= gc_inc_step_bytes )
				gc_incremental_step_locked(1000.0,true);
		}
		else {
			if( (gc_incremental_enabled || gc_incremental_active || gc_inc_reclaiming) && !(gc_flags & GC_FORCE_MAJOR) ) gc_inc_pressure_fallbacks++;
			double started = gc_frame_recording ? gc_frame_clock() : 0;
			gc_major();
			if( gc_frame_recording ) {
				gc_frame_charge(started);
				gc_frame.full_collections++;
			}
		}
	}
}

static void mark_thread_main( void *param ) {
	int index = (int)(int_val)param;
	gc_mthread *inf = &mark_threads[index];
	while( true ) {
		hl_semaphore_acquire(inf->ready);
		inf->mark_count += gc_flush_mark(&inf->stack);
		if( !atomic_bit_unset(&mark_threads_active, 1 << index) ) hl_fatal("assert");
		if( mark_threads_active == 0 ) hl_semaphore_release(mark_threads_done);
	}
}

HL_API int hl_gc_get_mark_threads( hl_thread **tids ) {
	if( gc_mark_threads <= 1 )
		return 0;
	if( tids == NULL )
		return gc_mark_threads;
	for( int i = 0; i < gc_mark_threads; i++ ) {
		tids[i] = mark_threads[i].tid;
	}
	return gc_mark_threads;
}

// Invalid diagnostic settings leave defaults intact; avoid atoi overflow/trailing text.
static int gc_inc_setting(const char *name, int fallback, int minimum, int maximum) {
	const char *value = getenv(name);
	if( !value || !*value ) return fallback;
	char *end;
	double parsed = strtod(value,&end);
	if( *end || !(parsed >= minimum && parsed <= maximum) || parsed != (int)parsed ) return fallback;
	return (int)parsed;
}

static void hl_gc_init() {
	const char *latency_trace = getenv("HL_GC_LATENCY_TRACE");
	gc_latency_trace = latency_trace && strcmp(latency_trace,"1") == 0;
#ifdef GC_INCREMENTAL_SOFTWARE
	gc_inc_tracking_configure();
#endif
	const char *incremental = getenv("HL_GC_INCREMENTAL");
	gc_incremental_enabled = incremental && strcmp(incremental,"1") == 0;
	gc_inc_start_percent = gc_inc_setting("HL_GC_INCREMENTAL_START_PERCENT",100,1,100);
	gc_inc_step_bytes = gc_inc_setting("HL_GC_INCREMENTAL_STEP_BYTES",256<<10,64<<10,16<<20);
#if defined(__linux__) && defined(__x86_64__) && defined(__GNUC__)
	const char *mark_serial = getenv("HL_GC_MARK_SERIAL");
	gc_mark_serial = mark_serial && strcmp(mark_serial,"1") == 0;
#endif

#ifdef GC_ALLOC_FAST_SUPPORTED
	const char *alloc_fast = getenv("HL_GC_ALLOC_FAST");
	gc_alloc_fast = alloc_fast == NULL || strcmp(alloc_fast,"0") != 0;
#endif
	int i;
	for(i=0;i<1<<GC_LEVEL0_BITS;i++)
		hl_gc_page_map[i] = gc_level1_null;
	gc_allocator_init();
#	ifndef HL_CONSOLE
	if( getenv("HL_GC_PROFILE") )
		gc_flags |= GC_PROFILE;
	if( getenv("HL_GC_PROFILE_MEM") )
		gc_flags |= GC_PROFILE_MEM;
	if( getenv("HL_DUMP_MEMORY") )
		gc_flags |= GC_DUMP_MEM;
	// HL_GC_MIN_TRIGGER=<bytes>: the least allocation between two major collections (default 64 MB).
	const char *min_trigger = getenv("HL_GC_MIN_TRIGGER");
	if( min_trigger && atoll(min_trigger) >= 0 )
		gc_min_trigger_bytes = atoll(min_trigger);
	// HL_GC_MARK_THRESHOLD=<fraction>: a major collection runs once the bytes allocated since the last one exceed
	// this fraction of the heap (see gc_check_mark). The heap settles near live / (1 - fraction).
	const char *mark_threshold = getenv("HL_GC_MARK_THRESHOLD");
	if( mark_threshold ) {
		double fraction = atof(mark_threshold);
		if( fraction > 0.0 && fraction < 0.95 )
			gc_mark_threshold = (float)fraction;
	}
#	endif
	gc_stats.mark_bytes = 4; // prevent reading out of bmp
	memset(&gc_threads,0,sizeof(gc_threads));
#	ifdef HL_THREADS
	hl_add_root(&gc_threads.global_lock);
	hl_add_root(&gc_threads.exclusive_lock);
	hl_add_root(&mark_threads_done);
#	endif
	gc_threads.global_lock = hl_mutex_alloc(false);
	gc_threads.exclusive_lock = hl_mutex_alloc(false);
#	ifdef HL_THREADS
	mark_threads_done = hl_semaphore_alloc(0);
	char *nthreads = getenv("HL_GC_THREADS");
	if( nthreads ) {
		gc_mark_threads = atoi(nthreads);
		if( gc_mark_threads < 1 ) gc_mark_threads = 1;
		if( gc_mark_threads > GC_MAX_MARK_THREADS ) gc_mark_threads = GC_MAX_MARK_THREADS;
	}
	if( gc_mark_threads > 1 ) {
		for(int i=0;i<gc_mark_threads;i++) {
			gc_mthread *t = &mark_threads[i];
			hl_add_root(&t->ready);
			t->ready = hl_semaphore_alloc(0);
			t->tid = hl_thread_start(mark_thread_main, (void*)(int_val)i, false);
		}
	}
#	endif
}

static void hl_gc_free() {
	gc_incremental_shutdown();
#	ifdef HL_THREADS
	hl_remove_root(&gc_threads.global_lock);
#	endif
}

// ---- UTILITIES ----------------------

HL_API bool hl_is_blocking() {
	hl_thread_info *t = current_thread;
	// when called from a non GC thread, tells if the main thread is blocking
	if( t == NULL ) {
		if( gc_threads.count == 0 )
			return false;
		t = gc_threads.threads[0];
	}
	return t->gc_blocking > 0;
}

HL_API void hl_blocking( bool b ) {
	hl_thread_info *t = current_thread;
	if( !t )
		return; // allow hl_blocking in non-GC threads
	if( b ) {
#		ifdef HL_THREADS
		if( t->gc_blocking == 0 )
			gc_save_context(t,&b);
#		endif
		gc_release_fence();
		t->gc_blocking++;
	} else if( t->gc_blocking == 0 )
		hl_error("Unblocked thread");
	else {
		t->gc_blocking--;
		if( t->gc_blocking == 0 && gc_threads.stopping_world ) {
			gc_global_lock(true);
			gc_global_lock(false);
		}
	}
}

HL_API void hl_gc_safepoint() {
	hl_thread_info *t = current_thread;
	if( !t )
		return; // allow hl_gc_safepoint in non-GC threads
	if( t->gc_blocking == 0 && gc_threads.stopping_world ) {
#		ifdef HL_THREADS
		gc_save_context(t,&t);
#		endif
		gc_global_lock(true);
		gc_global_lock(false);
	}
}

void hl_cache_free();
void hl_cache_init();

void hl_global_init() {
	hl_gc_init();
	hl_cache_init();
}

void hl_global_free() {
	if( hl_setup.stop_profiler ) hl_setup.stop_profiler();
	hl_cache_free();
	if( hl_setup.free_runtime_retirements ) hl_setup.free_runtime_retirements();
	if( hl_setup.free_module_registry ) hl_setup.free_module_registry();
	if( hl_setup.free_jit_support ) hl_setup.free_jit_support();
	hl_gc_free();
}

struct hl_alloc_block {
	int size;
	hl_alloc_block *next;
	unsigned char *p;
};

void hl_alloc_init( hl_alloc *a ) {
	a->cur = NULL;
}

void *hl_malloc( hl_alloc *a, int size ) {
	hl_alloc_block *b = a->cur;
	void *p;
	if( !size ) return NULL;
	size += hl_pad_size(size,&hlt_dyn);
	if( b == NULL || b->size <= size ) {
		int alloc = size < 4096-(int)sizeof(hl_alloc_block) ? 4096-(int)sizeof(hl_alloc_block) : size;
		b = (hl_alloc_block *)malloc(sizeof(hl_alloc_block) + alloc);
		if( b == NULL ) out_of_memory("malloc");
		b->p = ((unsigned char*)b) + sizeof(hl_alloc_block);
		b->size = alloc;
		b->next = a->cur;
		a->cur = b;
	}
	p = b->p;
	b->p += size;
	b->size -= size;
	return p;
}

void *hl_zalloc( hl_alloc *a, int size ) {
	void *p = hl_malloc(a,size);
	if( p ) MZERO(p,size);
	return p;
}

void hl_free( hl_alloc *a ) {
	hl_alloc_block *b = a->cur;
	int_val prev = 0;
	int size = 0;
	while( b ) {
		hl_alloc_block *n = b->next;
		size = (int)(b->p + b->size - ((unsigned char*)b));
		prev = (int_val)b;
		free(b);
		b = n;
	}
	// check if our allocator was not part of the last free block
	if( (int_val)a < prev || (int_val)a > prev+size )
		a->cur = NULL;
}

HL_PRIM void *hl_alloc_executable_memory( int size ) {
#ifdef __APPLE__
#  	ifndef MAP_ANONYMOUS
#     		define MAP_ANONYMOUS MAP_ANON
#       endif
#endif
#if defined(HL_WIN) && defined(HL_64)
	static char *jit_address = (char*)0x000076CA9F000000;
	void *ptr;
retry_jit_alloc:
	ptr = VirtualAlloc(jit_address,size,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if( !ptr ) {
		jit_address = (char*)(((int_val)jit_address)>>1); // fix for Win7 - will eventually reach NULL
		goto retry_jit_alloc;
	}
	jit_address += size + ((-size) & (GC_PAGE_SIZE - 1));
	return ptr;
#elif defined(HL_WIN)
	void *ptr = VirtualAlloc(NULL,size,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	return ptr;
#elif defined(HL_OS)
	return malloc(size);
#elif defined(HL_CONSOLE)
	return NULL;
#elif defined(__APPLE__) && defined(__aarch64__)
	// Hardened runtime forbids RWX pages; MAP_JIT gives a page whose mode
	// is toggled per-thread via pthread_jit_write_protect_np(). Binary must
	// be signed with com.apple.security.cs.allow-jit (see CMake target).
	void *p = mmap(NULL,size,PROT_READ|PROT_WRITE|PROT_EXEC,
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_JIT,-1,0);
	return p == MAP_FAILED ? NULL : p;
#else
	void *p;
	p = mmap(NULL,size,PROT_READ|PROT_WRITE|PROT_EXEC,(MAP_PRIVATE|MAP_ANONYMOUS),-1,0);
	return p == MAP_FAILED ? NULL : p;
#endif
}

HL_PRIM void hl_free_executable_memory( void *c, int size ) {
#if defined(HL_WIN)
	VirtualFree(c,0,MEM_RELEASE);
#elif !defined(HL_CONSOLE)
	munmap(c, size);
#endif
}

HL_PRIM void hl_jit_write_begin( void ) {
#if defined(__APPLE__) && defined(__aarch64__)
	pthread_jit_write_protect_np(0); // pages become writable for this thread
#endif
}

HL_PRIM void hl_jit_thread_init( void ) {
#if defined(__APPLE__) && defined(__aarch64__)
	// New thread starts in "writable" mode by default; switch to
	// "executable" so the upcoming BLR into the shared JIT mapping works.
	pthread_jit_write_protect_np(1);
#endif
}

HL_PRIM void hl_jit_write_end( void *code, int size ) {
#if defined(__APPLE__) && defined(__aarch64__)
	pthread_jit_write_protect_np(1); // back to executable
	sys_icache_invalidate(code, (size_t)size);
#elif defined(__aarch64__) || defined(__arm__)
	// Linux/Android ARM(64): no W^X enforcement, but i-cache must still be flushed.
	__builtin___clear_cache((char*)code, (char*)code + size);
#else
	(void)code; (void)size;
#endif
}

#if defined(HL_CONSOLE)
void *sys_alloc_align( int size, int align );
void sys_free_align( void *ptr, int size );
#elif !defined(HL_WIN)
static void *base_addr = (void*)0x40000000;
typedef struct _pextra pextra;
struct _pextra {
	void *page_ptr;
	void *base_ptr;
	pextra *next;
};
static pextra *extra_pages = NULL;
#define EXTRA_SIZE (GC_PAGE_SIZE + (4<<10))
#endif

#ifdef GC_INCREMENTAL_LINUX
typedef struct _gc_inc_mapping {
	void *address, *mapping;
	size_t reserved;
	struct _gc_inc_mapping *next;
} gc_inc_mapping;
static gc_inc_mapping *gc_inc_mappings;
#endif

static void *gc_alloc_page_memory( int size ) {
#ifdef GC_INCREMENTAL_LINUX
	if( gc_write_tracking.isolated_mappings() && (gc_incremental_enabled || gc_incremental_active || gc_inc_reclaiming) ) {
		// A new adjacent mmap can set VM_SOFTDIRTY on a merged VMA, making an
		// unchanged heap appear dirty. PROT_NONE guards prevent that merge.
		size_t reserved = (size_t)size + 2 * GC_PAGE_SIZE;
		void *mapping = mmap(base_addr,reserved,PROT_NONE,MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
		if( mapping == MAP_FAILED ) return NULL;
		void *address = (void*)(((uintptr_t)mapping + GC_PAGE_SIZE) & ~(uintptr_t)(GC_PAGE_SIZE-1));
		if( mprotect(address,size,PROT_READ | PROT_WRITE) != 0 ) {
			munmap(mapping,reserved);
			return NULL;
		}
		gc_inc_mapping *entry = (gc_inc_mapping*)malloc(sizeof(gc_inc_mapping));
		if( !entry ) { munmap(mapping,reserved); return NULL; }
		entry->address = address; entry->mapping = mapping; entry->reserved = reserved;
		entry->next = gc_inc_mappings; gc_inc_mappings = entry;
		base_addr = (char*)mapping + reserved;
		return address;
	}
#endif
#if defined(HL_WIN)
#	if defined(GC_DEBUG) && defined(HL_64)
#		define STATIC_ADDRESS
#	endif
#	ifdef STATIC_ADDRESS
	// force out of 32 bits addresses to check loss of precision
	static char *start_address = (char*)0x100000000;
#	else
	static void *start_address = NULL;
#	endif
	void *ptr = VirtualAlloc(start_address,size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
#	ifdef STATIC_ADDRESS
	if( ptr == NULL && start_address ) {
		start_address = NULL;
		return gc_alloc_page_memory(size);
	}
	start_address += size + ((-size) & (GC_PAGE_SIZE - 1));
#	endif
	return ptr;
#elif defined(HL_CONSOLE)
	return sys_alloc_align(size, GC_PAGE_SIZE);
#elif defined(HL_EMSCRIPTEN)
	return emscripten_builtin_memalign(GC_PAGE_SIZE, size);
#else
	static int recursions = 0;
	int i = 0;
	while( gc_will_collide(base_addr,size) ) {
		base_addr = (char*)base_addr + GC_PAGE_SIZE;
		i++;
		// most likely our hashing creates too many collisions
		if( i >= 1 << (GC_LEVEL0_BITS + GC_LEVEL1_BITS + 2) )
			return NULL;
	}
	void *ptr = mmap(base_addr,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if( ptr == (void*)-1 )
		return NULL;
	if( ((int_val)ptr) & (GC_PAGE_SIZE-1) ) {
		munmap(ptr,size);
		if( recursions >= 5 ) {
			ptr = mmap(base_addr,size+EXTRA_SIZE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
			int offset = (int)((int_val)ptr) & (GC_PAGE_SIZE-1);
			void *aligned = (char*)ptr + (GC_PAGE_SIZE - offset);
			pextra *inf = (pextra*)( (char*)ptr + size + EXTRA_SIZE - sizeof(pextra));
			inf->page_ptr = aligned;
			inf->base_ptr = ptr;
			inf->next = extra_pages;
			extra_pages = inf;
			return aligned;
		}
		void *tmp;
		int tmp_size = (int)((int_val)ptr - (int_val)base_addr);
		if( tmp_size > 0 ) {
			base_addr = (void*)((((int_val)ptr) & ~(GC_PAGE_SIZE-1)) + GC_PAGE_SIZE);
			tmp = ptr;
		} else {
			base_addr = (void*)(((int_val)ptr) & ~(GC_PAGE_SIZE-1));
			tmp = NULL;
		}
		if( tmp ) tmp = mmap(tmp,tmp_size,PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
		recursions++;
		ptr = gc_alloc_page_memory(size);
		recursions--;
		if( tmp ) munmap(tmp,tmp_size);
		return ptr;
	}
	base_addr = (char*)ptr+size;
	return ptr;
#endif
}

static void gc_free_page_memory( void *ptr, int size ) {
#ifdef GC_INCREMENTAL_LINUX
	gc_inc_mapping **cursor = &gc_inc_mappings;
	while( *cursor ) {
		gc_inc_mapping *entry = *cursor;
		if( entry->address == ptr ) {
			*cursor = entry->next;
			munmap(entry->mapping,entry->reserved);
			free(entry);
			return;
		}
		cursor = &entry->next;
	}
#endif
#ifdef HL_WIN
	VirtualFree(ptr, 0, MEM_RELEASE);
#elif defined(HL_CONSOLE)
	sys_free_align(ptr,size);
#elif defined(HL_EMSCRIPTEN)
	emscripten_builtin_free(ptr);
#else
	pextra *e = extra_pages, *prev = NULL;
	while( e ) {
		if( e->page_ptr == ptr ) {
			if( prev )
				prev->next = e->next;
			else
				extra_pages = e->next;
			munmap(e->base_ptr, size + EXTRA_SIZE);
			return;
		}
		prev = e;
		e = e->next;
	}
	munmap(ptr,size);
#endif
}

vdynamic *hl_alloc_dynamic( hl_type *t ) {
	vdynamic *d = (vdynamic*)hl_gc_alloc_gen(t, sizeof(vdynamic), (hl_is_ptr(t) ? (t->kind == HSTRUCT ? MEM_KIND_RAW : MEM_KIND_DYNAMIC) : MEM_KIND_NOPTR) | MEM_ZERO);
	d->t = t;
	return d;
}

#ifndef HL_64
#	define DYN_PAD	0,
#else
#	define DYN_PAD
#endif

static const vdynamic vdyn_true = { &hlt_bool, DYN_PAD {true} };
static const vdynamic vdyn_false = { &hlt_bool, DYN_PAD {false} };

vdynamic *hl_alloc_dynbool( bool b ) {
	return (vdynamic*)(b ? &vdyn_true : &vdyn_false);
}


HL_API vdynamic *hl_jit_alloc_slow(hl_type *type) {
	hl_gc_safepoint();
	return hl_alloc_obj(type);
}

vdynamic *hl_alloc_obj( hl_type *t ) {
	vobj *o;
	int i;
	hl_runtime_obj *rt = t->obj->rt;
	if( rt == NULL || rt->methods == NULL ) rt = hl_get_obj_proto(t);
	if( t->kind == HSTRUCT ) {
		o = (vobj*)hl_gc_alloc_gen(t, rt->size, (rt->hasPtr ? MEM_KIND_RAW : MEM_KIND_NOPTR) | MEM_ZERO);
	} else {
		o = (vobj*)hl_gc_alloc_gen(t, rt->size, (rt->hasPtr ? MEM_KIND_DYNAMIC : MEM_KIND_NOPTR) | MEM_ZERO);
		o->t = t;
	}
	for(i=0;i<rt->nbindings;i++) {
		hl_runtime_binding *b = rt->bindings + i;
		*(void**)(((char*)o) + rt->fields_indexes[b->fid]) = b->closure ? hl_alloc_closure_ptr(b->closure,b->ptr,o) : b->ptr;
	}
	return (vdynamic*)o;
}

vdynobj *hl_alloc_dynobj() {
	vdynobj *o = (vdynobj*)hl_gc_alloc_gen(&hlt_dynobj,sizeof(vdynobj),MEM_KIND_DYNAMIC | MEM_ZERO);
	o->t = &hlt_dynobj;
	return o;
}

vvirtual *hl_alloc_virtual( hl_type *t ) {
	vvirtual *v = (vvirtual*)hl_gc_alloc(t, t->virt->dataSize + sizeof(vvirtual) + sizeof(void*) * t->virt->nfields);
	void **fields = (void**)(v + 1);
	char *vdata = (char*)(fields + t->virt->nfields);
	int i;
	v->t = t;
	v->value = NULL;
	v->next = NULL;
	for(i=0;i<t->virt->nfields;i++)
		fields[i] = (char*)v + t->virt->indexes[i];
	MZERO(vdata,t->virt->dataSize);
	return v;
}

HL_API void hl_gc_stats( double *total_allocated, double *allocation_count, double *current_memory ) {
	*total_allocated = (double)gc_stats.total_allocated;
	*allocation_count = (double)gc_stats.allocation_count;
	*current_memory = (double)gc_stats.pages_total_memory;
}

HL_PRIM double hl_gc_total_allocated() {
	return (double)gc_stats.total_allocated;
}

HL_PRIM double hl_gc_collections() {
	return (double)gc_stats.mark_count;
}

HL_PRIM double hl_gc_last_pause_micros() {
	return gc_stats.last_mark_ms * 1000.0;
}

HL_PRIM double hl_gc_max_pause_micros() {
	return gc_stats.max_mark_ms * 1000.0;
}

HL_PRIM double hl_gc_allocated_since_collection() {
	return (double)(gc_stats.total_allocated - gc_stats.last_mark);
}

HL_PRIM double hl_gc_heap_bytes() {
	return (double)gc_stats.pages_total_memory;
}

// A collection starts once the bytes (or blocks) allocated since the last one exceed this fraction of the heap.
HL_PRIM void hl_gc_set_mark_threshold( double fraction ) {
	if( fraction < 0.05 ) fraction = 0.05;
	if( fraction > 4.0 ) fraction = 4.0;
	gc_mark_threshold = (float)fraction;
}

HL_PRIM double hl_gc_get_mark_threshold() {
	return (double)gc_mark_threshold;
}

HL_PRIM double hl_gc_mark_micros() {
	return gc_stats.mark_duration_ms * 1000.0;
}

HL_API void hl_gc_profile_stats( unsigned long long *allocated, unsigned long long *allocations, unsigned long long *heap, unsigned long long *collections, unsigned long long *mark_micros ) {
	*allocated = (unsigned long long)gc_stats.total_allocated;
	*allocations = (unsigned long long)gc_stats.allocation_count;
	*heap = (unsigned long long)gc_stats.pages_total_memory;
	*collections = (unsigned long long)gc_stats.mark_count;
	*mark_micros = (unsigned long long)(gc_stats.mark_duration_ms * 1000.0);
}

HL_PRIM void hl_gc_detailed_stats( double *allocated, double *allocations, double *collections, double *mark_micros ) {
	unsigned long long heap, allocated_value, allocation_value, collection_value, mark_value;
	hl_gc_profile_stats(&allocated_value,&allocation_value,&heap,&collection_value,&mark_value);
	*allocated = (double)allocated_value;
	*allocations = (double)allocation_value;
	*collections = (double)collection_value;
	*mark_micros = (double)mark_value;
}

HL_API void hl_gc_enable( bool b ) {
	gc_is_active = b;
}

HL_API int hl_gc_get_flags() {
	return gc_flags;
}

HL_API void hl_gc_set_flags( int f ) {
	gc_flags = f;
}

HL_API void hl_set_thread_flags( int flags, int mask ) {
	hl_thread_info *t = hl_get_thread();
	t->flags = (t->flags & ~mask) | flags;
}

HL_API void hl_gc_profile( bool b ) {
	if( b )
		gc_flags |= GC_PROFILE;
	else
		gc_flags &= GC_PROFILE;
}

static FILE *fdump;
static void fdump_i( int i ) {
	fwrite(&i,1,4,fdump);
}
static void fdump_p( void *p ) {
	fwrite(&p,1,sizeof(void*),fdump);
}
static void fdump_d( void *p, int size ) {
	fwrite(p,1,size,fdump);
}

static hl_types_dump gc_types_dump = NULL;
HL_API void hl_gc_set_dump_types( hl_types_dump tdump ) {
	gc_types_dump = tdump;
}

static void gc_dump_block( void *block, int size ) {
	fdump_p(block);
	fdump_i(size);
}

static void gc_dump_block_ptr( void *block, int size ) {
	fdump_p(block);
	fdump_i(size);
	if( size >= (int)sizeof(void*) ) fdump_p(*(void**)block);
}

static void gc_dump_page( gc_pheader *p, int private_data ) {
	fdump_p(p->base);
	fdump_i(p->page_kind);
	fdump_i(p->page_size);
	fdump_i(private_data);
	if( p->page_kind & MEM_KIND_NOPTR ) {
		gc_iter_live_blocks(p, gc_dump_block_ptr); // only dump type
		fdump_p(NULL);
	} else {
		gc_iter_live_blocks(p,gc_dump_block);
		fdump_p(NULL);
		fdump_d(p->base, p->page_size);
	}
}

HL_API void hl_gc_dump_memory( const char *filename ) {
	int i;
	gc_global_lock(true);
	gc_stop_world(true);
	gc_mark();
	fdump = fopen(filename,"wb");
	if( fdump == NULL ) {
		gc_stop_world(false);
		gc_global_lock(false);
		hl_error("Failed to open file");
		return;
	}

	// header
	fdump_d("HMD1",4);
	fdump_i(((sizeof(void*) == 8)?1:0) | ((sizeof(bool) == 4)?2:0));

	// pages
	int page_count, private_data;
	gc_get_stats(&page_count, &private_data);

	// all mallocs
	private_data += sizeof(gc_pheader) * page_count;
	private_data += sizeof(void*) * gc_roots_max;
	private_data += gc_threads.count * (sizeof(void*) + sizeof(hl_thread_info));
	for(i=0;i<1<<GC_LEVEL0_BITS;i++)
		if( hl_gc_page_map[i] != gc_level1_null )
			private_data += sizeof(void*) * (1<<GC_LEVEL1_BITS);

	fdump_i(private_data);
	int msize = global_mark_stack.size;
	for(i=0;i<GC_MAX_MARK_THREADS;i++)
		msize += mark_threads[i].stack.size;
	fdump_i(msize); // keep separate
	fdump_i(page_count);
	gc_iter_pages(gc_dump_page);

	// roots
	fdump_i(gc_roots_count);
	for(i=0;i<gc_roots_count;i++)
		fdump_p(*gc_roots[i]);
	// stacks
	fdump_i(gc_threads.count);
	for(i=0;i<gc_threads.count;i++) {
		hl_thread_info *t = gc_threads.threads[i];
		fdump_p(t->stack_top);
		int size = (int)((void**)t->stack_top - (void**)t->stack_cur);
		fdump_i(size);
		fdump_d(t->stack_cur,size*sizeof(void*));
	}
	// types
#	define fdump_t(t)	fdump_i(t.kind); fdump_p(&t);
	fdump_t(hlt_i32);
	fdump_t(hlt_i64);
	fdump_t(hlt_f32);
	fdump_t(hlt_f64);
	fdump_t(hlt_dyn);
	fdump_t(hlt_array);
	fdump_t(hlt_bytes);
	fdump_t(hlt_dynobj);
	fdump_t(hlt_bool);
	fdump_i(-1);
	if( gc_types_dump ) gc_types_dump(fdump_d);
	fclose(fdump);
	fdump = NULL;
	gc_stop_world(false);
	gc_global_lock(false);
}

typedef struct {
	hl_type *t;
	int count;
	int page_kinds;
	varray *arr;
	int index;
} gc_live_obj;
static gc_live_obj live_obj;

static void gc_count_live_block( void *block, int size ) {
	if( size < (int)sizeof(void*) ) return;
	hl_type *t = *(hl_type **)block;
	if( t != live_obj.t ) return;
	live_obj.count++;
	if( live_obj.index < live_obj.arr->size ) {
		hl_aptr(live_obj.arr, vdynamic*)[live_obj.index] = hl_make_dyn(&block, live_obj.t);
		live_obj.index++;
	}
}

static void gc_count_live_page( gc_pheader *p, int private_data ) {
	if( (1 << p->page_kind) & live_obj.page_kinds )
		gc_iter_live_blocks(p, gc_count_live_block);
}

HL_API int hl_gc_get_live_objects( hl_type *t, varray *arr ) {
	if( !hl_is_dynamic(t) ) return -1;
	gc_global_lock(true);
	gc_stop_world(true);
	gc_mark();

	live_obj.t = t;
	live_obj.count = 0;
	live_obj.page_kinds = (1 << MEM_KIND_DYNAMIC) + (1 << MEM_KIND_NOPTR);
	if( t->kind == HOBJ ) {
		live_obj.page_kinds = hl_get_obj_rt(t)->hasPtr ? 1 << MEM_KIND_DYNAMIC : 1 << MEM_KIND_NOPTR;
	}
	live_obj.arr = arr;
	live_obj.index = 0;
	gc_iter_pages(gc_count_live_page);

	gc_stop_world(false);
	gc_global_lock(false);
	return live_obj.count;
}

#ifdef HL_VCC
#	pragma optimize( "", off )
#endif
HL_API vdynamic *hl_debug_call( int mode, vdynamic *v ) {
	return NULL;
}
#ifdef HL_VCC
#	pragma optimize( "", on )
#endif

DEFINE_PRIM(_VOID, gc_major, _NO_ARG);
DEFINE_PRIM(_BOOL, gc_step, _F64);
DEFINE_PRIM(_BOOL, gc_frame_begin, _F64);
DEFINE_PRIM(_VOID, gc_frame_end, _NO_ARG);
DEFINE_PRIM(_F64, gc_frame_remaining, _NO_ARG);
DEFINE_PRIM(_F64, gc_trigger_bytes, _NO_ARG);
DEFINE_PRIM(_BOOL, gc_incremental_supported, _NO_ARG);
DEFINE_PRIM(_BOOL, gc_incremental_pending, _NO_ARG);
DEFINE_PRIM(_BOOL, gc_incremental_reclaiming, _NO_ARG);
DEFINE_PRIM(_VOID, gc_enable, _BOOL);
DEFINE_PRIM(_VOID, gc_profile, _BOOL);
DEFINE_PRIM(_VOID, gc_stats, _REF(_F64) _REF(_F64) _REF(_F64));
DEFINE_PRIM(_F64, gc_total_allocated, _NO_ARG);
DEFINE_PRIM(_F64, gc_collections, _NO_ARG);
DEFINE_PRIM(_F64, gc_mark_micros, _NO_ARG);
DEFINE_PRIM(_F64, gc_last_pause_micros, _NO_ARG);
DEFINE_PRIM(_F64, gc_max_pause_micros, _NO_ARG);
DEFINE_PRIM(_F64, gc_heap_bytes, _NO_ARG);
DEFINE_PRIM(_F64, gc_allocated_since_collection, _NO_ARG);
DEFINE_PRIM(_VOID, gc_set_mark_threshold, _F64);
DEFINE_PRIM(_F64, gc_get_mark_threshold, _NO_ARG);
DEFINE_PRIM(_VOID, gc_detailed_stats, _REF(_F64) _REF(_F64) _REF(_F64) _REF(_F64));
DEFINE_PRIM(_VOID, gc_dump_memory, _BYTES);
DEFINE_PRIM(_VOID, gc_census_start, _I32);
DEFINE_PRIM(_VOID, gc_census_stop, _NO_ARG);
DEFINE_PRIM(_VOID, gc_census_reset, _NO_ARG);
DEFINE_PRIM(_VOID, gc_census_dump, _BYTES);
DEFINE_PRIM(_I32, gc_get_live_objects, _TYPE _ARR);
DEFINE_PRIM(_I32, gc_get_flags, _NO_ARG);
DEFINE_PRIM(_VOID, gc_set_flags, _I32);
DEFINE_PRIM(_DYN, debug_call, _I32 _DYN);
DEFINE_PRIM(_VOID, blocking, _BOOL);
DEFINE_PRIM(_VOID, gc_safepoint, _NO_ARG);
DEFINE_PRIM(_VOID, set_thread_flags, _I32 _I32);

// Keep JIT-only descriptor preparation and rare refill out of ordinary runtime
// text to avoid displacing hot map/cast code on ELF targets.
#if defined(__linux__) && defined(__x86_64__) && defined(__GNUC__)
#define GC_JIT_COLD __attribute__((cold,section(".hl_jit_cold")))
#else
#define GC_JIT_COLD
#endif

// They share GC_TLAB_POLICY so runtime policy and generated guards stay in sync.
HL_API GC_JIT_COLD bool hl_jit_box_prepare(hl_type *type, hl_jit_alloc_data *data) {
#if defined(GC_TLAB) && defined(__linux__) && defined(__x86_64__) && defined(__GNUC__)
	if(type->kind != HI32 || type->gc_owner != NULL || sizeof(vdynamic) != 16) return false;
	memset(data,0,sizeof(*data));
	data->type = type; data->block = sizeof(vdynamic);
	intptr_t tls = (intptr_t)((uintptr_t)&current_thread - (uintptr_t)__builtin_thread_pointer());
	if(tls < (-2147483647-1) || tls > 2147483647) return false;
	data->tls_offset = (int)tls;
	data->slot_offset = (((sizeof(vdynamic) >> GC_ALIGN_BITS)-1) << PAGE_KIND_BITS | MEM_KIND_NOPTR) * sizeof(gc_tlab_slot);
#define GC_BOX_GUARD(value, bits, width) \
	data->guards[data->nguards].address = (void*)&(value); \
	data->guards[data->nguards].mask = (bits); \
	data->guards[data->nguards++].bytes = (width);
	GC_TLAB_POLICY(GC_BOX_GUARD)
	GC_BOX_GUARD(gc_threads.stopping_world,1,1)
#undef GC_BOX_GUARD
	return true;
#else
	(void)type; (void)data; return false;
#endif
}

HL_API GC_JIT_COLD vdynamic *hl_jit_box_slow(hl_type *type) {
	hl_gc_safepoint();
	return hl_alloc_dynamic(type);
}

#undef GC_JIT_COLD
