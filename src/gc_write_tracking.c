/* Included by gc_incremental.c. Platform write discovery, independent of marking.
 * begin/collect/rearm/end run with the GC lock held and the world stopped.
 * supported may probe capabilities under the GC lock before suspension.
 * collect merges kernel dirties with incoming software notifications; it never
 * edits marks. After a successful rearm, the collector freezes that queue as the
 * next tracing batch. Mutator arrivals cannot extend an already captured batch.
 * Linux partial walks retain kernel bits and require a final synchronous capture
 * before process-wide rearm. Software discovery is a barrier-populated queue.
 * Rearm occurs only after a complete capture; partial walks retain dirty bits.
 * Any capture/rearm failure requires a full collection; end must also tolerate cancellation/failed begin
 * and is also called during quiescent global shutdown.
 */
typedef struct {
	bool (*supported)(void);
	bool (*begin)(void);
	bool (*collect)(double deadline, bool *complete);
	bool (*rearm)(void);
	void (*end)(void);
	void (*disable)(void);
	void (*shutdown)(void);
	bool (*isolated_mappings)(void);
} gc_write_tracking_backend;

#if !defined(GC_EXTERN_API) && !defined(GC_DEBUG) && !defined(GC_MEMCHK)
#define GC_INCREMENTAL_MARKING
#endif
#if defined(GC_INCREMENTAL_MARKING) && defined(__GNUC__) && (defined(__linux__) || (defined(__APPLE__) && defined(__aarch64__) && defined(HL_GC_APPLE_SOFTWARE_TEST)))
#define GC_INCREMENTAL_SOFTWARE
#endif

#ifdef GC_INCREMENTAL_SOFTWARE
static gc_pheader *gc_software_dirty_head;
static gc_pheader *gc_dirty_batch_head;
static unsigned int gc_software_dirty_count;
/* One queued node per page across incoming and captured queues. Mutators never
 * allocate or take a lock here. Only a completed capture can transfer incoming
 * notifications to the batch the collector drains. Until a page is popped,
 * later writes coalesce into its pending scan; after popping they join the next
 * capture. The collector changes batch links only with the world stopped. */
static void gc_dirty_enqueue_source(gc_pheader *p, unsigned int source) {
	if( gc_scan_profile_enabled && MEM_HAS_PTR(p->page_kind) )
		__atomic_fetch_or(&p->scan_dirty_sources,source,__ATOMIC_RELAXED);
	if( !MEM_HAS_PTR(p->page_kind) || __atomic_exchange_n(&p->software_dirty,1,__ATOMIC_ACQ_REL) ) return;
	__atomic_add_fetch(&gc_software_dirty_count,1,__ATOMIC_RELAXED);
	gc_pheader *head = __atomic_load_n(&gc_software_dirty_head,__ATOMIC_RELAXED);
	do p->software_dirty_next = head;
	while( !__atomic_compare_exchange_n(&gc_software_dirty_head,&head,p,false,__ATOMIC_RELEASE,__ATOMIC_RELAXED) );
}
static void gc_dirty_enqueue(gc_pheader *p) { gc_dirty_enqueue_source(p,1); }
static unsigned int gc_dirty_sources(gc_pheader *p) {
	return __atomic_exchange_n(&p->scan_dirty_sources,0,__ATOMIC_RELAXED);
}
static void gc_dirty_capture_done(void) {
	if( gc_dirty_batch_head ) hl_fatal("Dirty capture with unfinished batch");
	gc_dirty_batch_head = __atomic_exchange_n(&gc_software_dirty_head,NULL,__ATOMIC_ACQ_REL);
}
static gc_pheader *gc_dirty_pop(void) {
	gc_pheader *p = gc_dirty_batch_head;
	if( !p ) return NULL;
	gc_dirty_batch_head = p->software_dirty_next;
	__atomic_sub_fetch(&gc_software_dirty_count,1,__ATOMIC_RELAXED);
	p->software_dirty_next = NULL;
	__atomic_store_n(&p->software_dirty,0,__ATOMIC_RELEASE);
	return p;
}
#else
static gc_pheader *gc_dirty_pop(void) { return NULL; }
static void gc_dirty_capture_done(void) {}
static unsigned int gc_dirty_sources(gc_pheader *p) { (void)p; return 0; }
#endif

/* Read by generated code; changed only with mutators suspended. */
int hl_gc_write_barrier_active = 0;
HL_API void hl_gc_write_barrier(void *address, size_t bytes) {
#ifdef GC_INCREMENTAL_SOFTWARE
	if( !__atomic_load_n(&hl_gc_write_barrier_active,__ATOMIC_RELAXED) || !bytes ) return;
	uintptr_t first = (uintptr_t)address, last = first + bytes - 1;
	if( last < first ) return;
	for(;;) {
		void *ptr = (void*)first;
		gc_pheader **level = __atomic_load_n(&GC_GET_LEVEL1(ptr),__ATOMIC_ACQUIRE);
		gc_pheader *p = __atomic_load_n(&level[(gc_hash(ptr)>>GC_MASK_BITS)&GC_LEVEL1_MASK],__ATOMIC_ACQUIRE);
		if( p && INPAGE(ptr,p) && MEM_HAS_PTR(p->page_kind) )
			gc_dirty_enqueue(p);
		if( (first >> GC_MASK_BITS) == (last >> GC_MASK_BITS) ) break;
		first = ((first >> GC_MASK_BITS) + 1) << GC_MASK_BITS;
	}
#else
	(void)address; (void)bytes;
#endif
}

#ifdef GC_INCREMENTAL_SOFTWARE
static bool gc_inc_test_software;

/* Internal test mode: initialize once, before mappings or mutators exist.
 * Keep the independent oracle mandatory even if the environment later changes. */
static void gc_inc_tracking_configure(void) {
	const char *mode = getenv("HL_GC_INCREMENTAL_TEST_SOFTWARE");
	gc_inc_test_software = mode && strcmp(mode,"1") == 0;
	if( gc_inc_test_software ) {
		const char *validate = getenv("HL_GC_INCREMENTAL_VALIDATE");
		if( !validate || strcmp(validate,"1") != 0 )
			hl_fatal("Test-only software GC requires HL_GC_INCREMENTAL_VALIDATE=1");
	}
}

static bool gc_inc_tracking_begin(void) {
	gc_software_dirty_head = gc_dirty_batch_head = NULL;
	gc_software_dirty_count = 0;
	for(int pid = 0; pid < GC_ALL_PAGES; pid++)
		for(gc_pheader *p = gc_pages[pid]; p; p = p->next_page) {
			p->software_dirty = 0;
			p->scan_dirty_sources = 0;
		}
	__atomic_store_n(&hl_gc_write_barrier_active,1,__ATOMIC_RELAXED);
	return true;
}
static void gc_inc_tracking_end(void) {
	__atomic_store_n(&hl_gc_write_barrier_active,0,__ATOMIC_RELAXED);
	gc_software_dirty_head = gc_dirty_batch_head = NULL;
	gc_software_dirty_count = 0;
}

static bool gc_software_collect(double deadline, bool *complete) {
	(void)deadline;
	*complete = true;
	return true;
}
#endif

#if defined(__linux__) && defined(GC_INCREMENTAL_MARKING)
#define GC_INCREMENTAL_LINUX
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
static int gc_inc_pagemap = -1, gc_inc_clear = -1;
static int gc_inc_supported = -1;
static long gc_inc_os_page;
static bool gc_inc_clear_dirty(void) {
	if( gc_inc_test_software ) return true;
	ssize_t count;
	do count = pwrite(gc_inc_clear,"4",1,0); while( count < 0 && errno == EINTR );
	return count == 1;
}

static bool gc_inc_read_dirty(void *address, uint64 *entries, int count) {
	ssize_t bytes;
	off_t offset = (off_t)((uintptr_t)address / gc_inc_os_page) * sizeof(uint64);
	do bytes = pread(gc_inc_pagemap,entries,count * sizeof(uint64),offset);
	while( bytes < 0 && errno == EINTR );
	return bytes == count * (ssize_t)sizeof(uint64);
}

static bool gc_inc_probe(void) {
	if( gc_inc_supported >= 0 ) return gc_inc_supported != 0;
	gc_inc_supported = 0;
	if( gc_inc_test_software ) { gc_inc_supported = 1; return true; }
	gc_inc_os_page = sysconf(_SC_PAGESIZE);
	if( gc_inc_os_page <= 0 || GC_PAGE_SIZE % gc_inc_os_page != 0 ) return false;
	gc_inc_pagemap = open("/proc/self/pagemap",O_RDONLY | O_CLOEXEC);
	gc_inc_clear = open("/proc/self/clear_refs",O_WRONLY | O_CLOEXEC);
	if( gc_inc_pagemap < 0 || gc_inc_clear < 0 ) goto failed;
	// Check CONFIG_MEM_SOFT_DIRTY and proc permissions rather than assuming Linux suffices.
	volatile unsigned char *probe = mmap(NULL,gc_inc_os_page,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
	if( probe == MAP_FAILED ) goto failed;
	uint64 before = 0, after = 0;
	*probe = 1;
	bool ok = gc_inc_clear_dirty() && gc_inc_read_dirty((void*)probe,&before,1);
	*probe = 2;
	ok = ok && gc_inc_read_dirty((void*)probe,&after,1);
	munmap((void*)probe,gc_inc_os_page);
	if( !ok || (before & (1ULL << 55)) || !(after & (1ULL << 55)) ) goto failed;
	gc_inc_supported = 1;
	return true;
failed:
	if( gc_inc_pagemap >= 0 ) close(gc_inc_pagemap);
	if( gc_inc_clear >= 0 ) close(gc_inc_clear);
	gc_inc_pagemap = gc_inc_clear = -1;
	return false;
}

static int gc_inc_dirty_pid, gc_inc_dirty_offset;
static gc_pheader *gc_inc_dirty_cursor;
static bool gc_inc_dirty_walk, gc_inc_dirty_spanned;

static void gc_inc_dirty_reset(void) {
	gc_inc_dirty_pid = gc_inc_dirty_offset = 0;
	gc_inc_dirty_cursor = NULL;
	gc_inc_dirty_walk = gc_inc_dirty_spanned = false;
}
static bool gc_inc_linux_begin(void) {
	gc_inc_dirty_reset();
	return gc_inc_tracking_begin() && gc_inc_clear_dirty();
}

/* Each read is bounded to 256 OS pages, even for very large allocations. */
static bool gc_inc_capture_chunk(gc_pheader *p, int *offset, bool *dirty) {
	uint64 entries[256];
	int count = (p->page_size - *offset) / gc_inc_os_page;
	if( count > 256 ) count = 256;
	if( count <= 0 || !gc_inc_read_dirty(p->base + *offset,entries,count) ) return false;
	for(int i = 0; i < count; i++) if( entries[i] & (1ULL << 55) ) *dirty = true;
	*offset += count * gc_inc_os_page;
	return true;
}

static bool gc_inc_capture_all(void) {
	for(int pid = 0; pid < GC_ALL_PAGES; pid++) {
		for(gc_pheader *p = gc_pages[pid]; p; p = p->next_page) {
			if( !MEM_HAS_PTR(p->page_kind) ) continue;
			bool dirty = false;
			for(int offset = 0; offset < p->page_size && !dirty; )
				if( !gc_inc_capture_chunk(p,&offset,&dirty) ) return false;
			if( dirty ) gc_dirty_enqueue_source(p,2);
		}
	}
	return true;
}

static bool gc_inc_collect_dirty(double deadline, bool *complete) {
	*complete = false;
	if( gc_inc_test_software ) return gc_software_collect(deadline,complete);
	if( !gc_inc_dirty_walk ) {
		gc_inc_dirty_reset();
		gc_inc_dirty_walk = true;
	}
	while( gc_inc_dirty_cursor || gc_inc_dirty_pid < GC_ALL_PAGES ) {
		if( !gc_inc_dirty_cursor ) {
			gc_inc_dirty_cursor = gc_pages[gc_inc_dirty_pid++];
			if( !gc_inc_dirty_cursor ) continue;
		}
		gc_pheader *p = gc_inc_dirty_cursor;
		bool dirty = false;
		if( MEM_HAS_PTR(p->page_kind) && !gc_inc_capture_chunk(p,&gc_inc_dirty_offset,&dirty) ) return false;
		if( dirty ) gc_dirty_enqueue_source(p,2);
		if( dirty || !MEM_HAS_PTR(p->page_kind) || gc_inc_dirty_offset >= p->page_size ) {
			gc_inc_dirty_cursor = p->next_page;
			gc_inc_dirty_offset = 0;
		}
		if( hl_sys_time() >= deadline ) {
			gc_inc_dirty_spanned = true;
			return true;
		}
	}
	// clear_refs clears every page. Capture writes to already-visited pages
	// (and new list heads) in this pause before permitting that global clear.
	if( gc_inc_dirty_spanned && !gc_inc_capture_all() ) return false;
	gc_inc_dirty_reset();
	*complete = true;
	return true;
}

static void gc_inc_tracking_disable(void) { gc_inc_supported = 0; }
static bool gc_inc_isolated_mappings(void) { return !gc_inc_test_software && gc_inc_supported != 0; }
static void gc_inc_tracking_shutdown(void) {
	if( gc_inc_pagemap >= 0 ) close(gc_inc_pagemap);
	if( gc_inc_clear >= 0 ) close(gc_inc_clear);
	gc_inc_pagemap = gc_inc_clear = -1;
	gc_inc_supported = -1;
	gc_inc_dirty_reset();
	gc_inc_test_software = false;
}
static const gc_write_tracking_backend gc_write_tracking = {
	gc_inc_probe, gc_inc_linux_begin, gc_inc_collect_dirty, gc_inc_clear_dirty,
	gc_inc_tracking_end, gc_inc_tracking_disable, gc_inc_tracking_shutdown, gc_inc_isolated_mappings
};
#elif defined(GC_INCREMENTAL_SOFTWARE)
static bool gc_software_disabled;
/* Apple AArch64 is build-gated and has no OS safety net. Only the explicitly
 * selected test backend reports support; final-remark validation is mandatory. */
static bool gc_software_probe(void) { return gc_inc_test_software && !gc_software_disabled; }
static bool gc_software_rearm(void) { return true; }
static bool gc_software_isolated(void) { return false; }
static void gc_software_disable(void) { gc_software_disabled = true; }
static void gc_software_shutdown(void) { gc_inc_tracking_end(); gc_inc_test_software = false; gc_software_disabled = false; }
static const gc_write_tracking_backend gc_write_tracking = {
	gc_software_probe, gc_inc_tracking_begin, gc_software_collect, gc_software_rearm,
	gc_inc_tracking_end, gc_software_disable, gc_software_shutdown, gc_software_isolated
};
#else
static bool gc_tracking_unavailable(void) { return false; }
static bool gc_tracking_no_pages(double deadline, bool *complete) { (void)deadline; *complete = false; return false; }
static void gc_tracking_noop(void) {}
static const gc_write_tracking_backend gc_write_tracking = {
	gc_tracking_unavailable, gc_tracking_unavailable, gc_tracking_no_pages, gc_tracking_unavailable,
	gc_tracking_noop, gc_tracking_noop, gc_tracking_noop, gc_tracking_unavailable
};
#endif
