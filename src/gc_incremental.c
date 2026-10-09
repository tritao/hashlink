/* Included by gc.c. Incremental marking, independent of platform write discovery.
 * All metadata and heap scans run with the world stopped and GC lock held.
 * No page or object is reclaimed until the roots, dirty pages and mark queue
 * reach a fixed point in one pause. New allocations are black for this cycle.
 * Native writers must obey the same registered-thread/blocking contract as the
 * ordinary collector. Concurrent DMA/shared aliases are not supported.
 */
#include "gc_write_tracking.c"

static void gc_major(void);
static void **gc_inc_cursor, **gc_inc_end;
static void *gc_inc_block;
static int64 gc_inc_start_bytes, gc_inc_start_allocs, gc_inc_last_step_bytes;
static double gc_inc_cycle_limit;
static unsigned long long gc_inc_cycles_started, gc_inc_cycles_completed;
static unsigned long long gc_inc_pressure_fallbacks, gc_inc_tracking_fallbacks;
static double gc_inc_cycle_started, gc_inc_last_cycle_micros;
static bool gc_inc_preparing, gc_inc_discovering, gc_inc_reclaiming;
static gc_pheader *gc_inc_rescan_cursor;
static int gc_inc_rescan_bid;
static int gc_inc_prepare_pid;
static gc_pheader *gc_inc_prepare_cursor;
#ifdef GC_INCREMENTAL_MARKING
static void gc_inc_prepare_page(gc_pheader *p, int ignored);
#endif

/* Diagnostic metadata is private to a cycle and never participates in marks.
 * high_water counts actual first reads, even when a partial scan restarts. */
typedef struct { size_t high_water; int64 birth_bytes; unsigned char sources, black; } gc_scan_object;
static bool gc_retention_profile;
static unsigned long long gc_scan_bytes[2][4];
static unsigned int gc_scan_current_sources, gc_scan_rescan_sources;
#ifdef GC_INCREMENTAL_MARKING
static gc_scan_object *gc_scan_metadata(gc_pheader *p, int bid) {
	if( !p->scan_profile ) {
		p->scan_profile = calloc(p->alloc.max_blocks,sizeof(gc_scan_object));
		if( !p->scan_profile ) out_of_memory("scan profile");
	}
	return (gc_scan_object*)p->scan_profile + bid;
}
#endif
static void gc_scan_report(const char *status) {
	if( !gc_scan_profile_enabled ) return;
	for(int repeat = 0; repeat < 2; repeat++)
		for(int source = 0; source < 4; source++)
			fprintf(stderr,"GC-SCAN-TOTAL,cycle=%llu,status=%s,repeat=%d,source=%d,bytes=%llu\n",
				gc_inc_cycles_started,status,repeat,source,gc_scan_bytes[repeat][source]);
}
#ifdef GC_INCREMENTAL_MARKING
static void gc_scan_range(void **start, void **end) {
	if( !gc_scan_profile_enabled || start == end ) return;
	gc_pheader *p = GC_GET_PAGE(gc_inc_block);
	int bid = ((unsigned char*)gc_inc_block-p->base)/p->alloc.block_size;
	gc_scan_object *m = gc_scan_metadata(p,bid);
	size_t first = start-(void**)gc_inc_block, last = end-(void**)gc_inc_block;
	size_t repeated = first < m->high_water ? (last < m->high_water ? last : m->high_water)-first : 0;
	size_t fresh = last-first-repeated;
	if( last > m->high_water ) m->high_water = last;
	gc_scan_bytes[0][gc_scan_current_sources] += fresh*sizeof(void*);
	gc_scan_bytes[1][gc_scan_current_sources] += repeated*sizeof(void*);
	if( gc_allocator_fast_block_size(p,gc_inc_block) >= (1<<20) )
		fprintf(stderr,"GC-SCAN-LARGE,cycle=%llu,block=%p,source=%u,black=%d,first_bytes=%zu,repeat_bytes=%zu\n",
			gc_inc_cycles_started,gc_inc_block,gc_scan_current_sources,m->black,fresh*sizeof(void*),repeated*sizeof(void*));
}

#endif
static void gc_incremental_allocated(void *ptr) {
	gc_pheader *p = GC_GET_PAGE(ptr);
#ifdef GC_INCREMENTAL_MARKING
	// Allocator allocation has already flushed this page's previous lazy sweep.
	// Preparing on demand keeps new allocations black without touching other pages.
	if( p->incremental_epoch != gc_incremental_epoch ) gc_inc_prepare_page(p,0);
#endif
	int bid = gc_allocator_get_block_id(p,ptr);
	if( bid < 0 || !p->bmp ) hl_fatal("Invalid incremental allocation");
	p->bmp[bid >> 3] |= 1 << (bid & 7);
#ifdef GC_INCREMENTAL_MARKING
	if( gc_scan_profile_enabled ) {
		gc_scan_object *m = gc_scan_metadata(p,bid);
		m->black = 1;
		m->birth_bytes = gc_stats.total_allocated;
	}
#endif
}

static void gc_inc_release_bitmap(gc_pheader *p, int ignored) {
	(void)ignored;
	free(p->scan_profile);
	p->scan_profile = NULL;
	if( p->incremental_bmp ) {
		p->bmp = NULL;
		free(p->incremental_bmp);
		p->incremental_bmp = NULL;
	}
}

static void gc_incremental_discard(void) {
	gc_inc_reclaiming = false;
	gc_empty_sweep_cancel();
	if( gc_incremental_active ) gc_scan_report("cancelled");
	// Preserve the allocator's original free lists: a partial mark is never a sweep bitmap.
	if( gc_incremental_active && global_mark_stack.size )
		global_mark_stack.cur = global_mark_stack.end - global_mark_stack.size + 1;
	if( gc_incremental_active ) gc_write_tracking.end();
	gc_incremental_active = false;
	gc_inc_preparing = gc_inc_discovering = false;
	gc_inc_rescan_cursor = NULL;
	gc_inc_rescan_bid = 0;
	gc_inc_prepare_cursor = NULL;
	gc_inc_prepare_pid = 0;
	gc_inc_cursor = gc_inc_end = NULL;
	gc_inc_block = NULL;
	if( gc_incremental_bitmaps ) {
		gc_iter_pages(gc_inc_release_bitmap);
		gc_incremental_bitmaps = false;
	}
}

#ifdef GC_INCREMENTAL_MARKING
static void gc_inc_enqueue(gc_pheader *page, int bid) {
	if( !MEM_HAS_PTR(page->page_kind) ) return;
	unsigned char *queued = page->incremental_bmp + ((page->alloc.max_blocks + 7) >> 3);
	if( queued[bid >> 3] & (1 << (bid & 7)) ) return;
	queued[bid >> 3] |= 1 << (bid & 7);
	GC_STACK_BEGIN(&global_mark_stack);
	GC_PUSH_GEN(page->base + bid * page->alloc.block_size,page);
	GC_STACK_END();
}

static HL_INLINE void gc_inc_visit_page(void *ptr, gc_pheader *page, bool interior) {
	int bid = interior ? gc_allocator_get_block_interior(page,&ptr) : gc_allocator_get_block_id(page,ptr);
	if( bid < 0 || (page->bmp[bid >> 3] & (1 << (bid & 7))) ) return;
	page->bmp[bid >> 3] |= 1 << (bid & 7);
	gc_inc_enqueue(page,bid);
}

static HL_INLINE void gc_inc_visit(void *ptr, bool interior) {
	if( !ptr ) return;
	gc_pheader *page = GC_GET_PAGE(ptr);
	if( !page || !INPAGE(ptr,page) ) return;
	gc_inc_visit_page(ptr,page,interior);
}

ASAN_DISABLE
static void gc_inc_roots_range(void *start, void *end) {
	for(void **p = start; p < (void**)end; p++) gc_inc_visit(*p,true);
}

static void gc_inc_roots(void) {
	for(int i = 0; i < gc_roots_count; i++) gc_inc_visit(*gc_roots[i],true);
	for(int i = 0; i < gc_threads.count; i++) {
		hl_thread_info *t = gc_threads.threads[i];
		gc_inc_roots_range(t->stack_cur,t->stack_top);
		gc_inc_roots_range(&t->gc_regs,(void**)&t->gc_regs + sizeof(jmp_buf)/(sizeof(void*)) - 1);
		gc_inc_roots_range(&t->extra_stack_data,(void**)&t->extra_stack_data + t->extra_stack_size);
	}
}

static void gc_inc_prepare_page(gc_pheader *p, int ignored) {
	(void)ignored;
	if( p->incremental_epoch == gc_incremental_epoch ) return;
	// Finish the previous collection's lazy sweep BEFORE replacing its marks.
	if( p->alloc.need_flush ) flush_free_list(p);
	free(p->scan_profile);
	p->scan_profile = NULL;
	int bytes = (p->alloc.max_blocks + 7) >> 3;
	free(p->incremental_bmp);
	p->incremental_bmp = (unsigned char*)calloc(bytes * 2,1);
	if( !p->incremental_bmp ) out_of_memory("incremental bitmap");
	p->bmp = p->incremental_bmp;
	p->incremental_epoch = gc_incremental_epoch;
	// need_flush stays false. Allocations can only use already-free blocks.
}

/* Lists only gain new heads while a cycle is active; those pages are born
 * prepared. No page is reclaimed until completion or cancellation. */
static bool gc_inc_prepare_slice(double deadline) {
	while( gc_inc_prepare_cursor || gc_inc_prepare_pid < GC_ALL_PAGES ) {
		if( !gc_inc_prepare_cursor ) {
			gc_inc_prepare_cursor = gc_pages[gc_inc_prepare_pid++];
			if( !gc_inc_prepare_cursor ) continue;
		}
		gc_pheader *p = gc_inc_prepare_cursor;
		gc_inc_prepare_cursor = p->next_page;
		gc_inc_prepare_page(p,0);
		// A single allocator page is the indivisible unit (including lazy sweep).
		if( hl_sys_time() >= deadline ) return false;
	}
	return true;
}

static bool gc_inc_rescan_dirty(double deadline) {
	unsigned int blocks = 0;
	for(;;) {
		if( !gc_inc_rescan_cursor ) {
			gc_inc_rescan_cursor = gc_dirty_pop();
			if( !gc_inc_rescan_cursor ) return true;
			gc_scan_rescan_sources = gc_scan_profile_enabled ? gc_dirty_sources(gc_inc_rescan_cursor) : 0;
			gc_inc_rescan_bid = gc_inc_rescan_cursor->alloc.first_block;
		}
		gc_pheader *p = gc_inc_rescan_cursor;
		while( gc_inc_rescan_bid < p->alloc.max_blocks ) {
			int bid = gc_inc_rescan_bid++;
			// Marked blocks include new black allocations and floating garbage.
			if( p->bmp[bid >> 3] & (1 << (bid & 7)) ) {
				void *block = p->base + bid * p->alloc.block_size;
				if( block == gc_inc_block ) {
					gc_inc_cursor = (void**)block;
					gc_scan_current_sources |= gc_scan_rescan_sources;
				} else {
					if( gc_scan_profile_enabled ) gc_scan_metadata(p,bid)->sources |= gc_scan_rescan_sources;
					gc_inc_enqueue(p,bid);
				}
			}
			if( (++blocks & 63) == 0 && hl_sys_time() >= deadline ) return false;
		}
		gc_inc_rescan_cursor = NULL;
		if( hl_sys_time() >= deadline ) return false;
	}
}

static bool gc_inc_drain(double deadline) {
	unsigned int words = 0, objects = 0;
	// Pages cannot be reclaimed while tracing. Keep this cache local to the
	// stopped-world drain; each resumed slice starts with an empty cache.
	gc_pheader *target_page = NULL;
	while( gc_inc_cursor || GC_STACK_COUNT(&global_mark_stack) > 0 ) {
		bool fresh = gc_inc_cursor == NULL;
		if( fresh ) gc_inc_block = *--global_mark_stack.cur;
		gc_pheader *source_page = GC_GET_PAGE(gc_inc_block);
		int offset = (int)((unsigned char*)gc_inc_block-source_page->base);
		// This is a known object start from our own worklist, not a candidate.
		int bid = source_page->alloc.size_bits ? offset >> source_page->alloc.size_bits : offset/source_page->alloc.block_size;
		if( fresh ) {
			if( gc_scan_profile_enabled ) {
				gc_scan_object *m = gc_scan_metadata(source_page,bid);
				gc_scan_current_sources = m->sources;
				m->sources = 0;
			}
			gc_inc_cursor = (void**)gc_inc_block;
			int size = source_page->alloc.block_size;
			if( source_page->alloc.sizes ) size *= source_page->alloc.sizes[bid];
			gc_inc_end = gc_inc_cursor + size/sizeof(void*);
		}
		void **scan_start = gc_inc_cursor, **cursor = gc_inc_cursor, **end = gc_inc_end;
		while( cursor < end ) {
			// Match exact heap-field references; roots still accept interior pointers.
			void *ptr = *cursor++;
			if( ptr ) {
				gc_pheader *page = target_page;
				if( !page || (uintptr_t)ptr - (uintptr_t)page->base >= (uintptr_t)page->page_size ) {
					page = GC_GET_PAGE(ptr);
					if( !page || !INPAGE(ptr,page) ) page = NULL;
					else target_page = page;
				}
				// A range hit skips only page lookup, never object-start validation.
				if( page ) gc_inc_visit_page(ptr,page,false);
			}
			if( (++words & 255) == 0 && hl_sys_time() >= deadline ) {
				gc_inc_cursor = cursor;
				gc_scan_range(scan_start,cursor);
				return false;
			}
		}
		gc_scan_range(scan_start,cursor);
		unsigned char *queued = source_page->incremental_bmp + ((source_page->alloc.max_blocks + 7) >> 3);
		queued[bid >> 3] &= ~(1 << (bid & 7));
		gc_inc_cursor = gc_inc_end = NULL;
		gc_inc_block = NULL;
		if( (++objects & 63) == 0 && hl_sys_time() >= deadline ) return false;
	}
	return true;
}

/* Phase clocks accumulate because final kernel capture may produce more work
 * in the same pause. Only the captured dirty batch is drained; incoming software
 * notifications wait for the next capture rather than extending this wave and
 * getting rediscovered by its later kernel capture. Roots remain fresh each pause. */
static bool gc_inc_trace_slice(double deadline, double *dirty, double *roots, double *mark) {
	double t = gc_latency_trace ? hl_sys_time() : 0;
	gc_inc_roots();
	double after_roots = gc_latency_trace ? hl_sys_time() : 0;
	bool clean = gc_inc_rescan_dirty(deadline);
	double after_dirty = gc_latency_trace ? hl_sys_time() : 0;
	bool done = clean && gc_inc_drain(deadline);
	double after_mark = gc_latency_trace ? hl_sys_time() : 0;
	*roots += after_roots - t;
	*dirty += after_dirty - after_roots;
	*mark += after_mark - after_dirty;
	return done;
}

static bool gc_inc_capture_slice(double deadline, bool *captured, double *capture, double *rearm) {
	double t = gc_latency_trace ? hl_sys_time() : 0;
	bool ok = gc_write_tracking.collect(deadline,captured);
	double after_capture = gc_latency_trace ? hl_sys_time() : 0;
	if( ok && *captured ) {
		ok = gc_write_tracking.rearm();
		// Capture and rearm precede tracing the batch: kernel and software
		// notifications for the same writes now share one pending page scan.
		if( ok ) gc_dirty_capture_done();
	}
	double after_rearm = gc_latency_trace ? hl_sys_time() : 0;
	*capture += after_capture - t;
	*rearm += after_rearm - after_capture;
	gc_inc_discovering = ok && !*captured;
	return ok;
}

/* Debug oracle: independent marks and worklist, never seeded with incremental
 * marks or dirty pages. It deliberately uses the same conservative pointer
 * model (exact heap references, interior roots), not typed ordinary GC marks. */
static void **gc_validation_queue;
static size_t gc_validation_count, gc_validation_capacity, gc_validation_missing;
static void *gc_validation_first_missing;

static void gc_validation_prepare(gc_pheader *p, int ignored) {
	(void)ignored;
	p->validation_bmp = calloc((p->alloc.max_blocks + 7) >> 3,1);
	if( !p->validation_bmp ) out_of_memory("incremental validation bitmap");
}
static void gc_validation_release(gc_pheader *p, int ignored) {
	(void)ignored;
	free(p->validation_bmp);
	p->validation_bmp = NULL;
}
static void gc_validation_visit(void *ptr, bool interior) {
	if( !ptr ) return;
	gc_pheader *page = GC_GET_PAGE(ptr);
	if( !page || !INPAGE(ptr,page) ) return;
	int bid = interior ? gc_allocator_get_block_interior(page,&ptr) : gc_allocator_get_block_id(page,ptr);
	if( bid < 0 ) return;
	unsigned char bit = 1 << (bid & 7);
	if( page->validation_bmp[bid >> 3] & bit ) return;
	page->validation_bmp[bid >> 3] |= bit;
	if( !(page->bmp[bid >> 3] & bit) ) {
		gc_validation_missing++;
		if( !gc_validation_first_missing ) gc_validation_first_missing = ptr;
	}
	if( !MEM_HAS_PTR(page->page_kind) ) return;
	if( gc_validation_count == gc_validation_capacity ) {
		size_t capacity = gc_validation_capacity ? gc_validation_capacity * 2 : 1024;
		if( capacity < gc_validation_capacity || capacity > SIZE_MAX / sizeof(void*) )
			out_of_memory("incremental validation queue");
		void **queue = realloc(gc_validation_queue,capacity * sizeof(void*));
		if( !queue ) out_of_memory("incremental validation queue");
		gc_validation_queue = queue;
		gc_validation_capacity = capacity;
	}
	gc_validation_queue[gc_validation_count++] = ptr;
}
ASAN_DISABLE
static void gc_validation_range(void *start, void *end, bool interior) {
	for(void **p = start; p < (void**)end; p++) gc_validation_visit(*p,interior);
}
/* Completion snapshot: independent reachability, not incremental marks, decides
 * liveness. Age is allocation volume since birth, only for this cycle's black
 * allocations. Pre-existing objects have no birth record in this profiler. */
static unsigned long long gc_retention_bytes[2][2][4], gc_retention_objects[2][2][4];
static void gc_retention_page(gc_pheader *p, int ignored) {
	(void)ignored;
	for(int bid = 0; bid < p->alloc.max_blocks; bid++) {
		unsigned char bit = 1 << (bid & 7);
		if( !(p->bmp[bid >> 3] & bit) ) continue;
		gc_scan_object *m = p->scan_profile ? (gc_scan_object*)p->scan_profile + bid : NULL;
		int black = m && m->black;
		int reachable = !!(p->validation_bmp[bid >> 3] & bit);
		int age = 0;
		if( black ) {
			int64 volume = gc_stats.total_allocated - m->birth_bytes;
			age = volume < (1<<20) ? 0 : volume < (16<<20) ? 1 : volume < (64<<20) ? 2 : 3;
		}
		void *block = p->base + (size_t)bid * p->alloc.block_size;
		size_t bytes = gc_allocator_fast_block_size(p,block);
		gc_retention_bytes[black][reachable][age] += bytes;
		gc_retention_objects[black][reachable][age]++;
	}
}
static void gc_retention_report(void) {
	memset(gc_retention_bytes,0,sizeof(gc_retention_bytes));
	memset(gc_retention_objects,0,sizeof(gc_retention_objects));
	gc_iter_pages(gc_retention_page);
	for(int black = 0; black < 2; black++)
		for(int reachable = 0; reachable < 2; reachable++)
			for(int age = 0; age < (black ? 4 : 1); age++)
				fprintf(stderr,"GC-RETENTION,cycle=%llu,black=%d,reachable=%d,age_bucket=%d,objects=%llu,bytes=%llu\n",
					gc_inc_cycles_started,black,reachable,age,gc_retention_objects[black][reachable][age],gc_retention_bytes[black][reachable][age]);
}
static void gc_inc_validate(void) {
	const char *enabled = getenv("HL_GC_INCREMENTAL_VALIDATE");
	bool required = false;
#ifdef GC_INCREMENTAL_SOFTWARE
	required = gc_inc_test_software;
#endif
	if( !gc_retention_profile && !required && (!enabled || strcmp(enabled,"1") != 0) ) return;
	gc_validation_count = gc_validation_capacity = gc_validation_missing = 0;
	gc_validation_first_missing = NULL;
	gc_iter_pages(gc_validation_prepare);
	for(int i = 0; i < gc_roots_count; i++) gc_validation_visit(*gc_roots[i],true);
	for(int i = 0; i < gc_threads.count; i++) {
		hl_thread_info *t = gc_threads.threads[i];
		gc_validation_range(t->stack_cur,t->stack_top,true);
		gc_validation_range(&t->gc_regs,(void**)&t->gc_regs + sizeof(jmp_buf)/sizeof(void*) - 1,true);
		gc_validation_range(&t->extra_stack_data,(void**)&t->extra_stack_data + t->extra_stack_size,true);
	}
	for(size_t index = 0; index < gc_validation_count; index++) {
		void *block = gc_validation_queue[index];
		gc_pheader *page = GC_GET_PAGE(block);
		size_t words = gc_allocator_fast_block_size(page,block)/sizeof(void*);
		gc_validation_range(block,(void**)block + words,false);
	}
	if( gc_retention_profile ) gc_retention_report();
	gc_iter_pages(gc_validation_release);
	free(gc_validation_queue);
	gc_validation_queue = NULL;
	gc_validation_count = gc_validation_capacity = 0;
	if( gc_validation_missing ) {
		fprintf(stderr,"GC incremental validation failed: %zu reachable objects missing; first=%p\n",
			gc_validation_missing,gc_validation_first_missing);
		hl_fatal("Incremental GC missed reachable objects (write barrier coverage)");
	}
}

static void gc_inc_publish_marks(gc_pheader *p, int ignored) {
	(void)ignored;
	p->alloc.need_flush = true;
}
#endif

HL_API bool hl_gc_incremental_supported(void) {
#ifdef GC_INCREMENTAL_MARKING
	gc_global_lock(true);
	bool supported = gc_write_tracking.supported();
	gc_global_lock(false);
	return supported;
#else
	return false;
#endif
}

HL_API bool hl_gc_incremental_pending(void) {
	gc_global_lock(true);
	bool active = gc_incremental_active || gc_inc_reclaiming;
	gc_global_lock(false);
	return active;
}

HL_API bool hl_gc_incremental_reclaiming(void) {
	gc_global_lock(true);
	bool reclaiming = gc_inc_reclaiming;
	gc_global_lock(false);
	return reclaiming;
}

HL_API bool hl_gc_incremental_preparing(void) {
	gc_global_lock(true);
	bool preparing = gc_incremental_active && gc_inc_preparing;
	gc_global_lock(false);
	return preparing;
}

HL_API bool hl_gc_incremental_rescanning(void) {
	gc_global_lock(true);
	bool rescanning = gc_incremental_active && gc_inc_rescan_cursor != NULL;
	gc_global_lock(false);
	return rescanning;
}

HL_API void hl_gc_incremental_stats(hl_gc_incremental_metrics *out) {
	gc_global_lock(true);
	memset(out,0,sizeof(*out));
	out->cycles_started = gc_inc_cycles_started;
	out->cycles_completed = gc_inc_cycles_completed;
	out->pressure_fallbacks = gc_inc_pressure_fallbacks;
	out->tracking_fallbacks = gc_inc_tracking_fallbacks;
	out->last_cycle_micros = gc_inc_last_cycle_micros;
	if( gc_incremental_active ) {
		out->cycle_age_micros = (hl_sys_time() - gc_inc_cycle_started) * 1000000.0;
#ifdef GC_INCREMENTAL_SOFTWARE
		out->dirty_pages = __atomic_load_n(&gc_software_dirty_count,__ATOMIC_RELAXED);
#endif
		if( gc_inc_rescan_cursor ) out->dirty_pages++;
		if( global_mark_stack.size ) out->mark_objects = GC_STACK_COUNT(&global_mark_stack);
		if( gc_inc_cursor ) out->mark_objects++;
	}
	gc_global_lock(false);
}

static double gc_latency_stamp(void) { return gc_latency_trace ? hl_sys_time() : 0; }

static bool gc_incremental_step_unbudgeted_locked(double budget_micros) {
	gc_inc_last_step_bytes = gc_stats.total_allocated;
	if( gc_inc_reclaiming ) {
		double started = hl_sys_time(), deadline = started+budget_micros/1000000.0;
		gc_stop_world(true);
		double suspended = gc_latency_stamp();
		gc_inc_reclaiming = !gc_empty_sweep_slice(deadline,true);
		double reclaimed = gc_latency_stamp();
		gc_stop_world(false);
		double elapsed_ms = (hl_sys_time()-started)*1000.0;
		gc_stats.last_mark_ms = elapsed_ms;
		if( elapsed_ms > gc_stats.max_mark_ms ) gc_stats.max_mark_ms = elapsed_ms;
		gc_stats.mark_duration_ms += elapsed_ms;
		gc_stats.mark_time += (int)(elapsed_ms*1000.0);
		if( gc_latency_trace ) fprintf(stderr,"GC-RECLAIM,done=%d,pause_ms=%.6f,suspend_ms=%.6f,reclaim_ms=%.6f,resume_ms=%.6f\n",
			!gc_inc_reclaiming,elapsed_ms,(suspended-started)*1000,(reclaimed-suspended)*1000,elapsed_ms-(reclaimed-started)*1000);
		return !gc_inc_reclaiming;
	}
	if( gc_incremental_active && gc_stats.total_allocated - gc_inc_start_bytes > gc_inc_cycle_limit * 4.0 ) {
		gc_inc_pressure_fallbacks++;
		gc_major();
		return true;
	}
#ifdef GC_INCREMENTAL_MARKING
	if( gc_write_tracking.supported() ) {
		double started = hl_sys_time();
		double deadline = started + budget_micros / 1000000.0;
		gc_stop_world(true);
		double suspended = gc_latency_stamp();
		bool fresh = !gc_incremental_active;
		bool tracking_ok = true;
		if( fresh ) {
			const char *profile = getenv("HL_GC_SCAN_PROFILE");
			const char *retention = getenv("HL_GC_RETENTION_PROFILE");
			gc_retention_profile = retention && strcmp(retention,"1") == 0;
			gc_scan_profile_enabled = gc_retention_profile || (profile && strcmp(profile,"1") == 0);
			memset(gc_scan_bytes,0,sizeof(gc_scan_bytes));
			gc_scan_current_sources = gc_scan_rescan_sources = 0;
			gc_inc_cycles_started++;
			gc_inc_cycle_started = started;
			gc_inc_cycle_limit = hl_gc_trigger_bytes();
			gc_inc_start_bytes = gc_stats.total_allocated;
			gc_inc_start_allocs = gc_stats.allocation_count;
			if( ++gc_incremental_epoch == 0 ) hl_fatal("Incremental GC epoch overflow");
			gc_inc_prepare_pid = 0;
			gc_inc_prepare_cursor = NULL;
			gc_inc_preparing = true;
			gc_incremental_bitmaps = true;
			if( !global_mark_stack.size ) hl_gc_mark_grow(&global_mark_stack);
			gc_incremental_active = true;
			// Keep writes dirty throughout preparation. No roots or partial marks
			// are scanned, and no dirty flags are consumed, until all pages are ready.
			tracking_ok = gc_write_tracking.begin();
		}
		bool preparing = gc_inc_preparing;
		if( tracking_ok && gc_inc_preparing ) gc_inc_preparing = !gc_inc_prepare_slice(deadline);
		double prepared = gc_latency_stamp();
		double dirty = 0, roots = 0, mark = 0, capture = 0, rearm = 0;
		bool done = false, captured = false;
		if( tracking_ok && !preparing ) {
			if( gc_inc_discovering ) tracking_ok = gc_inc_capture_slice(deadline,&captured,&capture,&rearm);
			if( tracking_ok && !gc_inc_discovering ) {
				done = gc_inc_trace_slice(deadline,&dirty,&roots,&mark);
				if( done && !captured ) {
					tracking_ok = gc_inc_capture_slice(deadline,&captured,&capture,&rearm);
					// A final kernel capture can introduce references from native
					// stores without software barriers. Revisit roots and queued work.
					done = tracking_ok && captured && gc_inc_trace_slice(deadline,&dirty,&roots,&mark);
				}
			}
		}
		double drained = gc_latency_stamp(), validated = drained, finished = drained, reclaim = 0;
		gc_latency_finalizers = 0;
		if( done ) {
			gc_scan_report("completed");
			// Nobody ran since dirty-page and root capture: this is the final remark.
			gc_inc_validate();
			validated = gc_latency_stamp();
			gc_iter_pages(gc_inc_publish_marks);
			gc_sweep_owned_allocs();
			// Finalizers remain synchronous. Empty page unmapping can continue
			// after publication, once tracking is stopped and mutators may resume.
			double finalizer_started = gc_latency_stamp();
			gc_call_finalizers();
			if( gc_latency_trace ) gc_latency_finalizers = gc_latency_stamp()-finalizer_started;
#ifdef GC_DEBUG
			gc_clear_unmarked_mem();
#endif
			gc_empty_sweep_begin();
			finished = gc_latency_stamp();
			gc_write_tracking.end();
			gc_incremental_active = false;
			double reclaim_started = gc_latency_stamp();
			gc_inc_reclaiming = !gc_empty_sweep_slice(deadline,true);
			reclaim = gc_latency_stamp()-reclaim_started;
			gc_inc_cycles_completed++;
			gc_inc_last_cycle_micros = (hl_sys_time() - gc_inc_cycle_started) * 1000000.0;
			// Charge allocations during marking to the NEXT cycle so pacing cannot hide churn.
			gc_stats.last_mark = gc_inc_start_bytes;
			gc_stats.last_mark_allocs = gc_inc_start_allocs;
			gc_stats.mark_count++;
		}
		double rearmed = gc_latency_stamp();
		gc_stop_world(false);
		double elapsed_ms = (hl_sys_time() - started) * 1000.0;
		gc_stats.last_mark_ms = elapsed_ms;
		if( elapsed_ms > gc_stats.max_mark_ms ) gc_stats.max_mark_ms = elapsed_ms;
		gc_stats.mark_duration_ms += elapsed_ms;
		gc_stats.mark_time += (int)(elapsed_ms * 1000.0);
		if( gc_latency_trace ) {
			/* Emit after resuming mutators. I/O is excluded from pause_ms, but
			 * remains visible in the caller's frame timing. */
			fprintf(stderr,"GC-LATENCY,fresh=%d,preparing=%d,done=%d,ok=%d,pause_ms=%.6f,suspend_ms=%.6f,prepare_ms=%.6f,dirty_ms=%.6f,capture_ms=%.6f,roots_ms=%.6f,mark_ms=%.6f,validate_ms=%.6f,finish_ms=%.6f,finalizers_ms=%.6f,reclaim_ms=%.6f,rearm_ms=%.6f,resume_ms=%.6f\n",
				fresh,preparing,done,tracking_ok,elapsed_ms,(suspended-started)*1000,
				(prepared-suspended)*1000,dirty*1000,capture*1000,roots*1000,
				mark*1000,(validated-drained)*1000,(finished-validated)*1000,
				gc_latency_finalizers*1000,reclaim*1000,rearm*1000+(rearmed-finished-reclaim)*1000,
				elapsed_ms-(rearmed-started)*1000);
		}
		if( tracking_ok ) return done && !gc_inc_reclaiming;
		// A failed read/clear must never publish a partial mark. A full collection
		// rebuilds the marks, and this process stops attempting incremental cycles.
		gc_inc_tracking_fallbacks++;
		gc_write_tracking.disable();
	}
#endif
	gc_major();
	return true;
}

HL_API double hl_gc_trigger_bytes(void) {
	double trigger = gc_stats.pages_total_memory * gc_mark_threshold;
	return trigger < gc_min_trigger_bytes ? (double)gc_min_trigger_bytes : trigger;
}

/* One process-wide frame allowance, serialized by the GC lock. The host owns
 * frame boundaries; allocation threads all consume the same allowance. */
#ifndef HL_WIN
#include <time.h>
#endif
static double gc_frame_clock(void) {
#ifdef HL_WIN
	LARGE_INTEGER ticks, frequency;
	QueryPerformanceCounter(&ticks);
	QueryPerformanceFrequency(&frequency);
	return (double)ticks.QuadPart / frequency.QuadPart;
#elif defined(CLOCK_MONOTONIC)
	struct timespec time;
	if( clock_gettime(CLOCK_MONOTONIC,&time) != 0 ) hl_fatal("GC frame clock failed");
	return time.tv_sec + time.tv_nsec * 1e-9;
#else
	return hl_sys_time();
#endif
}
static bool gc_frame_recording;
static hl_gc_frame_metrics gc_frame = { -1, 0, 0, 0, 0, 0 };
static void gc_frame_charge(double started) {
	double elapsed = gc_frame_clock()-started;
	if( elapsed > 0 ) gc_frame.spent_micros += elapsed*1000000.0;
}


HL_API bool hl_gc_frame_begin(double budget_micros) {
	if( budget_micros != -1 && (!(budget_micros >= 0) || budget_micros > 100000) ) return false;
	gc_global_lock(true);
	memset(&gc_frame,0,sizeof(gc_frame));
	gc_frame.budget_micros = budget_micros;
	gc_frame_recording = true;
	gc_global_lock(false);
	return true;
}
HL_API void hl_gc_frame_end(void) {
	gc_global_lock(true);
	gc_frame_recording = false;
	gc_frame.budget_micros = -1;
	gc_global_lock(false);
}
HL_API double hl_gc_frame_remaining(void) {
	gc_global_lock(true);
	double remaining = -1;
	if( gc_frame.budget_micros >= 0 ) {
		remaining = gc_frame.budget_micros - gc_frame.spent_micros;
		if( remaining < 0 ) remaining = 0;
	}
	gc_global_lock(false);
	return remaining;
}
HL_API void hl_gc_frame_stats(hl_gc_frame_metrics *out) {
	if( !out ) return;
	gc_global_lock(true);
	*out = gc_frame;
	gc_global_lock(false);
}
static bool gc_incremental_step_locked(double budget_micros, bool automatic) {
	if( !gc_frame_recording ) return gc_incremental_step_unbudgeted_locked(budget_micros);
	double started = gc_frame_clock();
	// Memory pressure and unsupported-platform full collections bypass deferral.
	bool pressure = gc_incremental_active && gc_stats.total_allocated - gc_inc_start_bytes > gc_inc_cycle_limit * 4.0;
	if( gc_frame.budget_micros >= 0 && !pressure && gc_write_tracking.supported() ) {
		double remaining = gc_frame.budget_micros - gc_frame.spent_micros;
		if( remaining <= 0 ) { gc_frame.deferred_checks++; return false; }
		if( budget_micros > remaining ) budget_micros = remaining;
	}
	if( automatic ) gc_frame.automatic_slices++; else gc_frame.explicit_slices++;
	int before = gc_stats.mark_count;
	unsigned long long completed = gc_inc_cycles_completed;
	bool done = gc_incremental_step_unbudgeted_locked(budget_micros);
	gc_frame_charge(started);
	gc_frame.full_collections += (gc_stats.mark_count-before) - (gc_inc_cycles_completed-completed);
	return done;
}

HL_API bool hl_gc_step(double budget_micros) {
	// Zero, negative, NaN and infinity are no-ops. Cap individual requested slices at 100 ms.
	if( !(budget_micros > 0.0) || budget_micros > 100000.0 ) return false;
	gc_global_lock(true);
	bool done = gc_incremental_step_locked(budget_micros,false);
	gc_global_lock(false);
	return done;
}

static void gc_incremental_shutdown(void) {
	gc_frame_recording = false;
	memset(&gc_frame,0,sizeof(gc_frame));
	gc_frame.budget_micros = -1;
	gc_incremental_discard();
	gc_write_tracking.shutdown();
	gc_inc_cycles_started = gc_inc_cycles_completed = 0;
	gc_inc_pressure_fallbacks = gc_inc_tracking_fallbacks = 0;
	gc_inc_cycle_started = gc_inc_last_cycle_micros = 0;
}
