/*
	Included by gc.c. Arenas released without a collection (region-based memory management, with a checked release).

	An arena is released by looking for pointers into its pages where they can be, instead of marking the heap. Its blocks
	did not exist before the arena was opened, so a pointer to one can only be in memory written since then: the pages of
	the heap written while it was open, the roots, and the thread stacks and registers. Pages written are found by the
	kernel: every page of the heap is registered with a userfaultfd in asynchronous write-protect mode, and PAGEMAP_SCAN
	reports the pages written since the last scan and protects them again, in one call whose cost follows the size of the
	heap's mappings, not of its contents. Each scan's pages go to a log; an arena remembers where the log stood when it was
	opened and reads the log from there, so nested and sequential arenas see every write, whichever release scanned it.

	When nothing points in, the arena's pages go to a pool that later pages of the same size and kind are taken from, and
	what the arena allocated no longer counts toward the next collection. When something does, or when writes could not
	be tracked for the whole life of the arena, its pages join the unowned ones, which the collector frees as their blocks
	die. Either way its owner class is free for the next arena at once. The check is conservative (any word that looks like a pointer into the arena counts), so it can only keep pages
	that could have been freed, never free a page that is still referenced.
*/

// Pages released arenas left, kept for reuse; beyond this they are returned to the system.
static int64 gc_arena_pool_cap = 256LL << 20;
static int64 gc_arena_pool_bytes = 0;
static gc_pheader *gc_arena_pool[GC_ALL_PAGES];

// Per owner class: whether it is an open arena, the log position when it was opened (-1 when opened untracked), and the
// tracking generation it was opened in.
static bool gc_arena_opened[GC_PAGE_CLASSES];
static int64 gc_arena_start[GC_PAGE_CLASSES];
static uint64 gc_arena_generation[GC_PAGE_CLASSES];

typedef struct { uintptr_t start, end; } gc_arena_range;
static gc_arena_range *gc_arena_log = NULL;
static int64 gc_arena_log_len = 0, gc_arena_log_cap = 0, gc_arena_log_base = 0;

#if defined(__linux__) && defined(HL_64) && !defined(GC_DEBUG)
#	include <linux/fs.h>
#	include <linux/userfaultfd.h>
#	if defined(PAGEMAP_SCAN) && defined(UFFD_FEATURE_WP_ASYNC) && defined(UFFD_USER_MODE_ONLY)
#		define GC_ARENA_TRACKING
#		include <sys/ioctl.h>
#		include <sys/syscall.h>
#		include <fcntl.h>
#		include <unistd.h>
#	endif
#endif

// The release entry is a stub that pushes the caller's registers (below), on this target.
#if defined(__x86_64__) && defined(__GNUC__) && defined(__linux__)
#	define GC_ARENA_FREE_STUB
#endif

// 0: not started, 1: every heap page is tracked, -1: unavailable (or failed: no arena can be released without a collection).
static int gc_arena_tracking = 0;
static uint64 gc_arena_tracking_generation = 1;
static uintptr_t gc_arena_low = UINTPTR_MAX, gc_arena_high = 0;
static double gc_arena_scan_ms = 0, gc_arena_check_ms = 0;
static int64 gc_arena_released = 0, gc_arena_kept = 0;

#ifdef GC_ARENA_TRACKING
static int gc_arena_uffd = -1, gc_arena_pagemap = -1;

static void gc_arena_tracking_failed( void ) {
	gc_arena_tracking = -1;
	gc_arena_tracking_generation++;
}

static bool gc_arena_protect( gc_pheader *ph ) {
	struct uffdio_register reg;
	memset(&reg,0,sizeof(reg));
	reg.range.start = (uintptr_t)ph->base;
	reg.range.len = (uint64)ph->page_size;
	reg.mode = UFFDIO_REGISTER_MODE_WP;
	if( ioctl(gc_arena_uffd,UFFDIO_REGISTER,&reg) != 0 ) return false;
	struct uffdio_writeprotect wp;
	memset(&wp,0,sizeof(wp));
	wp.range = reg.range;
	wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
	if( ioctl(gc_arena_uffd,UFFDIO_WRITEPROTECT,&wp) != 0 ) return false;
	if( (uintptr_t)ph->base < gc_arena_low ) gc_arena_low = (uintptr_t)ph->base;
	if( (uintptr_t)ph->base + ph->page_size > gc_arena_high ) gc_arena_high = (uintptr_t)ph->base + ph->page_size;
	return true;
}

// Locked. Tracks every page of the heap from now on; false when the system cannot.
static bool gc_arena_tracking_start( void ) {
	if( gc_arena_tracking != 0 ) return gc_arena_tracking > 0;
	gc_arena_tracking = -1;
	const char *option = getenv("HL_GC_ARENA_TRACKING");
	if( option && strcmp(option,"0") == 0 ) return false;
	if( gc_incremental_enabled ) return false; // its soft-dirty clears and our protection are not meant to mix
	int uffd = (int)syscall(SYS_userfaultfd,O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
	if( uffd < 0 ) return false;
	struct uffdio_api api;
	memset(&api,0,sizeof(api));
	api.api = UFFD_API;
	api.features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED;
	int pagemap = open("/proc/self/pagemap",O_RDONLY | O_CLOEXEC);
	if( ioctl(uffd,UFFDIO_API,&api) != 0 || pagemap < 0 ) {
		close(uffd);
		if( pagemap >= 0 ) close(pagemap);
		return false;
	}
	gc_arena_uffd = uffd;
	gc_arena_pagemap = pagemap;
	gc_arena_tracking = 1;
	for(int pid=0;pid<GC_PAGE_SLOTS;pid++)
		for(gc_pheader *ph=gc_pages[pid];ph;ph=ph->next_page)
			if( !gc_arena_protect(ph) ) { gc_arena_tracking_failed(); return false; }
	for(int slot=0;slot<GC_ALL_PAGES;slot++)
		for(gc_pheader *ph=gc_arena_pool[slot];ph;ph=ph->next_page)
			if( !gc_arena_protect(ph) ) { gc_arena_tracking_failed(); return false; }
	return true;
}

// Locked. A page the heap just mapped is tracked like the others.
static void gc_arena_track_page( gc_pheader *ph ) {
	if( gc_arena_tracking > 0 && !gc_arena_protect(ph) ) gc_arena_tracking_failed();
}

static void gc_arena_log_add( uintptr_t start, uintptr_t end ) {
	if( gc_arena_log_len > 0 && gc_arena_log[gc_arena_log_len-1].end == start ) {
		gc_arena_log[gc_arena_log_len-1].end = end;
		return;
	}
	if( gc_arena_log_len == gc_arena_log_cap ) {
		int64 cap = gc_arena_log_cap ? gc_arena_log_cap * 2 : 1024;
		gc_arena_range *log = (gc_arena_range*)realloc(gc_arena_log,sizeof(gc_arena_range) * cap);
		if( log == NULL ) out_of_memory("arena write log");
		gc_arena_log = log;
		gc_arena_log_cap = cap;
	}
	gc_arena_log[gc_arena_log_len].start = start;
	gc_arena_log[gc_arena_log_len].end = end;
	gc_arena_log_len++;
}

// World stopped. Moves the pages written since the last scan to the log, protecting them again; false on failure.
static bool gc_arena_scan( void ) {
	if( gc_arena_high <= gc_arena_low ) return true;
	struct page_region regions[512];
	uintptr_t start = gc_arena_low;
	while( start < gc_arena_high ) {
		struct pm_scan_arg arg;
		memset(&arg,0,sizeof(arg));
		arg.size = sizeof(arg);
		arg.flags = PM_SCAN_WP_MATCHING;
		arg.start = start;
		arg.end = gc_arena_high;
		arg.vec = (uintptr_t)regions;
		arg.vec_len = 512;
		arg.category_mask = PAGE_IS_WRITTEN;
		arg.return_mask = PAGE_IS_WRITTEN;
		long count = ioctl(gc_arena_pagemap,PAGEMAP_SCAN,&arg);
		if( count < 0 ) return false;
		for(long i=0;i<count;i++) {
			// Only pages of the heap that can hold pointers matter; a range may span several heap pages.
			uintptr_t from = regions[i].start, to = regions[i].end;
			while( from < to ) {
				uintptr_t next = ((from >> GC_MASK_BITS) + 1) << GC_MASK_BITS;
				if( next > to ) next = to;
				gc_pheader *ph = GC_GET_PAGE((void*)from);
				if( ph && INPAGE((void*)from,ph) && MEM_HAS_PTR(ph->page_kind) ) gc_arena_log_add(from,next);
				from = next;
			}
		}
		if( arg.walk_end <= start ) return false;
		start = arg.walk_end;
	}
	return true;
}
#else
static bool gc_arena_tracking_start( void ) { gc_arena_tracking = -1; return false; }
static void gc_arena_track_page( gc_pheader *ph ) { (void)ph; }
static bool gc_arena_scan( void ) { return false; }
#endif

// Locked. Called when an arena gets an owner class: it is an arena from now on, tracked if the system allows.
static void gc_arena_open( int oc ) {
	if( oc <= 0 || oc > GC_OWNER_CLASSES ) return;
	gc_arena_opened[oc] = true;
	gc_arena_start[oc] = gc_arena_tracking_start() ? gc_arena_log_base + gc_arena_log_len : -1;
	gc_arena_generation[oc] = gc_arena_tracking_generation;
}

// Locked. Forgets the log before the oldest open arena.
static void gc_arena_close( int oc ) {
	gc_arena_opened[oc] = false;
	int64 oldest = gc_arena_log_base + gc_arena_log_len;
	for(int i=1;i<=GC_OWNER_CLASSES;i++)
		if( gc_arena_opened[i] && gc_arena_start[i] >= 0 && gc_arena_start[i] < oldest ) oldest = gc_arena_start[i];
	int64 drop = oldest - gc_arena_log_base;
	if( drop <= 0 ) return;
	memmove(gc_arena_log,gc_arena_log + drop,sizeof(gc_arena_range) * (gc_arena_log_len - drop));
	gc_arena_log_len -= drop;
	gc_arena_log_base = oldest;
}

static int gc_arena_report_left = 0;

static void gc_arena_report( int oc, const char *where, int index, void *holder, void *value ) {
	if( gc_arena_report_left <= 0 ) return;
	gc_arena_report_left--;
	char target[160], held[160];
	gc_pheader *tp = GC_GET_PAGE(value);
	void *block = value;
	int bid = gc_allocator_get_block_interior(tp,&block);
	if( bid >= 0 ) gc_type_key_name(gc_block_type_key(tp,block),target,sizeof(target));
	else snprintf(target,sizeof(target),"?");
	if( holder ) {
		gc_pheader *hp = GC_GET_PAGE(holder);
		void *hblock = holder;
		if( gc_allocator_get_block_interior(hp,&hblock) >= 0 )
			gc_type_key_name(gc_block_type_key(hp,hblock),held,sizeof(held));
		else
			snprintf(held,sizeof(held),"(free block)");
		fprintf(stderr,"HL arena reference: %s +%d -> %s\n",held,(int)((char*)holder - (char*)hblock),target);
	} else
		fprintf(stderr,"HL arena reference: %s %d -> %s\n",where,index,target);
	(void)oc;
}

static HL_INLINE bool gc_arena_points_in( void *value, int oc, uintptr_t low, uintptr_t high ) {
	if( (uintptr_t)value < low || (uintptr_t)value >= high ) return false;
	gc_pheader *ph = GC_GET_PAGE(value);
	return ph && INPAGE(value,ph) && ph->owner_class == oc;
}

static int gc_arena_scan_words( void **from, void **to, int oc, uintptr_t low, uintptr_t high, const char *where, int index, bool holders ) {
	int found = 0;
	for(void **p=from;p<to;p++)
		if( gc_arena_points_in(*p,oc,low,high) ) {
			found++;
			gc_arena_report(oc,where,index,holders ? (void*)p : NULL,*p);
		}
	return found;
}

// World stopped. The words that point into class `oc` among those written since the arena was opened, the roots and
// the stacks and registers of every thread.
static int gc_arena_references( int oc, hl_thread_info *self, void *self_from ) {
	uintptr_t low = UINTPTR_MAX, high = 0;
	for(int pid=oc*GC_ALL_PAGES;pid<(oc+1)*GC_ALL_PAGES;pid++)
		for(gc_pheader *ph=gc_pages[pid];ph;ph=ph->next_page) {
			if( (uintptr_t)ph->base < low ) low = (uintptr_t)ph->base;
			if( (uintptr_t)ph->base + ph->page_size > high ) high = (uintptr_t)ph->base + ph->page_size;
		}
	if( high <= low ) return 0;
	int found = 0;
	for(int64 i=gc_arena_start[oc]-gc_arena_log_base;i<gc_arena_log_len;i++) {
		uintptr_t start = gc_arena_log[i].start, end = gc_arena_log[i].end;
		gc_pheader *ph = GC_GET_PAGE((void*)start);
		// A page freed since it was written holds nothing; the arena's own pages point into it freely.
		if( !ph || !INPAGE((void*)start,ph) || ph->owner_class == oc || !MEM_HAS_PTR(ph->page_kind) ) continue;
		if( end > (uintptr_t)ph->base + ph->page_size ) end = (uintptr_t)ph->base + ph->page_size;
		found += gc_arena_scan_words((void**)start,(void**)end,oc,low,high,"page",0,true);
	}
	for(int i=0;i<gc_roots_count;i++)
		found += gc_arena_scan_words(gc_roots[i],gc_roots[i] + 1,oc,low,high,"root",i,false);
	for(gc_pinned_list *l=gc_pinned_lists;l;l=l->next)
		found += gc_arena_scan_words(l->values,l->values + l->count,oc,low,high,"pinned",0,false);
	for(int i=0;i<gc_threads.count;i++) {
		hl_thread_info *t = gc_threads.threads[i];
		if( t == self ) {
			found += gc_arena_scan_words((void**)self_from,(void**)t->stack_top,oc,low,high,"stack of thread",i,false);
#			ifdef GC_ARENA_FREE_STUB
			// The entry pushed the caller's callee-saved registers on the stack read above: what the registers hold
			// since is the release's own work, not the program's.
			continue;
#			endif
		} else
			found += gc_arena_scan_words((void**)t->stack_cur,(void**)t->stack_top,oc,low,high,"stack of thread",i,false);
		found += gc_arena_scan_words((void**)&t->gc_regs,(void**)&t->gc_regs + (sizeof(jmp_buf) / sizeof(void*)),oc,low,high,"registers of thread",i,false);
		found += gc_arena_scan_words((void**)&t->extra_stack_data,(void**)&t->extra_stack_data + t->extra_stack_size,oc,low,high,"saved registers of thread",i,false);
	}
	return found;
}

// Locked. Detaches a page from the heap into the pool, empty, or returns it to the system when the pool is full.
static void gc_arena_pool_put( gc_pheader *ph, int slot ) {
	if( GC_PID_PART(slot) == GC_LARGE_PART || gc_arena_pool_bytes + ph->page_size > gc_arena_pool_cap ) {
		free_freelist(&ph->alloc.free);
		gc_free_page(ph,ph->alloc.max_blocks);
		return;
	}
	gc_page_detach(ph);
	gc_allocator_reset_page(ph);
	ph->bmp = NULL;
	ph->next_page = gc_arena_pool[slot];
	gc_arena_pool[slot] = ph;
	gc_arena_pool_bytes += ph->page_size;
}

// Locked. A pooled page of this size for the partition and kind of `pid`, attached to the heap again, or NULL.
static gc_pheader *gc_arena_pool_take( int pid, int size ) {
	int slot = pid % GC_ALL_PAGES;
	for(gc_pheader **link=&gc_arena_pool[slot];*link;link=&(*link)->next_page) {
		gc_pheader *ph = *link;
		if( ph->page_size != size ) continue;
		*link = ph->next_page;
		ph->next_page = NULL;
		gc_arena_pool_bytes -= ph->page_size;
		gc_page_attach(ph);
		return ph;
	}
	return NULL;
}

// Locked, world stopped. Gives every page of class `oc` to the pool and empties the class.
static void gc_arena_recycle( int oc ) {
	gc_empty_sweep_cancel();
	for(int pid=oc*GC_ALL_PAGES;pid<(oc+1)*GC_ALL_PAGES;pid++) {
		gc_pheader *ph = gc_pages[pid];
		while( ph ) {
			gc_pheader *next = ph->next_page;
			gc_arena_pool_put(ph,pid % GC_ALL_PAGES);
			ph = next;
		}
		gc_pages[pid] = NULL;
		gc_free_pages[pid] = NULL;
	}
}

// Locked, world stopped. Moves every page of class `oc` to the unowned class, where the collector frees its blocks as they
// die like any other's, and empties the class for the next arena.
static void gc_arena_handover( int oc ) {
	gc_empty_sweep_cancel();
	for(int pid=oc*GC_ALL_PAGES;pid<(oc+1)*GC_ALL_PAGES;pid++) {
		gc_pheader *first = gc_pages[pid];
		if( first == NULL ) continue;
		gc_pheader *last = first;
		for(gc_pheader *ph=first;ph;ph=ph->next_page) {
			ph->owner_class = 0;
			last = ph;
		}
		int to = pid % GC_ALL_PAGES;
		last->next_page = gc_pages[to];
		gc_pages[to] = first;
		// The allocation cursor starts at the list's head again at the next collection; until then the pages are reached
		// only once it has run out.
		if( gc_free_pages[to] == NULL ) gc_free_pages[to] = first;
		gc_pages[pid] = NULL;
		gc_free_pages[pid] = NULL;
	}
}

/*
	Releases `arena` without collecting. Returns 0 when nothing outside it pointed into it: its pages are reused at once
	and what it allocated no longer counts toward the next collection. Otherwise its pages join the unowned ones, which
	the collector frees as their blocks die, and it returns the number of references found, or -1 when the writes made
	while it was open could not all be tracked (the system has no write tracking, or it was opened before tracking
	started). No thread may still have the arena current. With HL_GC_ARENA_CENSUS set, the first references found are
	printed, by holder.
*/
#ifdef GC_ARENA_FREE_STUB
__attribute__((visibility("hidden"),used,noinline))
#endif
int gc_arena_free_from( void *arena, void *stack_from ) {
	if( arena == NULL ) return 0;
	hl_thread_info *self = hl_get_thread();
	gc_global_lock(true);
	int oc = gc_owner_class_lookup(arena);
	if( oc <= 0 ) {
		// No class of its own: it allocated nothing, or shares the overflow class, which only a collection can release.
		int shared = 0;
		for(int i=0;i<gc_overflow_count;i++)
			if( gc_overflow_owners[i] == arena ) {
				gc_overflow_owners[i] = gc_overflow_owners[--gc_overflow_count];
				shared = 1;
				break;
			}
		gc_global_lock(false);
		return shared ? -1 : 0;
	}
	double started = hl_sys_time();
	gc_stop_world(true);
	int found = -1;
	bool tracked = gc_arena_tracking > 0 && gc_arena_opened[oc] && gc_arena_start[oc] >= 0
		&& gc_arena_generation[oc] == gc_arena_tracking_generation && !gc_incremental_active && !gc_inc_reclaiming;
	for(int i=0;i<gc_threads.count;i++)
		if( gc_threads.threads[i]->gc_arena == arena ) {
			if( gc_threads.threads[i] == self ) { gc_stop_world(false); gc_global_lock(false); hl_error("Arena released while current"); }
			tracked = false;
		}
	if( tracked ) {
		if( !gc_arena_scan() ) {
#			ifdef GC_ARENA_TRACKING
			gc_arena_tracking_failed();
#			endif
		} else {
			double scanned = hl_sys_time();
			gc_arena_scan_ms += (scanned - started) * 1000.0;
			static int report = -1;
			if( report < 0 ) report = getenv("HL_GC_ARENA_CENSUS") != NULL;
			gc_arena_report_left = report ? 16 : 0;
			found = gc_arena_references(oc,self,stack_from);
			gc_arena_check_ms += (hl_sys_time() - scanned) * 1000.0;
		}
	}
	if( found == 0 ) {
		gc_arena_recycle(oc);
		gc_owner_table[oc] = NULL;
		// What it allocated since the last collection is gone without one: the next collection waits for as much again.
		gc_stats.last_mark += gc_class_allocated[oc];
		gc_stats.last_mark_allocs += gc_class_allocations[oc];
		gc_arena_released++;
	} else {
		gc_arena_handover(oc);
		gc_owner_table[oc] = NULL;
		gc_arena_kept++;
	}
	gc_class_allocated[oc] = 0;
	gc_class_allocations[oc] = 0;
	gc_arena_close(oc);
	gc_stop_world(false);
	gc_global_lock(false);
	return found;
}

/* Arena statistics: releases without a collection, releases handed to the collector, and the milliseconds spent
   finding written pages and checking them. */
HL_API void hl_gc_arena_stats( double *released, double *kept, double *scan_ms, double *check_ms ) {
	*released = (double)gc_arena_released;
	*kept = (double)gc_arena_kept;
	*scan_ms = gc_arena_scan_ms;
	*check_ms = gc_arena_check_ms;
}

/*
	The entry: this thread's stack is read from the caller's frame up, with the caller's callee-saved registers pushed just
	below it. Frames made after the arena's work returned (this call's, and the checker's) reuse the stack that work used,
	and their slots not yet written still hold its values, which would read as references into the arena.
*/
#ifdef GC_ARENA_FREE_STUB
__asm__(
	".text\n"
	".globl hl_gc_arena_free\n"
	".type hl_gc_arena_free,@function\n"
	"hl_gc_arena_free:\n"
	"	push %rbx\n	push %rbp\n	push %r12\n	push %r13\n	push %r14\n	push %r15\n"
	"	mov %rsp,%rsi\n"
	"	sub $8,%rsp\n"
	"	call gc_arena_free_from\n"
	"	add $8,%rsp\n"
	"	pop %r15\n	pop %r14\n	pop %r13\n	pop %r12\n	pop %rbp\n	pop %rbx\n"
	"	ret\n"
	".size hl_gc_arena_free,.-hl_gc_arena_free\n"
);
#else
// Elsewhere the stack is read from this frame up: its unwritten slots may still keep an arena (a false reference).
HL_API int hl_gc_arena_free( void *arena ) {
	void * volatile anchor = NULL;
	return gc_arena_free_from(arena,(void*)((uintptr_t)&anchor & ~(uintptr_t)(sizeof(void*) - 1)));
}
#endif
