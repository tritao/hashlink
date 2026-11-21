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
	static bool std_layouts = false;
	if( !std_layouts ) {
		std_layouts = true;
		hl_gc_arena_register_layout(USTR("hl_bytes_map"),hl_gc_arena_map_layout);
		hl_gc_arena_register_layout(USTR("hl_int_map"),hl_gc_arena_map_layout);
		hl_gc_arena_register_layout(USTR("hl_int64_map"),hl_gc_arena_map_layout);
		hl_gc_arena_register_layout(USTR("hl_obj_map"),hl_gc_arena_map_layout);
	}
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
static void gc_arena_evacuate( int oc );
static bool gc_arena_evacuation;

// HL_GC_ARENA_SITES: the call stack of every block allocated in an arena, so a report names where a kept block was made.
// Allocations then take the locked path (see gc.c); a diagnostic, for an escape check on a sample build.
#define GC_ARENA_SITE_FRAMES 6
typedef struct { void *block; void *frames[GC_ARENA_SITE_FRAMES]; } gc_arena_site;
static gc_arena_site *gc_arena_sites_table = NULL;
static int64 gc_arena_sites_cap = 0, gc_arena_sites_count = 0;

static gc_arena_site *gc_arena_site_slot( void *block, bool insert ) {
	if( gc_arena_sites_cap == 0 ) {
		if( !insert ) return NULL;
		gc_arena_sites_cap = 1 << 16;
		gc_arena_sites_table = (gc_arena_site*)calloc(gc_arena_sites_cap,sizeof(gc_arena_site));
	}
	uint64 h = ((uint64)(uintptr_t)block * 0x9E3779B97F4A7C15ULL) >> 17;
	int64 i = (int64)(h & (gc_arena_sites_cap - 1));
	while( gc_arena_sites_table[i].block ) {
		if( gc_arena_sites_table[i].block == block ) return &gc_arena_sites_table[i];
		i = (i + 1) & (gc_arena_sites_cap - 1);
	}
	if( !insert ) return NULL;
	gc_arena_sites_table[i].block = block;
	gc_arena_sites_count++;
	return &gc_arena_sites_table[i];
}

// Locked. Records where `block`, just allocated in an arena, was made.
static void gc_arena_site_record( void *block, void **frames, int nframes ) {
	if( (gc_arena_sites_count + 1) * 2 > gc_arena_sites_cap ) {
		gc_arena_site *old = gc_arena_sites_table;
		int64 cap = gc_arena_sites_cap;
		gc_arena_sites_cap = cap ? cap * 2 : 1 << 16;
		gc_arena_sites_table = (gc_arena_site*)calloc(gc_arena_sites_cap,sizeof(gc_arena_site));
		gc_arena_sites_count = 0;
		for(int64 i=0;i<cap;i++)
			if( old[i].block ) *gc_arena_site_slot(old[i].block,true) = old[i];
		free(old);
	}
	gc_arena_site *site = gc_arena_site_slot(block,true);
	memset(site->frames,0,sizeof(site->frames));
	memcpy(site->frames,frames,sizeof(void*) * (nframes < GC_ARENA_SITE_FRAMES ? nframes : GC_ARENA_SITE_FRAMES));
}

// Locked. Forgets the sites of the blocks of class `oc`, which is being released.
static void gc_arena_sites_forget( int oc ) {
	if( gc_arena_sites_cap == 0 ) return;
	gc_arena_site *old = gc_arena_sites_table;
	int64 cap = gc_arena_sites_cap;
	gc_arena_sites_table = (gc_arena_site*)calloc(cap,sizeof(gc_arena_site));
	gc_arena_sites_count = 0;
	for(int64 i=0;i<cap;i++) {
		if( !old[i].block ) continue;
		gc_pheader *ph = GC_GET_PAGE(old[i].block);
		if( ph && INPAGE(old[i].block,ph) && ph->owner_class == oc ) continue;
		*gc_arena_site_slot(old[i].block,true) = old[i];
	}
	free(old);
}

// The name of the field of a block of type `t` at byte `offset`, or "+offset".
static void gc_arena_field_name( hl_type *t, void *block, int offset, char *out, int size ) {
	if( t && gc_plausible_type(t) ) {
		if( (t->kind == HOBJ || t->kind == HSTRUCT) && t->obj->rt ) {
			hl_runtime_obj *rt = t->obj->rt;
			hl_type *chain[64]; int depth = 0;
			for(hl_type *c=t;c && depth<64;c=c->obj->super) chain[depth++] = c;
			int index = 0;
			for(int d=depth-1;d>=0;d--) {
				hl_type_obj *o = chain[d]->obj;
				for(int f=0;f<o->nfields;f++,index++)
					if( index < rt->nfields && rt->fields_indexes[index] == offset ) {
						snprintf(out,size,".%s",hl_to_utf8(o->fields[f].name));
						return;
					}
			}
		}
		if( t->kind == HVIRTUAL )
			for(int f=0;f<t->virt->nfields;f++)
				if( t->virt->indexes[f] == offset ) { snprintf(out,size,".%s",hl_to_utf8(t->virt->fields[f].name)); return; }
		if( t->kind == HENUM ) {
			int index = ((venum*)block)->index;
			if( index >= 0 && index < t->tenum->nconstructs ) {
				hl_enum_construct *c = &t->tenum->constructs[index];
				for(int p=0;p<c->nparams;p++)
					if( c->offsets[p] == offset ) { snprintf(out,size,".%s#%d",hl_to_utf8(c->name),p); return; }
				snprintf(out,size,".%s+%d",hl_to_utf8(c->name),offset);
				return;
			}
		}
	}
	snprintf(out,size,"+%d",offset);
}

static void gc_arena_report( int oc, const char *where, int index, void *holder, void *value ) {
	if( gc_arena_report_left <= 0 ) return;
	gc_arena_report_left--;
	char target[160], held[160], field[96], site[1024];
	gc_pheader *tp = GC_GET_PAGE(value);
	void *block = value;
	int bid = gc_allocator_get_block_interior(tp,&block);
	if( bid >= 0 ) gc_type_key_name(gc_block_type_key(tp,block),target,sizeof(target));
	else snprintf(target,sizeof(target),"?");
	site[0] = 0;
	gc_arena_site *made = bid >= 0 ? gc_arena_site_slot(block,false) : NULL;
	if( made ) {
		int len = snprintf(site,sizeof(site)," made at");
		for(int i=0;i<GC_ARENA_SITE_FRAMES && made->frames[i] && len < (int)sizeof(site) - 200;i++) {
			uchar out[256];
			int size = 256;
			uchar *name = hl_resolve_symbol(made->frames[i],out,&size);
			len += snprintf(site+len,sizeof(site)-len," %s%s",i ? "< " : "",name ? hl_to_utf8(name) : "?");
		}
	}
	if( holder ) {
		gc_pheader *hp = GC_GET_PAGE(holder);
		void *hblock = holder;
		if( gc_allocator_get_block_interior(hp,&hblock) >= 0 ) {
			gc_type_key_name(gc_block_type_key(hp,hblock),held,sizeof(held));
			hl_type *ht = hp->page_kind == MEM_KIND_DYNAMIC ? *(hl_type**)hblock : NULL;
			gc_arena_field_name(ht,hblock,(int)((char*)holder - (char*)hblock),field,sizeof(field));
		} else {
			snprintf(held,sizeof(held),"(free block)");
			field[0] = 0;
		}
		fprintf(stderr,"HL arena reference: %s%s -> %s%s\n",held,field,target,site);
	} else
		fprintf(stderr,"HL arena reference: %s %d -> %s%s\n",where,index,target,site);
	(void)oc;
}

static HL_INLINE bool gc_arena_points_in( void *value, int oc, uintptr_t low, uintptr_t high ) {
	if( (uintptr_t)value < low || (uintptr_t)value >= high ) return false;
	gc_pheader *ph = GC_GET_PAGE(value);
	return ph && INPAGE(value,ph) && ph->owner_class == oc;
}

// How a slot holds its pointer: to a block of its own type (or bytes), to an array's storage of element type `at`, or to an
// untyped block of a registered layout.
enum { GC_SLOT_VALUE, GC_SLOT_STORAGE, GC_SLOT_LAYOUT };
typedef struct { int kind; hl_type *at; hl_gc_arena_layout layout; } gc_slot_kind;

// Whether the heap word `slot` is one the collector reads as a pointer: a pointer field of a typed block (by its layout), or
// any word of an untyped one. A typed block's integer or float that happens to spell an address is no reference, and must
// not be rewritten by an evacuation.
static bool gc_arena_pointer_word( void **slot ) {
	gc_pheader *ph = GC_GET_PAGE(slot);
	if( !ph || !INPAGE(slot,ph) || ph->page_kind != MEM_KIND_DYNAMIC ) return true;
	void *start = slot;
	if( gc_allocator_get_block_interior(ph,&start) < 0 ) return true;
	hl_type *t = *(hl_type**)start;
	if( !t || !gc_plausible_type(t) || !t->mark_bits || t->kind == HFUN ) return true;
	int pos = (int)((void**)slot - (void**)start);
	unsigned int *mark_bits = t->mark_bits;
	if( t->kind == HENUM ) {
		if( pos < 2 ) return false;
		mark_bits += ((venum*)start)->index;
		pos -= 2;
	} else if( pos == 0 )
		return false;
	return (mark_bits[pos >> 5] & (1 << (pos&31))) != 0;
}

// The references found into the arena that are pointer fields of typed blocks, by their layout, which an evacuation may
// rewrite, and how many were found that it may not (a word of an untyped block, a root, a stack or register word).
typedef struct { void **slot; gc_slot_kind kind; } gc_arena_slot_entry;
static gc_arena_slot_entry *gc_arena_slots = NULL;
static int gc_arena_slot_count = 0, gc_arena_slot_cap = 0, gc_arena_fixed_refs = 0;
static gc_slot_kind gc_arena_field_kind( void **slot, bool *precise );

static int gc_arena_scan_words( void **from, void **to, int oc, uintptr_t low, uintptr_t high, const char *where, int index, bool holders ) {
	int found = 0;
	for(void **p=from;p<to;p++)
		if( gc_arena_points_in(*p,oc,low,high) ) {
			if( holders && !gc_arena_pointer_word(p) ) continue;
			found++;
			gc_arena_report(oc,where,index,holders ? (void*)p : NULL,*p);
			bool precise = false;
			gc_slot_kind kind = { GC_SLOT_VALUE, NULL, NULL };
			if( holders ) kind = gc_arena_field_kind(p,&precise);
			if( !precise ) {
				gc_arena_fixed_refs++;
				continue;
			}
			if( gc_arena_slot_count == gc_arena_slot_cap ) {
				gc_arena_slot_cap = gc_arena_slot_cap ? gc_arena_slot_cap * 2 : 256;
				gc_arena_slots = (gc_arena_slot_entry*)realloc(gc_arena_slots,sizeof(gc_arena_slot_entry) * gc_arena_slot_cap);
				if( gc_arena_slots == NULL ) out_of_memory("arena slots");
			}
			gc_arena_slots[gc_arena_slot_count].slot = p;
			gc_arena_slots[gc_arena_slot_count++].kind = kind;
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
	gc_arena_slot_count = 0;
	gc_arena_fixed_refs = 0;
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
	gc_release_page_memory(ph);
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
		ph->alloc.released = 0;
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
		// The allocation cursor moves to them, so their free blocks serve the next allocations rather than new pages; the
		// pages it passed are walked again, quickly, as they have nothing free.
		gc_free_pages[to] = first;
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
			gc_arena_report_left = report || gc_arena_sites ? 16 : 0;
			found = gc_arena_references(oc,self,stack_from);
			if( found > 0 && gc_arena_fixed_refs == 0 && gc_arena_evacuation ) {
				gc_arena_evacuate(oc);
				found = 0;
			}
			gc_arena_check_ms += (hl_sys_time() - scanned) * 1000.0;
		}
	}
	if( gc_arena_sites ) gc_arena_sites_forget(oc);
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

/* Whether releases are checked (hl_gc_arena_free can return 0): the system tracks writes, HL_GC_ARENA_TRACKING is not 0
   and the incremental collector is off. Starts tracking as opening the first arena would; false once tracking failed. */
HL_API bool hl_gc_arena_tracking_available( void ) {
	gc_global_lock(true);
	bool available = gc_arena_tracking_start();
	gc_global_lock(false);
	return available;
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

/*
	Copying out at a unit's finish: hl_gc_arena_copy(value, arena, target) returns `value` with the blocks of `arena` it
	reaches copied to `target` (an arena, or NULL or hl_gc_arena_global() for the collector's pages), pointers between them
	rewritten, sharing and cycles kept; blocks outside `arena` are shared, not copied.

	Only words known to be pointers are ever rewritten, by the layout of the block that holds them: a pointer field of an
	object, an enum constructor's pointer parameter, a closure's bound value, an array's storage and, when the array's
	element type is a pointer, its elements, and the words a registered layout names for an untyped block (a map's tables,
	hl_gc_arena_register_layout). A block whose layout is not known (an untyped block reached any other way, a virtual,
	a dynamic object) is not copied: the pointer to it stays, the arena's release finds it and keeps the arena. A word
	that merely looks like an address is never changed. No collection runs while it copies.
*/
typedef struct { const uchar *name; hl_gc_arena_layout layout; } gc_arena_layout_entry;
static gc_arena_layout_entry *gc_arena_layouts = NULL;
static int gc_arena_layout_count = 0;

/* Says that an untyped block reached through a field of the abstract type `name` has the pointers `layout` visits. */
HL_API void hl_gc_arena_register_layout( const uchar *name, hl_gc_arena_layout layout ) {
	gc_global_lock(true);
	for(int i=0;i<gc_arena_layout_count;i++)
		if( ucmp(gc_arena_layouts[i].name,name) == 0 ) {
			gc_arena_layouts[i].layout = layout;
			gc_global_lock(false);
			return;
		}
	gc_arena_layouts = (gc_arena_layout_entry*)realloc(gc_arena_layouts,sizeof(gc_arena_layout_entry) * (gc_arena_layout_count + 1));
	if( gc_arena_layouts == NULL ) out_of_memory("arena layouts");
	gc_arena_layouts[gc_arena_layout_count].name = name;
	gc_arena_layouts[gc_arena_layout_count++].layout = layout;
	gc_global_lock(false);
}

static hl_gc_arena_layout gc_arena_layout_of( hl_type *t ) {
	if( t == NULL || t->kind != HABSTRACT || t->abs_name == NULL ) return NULL;
	for(int i=0;i<gc_arena_layout_count;i++)
		if( ucmp(gc_arena_layouts[i].name,t->abs_name) == 0 ) return gc_arena_layouts[i].layout;
	return NULL;
}


// The kind of a slot whose static type is `t`, or false when what it points to cannot be copied by layout.
static bool gc_arena_slot_kind_of( hl_type *t, gc_slot_kind *k ) {
	k->at = NULL;
	k->layout = NULL;
	if( t && t->kind == HABSTRACT ) {
		k->kind = GC_SLOT_LAYOUT;
		k->layout = gc_arena_layout_of(t);
		return k->layout != NULL;
	}
	k->kind = GC_SLOT_VALUE;
	return true;
}

// An entry belongs to the copy whose epoch it has: starting a copy empties the table by moving to the next epoch.
typedef struct { void *from, *to; uint64 epoch; } gc_arena_copy_entry;
typedef struct { void *block; gc_slot_kind kind; } gc_arena_copy_work;
static uint64 gc_arena_copy_epoch = 0;
static int64 gc_arena_copy_bytes = 0;
static gc_arena_copy_entry *gc_arena_copy_table;
static int64 gc_arena_copy_cap, gc_arena_copy_count;
static gc_arena_copy_work *gc_arena_copy_stack;
static int64 gc_arena_copy_depth, gc_arena_copy_stack_cap;
static int gc_arena_copy_class;
static void *gc_arena_copy_target;

static gc_arena_copy_entry *gc_arena_copy_slot( void *from ) {
	uint64 h = ((uint64)(uintptr_t)from * 0x9E3779B97F4A7C15ULL) >> 17;
	int64 i = (int64)(h & (gc_arena_copy_cap - 1));
	while( gc_arena_copy_table[i].epoch == gc_arena_copy_epoch && gc_arena_copy_table[i].from != from )
		i = (i + 1) & (gc_arena_copy_cap - 1);
	return &gc_arena_copy_table[i];
}

static void gc_arena_copy_grow( void ) {
	gc_arena_copy_entry *old = gc_arena_copy_table;
	int64 cap = gc_arena_copy_cap;
	gc_arena_copy_cap = cap ? cap * 2 : 1 << 12;
	gc_arena_copy_table = (gc_arena_copy_entry*)calloc(gc_arena_copy_cap,sizeof(gc_arena_copy_entry));
	if( gc_arena_copy_table == NULL ) out_of_memory("arena copy");
	for(int64 i=0;i<cap;i++)
		if( old[i].epoch == gc_arena_copy_epoch ) *gc_arena_copy_slot(old[i].from) = old[i];
	free(old);
}

static void gc_arena_copy_begin( int oc, void *target ) {
	gc_arena_copy_count = 0;
	gc_arena_copy_epoch++;
	gc_arena_copy_depth = 0;
	gc_arena_copy_class = oc;
	gc_arena_copy_target = target;
}

// A boxed scalar (a Dynamic holding an Int, a Float, a Bool): bytes with a type word, no pointer.
static bool gc_arena_scalar_box( hl_type *t ) {
	switch( t->kind ) {
	case HUI8: case HUI16: case HI32: case HI64: case HF32: case HF64: case HBOOL: return true;
	default: return false;
	}
}

// The copy of the block `value` points to, when it is a block of the arena whose layout `kind` gives, made now if it was not
// yet; `value` itself otherwise.
static void *gc_arena_copy_block( void *value, gc_slot_kind kind ) {
	if( value == NULL ) return NULL;
	int oc = gc_arena_copy_class;
	gc_pheader *ph = GC_GET_PAGE(value);
	if( !ph || !INPAGE(value,ph) || ph->owner_class != oc ) return value;
	void *start = value;
	if( gc_allocator_get_block_interior(ph,&start) < 0 || (ph->alloc.sizes && ph->alloc.sizes[((unsigned char*)start - ph->base) / ph->alloc.block_size] == 0) )
		return value;
	// The block's layout: bytes, an object of its own type, an array's storage, or a registered untyped layout.
	hl_type *t = ph->page_kind == MEM_KIND_DYNAMIC ? *(hl_type**)start : NULL;
	switch( ph->page_kind ) {
	case MEM_KIND_NOPTR:
		break;
	case MEM_KIND_RAW:
		if( kind.kind != GC_SLOT_LAYOUT ) return value;
		break;
	case MEM_KIND_DYNAMIC:
		if( start != value ) return value; // a typed block is pointed to by its start
		if( kind.kind == GC_SLOT_STORAGE ) {
			if( t != &hlt_array ) return value;
			break;
		}
		if( kind.kind != GC_SLOT_VALUE || !t || !gc_plausible_type(t) ) return value;
		if( t->kind == HOBJ ) {
			if( !t->obj->rt ) return value;
		} else if( t->kind == HARRAY ) {
			if( t != &hlt_array || !gc_plausible_type(((varray*)start)->at) ) return value;
		} else if( t->kind == HABSTRACT ) {
			if( !gc_arena_layout_of(t) ) return value; // a box of an abstract value: copied only when its layout is known
		} else if( t->kind != HENUM && t->kind != HFUN && !gc_arena_scalar_box(t) )
			return value;
		break;
	default:
		return value; // finalized blocks
	}
	if( start != value )
		return (char*)gc_arena_copy_block(start,kind) + ((char*)value - (char*)start);
	if( (gc_arena_copy_count + 1) * 2 > gc_arena_copy_cap ) gc_arena_copy_grow();
	gc_arena_copy_entry *e = gc_arena_copy_slot(value);
	if( e->epoch == gc_arena_copy_epoch ) return e->to;
	int size = gc_allocator_fast_block_size(ph,value);
	void *copy = hl_gc_alloc_gen_owner(t,size,ph->page_kind,gc_arena_copy_target);
	memcpy(copy,value,size);
	gc_arena_copy_bytes += size;
	e = gc_arena_copy_slot(value);
	e->from = value;
	e->to = copy;
	e->epoch = gc_arena_copy_epoch;
	gc_arena_copy_count++;
	if( ph->page_kind != MEM_KIND_NOPTR ) {
		if( gc_arena_copy_depth == gc_arena_copy_stack_cap ) {
			gc_arena_copy_stack_cap = gc_arena_copy_stack_cap ? gc_arena_copy_stack_cap * 2 : 1024;
			gc_arena_copy_stack = (gc_arena_copy_work*)realloc(gc_arena_copy_stack,sizeof(gc_arena_copy_work) * gc_arena_copy_stack_cap);
			if( gc_arena_copy_stack == NULL ) out_of_memory("arena copy");
		}
		gc_arena_copy_stack[gc_arena_copy_depth].block = copy;
		gc_arena_copy_stack[gc_arena_copy_depth++].kind = kind;
	}
	return copy;
}

static void gc_arena_copy_slot_to( void **slot, hl_type *static_type ) {
	gc_slot_kind k;
	if( *slot && gc_arena_slot_kind_of(static_type,&k) ) *slot = gc_arena_copy_block(*slot,k);
}

static void gc_arena_copy_visit( void **slot, void *layout, void *ctx ) {
	(void)ctx;
	gc_slot_kind k = { layout ? GC_SLOT_LAYOUT : GC_SLOT_VALUE, NULL, (hl_gc_arena_layout)layout };
	if( *slot ) *slot = gc_arena_copy_block(*slot,k);
}

// Rewrites the pointers of a copied block, by its layout, to their copies.
static void gc_arena_copy_fields( gc_arena_copy_work *w ) {
	void *block = w->block;
	gc_pheader *ph = GC_GET_PAGE(block);
	int size = gc_allocator_fast_block_size(ph,block);
	if( w->kind.kind == GC_SLOT_LAYOUT ) {
		w->kind.layout(block,size,gc_arena_copy_visit,NULL);
		return;
	}
	if( w->kind.kind == GC_SLOT_STORAGE ) {
		hl_type *at = w->kind.at;
		if( !hl_is_ptr(at) || at->kind == HSTRUCT || at->kind == HPACKED ) return;
		for(int word=1;word<size / HL_WSIZE;word++) gc_arena_copy_slot_to((void**)block + word,at);
		return;
	}
	hl_type *t = *(hl_type**)block;
	switch( t->kind ) {
	case HOBJ: {
		hl_runtime_obj *rt = t->obj->rt;
		hl_type *chain[64]; int depth = 0;
		for(hl_type *c=t;c && depth<64;c=c->obj->super) chain[depth++] = c;
		int index = 0;
		for(int d=depth-1;d>=0;d--) {
			hl_type_obj *o = chain[d]->obj;
			for(int f=0;f<o->nfields;f++,index++) {
				hl_type *ft = o->fields[f].t;
				if( index < rt->nfields && hl_is_ptr(ft) && ft->kind != HPACKED )
					gc_arena_copy_slot_to((void**)((char*)block + rt->fields_indexes[index]),ft);
			}
		}
		break;
	}
	case HENUM: {
		int index = ((venum*)block)->index;
		if( index < 0 || index >= t->tenum->nconstructs ) break;
		hl_enum_construct *c = &t->tenum->constructs[index];
		for(int p=0;p<c->nparams;p++)
			if( hl_is_ptr(c->params[p]) && c->params[p]->kind != HPACKED )
				gc_arena_copy_slot_to((void**)((char*)block + c->offsets[p]),c->params[p]);
		break;
	}
	case HARRAY: {
		varray *a = (varray*)block;
		gc_slot_kind k = { GC_SLOT_STORAGE, a->at, NULL };
		if( a->data ) a->data = (vbyte*)gc_arena_copy_block(a->data,k);
		break;
	}
	case HFUN: {
		vclosure *c = (vclosure*)block;
		if( c->hasValue ) gc_arena_copy_slot_to(&c->value,NULL);
		break;
	}
	case HABSTRACT: {
		// A Dynamic holding an abstract value (a map stored in a table of references): the value has the abstract's layout.
		gc_slot_kind k = { GC_SLOT_LAYOUT, NULL, gc_arena_layout_of(t) };
		vdynamic *box = (vdynamic*)block;
		if( k.layout && box->v.ptr ) box->v.ptr = gc_arena_copy_block(box->v.ptr,k);
		break;
	}
	default:
		break;
	}
}

static void gc_arena_copy_drain( void ) {
	while( gc_arena_copy_depth > 0 ) {
		gc_arena_copy_work w = gc_arena_copy_stack[--gc_arena_copy_depth];
		gc_arena_copy_fields(&w);
	}
}

HL_API vdynamic *hl_gc_arena_copy( vdynamic *value, void *arena, void *target ) {
	if( value == NULL ) return value;
	if( arena == NULL ) {
		// The thread's current arena.
		arena = current_thread ? current_thread->gc_arena : NULL;
		if( arena == NULL ) return value;
	}
	if( target == GC_ARENA_GLOBAL ) target = NULL;
	gc_global_lock(true);
	int oc = gc_owner_class_lookup(arena);
	gc_global_lock(false);
	if( oc <= 0 ) return value;
	// The copies are reachable from nowhere the collector sees until the copy returns.
	bool active = gc_is_active;
	gc_is_active = false;
	gc_arena_copy_begin(oc,target);
	gc_slot_kind k = { GC_SLOT_VALUE, NULL, NULL };
	void *result = gc_arena_copy_block(value,k);
	gc_arena_copy_drain();
	gc_is_active = active;
	return (vdynamic*)result;
}

/*
	The layout of a map of the VM's std library (maps.h): its first four words point to its cell table (bytes), its chain table
	(inside the cell table), its entries (bytes) and its values (an untyped block every word of which is a pointer: a key or a
	value; a map of scalar values keeps them in bytes). Libraries whose map types are these maps register their abstract
	names with it.
*/
static void gc_arena_pointers_layout( void *block, int size, hl_gc_arena_visit visit, void *ctx ) {
	for(int word=0;word<size / HL_WSIZE;word++) visit((void**)block + word,NULL,ctx);
}

HL_API void hl_gc_arena_map_layout( void *block, int size, hl_gc_arena_visit visit, void *ctx ) {
	(void)size;
	void **words = (void**)block;
	visit(&words[0],NULL,ctx);
	visit(&words[1],NULL,ctx);
	visit(&words[2],NULL,ctx);
	visit(&words[3],(void*)gc_arena_pointers_layout,ctx);
}

/*
	An evacuating release (hl_gc_arena_set_evacuation): when every reference into an arena is a pointer field of a block
	outside it, read by that block's layout as hl_gc_arena_copy reads one, what those fields reach is copied out, each to the
	owner of the page holding the field, the fields are rewritten to the copies, and the arena is released. The copies are
	then the only live version of what they copy. Any other reference keeps the arena: a word of an untyped block, a root, a
	stack or register word, a field whose target has no known layout.
*/
static bool gc_arena_evacuation = false;
static int64 gc_arena_evacuated = 0, gc_arena_evacuated_bytes = 0;

HL_API void hl_gc_arena_set_evacuation( bool on ) {
	gc_arena_evacuation = on;
}

/* How many arenas an evacuating release has released, and the bytes it copied out of them. */
HL_API double hl_gc_arena_evacuated( void ) {
	return (double)gc_arena_evacuated;
}

HL_API double hl_gc_arena_evacuated_bytes( void ) {
	return (double)gc_arena_evacuated_bytes;
}

// The static type of the pointer field at `slot` of a typed block, by the block's layout, with `*precise` set; `*precise`
// false when the slot is a word of an untyped block, which no evacuation may rewrite.
static gc_slot_kind gc_arena_field_kind( void **slot, bool *precise ) {
	gc_slot_kind k = { GC_SLOT_VALUE, NULL, NULL };
	*precise = false;
	gc_pheader *ph = GC_GET_PAGE(slot);
	if( !ph || !INPAGE(slot,ph) || ph->page_kind != MEM_KIND_DYNAMIC ) return k;
	void *start = slot;
	if( gc_allocator_get_block_interior(ph,&start) < 0 ) return k;
	hl_type *t = *(hl_type**)start;
	if( !t || !gc_plausible_type(t) ) return k;
	int offset = (int)((char*)slot - (char*)start);
	switch( t->kind ) {
	case HOBJ: {
		hl_runtime_obj *rt = t->obj->rt;
		if( !rt ) return k;
		hl_type *chain[64]; int depth = 0;
		for(hl_type *c=t;c && depth<64;c=c->obj->super) chain[depth++] = c;
		int index = 0;
		for(int d=depth-1;d>=0;d--) {
			hl_type_obj *o = chain[d]->obj;
			for(int f=0;f<o->nfields;f++,index++)
				if( index < rt->nfields && rt->fields_indexes[index] == offset && hl_is_ptr(o->fields[f].t) && o->fields[f].t->kind != HPACKED ) {
					*precise = gc_arena_slot_kind_of(o->fields[f].t,&k);
					return k;
				}
		}
		return k;
	}
	case HENUM: {
		int index = ((venum*)start)->index;
		if( index < 0 || index >= t->tenum->nconstructs ) return k;
		hl_enum_construct *c = &t->tenum->constructs[index];
		for(int p=0;p<c->nparams;p++)
			if( c->offsets[p] == offset && hl_is_ptr(c->params[p]) && c->params[p]->kind != HPACKED ) {
				*precise = gc_arena_slot_kind_of(c->params[p],&k);
				return k;
			}
		return k;
	}
	case HARRAY:
		if( t == &hlt_array && offset == (int)offsetof(varray,data) && gc_plausible_type(((varray*)start)->at) ) {
			k.kind = GC_SLOT_STORAGE;
			k.at = ((varray*)start)->at;
			*precise = true;
		}
		return k;
	case HFUN:
		if( offset == (int)offsetof(vclosure,value) && ((vclosure*)start)->hasValue ) *precise = true;
		return k;
	case HABSTRACT:
		if( offset == (int)offsetof(vdynamic,v) && (k.layout = gc_arena_layout_of(t)) != NULL ) {
			k.kind = GC_SLOT_LAYOUT;
			*precise = true;
		}
		return k;
	default:
		return k;
	}
}

// Locked, world stopped, after gc_arena_references found only precise fields.
static void gc_arena_evacuate( int oc ) {
	bool active = gc_is_active;
	gc_is_active = false;
	int64 before = gc_arena_copy_bytes;
	gc_arena_copy_begin(oc,NULL);
	for(int i=0;i<gc_arena_slot_count;i++) {
		void **slot = gc_arena_slots[i].slot;
		void *target = hl_gc_arena_owner_of(slot);
		gc_arena_copy_target = target == GC_ARENA_GLOBAL ? NULL : target;
		*slot = gc_arena_copy_block(*slot,gc_arena_slots[i].kind);
		gc_arena_copy_drain();
	}
	gc_is_active = active;
	gc_arena_evacuated++;
	gc_arena_evacuated_bytes += gc_arena_copy_bytes - before;
}
