/*
	Included by gc.c. A heap census for finding what sets a program's peak memory, off unless asked for.

	hl_gc_census(label) collects and prints to stderr, one `census <label> ...` line per entry:
	- per size class: pages, bytes mapped, bytes resident (Linux and macOS), bytes live, bytes in pages with nothing live;
	- live bytes by type;
	- live bytes by nearest owner: arrays, maps, strings, closures and untyped blocks are charged to the closest block on
	  their path from the roots that is none of these (an `IrBlock`'s instruction array is charged to the `IrBlock`);
	- live bytes by root path: the first owners on a breadth-first path from the roots, with the fields that lead to them,
	  to a depth of CENSUS_DEPTH (`stack > Compiler.state > SessionState.modules > ModuleState`).

	HL_GC_CENSUS_AT=N runs the same census inside the Nth collection, right after its mark (0: every collection), so it
	shows what that collection keeps without adding one. HL_GC_CENSUS_NOGC makes hl_gc_census print, without collecting,
	the bytes mapped and in use per size class (in use: live or garbage since the last collection). HL_GC_CENSUS_TOP sets
	how many entries each list prints (60), HL_GC_CENSUS_PAGES_ONLY stops after the size classes, and
	HL_GC_CENSUS_STACK_FIRST walks the thread stacks before the globals, so a block both reach is charged to the stack.

	A block the mark found but the walk does not reach was kept by a stale word that the census's own frames have since
	overwritten (a register or stack slot of the code that called it); such blocks are listed as `unreached`.
*/
#if defined(__linux__) || defined(__APPLE__)
#	include <unistd.h>
#	define CENSUS_MINCORE
#endif

#define CENSUS_DEPTH 4
// The owner of a container no owner holds: a root, or another such container.
#define CS_ROOT_OWNER ((void*)(int_val)8)

typedef struct { void *k; void *owner; int prefix; int owner_off; } cs_slot;
typedef struct { int parent; int off; void *key; void *holder_key; int depth; int64 bytes; int64 count; } cs_prefix;
typedef struct { void *key; int64 count; int64 bytes; } cs_entry;
typedef struct { void *key; int container; } cs_kind;

static cs_slot *cs_tab; static int64 cs_cap;
static void **cs_queue; static int64 cs_qlen, cs_qcap;
static cs_prefix *cs_prefixes; static int cs_nprefix, cs_prefix_cap;
static int *cs_prefix_hash; static int cs_prefix_hcap;
static cs_kind cs_kinds[1<<16];
static bool cs_inside = false;

static cs_slot *cs_find( void *k, bool insert ) {
	uint64 h = ((uint64)(int_val)k * 0x9E3779B97F4A7C15ULL) >> 17;
	int64 i = (int64)(h % (uint64)cs_cap);
	while( cs_tab[i].k ) {
		if( cs_tab[i].k == k ) return &cs_tab[i];
		if( ++i == cs_cap ) i = 0;
	}
	if( !insert ) return NULL;
	cs_tab[i].k = k;
	return &cs_tab[i];
}

// Whether blocks of this type key are charged to whoever holds them.
static bool cs_is_container( void *key ) {
	int_val k = (int_val)key;
	if( k >= 1 && k <= 4 ) return true;
	if( k & 1 ) return true;
	int i = (int)(((uint64)k * 0x9E3779B97F4A7C15ULL) >> 48);
	while( cs_kinds[i].key && cs_kinds[i].key != key ) i = (i + 1) & 0xFFFF;
	if( cs_kinds[i].key ) return cs_kinds[i].container;
	hl_type *t = (hl_type*)key;
	int c = 0;
	switch( t->kind ) {
	case HARRAY: case HABSTRACT: case HDYNOBJ: case HVIRTUAL: case HFUN: case HMETHOD: case HDYN: case HNULL: case HBYTES:
		c = 1;
		break;
	case HOBJ: case HSTRUCT: {
		const char *n = hl_to_utf8(t->obj->name);
		c = strncmp(n,"hl.types.",9) == 0 || strncmp(n,"haxe.ds.",8) == 0 || strcmp(n,"String") == 0
			|| strncmp(n,"hl.NativeArray",14) == 0 || strncmp(n,"haxe.iterators.",15) == 0;
		break;
	}
	default:
		break;
	}
	cs_kinds[i].key = key;
	cs_kinds[i].container = c;
	return c;
}

static int cs_intern( int parent, int off, void *key, void *holder_key, int depth ) {
	uint64 h = ((uint64)(int_val)key * 0x9E3779B97F4A7C15ULL) ^ ((uint64)(parent + 1) * 0xC2B2AE3D27D4EB4FULL) ^ ((uint64)(off + 7) * 0x165667B19E3779F9ULL);
	int i = (int)(h % (uint64)cs_prefix_hcap);
	while( cs_prefix_hash[i] >= 0 ) {
		cs_prefix *p = &cs_prefixes[cs_prefix_hash[i]];
		if( p->parent == parent && p->off == off && p->key == key ) return cs_prefix_hash[i];
		if( ++i == cs_prefix_hcap ) i = 0;
	}
	if( cs_nprefix == cs_prefix_cap ) return parent; // full: charged to the shorter path
	cs_prefix *p = &cs_prefixes[cs_nprefix];
	p->parent = parent; p->off = off; p->key = key; p->holder_key = holder_key; p->depth = depth; p->bytes = 0; p->count = 0;
	cs_prefix_hash[i] = cs_nprefix;
	return cs_nprefix++;
}

static void cs_visit( void *p, cs_slot *from, int off, bool interior, int root ) {
	gc_pheader *page = GC_GET_PAGE(p);
	if( !page || !INPAGE(p,page) ) return;
	int bid = interior ? gc_allocator_get_block_interior(page,&p) : gc_allocator_get_block_id(page,p);
	if( bid < 0 || !gc_block_marked(page,bid) ) return;
	if( cs_find(p,false) ) return;
	void *key = gc_block_type_key(page,p);
	void *fromOwner = from ? from->owner : NULL;
	int fromPrefix = from ? from->prefix : root;
	int fromOwnerOff = from ? from->owner_off : -1;
	if( from ) {
		void *fkey = gc_block_type_key(GC_GET_PAGE(from->k),from->k);
		if( !cs_is_container(fkey) ) { fromOwner = fkey; fromOwnerOff = off; }
	}
	cs_slot *s = cs_find(p,true);
	if( cs_is_container(key) ) {
		s->owner = fromOwner;
		s->owner_off = fromOwnerOff;
		s->prefix = fromPrefix;
	} else {
		s->owner = key;
		s->owner_off = -1;
		int depth = cs_prefixes[fromPrefix].depth;
		s->prefix = depth < CENSUS_DEPTH ? cs_intern(fromPrefix,fromOwnerOff,key,fromOwner,depth + 1) : fromPrefix;
	}
	if( cs_qlen == cs_qcap ) { cs_qcap *= 2; cs_queue = (void**)realloc(cs_queue,cs_qcap*sizeof(void*)); }
	cs_queue[cs_qlen++] = p;
}

static void cs_field( void *key, int off, char *out, int size ) {
	int_val k = (int_val)key;
	out[0] = 0;
	if( key == NULL || off < 0 || (k >= 1 && k <= 4) || (k & 1) ) return;
	hl_type *t = (hl_type*)key;
	if( (t->kind == HOBJ || t->kind == HSTRUCT) && t->obj->rt ) {
		hl_runtime_obj *rt = t->obj->rt;
		hl_type *chain[64]; int depth = 0;
		for(hl_type *c=t;c && depth<64;c=c->obj->super) chain[depth++] = c;
		int index = 0;
		for(int d=depth-1;d>=0;d--) {
			hl_type_obj *o = chain[d]->obj;
			for(int f=0;f<o->nfields;f++,index++)
				if( index < rt->nfields && rt->fields_indexes[index] == off ) {
					snprintf(out,size,".%s",hl_to_utf8(o->fields[f].name));
					return;
				}
		}
	}
	snprintf(out,size,"+%d",off);
}

static void cs_prefix_name( int id, char *out, int size ) {
	int chain[CENSUS_DEPTH+2]; int n = 0;
	while( id >= 0 && n < CENSUS_DEPTH+2 ) { chain[n++] = id; id = cs_prefixes[id].parent; }
	int len = 0;
	char name[200], field[100];
	for(int i=n-1;i>=0 && len < size - 320;i--) {
		cs_prefix *p = &cs_prefixes[chain[i]];
		if( p->key == NULL ) { len += snprintf(out+len,size-len,"%s",p->off == 0 ? "globals" : "stack"); continue; }
		cs_field(p->holder_key,p->off,field,sizeof(field));
		gc_type_key_name(p->key,name,sizeof(name));
		len += snprintf(out+len,size-len,"%s > %.90s",field,name);
	}
}

static int cs_entry_cmp( const void *a, const void *b ) {
	int64 x = ((cs_entry*)a)->bytes, y = ((cs_entry*)b)->bytes;
	return x < y ? 1 : x > y ? -1 : 0;
}

static void cs_add( cs_entry *entries, int cap, void *key, int64 bytes ) {
	int i = (int)((((uint64)(int_val)key * 0x9E3779B97F4A7C15ULL) >> 20) % (uint64)cap);
	while( entries[i].key && entries[i].key != key ) if( ++i == cap ) i = 0;
	entries[i].key = key;
	entries[i].count++;
	entries[i].bytes += bytes;
}

static void cs_print( const char *label, const char *title, cs_entry *entries, int cap, int top ) {
	qsort(entries,cap,sizeof(cs_entry),cs_entry_cmp);
	char name[200];
	for(int i=0;i<cap && i<top && entries[i].key;i++) {
		if( entries[i].key == CS_ROOT_OWNER ) snprintf(name,sizeof(name),"(a root)");
		else gc_type_key_name(entries[i].key,name,sizeof(name));
		fprintf(stderr,"census %s %s %9.2f MB %10lld  %s\n",label,title,entries[i].bytes/1048576.0,(long long)entries[i].count,name);
	}
}

static int64 cs_resident( void *base, int64 size ) {
#	ifdef CENSUS_MINCORE
	int64 pagesz = sysconf(_SC_PAGESIZE);
	int64 n = (size + pagesz - 1) / pagesz;
	unsigned char *vec = (unsigned char*)malloc(n);
	if( !vec || mincore(base,size,(void*)vec) != 0 ) { free(vec); return size; }
	int64 r = 0;
	for(int64 i=0;i<n;i++) if( vec[i] & 1 ) r += pagesz;
	free(vec);
	return r;
#	else
	return size;
#	endif
}

// The process's resident and peak resident bytes, 0 where /proc is not there.
static void cs_rss( int64 *rss, int64 *hwm ) {
	*rss = *hwm = 0;
	FILE *f = fopen("/proc/self/status","r");
	if( !f ) return;
	char line[256];
	while( fgets(line,sizeof(line),f) ) {
		if( strncmp(line,"VmRSS:",6) == 0 ) *rss = atoll(line+6) * 1024;
		if( strncmp(line,"VmHWM:",6) == 0 ) *hwm = atoll(line+6) * 1024;
	}
	fclose(f);
}

// With the marks of the last collection in place and the global lock held.
static void gc_census_walk( const char *label ) {
	int64 rss, hwm;
	cs_rss(&rss,&hwm);
	fprintf(stderr,"census %s rss %.1f MB hwm %.1f MB\n",label,rss/1048576.0,hwm/1048576.0);
	int64 part_pages[GC_PARTITIONS] = {0}, part_bytes[GC_PARTITIONS] = {0}, part_res[GC_PARTITIONS] = {0}, part_live[GC_PARTITIONS] = {0}, part_empty[GC_PARTITIONS] = {0};
	int64 live_blocks = 0;
	for(int pid=0;pid<GC_PAGE_SLOTS;pid++) {
		int part = GC_PID_PART(pid);
		for(gc_pheader *ph=gc_pages[pid];ph;ph=ph->next_page) {
			part_pages[part]++;
			part_bytes[part] += ph->page_size;
			part_res[part] += cs_resident(ph->base,ph->page_size);
			if( ph->bmp == NULL ) continue;
			gc_allocator_page_data *p = &ph->alloc;
			int64 live = 0;
			for(int bid=p->first_block;bid<p->max_blocks;bid++) {
				if( !gc_block_marked(ph,bid) ) continue;
				live += p->sizes ? p->sizes[bid] * p->block_size : p->block_size;
				live_blocks++;
			}
			part_live[part] += live;
			if( live == 0 ) part_empty[part] += ph->page_size;
		}
	}
	int64 tb = 0, tr = 0, tl = 0, te = 0;
	for(int i=0;i<GC_PARTITIONS;i++) {
		if( !part_pages[i] ) continue;
		fprintf(stderr,"census %s class %2d size %5d pages %6lld mapped %8.1f MB resident %8.1f MB live %8.1f MB empty-pages %7.1f MB\n",
			label,i,GC_SIZES[i],(long long)part_pages[i],part_bytes[i]/1048576.0,part_res[i]/1048576.0,part_live[i]/1048576.0,part_empty[i]/1048576.0);
		tb += part_bytes[i]; tr += part_res[i]; tl += part_live[i]; te += part_empty[i];
	}
	fprintf(stderr,"census %s total mapped %.1f MB resident %.1f MB live %.1f MB empty-pages %.1f MB, outside the pages %.1f MB, live blocks %lld\n",
		label,tb/1048576.0,tr/1048576.0,tl/1048576.0,te/1048576.0,rss ? (rss-tr)/1048576.0 : 0.0,(long long)live_blocks);
	if( getenv("HL_GC_CENSUS_PAGES_ONLY") ) return;
	cs_cap = live_blocks + live_blocks / 2 + 1024;
	cs_tab = (cs_slot*)calloc(cs_cap,sizeof(cs_slot));
	cs_qcap = 1 << 20; cs_qlen = 0;
	cs_queue = (void**)malloc(cs_qcap * sizeof(void*));
	cs_prefix_cap = 1 << 20; cs_nprefix = 0;
	cs_prefixes = (cs_prefix*)malloc(cs_prefix_cap * sizeof(cs_prefix));
	cs_prefix_hcap = cs_prefix_cap * 2 + 1;
	cs_prefix_hash = (int*)malloc(cs_prefix_hcap * sizeof(int));
	int ecap = 1 << 16;
	cs_entry *byType = (cs_entry*)calloc(ecap,sizeof(cs_entry)), *byOwner = (cs_entry*)calloc(ecap,sizeof(cs_entry)), *unreached = (cs_entry*)calloc(ecap,sizeof(cs_entry));
	if( !cs_tab || !cs_queue || !cs_prefixes || !cs_prefix_hash || !byType || !byOwner || !unreached ) {
		fprintf(stderr,"census %s: out of memory for the walk\n",label);
		goto done;
	}
	memset(cs_prefix_hash,0xFF,cs_prefix_hcap * sizeof(int));
	memset(cs_kinds,0,sizeof(cs_kinds));
	int rootGlobals = cs_intern(-1,0,NULL,NULL,0);
	int rootStack = cs_intern(-1,1,NULL,NULL,0);
	bool stackFirst = getenv("HL_GC_CENSUS_STACK_FIRST") != NULL;
	for(int pass=0;pass<2;pass++) {
		if( (pass == 0) != stackFirst ) {
			for(int i=0;i<gc_roots_count;i++) if( *gc_roots[i] ) cs_visit(*gc_roots[i],NULL,0,false,rootGlobals);
		} else {
			for(int i=0;i<gc_threads.count;i++) {
				hl_thread_info *t = gc_threads.threads[i];
				for(void **s=(void**)t->stack_cur;(void*)(s+1)<=t->stack_top;s++) if( *s ) cs_visit(*s,NULL,0,true,rootStack);
				for(void **s=(void**)&t->gc_regs;s<(void**)&t->gc_regs + (sizeof(jmp_buf) / sizeof(void*) - 1);s++) if( *s ) cs_visit(*s,NULL,0,true,rootStack);
				for(void **s=(void**)&t->extra_stack_data;s<(void**)&t->extra_stack_data + t->extra_stack_size;s++) if( *s ) cs_visit(*s,NULL,0,true,rootStack);
			}
			for(gc_pinned_list *l=gc_pinned_lists;l;l=l->next)
				for(int i=0;i<l->count;i++) if( l->values[i] ) cs_visit(l->values[i],NULL,0,true,rootStack);
		}
	}
	int64 walked = 0;
	for(int64 q=0;q<cs_qlen;q++) {
		void **block = (void**)cs_queue[q];
		gc_pheader *page = GC_GET_PAGE(block);
		cs_slot here = *cs_find(block,false);
		int size = gc_allocator_fast_block_size(page,block);
		walked += size;
		cs_add(byType,ecap,gc_block_type_key(page,block),size);
		cs_add(byOwner,ecap,here.owner ? here.owner : CS_ROOT_OWNER,size);
		cs_prefixes[here.prefix].bytes += size;
		cs_prefixes[here.prefix].count++;
		if( !MEM_HAS_PTR(page->page_kind) ) continue;
		// The words the mark follows, as gc_flush_mark reads them.
		int nwords = size / HL_WSIZE, pos = 0;
		unsigned int *mark_bits = NULL;
		void **base = block;
		if( page->page_kind == MEM_KIND_DYNAMIC ) {
			hl_type *t = *(hl_type**)block;
			if( !t ) continue;
			if( gc_plausible_type(t) && t->mark_bits && t->kind != HFUN ) {
				mark_bits = t->mark_bits;
				if( t->kind == HENUM ) { mark_bits += ((venum*)block)->index; base += 2; nwords -= 2; }
				else { base++; pos++; }
			}
		}
		int start = (int)(base - block);
		for(int w=0;pos<nwords;w++,pos++) {
			if( mark_bits && (mark_bits[pos >> 5] & (1 << (pos&31))) == 0 ) continue;
			if( base[w] ) cs_visit(base[w],&here,(start + w) * HL_WSIZE,false,0);
		}
	}
	int64 unreachedBytes = 0;
	for(int pid=0;pid<GC_PAGE_SLOTS;pid++)
		for(gc_pheader *ph=gc_pages[pid];ph;ph=ph->next_page) {
			if( ph->bmp == NULL ) continue;
			gc_allocator_page_data *pd = &ph->alloc;
			for(int bid=pd->first_block;bid<pd->max_blocks;bid++) {
				if( !gc_block_marked(ph,bid) ) continue;
				void *b = ph->base + bid * pd->block_size;
				if( cs_find(b,false) ) continue;
				int size = pd->sizes ? pd->sizes[bid] * pd->block_size : pd->block_size;
				unreachedBytes += size;
				cs_add(unreached,ecap,gc_block_type_key(ph,b),size);
			}
		}
	fprintf(stderr,"census %s walked %lld blocks %.1f MB, unreached %.1f MB\n",label,(long long)cs_qlen,walked/1048576.0,unreachedBytes/1048576.0);
	int top = 60;
	const char *topEnv = getenv("HL_GC_CENSUS_TOP");
	if( topEnv ) top = atoi(topEnv);
	cs_print(label,"type",byType,ecap,top);
	cs_print(label,"owner",byOwner,ecap,top);
	if( unreachedBytes ) cs_print(label,"unreached",unreached,ecap,top < 20 ? top : 20);
	// Each path's bytes with its longer paths', deepest first: a path's id is always above its parent's.
	int64 *incl = (int64*)calloc(cs_nprefix,sizeof(int64));
	cs_entry *paths = (cs_entry*)calloc(cs_nprefix,sizeof(cs_entry));
	if( incl && paths ) {
		for(int i=cs_nprefix-1;i>=0;i--) {
			incl[i] += cs_prefixes[i].bytes;
			if( cs_prefixes[i].parent >= 0 ) incl[cs_prefixes[i].parent] += incl[i];
		}
		char path[1600], title[16];
		for(int d=1;d<=CENSUS_DEPTH;d++) {
			int n = 0;
			for(int i=0;i<cs_nprefix;i++) if( cs_prefixes[i].depth == d ) { paths[n].key = (void*)(int_val)i; paths[n].bytes = incl[i]; paths[n].count = cs_prefixes[i].count; n++; }
			qsort(paths,n,sizeof(cs_entry),cs_entry_cmp);
			snprintf(title,sizeof(title),"path%d",d);
			for(int i=0;i<n && i<top && paths[i].bytes >= (1 << 20);i++) {
				cs_prefix_name((int)(int_val)paths[i].key,path,sizeof(path));
				fprintf(stderr,"census %s %s %9.2f MB  %s\n",label,title,paths[i].bytes/1048576.0,path);
			}
		}
	}
	free(incl); free(paths);
done:
	free(byType); free(byOwner); free(unreached); free(cs_tab); free(cs_queue); free(cs_prefixes); free(cs_prefix_hash);
	cs_tab = NULL; cs_queue = NULL; cs_prefixes = NULL; cs_prefix_hash = NULL;
}

// Called by gc_major after each mark, with the world stopped.
static void gc_census_after_mark( int collection ) {
	static int at = -2;
	if( at == -2 ) { const char *v = getenv("HL_GC_CENSUS_AT"); at = v && *v ? atoi(v) : -1; }
	if( at < 0 || cs_inside || (at != collection && at != 0) ) return;
	char label[32];
	snprintf(label,sizeof(label),"gc%d",collection);
	gc_census_walk(label);
}

// Without collecting: per size class, bytes mapped and in use (live or garbage since the last collection).
static void gc_census_pages( const char *label ) {
	int64 mapped[GC_PARTITIONS] = {0}, used[GC_PARTITIONS] = {0}, tm = 0, tu = 0, rss, hwm;
	gc_global_lock(true);
	for(int pid=0;pid<GC_PAGE_SLOTS;pid++) {
		int part = GC_PID_PART(pid);
		for(gc_pheader *ph=gc_pages[pid];ph;ph=ph->next_page) {
			mapped[part] += ph->page_size;
			used[part] += part == GC_LARGE_PART ? ph->page_size : ph->page_size - gc_free_memory(ph);
		}
	}
	gc_global_lock(false);
	cs_rss(&rss,&hwm);
	char line[4096]; int len = 0;
	for(int i=0;i<GC_PARTITIONS;i++) {
		tm += mapped[i]; tu += used[i];
		if( mapped[i] && len < (int)sizeof(line) - 64 ) len += snprintf(line+len,sizeof(line)-len," %d:%.0f/%.0f",GC_SIZES[i],mapped[i]/1048576.0,used[i]/1048576.0);
	}
	fprintf(stderr,"census %s pages rss %.0f mapped %.0f used %.0f MB | size:mapped/used%s\n",label,rss/1048576.0,tm/1048576.0,tu/1048576.0,line);
}

// The census's own mark must not find stale pointers that earlier, deeper calls left below the caller's frame.
static GC_ALLOC_NOINLINE void cs_wipe_stack() {
	volatile char buffer[1 << 16];
	memset((char*)buffer,0,sizeof(buffer));
}

HL_API void hl_gc_census( vbyte *label ) {
	const char *name = label ? (const char*)label : "census";
	if( getenv("HL_GC_CENSUS_NOGC") ) {
		gc_census_pages(name);
		return;
	}
	cs_wipe_stack();
	gc_global_lock(true);
	cs_inside = true;
	gc_major();
	cs_inside = false;
	gc_census_walk(name);
	gc_global_lock(false);
}

DEFINE_PRIM(_VOID, gc_census, _BYTES);
