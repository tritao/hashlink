#include <hlmodule.h>
#include <jit.h>
#include "jit_gdb.h"
#include <stdlib.h>
#include <string.h>

typedef struct { const unsigned char *p, *end; const char *error; } patch_reader;

struct _hl_patch_code {
	void *code;
	int code_size;
	int revision;
	int references;
	int function_count;
	hl_function *functions;
	int jit_debug_count;
	hl_debug_infos *jit_debug;
	hl_source_span **debug_spans;
	int source_snapshot_count;
	hl_source_snapshot *source_snapshots;
	void *gdb_jit_entry;
	bool listed;
#ifdef WIN64_UNWIND_TABLES
	/* The patch code's own function table, registered at its base address so Windows can unwind through it. */
	PRUNTIME_FUNCTION unwind_table;
	bool unwind_registered;
#endif
	hl_patch_code *next_retired;
};

/* Slots in use: the loaded functions and natives, then the functions patches have added. */
static int module_slot_count( hl_module *m ) {
	return m->code->nfunctions + m->code->nnatives + m->code->npatchfunctions;
}

/*
 * The functions a patch is checked and compiled against: the module's functions, then the ones the patch adds, with the
 * natives after them all. JIT code tells natives from functions by their index, so the natives' indexes move past the
 * added functions here; the module's own table keeps them where its load-time code expects.
 */
typedef struct {
	hl_function *functions;
	int count;
	int *indexes;
	int slots;
} patch_layout;

static hl_function *layout_function( patch_layout *layout, int findex ) {
	int index = findex < 0 || findex >= layout->slots ? -1 : layout->indexes[findex];
	return index < 0 || index >= layout->count ? NULL : layout->functions + index;
}

static int find_debug_file( hl_code *code, const char *path, int length ) {
	for(int i=0;i<code->ndebugfiles;i++)if(code->debugfiles_lens[i]==length&&!memcmp(code->debugfiles[i],path,length))return i;
	return -1;
}

static void patch_code_free( hl_patch_code *code ) {
	if(!code)return;
	if(code->gdb_jit_entry){hl_module module={0};module.gdb_jit_entry=code->gdb_jit_entry;hl_gdb_jit_unregister(&module);code->gdb_jit_entry=NULL;}
	for(int i=0;i<code->function_count;i++) {
		for(int j=0;j<code->functions[i].nops;j++) {
			hl_opcode *op=code->functions[i].ops+j;
			if(op->extra && (op->op==OCall3||op->op==OCall4||op->op==OCallN||op->op==OCallMethod||op->op==OCallThis||op->op==OCallClosure||op->op==OMakeEnum)) free(op->extra);
		}
		free(code->functions[i].regs);
		free(code->functions[i].ops);
		free(code->functions[i].debug);
		free(code->debug_spans == NULL ? NULL : code->debug_spans[i]);
	}
	for(int i=0;i<code->jit_debug_count;i++){free(code->jit_debug[i].offsets);free(code->jit_debug[i].vars);free(code->jit_debug[i].opcodes);}
	free(code->jit_debug);
	free(code->debug_spans);
	for(int i=0;i<code->source_snapshot_count;i++) free(code->source_snapshots[i].content);
	free(code->source_snapshots);
#ifdef WIN64_UNWIND_TABLES
	if(code->unwind_registered) RtlDeleteFunctionTable(code->unwind_table);
	free(code->unwind_table);
#endif
	if(code->code) hl_free_executable_memory(code->code,code->code_size);
	free(code->functions);
	free(code);
}

/*
 * The allocations live slots use, by code address. Readers on other threads (profilers, debuggers), and a Linux sampler
 * interrupting the patching thread, may hold an earlier list, so a list is published by one pointer store and superseded
 * lists stay until the module releases its patches. An allocation no slot uses any more is freed once the new list is
 * published, unless a concurrent reader is registered: it is then retired, as is code direct calls may still reach, and
 * stays until the module releases its patches.
 */
struct _hl_patch_live {
	struct _hl_patch_live *previous;
	int count;
	hl_patch_code *entries[1];
};

static bool patch_code_contains( hl_patch_code *owner, void *addr );

/*
 * Threads that read patch code without the patching thread's cooperation (the profiler's sampler, a diagnostics
 * connection) count themselves here while they may hold a patch address or list. A commit publishes its list before it
 * reads the count and a reader counts itself before it loads the list, all sequentially consistent, so either the commit
 * sees the reader and keeps the superseded code, or the reader sees the new list.
 */
static int patch_readers = 0;

#if defined(__GNUC__) || defined(__clang__)
#	define patch_readers_add(delta) __atomic_fetch_add(&patch_readers,(delta),__ATOMIC_SEQ_CST)
#	define patch_readers_get() __atomic_load_n(&patch_readers,__ATOMIC_SEQ_CST)
#	define patch_store(target,value) __atomic_store_n(&(target),(value),__ATOMIC_SEQ_CST)
#	define patch_load(source) __atomic_load_n(&(source),__ATOMIC_SEQ_CST)
#else
#	define patch_readers_add(delta) InterlockedExchangeAdd((volatile LONG*)&patch_readers,(LONG)(delta))
#	define patch_readers_get() InterlockedCompareExchange((volatile LONG*)&patch_readers,0,0)
#	define patch_store(target,value) InterlockedExchangePointer((PVOID volatile*)&(target),(PVOID)(value))
#	define patch_load(source) InterlockedCompareExchangePointer((PVOID volatile*)&(source),NULL,NULL)
#endif

void hl_module_patch_readers( int delta ) {
	patch_readers_add(delta);
}

static int by_code( const void *a, const void *b ) {
	unsigned char *x = (unsigned char*)(*(hl_patch_code*const*)a)->code, *y = (unsigned char*)(*(hl_patch_code*const*)b)->code;
	return x < y ? -1 : x > y ? 1 : 0;
}

/* A commit adds one allocation at most, so the next list needs room for one entry more than the current one. */
static hl_patch_live *patch_live_alloc( hl_module *m ) {
	return (hl_patch_live*)malloc(sizeof(hl_patch_live) + sizeof(hl_patch_code*) * ((m->patch_live ? m->patch_live->count : 0) + 1));
}

static void patch_live_publish( hl_module *m, hl_patch_live *next ) {
	int slots = module_slot_count(m), n = 0;
	for(int i=0;i<slots;i++){hl_patch_code *owner=m->patch_owners[i];if(owner)owner->listed=true;}
	for(int i=0;i<slots;i++){hl_patch_code *owner=m->patch_owners[i];if(owner&&owner->listed){owner->listed=false;next->entries[n++]=owner;}}
	qsort(next->entries,n,sizeof(hl_patch_code*),by_code);
	next->count = n;
	next->previous = m->patch_live;
	patch_store(m->patch_live,next);
}

static void patch_live_free( hl_module *m ) {
	hl_patch_live *list = m->patch_live;
	m->patch_live = NULL;
	while( list ) {
		hl_patch_live *previous = list->previous;
		free(list);
		list = previous;
	}
}

static hl_patch_code *patch_live_find( hl_patch_live *list, void *addr ) {
	int lo = 0, hi = list ? list->count : 0;
	while( lo < hi ) {
		int mid = (lo + hi) >> 1;
		if( (unsigned char*)list->entries[mid]->code <= (unsigned char*)addr ) lo = mid + 1; else hi = mid;
	}
	return lo > 0 && patch_code_contains(list->entries[lo - 1],addr) ? list->entries[lo - 1] : NULL;
}

void hl_module_patch_release_all( hl_module *m ) {
	if(m)patch_live_free(m);
	if(!m||!m->patch_owners)return;
	for(int i=0;i<module_slot_count(m);i++){hl_patch_code *owner=m->patch_owners[i];if(owner){m->patch_owners[i]=NULL;if(--owner->references==0)patch_code_free(owner);}}
	while(m->retired_patch_code){hl_patch_code *owner=m->retired_patch_code;m->retired_patch_code=owner->next_retired;patch_code_free(owner);}
}

int hl_module_patch_allocation_count( hl_module *m ) {
	hl_patch_live *live = m == NULL ? NULL : (hl_patch_live*)patch_load(m->patch_live);
	return live == NULL ? 0 : live->count;
}

int hl_module_patch_retired_allocation_count( hl_module *m ) {
	int count=0;
	for(hl_patch_code *owner=m==NULL?NULL:(hl_patch_code*)patch_load(m->retired_patch_code);owner;owner=owner->next_retired)count++;
	return count;
}

static bool patch_code_contains( hl_patch_code *owner, void *addr ) {
	unsigned char *code = (unsigned char*)owner->code;
	return code != NULL && addr >= (void*)code && addr < (void*)(code + owner->code_size);
}

static bool patch_code_resolve_pos( hl_module *m, hl_patch_code *owner, void *addr, hl_function **function, int *opcode ) {
	int code_pos, best_start = -1, best_function = -1;
	if( !patch_code_contains(owner,addr) || owner->jit_debug == NULL ) return false;
	code_pos = (int)((unsigned char*)addr - (unsigned char*)owner->code);
	for(int i=0;i<owner->function_count;i++) {
		hl_function *candidate = owner->functions + i;
		int index = m->functions_indexes[candidate->findex];
		hl_debug_infos *debug;
		if( index < 0 || index >= owner->jit_debug_count ) continue;
		debug = owner->jit_debug + index;
		if( debug->offsets != NULL && debug->start <= code_pos && debug->start > best_start ) {
			best_start = debug->start;
			best_function = i;
		}
	}
	if( best_function < 0 ) return false;
	{
		hl_function *resolved = owner->functions + best_function;
		int index = m->functions_indexes[resolved->findex];
		hl_debug_infos *debug = owner->jit_debug + index;
		int min = 0, max = resolved->nops;
		code_pos -= debug->start;
		while( min < max ) {
			int mid = (min + max) >> 1;
			int offset = debug->large ? ((int*)debug->offsets)[mid] : ((unsigned short*)debug->offsets)[mid];
			if( offset < code_pos ) min = mid + 1; else max = mid;
		}
		if( min == 0 ) min = 1; /* function prologue maps to its first opcode */
		*function = resolved;
		*opcode = min - 1;
		return true;
	}
}

bool hl_module_patch_resolve_pos( hl_module *m, void *addr, hl_function **function, int *opcode ) {
	if( m == NULL || m->patch_owners == NULL ) return false;
	// Most addresses asked about are not patch code (a stack scan asks about every candidate), and deciding that by
	// walking every function's owner costs time proportional to the module size.
	if( m->patch_hi == NULL || addr < m->patch_lo || addr >= m->patch_hi ) return false;
	{
		hl_patch_code *owner = patch_live_find((hl_patch_live*)patch_load(m->patch_live),addr);
		if( owner != NULL && patch_code_resolve_pos(m,owner,addr,function,opcode) ) return true;
	}
	for(hl_patch_code *owner=(hl_patch_code*)patch_load(m->retired_patch_code);owner;owner=owner->next_retired)
		if( patch_code_resolve_pos(m,owner,addr,function,opcode) ) return true;
	return false;
}

bool hl_module_patch_contains_address( hl_module *m, void *addr ) {
	hl_function *function;
	int opcode;
	return hl_module_patch_resolve_pos(m,addr,&function,&opcode);
}

int hl_module_patch_debug_region_count( hl_module *m ) {
	return hl_module_patch_allocation_count(m) + hl_module_patch_retired_allocation_count(m);
}

static hl_patch_code *patch_debug_region_at( hl_module *m, int region, bool *retired ) {
	hl_patch_live *live;
	int current;
	if( m == NULL || region < 0 ) return NULL;
	live = (hl_patch_live*)patch_load(m->patch_live);
	current = live ? live->count : 0;
	if( region < current ) { *retired = false; return live->entries[region]; }
	for(hl_patch_code *owner=(hl_patch_code*)patch_load(m->retired_patch_code);owner;owner=owner->next_retired)
		if( current++ == region ) { *retired = true; return owner; }
	return NULL;
}

bool hl_module_patch_debug_region_get( hl_module *m, int region, hl_patch_debug_region *out ) {
	bool retired;
	hl_patch_code *owner;
	if( out == NULL ) return false;
	owner = patch_debug_region_at(m,region,&retired);
	if( owner == NULL ) return false;
	out->code = owner->code;
	out->code_size = owner->code_size;
	out->function_count = owner->function_count;
	out->revision = owner->revision;
	out->retired = retired;
	return true;
}

bool hl_module_patch_debug_function_get( hl_module *m, int region, int function, int *function_index, hl_function **bytecode, hl_debug_infos **debug ) {
	bool retired;
	hl_patch_code *owner = patch_debug_region_at(m,region,&retired);
	int index;
	if( owner == NULL || function < 0 || function >= owner->function_count || function_index == NULL || bytecode == NULL || debug == NULL ) return false;
	*bytecode = owner->functions + function;
	index = m->functions_indexes[(*bytecode)->findex];
	if( index < 0 || index >= owner->jit_debug_count ) return false;
	*function_index = index;
	*debug = owner->jit_debug + index;
	return (*debug)->offsets != NULL;
}

bool hl_module_patch_debug_source_span_get( hl_module *m, int region, int function, int opcode, hl_source_span *out ) {
	bool retired;
	hl_patch_code *owner = patch_debug_region_at(m,region,&retired);
	if( owner == NULL || function < 0 || function >= owner->function_count || opcode < 0 || opcode >= owner->functions[function].nops
		|| owner->debug_spans == NULL || owner->debug_spans[function] == NULL || out == NULL ) return false;
	*out = owner->debug_spans[function][opcode];
	return true;
}

int hl_module_patch_debug_source_snapshot_count( hl_module *m, int region ) {
	bool retired;
	hl_patch_code *owner = patch_debug_region_at(m,region,&retired);
	return owner == NULL ? 0 : owner->source_snapshot_count;
}

bool hl_module_patch_debug_source_snapshot_get( hl_module *m, int region, int snapshot, hl_source_snapshot *out ) {
	bool retired;
	hl_patch_code *owner = patch_debug_region_at(m,region,&retired);
	if( owner == NULL || snapshot < 0 || snapshot >= owner->source_snapshot_count || out == NULL ) return false;
	*out = owner->source_snapshots[snapshot];
	return true;
}

static bool take( patch_reader *r, int count, const unsigned char **out ) {
	if( count < 0 || r->end - r->p < count ) { r->error = "Truncated HLP data"; return false; }
	*out = r->p; r->p += count; return true;
}

static bool read_byte( patch_reader *r, int *out ) {
	const unsigned char *p; if( !take(r,1,&p) ) return false; *out = *p; return true;
}

static bool read_index( patch_reader *r, int *out ) {
	int first, value; const unsigned char *p;
	if( !read_byte(r,&first) ) return false;
	if( !(first & 0x80) ) { *out = first; return true; }
	if( !(first & 0x40) ) {
		if( !take(r,1,&p) ) return false;
		value = p[0] | ((first & 31) << 8);
	} else {
		if( !take(r,3,&p) ) return false;
		value = ((first & 31) << 24) | (p[0] << 16) | (p[1] << 8) | p[2];
	}
	*out = (first & 0x20) ? -value : value; return true;
}

static bool read_count( patch_reader *r, int *out ) {
	if( !read_index(r,out) ) return false;
	if( *out < 0 || *out > 0x1000000 ) { r->error = "Invalid HLP count"; return false; }
	return true;
}

static bool read_hash( patch_reader *r, unsigned int *out ) {
	const unsigned char *p;
	if( !take(r,4,&p) ) return false;
	*out = p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned int)p[3] << 24);
	return true;
}

static bool read_i32( patch_reader *r, int *out ) {
	unsigned int value;
	if( !read_hash(r,&value) ) return false;
	*out = (int)value;
	return true;
}

static unsigned int hash_bytes( unsigned int hash, const unsigned char *p, int length ) {
	for(int i=0;i<length;i++) hash = (hash ^ p[i]) * 16777619U;
	return hash;
}

static unsigned int hash_i32( unsigned int hash, int value ) {
	unsigned char bytes[4] = { value & 255, (value >> 8) & 255, (value >> 16) & 255, ((unsigned int)value >> 24) & 255 };
	return hash_bytes(hash,bytes,4);
}

static unsigned int hash_int_prefix( hl_code *code, int count ) {
	unsigned int hash=2166136261U;for(int i=0;i<count;i++)hash=hash_i32(hash,code->ints[i]);return hash;
}

static unsigned int hash_float_prefix( hl_code *code, int count ) {
	unsigned int hash=2166136261U;for(int i=0;i<count;i++)hash=hash_bytes(hash,(unsigned char*)(code->floats+i),8);return hash;
}

static unsigned int hash_string_prefix( hl_code *code, int count ) {
	unsigned int hash=2166136261U;for(int i=0;i<count;i++){int length=code->strings_lens[i];hash=hash_i32(hash,length);hash=hash_bytes(hash,(unsigned char*)code->strings[i],length);}return hash;
}

/* Maps string content to the first string-table index holding it. Hashing a type prefix looks up every type, field,
   method and constructor name, and scanning the table for each made a patch of the editor take about 2 s. */
typedef struct {
	int *slots;
	int *lengths;
	int mask;
} type_string_index;

static unsigned int hash_ustring( const uchar *s, int length ) {
	return hash_bytes(2166136261U,(const unsigned char*)s,length * (int)sizeof(uchar));
}

static void type_string_index_free( type_string_index *index ) {
	free(index->slots);free(index->lengths);index->slots=NULL;index->lengths=NULL;
}

/* Leaves the index empty when out of memory; lookups then scan the table. */
static void type_string_index_build( hl_code *code, type_string_index *index ) {
	int size=16;
	while( size < code->nstrings * 2 ) size<<=1;
	index->slots=(int*)malloc(sizeof(int)*size);index->lengths=(int*)malloc(sizeof(int)*(code->nstrings>0?code->nstrings:1));index->mask=size-1;
	if( !index->slots || !index->lengths ) { type_string_index_free(index); return; }
	memset(index->slots,0xFF,sizeof(int)*size);
	for(int i=0;i<code->nstrings;i++) {
		const uchar *s=hl_get_ustring(code,i);int length=ustrlen(s);unsigned int slot=hash_ustring(s,length)&index->mask;
		index->lengths[i]=length;
		while( index->slots[slot] >= 0 ) {
			int other=index->slots[slot];
			if( index->lengths[other] == length && memcmp(hl_get_ustring(code,other),s,length * sizeof(uchar)) == 0 ) break;
			slot=(slot+1)&index->mask;
		}
		if( index->slots[slot] < 0 ) index->slots[slot]=i;
	}
}

static int hash_type_string_index( hl_code *code, type_string_index *index, const uchar *name ) {
	int length = ustrlen(name);
	if( index->slots ) {
		unsigned int slot=hash_ustring(name,length)&index->mask;
		while( index->slots[slot] >= 0 ) {
			int i=index->slots[slot];
			if( index->lengths[i] == length && memcmp(hl_get_ustring(code,i),name,length * sizeof(uchar)) == 0 ) return i;
			slot=(slot+1)&index->mask;
		}
		return -1;
	}
	for(int i=0;i<code->nstrings;i++) {
		const uchar *candidate = hl_get_ustring(code,i);
		if( ustrlen(candidate) == length && memcmp(candidate,name,length * sizeof(uchar)) == 0 )
			return i;
	}
	return -1;
}

static int hash_type_index( hl_code *code, hl_type *type ) {
	return type == NULL ? -1 : (int)(type - code->types);
}

static int hash_type_global_index( hl_module *module, void **value ) {
	int i;
	if( value == NULL ) return 0;
	for( i = 0; i < module->code->nglobals; i++ )
		if( module->globals_data + module->globals_indexes[i] == (unsigned char*)value ) return i + 1;
	return -1;
}

static unsigned int hash_type_prefix( hl_module *module, int count ) {
	hl_code *code = module->code;
	unsigned int hash=2166136261U;
	type_string_index strings={0};
	type_string_index_build(code,&strings);
	for(int i=0;i<count;i++){
		hl_type *type=code->types+i;
		hash=hash_i32(hash,type->kind);
		switch(type->kind) {
		case HFUN:
			hash=hash_i32(hash,type->fun->nargs);
			for(int j=0;j<type->fun->nargs;j++) hash=hash_i32(hash,hash_type_index(code,type->fun->args[j]));
			hash=hash_i32(hash,hash_type_index(code,type->fun->ret));
			break;
		case HABSTRACT:
			hash=hash_i32(hash,hash_type_string_index(code,&strings,type->abs_name));
			break;
		case HREF: case HNULL:
			hash=hash_i32(hash,hash_type_index(code,type->tparam));
			break;
		case HOBJ: case HSTRUCT: {
			hl_type_obj *obj=type->obj;
			hash=hash_i32(hash,hash_type_string_index(code,&strings,obj->name));
			hash=hash_i32(hash,obj->super == NULL ? -1 : hash_type_index(code,obj->super));
			hash=hash_i32(hash,hash_type_global_index(module,obj->global_value));
			hash=hash_i32(hash,obj->nfields);
			for(int j=0;j<obj->nfields;j++) { hash=hash_i32(hash,hash_type_string_index(code,&strings,obj->fields[j].name)); hash=hash_i32(hash,hash_type_index(code,obj->fields[j].t)); }
			hash=hash_i32(hash,obj->nproto);
			for(int j=0;j<obj->nproto;j++) { hash=hash_i32(hash,hash_type_string_index(code,&strings,obj->proto[j].name)); hash=hash_i32(hash,obj->proto[j].findex); hash=hash_i32(hash,obj->proto[j].pindex); }
			hash=hash_i32(hash,obj->nbindings);
			for(int j=0;j<obj->nbindings*2;j++) hash=hash_i32(hash,obj->bindings[j]);
			break;
		}
		case HVIRTUAL:
			hash=hash_i32(hash,type->virt->nfields);
			for(int j=0;j<type->virt->nfields;j++) { hash=hash_i32(hash,hash_type_string_index(code,&strings,type->virt->fields[j].name)); hash=hash_i32(hash,hash_type_index(code,type->virt->fields[j].t)); }
			break;
		case HENUM:
			hash=hash_i32(hash,hash_type_string_index(code,&strings,type->tenum->name));
			hash=hash_i32(hash,hash_type_global_index(module,type->tenum->global_value));
			hash=hash_i32(hash,type->tenum->nconstructs);
			for(int j=0;j<type->tenum->nconstructs;j++) { hl_enum_construct *c=type->tenum->constructs+j; hash=hash_i32(hash,hash_type_string_index(code,&strings,c->name)); hash=hash_i32(hash,c->nparams); for(int k=0;k<c->nparams;k++) hash=hash_i32(hash,hash_type_index(code,c->params[k])); }
			break;
		default:
			break;
		}
	}
	type_string_index_free(&strings);
	return hash;
}

#define OP_BEGIN static const signed char opcode_operand_counts[] = {
#define OP(o,a,b,c) c == VAR_ARGS ? -1 : b == AR ? c : (a != X) + (b != X) + (c != X),
#define OP_END };
#include "opcodes.h"

static int opcode_operands( int opcode ) {
	if( opcode < 0 || opcode >= OLast ) return -2;
	return opcode_operand_counts[opcode];
}

void hl_patch_free( hl_patch *patch ) {
	int i, j;
	if( patch == NULL ) return;
	for(i=0;i<patch->string_count;i++) free(patch->strings[i]);
	for(i=0;i<patch->function_count;i++) {
		hl_patch_function *f = patch->functions + i;
		for(j=0;j<f->instruction_count;j++) free(f->instructions[j].operands);
		free(f->instructions); free(f->registers); free(f->relocation_instructions); free(f->relocation_stable_ids); free(f->debug_spans);
	}
	for(i=0;i<patch->type_count;i++) if(patch->types[i].tag==HFUN) free(patch->types[i].data.fun.arguments);
	free(patch->types);
	for(i=0;i<patch->added_function_count;i++) free(patch->added_functions[i].name);
	free(patch->added_functions);
	for(i=0;i<patch->debug_file_count;i++) free(patch->debug_files[i]);
	for(i=0;i<patch->source_snapshot_count;i++) free(patch->source_snapshots[i].content);
	free(patch->source_snapshots);
	free(patch->debug_files); free(patch->debug_file_lens); free(patch->functions); free(patch->strings); free(patch->string_lens); free(patch->floats); free(patch->ints); free(patch);
}

hl_patch *hl_patch_read( const unsigned char *data, int size, const char **error_msg ) {
	patch_reader r = { data, data + (size < 0 ? 0 : size), NULL };
	hl_patch *patch = (hl_patch*)calloc(1,sizeof(hl_patch));
	const unsigned char *p; int version, i, j, count, tag, section_count, section_length;
	bool have_symbols = false, have_functions = false, have_debug = false, have_snapshots = false, have_added = false;
#define FAIL(msg) do { r.error = msg; goto fail; } while(0)
	if( patch == NULL ) FAIL("Out of memory reading HLP");
	if( !take(&r,3,&p) ) goto fail;
	if( memcmp(p,"HLP",3) != 0 ) FAIL("Invalid HLP magic");
	if( !read_byte(&r,&version) ) goto fail;
	if( version != 8 ) FAIL("Unsupported HLP version");
	if( !take(&r,16,&p) ) goto fail;
	memcpy(patch->module_id,p,16);
	if( !read_count(&r,&patch->base_revision) || !read_count(&r,&patch->revision) ) goto fail;
	if( patch->revision <= patch->base_revision ) FAIL("Invalid patch revision range");
	if( !read_count(&r,&section_count) ) goto fail;
	for(int section=0;section<section_count;section++) {
		patch_reader s;
		if( !read_byte(&r,&tag) || !read_count(&r,&section_length) || r.end-r.p<section_length ) goto fail;
		s.p=r.p;s.end=r.p+section_length;s.error=NULL;r.p=s.end;
		if( tag == 1 ) {
			if( have_symbols ) FAIL("Duplicate HLP symbols section");
			have_symbols=true;
			if( !read_hash(&s,&patch->int_prefix_hash) || !read_count(&s,&patch->base_int_count) || !read_count(&s,&patch->int_count) ) goto section_fail;
			patch->ints=(int*)calloc(patch->int_count,sizeof(int));
			for(i=0;i<patch->int_count;i++){if(!take(&s,4,&p))goto section_fail;patch->ints[i]=(int)(p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned int)p[3]<<24));}
			if(!read_hash(&s,&patch->float_prefix_hash)||!read_count(&s,&patch->base_float_count)||!read_count(&s,&patch->float_count))goto section_fail;
			patch->floats=(double*)calloc(patch->float_count,sizeof(double));for(i=0;i<patch->float_count;i++){if(!take(&s,8,&p))goto section_fail;memcpy(patch->floats+i,p,8);}
			if(!read_hash(&s,&patch->string_prefix_hash)||!read_count(&s,&patch->base_string_count)||!read_count(&s,&patch->string_count))goto section_fail;
			patch->strings=(char**)calloc(patch->string_count,sizeof(char*));patch->string_lens=(int*)calloc(patch->string_count,sizeof(int));for(i=0;i<patch->string_count;i++){if(!read_count(&s,&count)||!take(&s,count,&p))goto section_fail;patch->string_lens[i]=count;patch->strings[i]=(char*)malloc(count+1);if(!patch->strings[i])FAIL("Out of memory reading HLP");memcpy(patch->strings[i],p,count);patch->strings[i][count]=0;}
			if(!read_hash(&s,&patch->type_prefix_hash)||!read_count(&s,&patch->base_type_count)||!read_count(&s,&patch->type_count))goto section_fail;
			patch->types=(hl_patch_type*)calloc(patch->type_count,sizeof(hl_patch_type));if(patch->type_count&&!patch->types)FAIL("Out of memory reading patch types");
			for(i=0;i<patch->type_count;i++){
				hl_patch_type *type=patch->types+i;if(!read_byte(&s,&type->tag))goto section_fail;
				if(type->tag==HFUN){if(!read_byte(&s,&type->data.fun.count))goto section_fail;type->data.fun.arguments=(int*)calloc(type->data.fun.count,sizeof(int));if(type->data.fun.count&&!type->data.fun.arguments)FAIL("Out of memory reading function type");for(j=0;j<type->data.fun.count;j++)if(!read_index(&s,type->data.fun.arguments+j))goto section_fail;if(!read_index(&s,&type->data.fun.result))goto section_fail;}
				else if(type->tag==HABSTRACT){if(!read_index(&s,&type->data.name))goto section_fail;}
				else if(type->tag==HREF||type->tag==HNULL){if(!read_index(&s,&type->data.parameter))goto section_fail;}
				else if(type->tag<HVOID||type->tag>HGUID||type->tag==HOBJ||type->tag==HVIRTUAL||type->tag==HENUM||type->tag==HPACKED)FAIL("Unsupported HLP type");
			}
		} else if( tag == 2 ) {
			if( have_functions ) FAIL("Duplicate HLP functions section");
			have_functions=true;if(!read_count(&s,&patch->function_count))goto section_fail;
			patch->functions=(hl_patch_function*)calloc(patch->function_count,sizeof(hl_patch_function));
				for(i=0;i<patch->function_count;i++){hl_patch_function *f=patch->functions+i;int length;const unsigned char *end;if(!read_count(&s,&length)||s.end-s.p<length)goto section_fail;end=s.p+length;if(!read_count(&s,&f->stable_id)||!read_index(&s,&f->type)||!read_count(&s,&f->findex)||!read_count(&s,&f->register_count)||!read_count(&s,&f->instruction_count))goto section_fail;f->registers=(int*)calloc(f->register_count,sizeof(int));for(j=0;j<f->register_count;j++)if(!read_index(&s,f->registers+j))goto section_fail;f->instructions=(hl_patch_instruction*)calloc(f->instruction_count,sizeof(hl_patch_instruction));for(j=0;j<f->instruction_count;j++){hl_patch_instruction *op=f->instructions+j;if(!read_byte(&s,&op->opcode))goto section_fail;op->operand_count=opcode_operands(op->opcode);if(op->operand_count<0){if(op->opcode!=OCallN&&op->opcode!=OCallMethod&&op->opcode!=OCallThis&&op->opcode!=OCallClosure&&op->opcode!=OMakeEnum)FAIL("Unsupported patch opcode");op->operand_count=3;}op->operands=(int*)calloc(op->operand_count,sizeof(int));for(int k=0;k<op->operand_count;k++)if(!read_index(&s,op->operands+k))goto section_fail;if(opcode_operands(op->opcode)<0){int count=op->operands[2];if(count<0||count>0x1000000)FAIL("Invalid variable operand count");op->operand_count=3+count;op->operands=(int*)realloc(op->operands,sizeof(int)*op->operand_count);if(!op->operands)FAIL("Out of memory reading patch operands");for(int k=3;k<op->operand_count;k++)if(!read_index(&s,op->operands+k))goto section_fail;}}if(!read_count(&s,&f->relocation_count))goto section_fail;f->relocation_instructions=(int*)calloc(f->relocation_count,sizeof(int));f->relocation_stable_ids=(int*)calloc(f->relocation_count,sizeof(int));for(j=0;j<f->relocation_count;j++)if(!read_count(&s,f->relocation_instructions+j)||!read_count(&s,f->relocation_stable_ids+j))goto section_fail;if(s.p!=end)FAIL("Invalid patch function length");}
		} else if( tag == 3 ) {
			if( have_debug || !have_functions ) FAIL("Duplicate or misplaced HLP debug section");
			have_debug=true;if(!read_count(&s,&patch->debug_file_count))goto section_fail;
			patch->debug_files=(char**)calloc(patch->debug_file_count,sizeof(char*));patch->debug_file_lens=(int*)calloc(patch->debug_file_count,sizeof(int));if(patch->debug_file_count&&(!patch->debug_files||!patch->debug_file_lens))FAIL("Out of memory reading patch debug files");
			for(i=0;i<patch->debug_file_count;i++){if(!read_count(&s,&count)||!take(&s,count,&p))goto section_fail;patch->debug_file_lens[i]=count;patch->debug_files[i]=(char*)malloc(count+1);if(!patch->debug_files[i])FAIL("Out of memory reading patch debug files");memcpy(patch->debug_files[i],p,count);patch->debug_files[i][count]=0;}
			if(!read_count(&s,&count)||count!=patch->function_count)FAIL("HLP debug function count mismatch");
			for(i=0;i<count;i++){
				int stable_id,nops,found=-1;
				if(!read_count(&s,&stable_id)||!read_count(&s,&nops))goto section_fail;
				for(j=0;j<patch->function_count;j++)if(patch->functions[j].stable_id==stable_id){if(found>=0)FAIL("Duplicate HLP function debug metadata");found=j;}
				if(found<0)FAIL("Unknown HLP debug function");
				hl_patch_function *f=patch->functions+found;
				if(f->debug_count)FAIL("Duplicate HLP function debug metadata");
				if(nops!=f->instruction_count)FAIL("HLP debug opcode count mismatch");
				f->debug_count=nops;f->debug_spans=(hl_source_span*)calloc(nops,sizeof(hl_source_span));
				if(nops&&!f->debug_spans)FAIL("Out of memory reading patch debug metadata");
				for(j=0;j<nops;j++){
					hl_source_span *span=f->debug_spans+j;
					if(!read_count(&s,&span->file)||!read_count(&s,&span->line)||!read_count(&s,&span->column)||!read_count(&s,&span->end_line)
						||!read_count(&s,&span->end_column)||!read_i32(&s,&span->source_hash)||!read_index(&s,&span->start)||!read_index(&s,&span->end)||!read_count(&s,&span->flags))goto section_fail;
					span->start--;span->end--;
					if(span->file>=patch->debug_file_count||span->line<1||span->column<1||span->end_line<span->line||span->end_column<1
						||(span->end_line==span->line&&span->end_column<span->column)
						||!((span->start==-1&&span->end==-1)||(span->start>=0&&span->end>=span->start)))FAIL("Invalid HLP debug location");
				}
			}
		} else if( tag == 4 ) {
			if( have_snapshots ) FAIL("Duplicate HLP source snapshot section");
			have_snapshots=true;
			if(!read_count(&s,&patch->source_snapshot_count))goto section_fail;
			patch->source_snapshots=(hl_source_snapshot*)calloc(patch->source_snapshot_count,sizeof(hl_source_snapshot));
			if(patch->source_snapshot_count&&!patch->source_snapshots)FAIL("Out of memory reading source snapshots");
			for(i=0;i<patch->source_snapshot_count;i++) {
				hl_source_snapshot *snapshot=patch->source_snapshots+i;const unsigned char *content;unsigned int hash=2166136261u;
				if(!read_i32(&s,&snapshot->source_hash)||snapshot->source_hash==0||!read_count(&s,&snapshot->length)||!take(&s,snapshot->length,&content))goto section_fail;
				for(j=0;j<i;j++)if(patch->source_snapshots[j].source_hash==snapshot->source_hash)FAIL("Duplicate HLP source snapshot");
				for(j=0;j<snapshot->length;j++){hash^=content[j];hash*=16777619u;}
				if((int)hash!=snapshot->source_hash)FAIL("Invalid HLP source snapshot hash");
				snapshot->content=(unsigned char*)malloc(snapshot->length);if(snapshot->length&&!snapshot->content)FAIL("Out of memory reading source snapshot");
				memcpy(snapshot->content,content,snapshot->length);
			}
		} else if( tag == 5 ) {
			if( have_added ) FAIL("Duplicate HLP added functions section");
			have_added=true;
			if(!read_count(&s,&patch->added_function_count))goto section_fail;
			patch->added_functions=(hl_patch_added_function*)calloc(patch->added_function_count,sizeof(hl_patch_added_function));
			if(patch->added_function_count&&!patch->added_functions)FAIL("Out of memory reading added functions");
			for(i=0;i<patch->added_function_count;i++) {
				hl_patch_added_function *added=patch->added_functions+i;
				if(!read_count(&s,&added->stable_id)||!read_count(&s,&added->findex)||!read_index(&s,&added->type)||!read_count(&s,&count)||!take(&s,count,&p))goto section_fail;
				added->name=(char*)malloc(count+1);if(!added->name)FAIL("Out of memory reading added functions");
				memcpy(added->name,p,count);added->name[count]=0;
				for(j=0;j<i;j++)if(patch->added_functions[j].stable_id==added->stable_id||patch->added_functions[j].findex==added->findex)FAIL("Duplicate HLP added function");
			}
		} else {
			s.p = s.end;
		}
		if( s.p != s.end ) FAIL("Invalid HLP section length");
		continue;
section_fail:
		r.error=s.error?s.error:"Truncated HLP data";goto fail;
	}
	if( !have_symbols || !have_functions ) FAIL("Missing required HLP section");
	if(r.p!=r.end)FAIL("Trailing HLP data");
	if( error_msg ) *error_msg=NULL;
	return patch;
fail:
	if( error_msg ) *error_msg=r.error?r.error:"Truncated HLP data";
	hl_patch_free(patch);
	return NULL;
#undef FAIL
}

static bool valid_reg( hl_patch_function *f, int reg ) { return reg >= 0 && reg < f->register_count; }

static bool valid_call_target( hl_module *m, patch_layout *layout, int index ) {
	return index >= 0 && index < layout->slots && m->functions_ptrs[index] != NULL;
}

static bool valid_function_target( hl_module *m, patch_layout *layout, int index ) {
	return valid_call_target(m,layout,index) && layout_function(layout,index) != NULL;
}

/* A static closure may also wrap a native, which the layout places after the functions. */
static bool valid_closure_target( hl_module *m, patch_layout *layout, int index ) {
	int native;
	if( !valid_call_target(m,layout,index) ) return false;
	native = layout->indexes[index] - layout->count;
	return layout_function(layout,index) != NULL || (native >= 0 && native < m->code->nnatives);
}

// The JIT keeps at most this many try regions open (jit_emit.c MAX_TRAPS).
#define PATCH_MAX_TRAPS 32

// Trap depth is a property of each control-flow path, not of instruction order: every exit from a try body
// (fallthrough, return, break, continue) carries its own end-trap, and handlers may be laid out anywhere.
// Walk the branches, require each instruction to be reached at one depth, and require returns outside traps.
// The JIT, though, tracks traps in instruction order: an OTrap opens a region that closes at its handler, an
// OEndTrap outside every region aborts the process, and stores write through for the catch only inside a region.
// So each reachable instruction must also lie inside at least as many regions as traps are active on its paths.
static bool validate_traps( hl_patch_function *f, const char **error ) {
	int n=f->instruction_count, top=0, open=0, targets[PATCH_MAX_TRAPS];
	int *depth=(int*)malloc(sizeof(int)*(n>0?n:1)), *pending=(int*)malloc(sizeof(int)*(n>0?n:1)), *regions=(int*)malloc(sizeof(int)*(n>0?n:1));
	bool ok=true;
	if(!depth||!pending||!regions){free(depth);free(pending);free(regions);*error="Out of memory validating patch traps";return false;}
	// The JIT closes one region per instruction, the innermost, when it reaches that region's handler.
	for(int i=0;ok&&i<n;i++){
		if(open>0&&targets[open-1]==i)open--;
		regions[i]=open;
		if(f->instructions[i].opcode==OTrap){
			if(open==PATCH_MAX_TRAPS){*error="Too many nested patch traps";ok=false;break;}
			targets[open++]=i+1+f->instructions[i].operands[1];
		}
	}
	for(int i=0;i<n;i++)depth[i]=-1;
	if(n>0){depth[0]=0;pending[top++]=0;}
	while(ok&&top>0){
		int i=pending[--top],d=depth[i],next[2],next_depth[2],count=0;
		hl_patch_instruction *op=f->instructions+i;int *p=op->operands;
		if(regions[i]<d){*error="Patch trap outside its try region";ok=false;break;}
		switch(op->opcode){
		case OJTrue:case OJFalse:case OJNull:case OJNotNull:
			next[count]=i+1+p[1];next_depth[count++]=d;next[count]=i+1;next_depth[count++]=d;break;
		case OJSLt:case OJSGte:case OJSGt:case OJSLte:case OJULt:case OJUGte:case OJNotLt:case OJNotGte:case OJEq:case OJNotEq:
			next[count]=i+1+p[2];next_depth[count++]=d;next[count]=i+1;next_depth[count++]=d;break;
		case OJAlways:next[count]=i+1+p[0];next_depth[count++]=d;break;
		case ORet:if(d!=0){*error="Unbalanced patch traps";ok=false;}break;
		case OThrow:case ORethrow:break;
		case OTrap:
			if(d==PATCH_MAX_TRAPS){*error="Too many nested patch traps";ok=false;break;}
			next[count]=i+1+p[1];next_depth[count++]=d;next[count]=i+1;next_depth[count++]=d+1;break;
		case OEndTrap:
			if(d==0){*error="Invalid end-trap operands";ok=false;break;}
			next[count]=i+1;next_depth[count++]=d-1;break;
		default:next[count]=i+1;next_depth[count++]=d;break;
		}
		for(int k=0;ok&&k<count;k++){
			if(next[k]>=n)continue;
			if(depth[next[k]]<0){depth[next[k]]=next_depth[k];pending[top++]=next[k];}
			else if(depth[next[k]]!=next_depth[k]){*error="Inconsistent patch trap depth";ok=false;}
		}
	}
	free(depth);free(pending);free(regions);
	return ok;
}

static bool validate_function( hl_module *m, hl_patch *patch, patch_layout *layout, hl_patch_function *f, const char **error ) {
	hl_function *live=layout_function(layout,f->findex);
	int type_count=patch->base_type_count+patch->type_count;
	if(!live){*error="Unknown stable function slot";return false;}
	if(f->type<0||f->type>=type_count||live->type!=m->code->types+f->type){*error="Patch function signature changed";return false;}
	for(int i=0;i<f->register_count;i++)if(f->registers[i]<0||f->registers[i]>=type_count){*error="Invalid patch register type";return false;}
	for(int i=0;i<f->instruction_count;i++){
		hl_patch_instruction *op=f->instructions+i;int *p=op->operands;
		switch(op->opcode){
		case OLabel:break;
		case OMov:if(!valid_reg(f,p[0])||!valid_reg(f,p[1])){*error="Invalid move operands";return false;}break;
		case OInt:if(!valid_reg(f,p[0])||p[1]<0||p[1]>=patch->base_int_count+patch->int_count){*error="Invalid Int operands";return false;}break;
		case OFloat:if(!valid_reg(f,p[0])||p[1]<0||p[1]>=patch->base_float_count+patch->float_count){*error="Invalid Float operands";return false;}break;
		case OString:if(!valid_reg(f,p[0])||p[1]<0||p[1]>=patch->base_string_count+patch->string_count){*error="Invalid String operands";return false;}break;
		case OBool:if(!valid_reg(f,p[0])||(p[1]!=0&&p[1]!=1)){*error="Invalid Bool operands";return false;}break;
		case OAdd:case OSub:case OMul:case OSDiv:case OSMod:case OShl:case OSShr:case OUShr:case OAnd:case OOr:case OXor:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||!valid_reg(f,p[2])){*error="Invalid arithmetic operands";return false;}break;
		case OCall0:case OCall1:case OCall2:case OCall3:case OCall4:
			if(!valid_reg(f,p[0])||!valid_call_target(m,layout,p[1])){*error="Invalid call target";return false;}
			for(int k=2;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OCallN:
			if(!valid_reg(f,p[0])||!valid_call_target(m,layout,p[1])||p[2]<0||p[2]!=op->operand_count-3){*error="Invalid variadic call";return false;}
			for(int k=3;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OCallMethod:case OCallThis:
			if(!valid_reg(f,p[0])||p[1]<0||p[2]<0||p[2]!=op->operand_count-3){*error="Invalid method call";return false;}
			for(int k=3;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OCallClosure:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||p[2]<0||p[2]!=op->operand_count-3){*error="Invalid closure call";return false;}
			for(int k=3;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OStaticClosure:
			if(!valid_reg(f,p[0])||!valid_closure_target(m,layout,p[1])){*error="Invalid static closure";return false;}
			break;
		case OInstanceClosure:
			if(!valid_reg(f,p[0])||!valid_function_target(m,layout,p[1])||!valid_reg(f,p[2])){*error="Invalid instance closure";return false;}
			break;
		case OField:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||p[2]<0){*error="Invalid field read";return false;}
			break;
		case OSetField:
			if(!valid_reg(f,p[0])||p[1]<0||!valid_reg(f,p[2])){*error="Invalid field write";return false;}
			break;
		case OGetArray:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||!valid_reg(f,p[2])){*error="Invalid array read";return false;}
			break;
		case OSetArray:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||!valid_reg(f,p[2])){*error="Invalid array write";return false;}
			break;
		case OArraySize:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])){*error="Invalid array size";return false;}
			break;
		case ONew:
			if(!valid_reg(f,p[0])){*error="Invalid object allocation";return false;}
			break;
		case OMakeEnum:
			if(!valid_reg(f,p[0])||p[1]<0||p[2]<0||p[2]!=op->operand_count-3){*error="Invalid enum construction";return false;}
			for(int k=3;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid enum argument";return false;}
			break;
		case OEnumAlloc:case OEnumIndex:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])){*error="Invalid enum operation";return false;}
			break;
		case OEnumField:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||p[2]<0||p[3]<0){*error="Invalid enum field";return false;}
			break;
		case OType:
			if(!valid_reg(f,p[0])||p[1]<0||p[1]>=type_count){*error="Invalid type literal";return false;}
			break;
		case OGetGlobal:
			if(!valid_reg(f,p[0])||p[1]<0||p[1]>=m->code->nglobals){*error="Invalid global read";return false;}
			break;
		case OSetGlobal:
			if(p[0]<0||p[0]>=m->code->nglobals||!valid_reg(f,p[1])){*error="Invalid global write";return false;}
			break;
		case ONull:case OGetThis:case OSetThis:case OToDyn:case OToSFloat:case OToUFloat:case OToInt:case OSafeCast:case OUnsafeCast:case OToVirtual:
			if(!valid_reg(f,p[0])||(op->operand_count>1&&!valid_reg(f,p[1]))){*error="Invalid unary operation";return false;}
			break;
		case OJTrue:case OJFalse:case OJNull:case OJNotNull:
			if(!valid_reg(f,p[0])||i+1+p[1]<0||i+1+p[1]>=f->instruction_count){*error="Invalid conditional branch";return false;}break;
		case OJSLt:case OJSGte:case OJSGt:case OJSLte:case OJULt:case OJUGte:case OJNotLt:case OJNotGte:case OJEq:case OJNotEq:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||i+1+p[2]<0||i+1+p[2]>=f->instruction_count){*error="Invalid comparison branch";return false;}break;
		case OJAlways:if(i+1+p[0]<0||i+1+p[0]>=f->instruction_count){*error="Invalid branch";return false;}break;
		case ORet:if(!valid_reg(f,p[0])){*error="Invalid return register";return false;}break;
		case OThrow:case ORethrow:if(!valid_reg(f,p[0])){*error="Invalid throw register";return false;}break;
		case ONullCheck:if(!valid_reg(f,p[0])){*error="Invalid null check register";return false;}break;
		// Operations on registers alone: the JIT compiles them in a patch as it does at load.
		case OIncr:case ODecr:
			if(!valid_reg(f,p[0])){*error="Invalid register operand";return false;}break;
		case ONeg:case ONot:case OGetType:case OGetTID:case ORef:case OUnref:case OSetref:case ORefData:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])){*error="Invalid register operands";return false;}break;
		case OUDiv:case OUMod:case OGetI8:case OGetI16:case OGetMem:case OSetI8:case OSetI16:case OSetMem:case ORefOffset:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||!valid_reg(f,p[2])){*error="Invalid register operands";return false;}break;
		case OTrap:
			if(!valid_reg(f,p[0])||p[1]<0||i+1+p[1]>=f->instruction_count){*error="Invalid trap operands";return false;}
			break;
		case OEndTrap:
			if(!valid_reg(f,p[0])){*error="Invalid end-trap operands";return false;}
			break;
		default:*error="Unsupported patch opcode";return false;
		}
	}
	return validate_traps(f,error);
}

static bool validate_patch_types( hl_module *m, hl_patch *patch, int string_count, const char **error ) {
	int total=patch->base_type_count+patch->type_count;
	if(total>m->code->types_capacity){*error="Type arena capacity exceeded";return false;}
	for(int i=0;i<patch->type_count;i++){
		hl_patch_type *type=patch->types+i;
		if(type->tag==HFUN){
			for(int j=0;j<type->data.fun.count;j++)if(type->data.fun.arguments[j]<0||type->data.fun.arguments[j]>=total){*error="Invalid appended function argument type";return false;}
			if(type->data.fun.result<0||type->data.fun.result>=total){*error="Invalid appended function result type";return false;}
		}else if(type->tag==HABSTRACT){
			if(type->data.name<0||type->data.name>=string_count){*error="Invalid appended abstract name";return false;}
		}else if(type->tag==HREF||type->tag==HNULL){
			if(type->data.parameter<0||type->data.parameter>=total){*error="Invalid appended parameterized type reference";return false;}
		}else if(type->tag<HVOID||type->tag>HGUID||type->tag==HOBJ||type->tag==HVIRTUAL||type->tag==HENUM||type->tag==HPACKED||type->tag==HSTRUCT||type->tag==HMETHOD){
			/* HLP carries no layout or signature for these, so staging would leave them half built: a struct without object
			   data, which the next patch's type hash dereferences, or a method without a signature. */
			*error="Unsupported HLP type";return false;
		}
	}
	return true;
}

/* Checks the functions a patch adds, and builds the layout its code is checked and compiled against. */
static bool stage_patch_layout( hl_module *m, hl_patch *patch, patch_layout *layout, const char **error ) {
	int loaded=m->code->nfunctions+m->code->npatchfunctions,added=patch->added_function_count,base_types=patch->base_type_count;
	if(added&&m->patch_targets==NULL){*error="Module cannot take added functions";return false;}
	if(added>m->code->functions_capacity-loaded){*error="Added function capacity exceeded";return false;}
	for(int i=0;i<added;i++){
		hl_patch_added_function *a=patch->added_functions+i;int kind,bodies=0;
		if(a->findex!=module_slot_count(m)+i){*error="Added function is not in the next free slot";return false;}
		if(a->type<0||a->type>=base_types+patch->type_count){*error="Invalid added function type";return false;}
		kind=a->type<base_types?m->code->types[a->type].kind:patch->types[a->type-base_types].tag;
		if(kind!=HFUN&&kind!=HMETHOD){*error="Invalid added function type";return false;}
		for(int j=0;j<patch->function_count;j++)if(patch->functions[j].findex==a->findex)bodies++;
		if(bodies!=1){*error="Added function has no body";return false;}
	}
	layout->count=loaded+added;layout->slots=module_slot_count(m)+added;
	layout->functions=(hl_function*)calloc(layout->count>0?layout->count:1,sizeof(hl_function));
	layout->indexes=(int*)malloc(sizeof(int)*layout->slots);
	if(!layout->functions||!layout->indexes){free(layout->functions);free(layout->indexes);layout->functions=NULL;layout->indexes=NULL;*error="Out of memory applying patch";return false;}
	memcpy(layout->functions,m->code->functions,sizeof(hl_function)*loaded);
	memcpy(layout->indexes,m->functions_indexes,sizeof(int)*module_slot_count(m));
	for(int i=0;i<added;i++){
		hl_function *f=layout->functions+loaded+i;
		f->type=m->code->types+patch->added_functions[i].type;f->findex=patch->added_functions[i].findex;
		layout->indexes[f->findex]=loaded+i;
	}
	for(int i=0;i<m->code->nnatives;i++)layout->indexes[m->code->natives[i].findex]=layout->count+i;
	return true;
}

/* Records the functions a committed patch added, so later patches and lookups see them as the module's own. */
static void publish_added_functions( hl_module *m, hl_patch *patch ) {
	for(int i=0;i<patch->added_function_count;i++){
		hl_patch_added_function *a=patch->added_functions+i;
		int at=m->code->nfunctions+m->code->npatchfunctions,length=(int)strlen(a->name);
		hl_function *f=m->code->functions+at;
		memset(f,0,sizeof(*f));f->type=m->code->types+a->type;f->findex=a->findex;
		m->code->function_stable_ids[at]=a->stable_id;
		m->code->function_names[at]=(char*)hl_malloc(&m->code->alloc,length+1);
		memcpy(m->code->function_names[at],a->name,length+1);
		m->code->function_names_lens[at]=length;
		m->functions_indexes[a->findex]=at;
		m->ctx.functions_types[a->findex]=f->type;
		m->code->npatchfunctions++;
	}
}

/* Undoes what staging wrote into the module's unused entries for added functions. */
static void unstage_added_functions( hl_module *m, hl_patch *patch ) {
	int loaded=m->code->nfunctions+m->code->npatchfunctions;
	for(int i=0;i<patch->added_function_count;i++){
		m->code->function_names[loaded+i]=NULL;m->code->function_names_lens[loaded+i]=0;
		m->ctx.functions_types[patch->added_functions[i].findex]=NULL;
	}
}

static bool inject_patch_failure( hl_module *m, int stage, const char **error ) {
	if(m->patch_failure_stage!=stage)return false;
	m->patch_failure_stage=0;*error="Injected patch staging failure";return true;
}

static bool stage_patch_types( hl_module *m, hl_patch *patch, uchar **strings, void ***allocations, int *allocation_count, const char **error ) {
	*allocations=(void**)calloc(patch->type_count,sizeof(void*));
	if(patch->type_count&&!*allocations){*error="Out of memory staging patch types";return false;}
	for(int i=0;i<patch->type_count;i++){
		hl_patch_type *src=patch->types+i;hl_type *dst=m->code->types+patch->base_type_count+i;
		memset(dst,0,sizeof(*dst));dst->kind=(hl_type_kind)src->tag;
		if(src->tag==HFUN){
			size_t size=sizeof(hl_type_fun)+sizeof(hl_type*)*src->data.fun.count;hl_type_fun *fun=(hl_type_fun*)calloc(1,size);
			if(!fun){*error="Out of memory staging function type";return false;}
			(*allocations)[(*allocation_count)++]=fun;fun->nargs=src->data.fun.count;fun->args=(hl_type**)(fun+1);fun->ret=m->code->types+src->data.fun.result;
			for(int j=0;j<src->data.fun.count;j++)fun->args[j]=m->code->types+src->data.fun.arguments[j];
			dst->fun=fun;
		}else if(src->tag==HABSTRACT){
			dst->abs_name=strings[src->data.name];
		}else if(src->tag==HREF||src->tag==HNULL){
			dst->tparam=m->code->types+src->data.parameter;
		}
	}
	return true;
}

h_bool hl_module_apply_patch( hl_module *m, hl_patch *patch, const char **error_msg ) {
	const char *error=NULL;hl_patch_code *allocation=NULL;jit_ctx *jit=NULL;int *offsets=NULL,*combined_ints=NULL,*combined_string_lens=NULL;double *combined_floats=NULL;char **combined_strings=NULL,*combined_string_data=NULL;uchar **combined_ustrings=NULL;hl_function *combined_functions=NULL;void **type_allocations=NULL;int type_allocation_count=0;hl_code code;hl_module temp;patch_layout layout={0};bool staged_added=false;hl_patch_live *live_block=NULL;hl_patch_code *superseded=NULL;
	if(!m||!patch||!m->patchable){error="Module is not patchable";goto fail;}
	if(patch->function_count<=0){error="Patch contains no functions";goto fail;}
	if(m->revision!=patch->base_revision||patch->revision<=patch->base_revision){error="Stale patch revision";goto fail;}
	if(patch->base_int_count!=m->code->nints||patch->base_float_count!=m->code->nfloats||patch->base_string_count!=m->code->nstrings||patch->base_type_count!=m->code->ntypes){error="Patch symbol base does not match module";goto fail;}
	if(patch->int_prefix_hash!=hash_int_prefix(m->code,patch->base_int_count)||patch->float_prefix_hash!=hash_float_prefix(m->code,patch->base_float_count)||patch->string_prefix_hash!=hash_string_prefix(m->code,patch->base_string_count)||patch->type_prefix_hash!=hash_type_prefix(m,patch->base_type_count)){error="Patch symbol prefix hash does not match module";goto fail;}
	if(!validate_patch_types(m,patch,patch->base_string_count+patch->string_count,&error))goto fail;
	if(!stage_patch_layout(m,patch,&layout,&error))goto fail;
	combined_functions=layout.functions; // owned through combined_functions from here
	for(int i=0;i<patch->function_count;i++){for(int j=0;j<i;j++)if(patch->functions[j].findex==patch->functions[i].findex){error="Duplicate stable function slot";goto fail;}if(!validate_function(m,patch,&layout,patch->functions+i,&error))goto fail;}
	combined_ints=(int*)malloc(sizeof(int)*(patch->base_int_count+patch->int_count));if(!combined_ints){error="Out of memory applying patch";goto fail;}memcpy(combined_ints,m->code->ints,sizeof(int)*patch->base_int_count);memcpy(combined_ints+patch->base_int_count,patch->ints,sizeof(int)*patch->int_count);
	combined_floats=(double*)malloc(sizeof(double)*(patch->base_float_count+patch->float_count));if(!combined_floats){error="Out of memory applying patch";goto fail;}memcpy(combined_floats,m->code->floats,sizeof(double)*patch->base_float_count);memcpy(combined_floats+patch->base_float_count,patch->floats,sizeof(double)*patch->float_count);
	{int total=patch->base_string_count+patch->string_count,bytes=0,pos=0;for(int i=0;i<patch->base_string_count;i++)bytes+=m->code->strings_lens[i]+1;for(int i=0;i<patch->string_count;i++)bytes+=patch->string_lens[i]+1;combined_strings=(char**)malloc(sizeof(char*)*total);combined_string_lens=(int*)malloc(sizeof(int)*total);combined_ustrings=(uchar**)calloc(total,sizeof(uchar*));combined_string_data=(char*)malloc(bytes);if((total>0)&&(!combined_strings||!combined_string_lens||!combined_ustrings||!combined_string_data)){error="Out of memory applying patch";goto fail;}for(int i=0;i<total;i++){const char *src;int length;if(i<patch->base_string_count){src=m->code->strings[i];length=m->code->strings_lens[i];combined_ustrings[i]=(uchar*)hl_get_ustring(m->code,i);}else{src=patch->strings[i-patch->base_string_count];length=patch->string_lens[i-patch->base_string_count];int usize=hl_utf8_length((vbyte*)src,0);combined_ustrings[i]=(uchar*)malloc((usize+1)*sizeof(uchar));if(!combined_ustrings[i]){error="Out of memory applying patch";goto fail;}hl_from_utf8(combined_ustrings[i],usize,src);}combined_strings[i]=combined_string_data+pos;combined_string_lens[i]=length;memcpy(combined_string_data+pos,src,length);combined_string_data[pos+length]=0;pos+=length+1;}}
	if(inject_patch_failure(m,1,&error))goto fail;
	if(!stage_patch_types(m,patch,combined_ustrings,&type_allocations,&type_allocation_count,&error))goto fail;
	if(inject_patch_failure(m,2,&error))goto fail;
	allocation=(hl_patch_code*)calloc(1,sizeof(hl_patch_code));if(!allocation){error="Out of memory applying patch";goto fail;}
	allocation->revision=patch->revision;
	allocation->source_snapshot_count=patch->source_snapshot_count;
	allocation->source_snapshots=(hl_source_snapshot*)calloc(patch->source_snapshot_count,sizeof(hl_source_snapshot));
	if(patch->source_snapshot_count&&!allocation->source_snapshots){error="Out of memory applying source snapshots";goto fail;}
	for(int i=0;i<patch->source_snapshot_count;i++){allocation->source_snapshots[i]=patch->source_snapshots[i];allocation->source_snapshots[i].content=(unsigned char*)malloc(patch->source_snapshots[i].length);if(patch->source_snapshots[i].length&&!allocation->source_snapshots[i].content){error="Out of memory applying source snapshot";goto fail;}memcpy(allocation->source_snapshots[i].content,patch->source_snapshots[i].content,patch->source_snapshots[i].length);}
	allocation->function_count=patch->function_count;allocation->functions=(hl_function*)calloc(patch->function_count,sizeof(hl_function));allocation->debug_spans=(hl_source_span**)calloc(patch->function_count,sizeof(hl_source_span*));
	offsets=(int*)calloc(patch->function_count,sizeof(int));if(!allocation->functions||!allocation->debug_spans||!offsets){error="Out of memory applying patch";goto fail;}
	for(int i=0;i<patch->function_count;i++){hl_patch_function *src=patch->functions+i;hl_function *dst=allocation->functions+i;hl_function *live;dst->type=m->code->types+src->type;dst->findex=src->findex;live=combined_functions+layout.indexes[dst->findex];if(live){dst->obj=live->obj;dst->field=live->field;dst->ref=live->ref;}dst->nregs=src->register_count;dst->nops=src->instruction_count;dst->regs=(hl_type**)calloc(dst->nregs,sizeof(hl_type*));dst->ops=(hl_opcode*)calloc(dst->nops,sizeof(hl_opcode));if(!dst->regs||!dst->ops){error="Out of memory applying patch";goto fail;}for(int j=0;j<dst->nregs;j++)dst->regs[j]=m->code->types+src->registers[j];for(int j=0;j<dst->nops;j++){hl_patch_instruction *s=src->instructions+j;hl_opcode *d=dst->ops+j;d->op=(hl_op)s->opcode;if(s->operand_count>0)d->p1=s->operands[0];if(s->operand_count>1)d->p2=s->operands[1];if(s->operand_count>2)d->p3=s->operands[2];if(s->operand_count==4&&d->op!=OCallN&&d->op!=OCallMethod&&d->op!=OCallThis&&d->op!=OCallClosure&&d->op!=OMakeEnum)d->extra=(int*)(int_val)s->operands[3];if(s->operand_count>3&&(d->op==OCall3||d->op==OCall4||d->op==OCallN||d->op==OCallMethod||d->op==OCallThis||d->op==OCallClosure||d->op==OMakeEnum)){int count=d->op==OCall3?2:d->op==OCall4?3:s->operand_count-3;d->extra=(int*)malloc(sizeof(int)*count);if(!d->extra){error="Out of memory applying patch";goto fail;}memcpy(d->extra,s->operands+3,sizeof(int)*count);}}}
	for(int i=0;i<patch->function_count;i++){hl_patch_function *src=patch->functions+i;hl_function *dst=allocation->functions+i;if(src->debug_count){dst->debug=(int*)calloc(src->debug_count*2,sizeof(int));allocation->debug_spans[i]=(hl_source_span*)calloc(src->debug_count,sizeof(hl_source_span));if(!dst->debug||!allocation->debug_spans[i]){error="Out of memory applying patch debug metadata";goto fail;}for(int j=0;j<src->debug_count;j++){hl_source_span span=src->debug_spans[j];int file=find_debug_file(m->code,patch->debug_files[span.file],patch->debug_file_lens[span.file]);if(file<0){error="Patch debug file is not present in module";goto fail;}span.file=file;dst->debug[j*2]=file;dst->debug[j*2+1]=span.line;allocation->debug_spans[i][j]=span;}}}
	for(int i=0;i<patch->function_count;i++) {
		int function_index=layout.indexes[allocation->functions[i].findex];
		if(function_index<0||function_index>=layout.count){error="Invalid patch function slot";goto fail;}
		combined_functions[function_index]=allocation->functions[i];
	}
	// The JIT reads the added functions' names and types by slot; those entries are unused until the patch commits.
	staged_added=true;
	for(int i=0;i<patch->added_function_count;i++){
		int at=m->code->nfunctions+m->code->npatchfunctions+i;
		m->code->function_names[at]=patch->added_functions[i].name;m->code->function_names_lens[at]=(int)strlen(patch->added_functions[i].name);
		m->ctx.functions_types[patch->added_functions[i].findex]=combined_functions[at].type;
	}
	memset(&code,0,sizeof(code));code.nints=patch->base_int_count+patch->int_count;code.ints=combined_ints;code.nfloats=patch->base_float_count+patch->float_count;code.floats=combined_floats;code.nstrings=patch->base_string_count+patch->string_count;code.strings=combined_strings;code.strings_lens=combined_string_lens;code.ustrings=combined_ustrings;code.ntypes=patch->base_type_count+patch->type_count;code.types_capacity=m->code->types_capacity;code.types=m->code->types;code.nfunctions=layout.count;code.functions_capacity=m->code->functions_capacity;code.nnatives=m->code->nnatives;code.natives=m->code->natives;code.functions=combined_functions;code.function_names=m->code->function_names;code.function_names_lens=m->code->function_names_lens;code.hasdebug=m->code->hasdebug;code.ndebugfiles=m->code->ndebugfiles;code.debugfiles=m->code->debugfiles;code.debugfiles_lens=m->code->debugfiles_lens;code.alloc=m->code->alloc;
	temp=*m;temp.code=&code;temp.functions_indexes=layout.indexes;temp.jit_code=NULL;temp.jit_debug=NULL;temp.jit_ctx=NULL;temp.staging_patch=true;
#ifdef WIN64_UNWIND_TABLES
	// The JIT records each function it emits in the module's unwind table; the live module's table is registered for its own code.
	temp.unwind_table_size=patch->function_count+10;temp.unwind_table=allocation->unwind_table=(PRUNTIME_FUNCTION)calloc(temp.unwind_table_size,sizeof(RUNTIME_FUNCTION));if(!temp.unwind_table){error="Out of memory applying patch unwind table";goto fail;}
#endif
	jit=hl_jit_alloc();if(!jit){error="Could not allocate patch JIT";goto fail;}hl_jit_init(jit,&temp);
	for(int i=0;i<patch->function_count;i++){int function_index=layout.indexes[allocation->functions[i].findex];offsets[i]=hl_jit_function(jit,&temp,combined_functions+function_index);if(offsets[i]<0){error="Could not JIT patch function";goto fail;}}
	allocation->code=hl_jit_patch_code(jit,&temp,&allocation->code_size,&temp.jit_debug);allocation->jit_debug=temp.jit_debug;allocation->jit_debug_count=code.nfunctions;temp.jit_debug=NULL;if(!allocation->code){error="Could not finalize patch JIT";goto fail;}hl_jit_free(jit,false);jit=NULL;
#ifdef WIN64_UNWIND_TABLES
	if(!RtlAddFunctionTable(allocation->unwind_table,temp.unwind_table_size,(DWORD64)allocation->code)){error="Could not register patch unwind table";goto fail;}
	allocation->unwind_registered=true;
#endif
	live_block=patch_live_alloc(m);if(!live_block){error="Out of memory listing patch code";goto fail;}
	if(inject_patch_failure(m,3,&error))goto fail;
	temp.jit_code=allocation->code;temp.codesize=allocation->code_size;temp.jit_debug=allocation->jit_debug;temp.gdb_jit_entry=NULL;hl_gdb_jit_register_patch(&temp);allocation->gdb_jit_entry=temp.gdb_jit_entry;free(combined_functions);combined_functions=NULL;
	if(type_allocation_count){int needed=m->patch_type_allocation_count+type_allocation_count;if(needed>m->patch_type_allocation_capacity){int capacity=needed<16?16:needed*2;void **owners=(void**)realloc(m->patch_type_allocations,sizeof(void*)*capacity);if(!owners){error="Out of memory publishing patch types";goto fail;}m->patch_type_allocations=owners;m->patch_type_allocation_capacity=capacity;}}
	for(int i=0;i<type_allocation_count;i++)m->patch_type_allocations[m->patch_type_allocation_count++]=type_allocations[i];
	free(type_allocations);type_allocations=NULL;type_allocation_count=0;for(int i=m->code->ntypes;i<code.ntypes;i++)m->code->types[i].gc_owner=m;m->code->ntypes=code.ntypes;
	hl_module_crash_write_lock();
	if(m->patch_lo==NULL||allocation->code<m->patch_lo)m->patch_lo=allocation->code;
	if(m->patch_hi==NULL||(void*)((unsigned char*)allocation->code+allocation->code_size)>m->patch_hi)m->patch_hi=(unsigned char*)allocation->code+allocation->code_size;
	for(int i=0;i<patch->function_count;i++){int slot=allocation->functions[i].findex;hl_patch_code *old=m->patch_owners[slot];void *target=(unsigned char*)allocation->code+offsets[i];hl_module_redirect_slot(m,slot,target);m->patch_owners[slot]=allocation;allocation->references++;if(old&&--old->references==0){if(m->patch_targets){old->next_retired=superseded;superseded=old;}else{old->next_retired=m->retired_patch_code;patch_store(m->retired_patch_code,old);}}}
	publish_added_functions(m,patch);staged_added=false;
	patch_live_publish(m,live_block);live_block=NULL;
	// Stable dispatch no longer reaches superseded code; only a concurrent reader may still hold it.
	if(superseded&&patch_readers_get()==0)while(superseded){hl_patch_code *next=superseded->next_retired;patch_code_free(superseded);superseded=next;}
	while(superseded){hl_patch_code *next=superseded->next_retired;superseded->next_retired=m->retired_patch_code;patch_store(m->retired_patch_code,superseded);superseded=next;}
	free(layout.indexes);layout.indexes=NULL;
	if(m->patch_ustrings==NULL)m->patch_initial_string_count=patch->base_string_count;
	free(m->patch_ints);free(m->patch_floats);free(m->patch_strings);free(m->patch_string_lens);free(m->patch_ustrings);free(m->patch_string_data);
	m->patch_ints=combined_ints;m->patch_floats=combined_floats;m->patch_strings=combined_strings;m->patch_string_lens=combined_string_lens;m->patch_ustrings=combined_ustrings;m->patch_string_data=combined_string_data;
	m->code->ints=combined_ints;m->code->nints=code.nints;m->code->floats=combined_floats;m->code->nfloats=code.nfloats;m->code->strings=combined_strings;m->code->strings_lens=combined_string_lens;m->code->ustrings=combined_ustrings;m->code->nstrings=code.nstrings;
	combined_ints=NULL;combined_floats=NULL;combined_strings=NULL;combined_string_lens=NULL;combined_ustrings=NULL;combined_string_data=NULL;
	m->revision=patch->revision;m->patch_jit_count+=patch->function_count;hl_module_crash_write_unlock();free(offsets);if(error_msg)*error_msg=NULL;return true;
fail:
	if(jit) hl_jit_free(jit,false);
	if(staged_added) unstage_added_functions(m,patch);
	free(live_block);
	free(layout.indexes);
	free(combined_functions);
	free(offsets);
	free(combined_ints);
	free(combined_floats);free(combined_strings);free(combined_string_lens);if(combined_ustrings)for(int i=patch->base_string_count;i<patch->base_string_count+patch->string_count;i++)free(combined_ustrings[i]);free(combined_ustrings);free(combined_string_data);
	for(int i=0;i<type_allocation_count;i++)free(type_allocations[i]);
	free(type_allocations);if(m&&patch&&m->code&&patch->base_type_count<=m->code->types_capacity&&patch->type_count<=m->code->types_capacity-patch->base_type_count)memset(m->code->types+patch->base_type_count,0,sizeof(hl_type)*patch->type_count);
	patch_code_free(allocation);
	if(error_msg) *error_msg=error?error:"Invalid patch";
	return false;
}
