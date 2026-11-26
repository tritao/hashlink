/*
 * Copyright (C)2015-2016 Haxe Foundation
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

/*
	The HLB 9 reader: a file of per-module sections, each with module-local tables that name what they use from other
	sections by text key. Linking them builds the same dense hl_code that hl_code_read builds from HLB 8, so the JIT,
	module.c, the debugger and the profiler read either. The format and the algorithm are in docs/design/MODULE_SECTIONS.md
	of the compiler's repository.

	Three passes over the sections:
	1. Interfaces: every section's heads. Owned functions, globals and nominal types get their global slots, in section
	   order, and are entered under their keys; natives are deduplicated by (lib, name); a shared definition takes its slot
	   from the first section that defines it.
	2. Types: per section, imports resolve by key, literal tables deduplicate by content, structural types are hash-consed
	   (each refers only to entries before it, so table order is enough) and definitions are filled through the maps. A
	   shared definition other than the first must equal it after mapping. Then every import's expected type is compared
	   with the definition's, a pointer compare once the types are unified.
	3. Code: per section, literal constants deduplicate by content and functions are read with every table operand mapped.
*/
#include "hlmodule.h"
#include "../include/lz4/lz4.h"
#include <stdarg.h>

#define OP(_,_a,_b,_c) (_b == AR ? _c : (_c == X ? (_b == X ? (_a == X ? 0 : 1) : 2) : 3)),
#define OP_BEGIN static int link_op_nargs[] = {
#define OP_END };
#include "opcodes.h"

#define LINK_VERSION 9
#define LINK_FILE_DEBUG 1
#define LINK_SECTION_CODE 1
#define LINK_SECTION_CODE_VERSION 1
#define LINK_SECTION_LZ4 1

typedef enum { ROLE_STRUCTURAL = 0, ROLE_OWNED = 1, ROLE_SHARED = 2 } link_role;
/* What a key names. Natives are keyed by (lib, name) and sections by their module path, in the same table. */
typedef enum { KEY_FUNCTION, KEY_GLOBAL, KEY_TYPE, KEY_NATIVE, KEY_SECTION } link_key_kind;

static const char *key_kind_names[] = { "function", "global", "type", "native", "section" };

typedef struct {
	const char *s;
	int len;
} link_text;

/* An import: a key, and the type the importer expects (functions, globals, natives) or the kind (types). */
typedef struct {
	link_text module;
	link_text member;
	int expected;
	int resolved;
} link_import;

typedef struct {
	link_text path;
	int offset;
	const unsigned char *data;
	int size;
	unsigned char *decoded;
	/* Where pass 2 and pass 3 go on reading. */
	int types_pos;
	int code_pos;
	int nnames, nfimports, ngimports, ntimports, nnatives, ntypes, nglobals, nfunctions;
	int nints, nfloats, nstrings, nbytes, nconstants, ndebugfiles;
	link_text *names;
	link_import *fimports, *gimports, *timports, *natives;
	unsigned char *type_roles;
	unsigned char *type_kinds;
	int *type_keys;
	int *global_keys, *global_types;
	int *function_keys, *function_types;
	int first_global, first_function;
	/* Local index to global index, per table. Function indices are imports, then natives, then owned functions; globals are
	   imports, then owned globals, then constants; types are imports, then the section's type table. */
	int *fmap, *gmap, *tmap, *imap, *flmap, *smap, *bmap, *dmap;
} link_section;

typedef struct {
	link_key_kind kind;
	link_text module;
	link_text member;
	int value;
	/* The section that entered the key: the owner, or for a shared definition the one whose definition is kept. */
	int section;
	/* A type's kind; for a native, the section whose declared type the others must match. */
	int extra;
} link_entry;

/* An open-addressed set of entry ids; the caller hashes and compares. */
typedef struct {
	int *ids;
	unsigned int *hashes;
	int mask;
	int count;
} link_table;

typedef struct link_ctx link_ctx;
typedef bool (*link_equal)( link_ctx *L, int id, const void *key );

struct link_ctx {
	hl_code *c;
	hl_alloc tmp;
	hl_alloc scratch;
	const char *error;
	link_section *sections;
	int nsections;
	int cur;
	const unsigned char *b;
	int size;
	int pos;
	link_entry *entries;
	int nentries, entries_capacity;
	link_table keys, files, strings, ints, floats, bytes, types, constants;
	/* The function type of each findex, for the import checks. */
	hl_type **ftypes;
	unsigned char *bytes_data;
	int bytes_size, bytes_capacity;
	int nowned_types;
};

HL_THREAD_STATIC_VAR char link_message[1024];

static void link_fail( link_ctx *L, const char *fmt, ... ) {
	va_list args;
	if( L->error ) return;
	va_start(args, fmt);
	vsnprintf(link_message, sizeof(link_message), fmt, args);
	va_end(args);
	L->error = link_message;
}

static void malformed( link_ctx *L, const char *what ) {
	if( L->cur < 0 )
		link_fail(L, "Malformed HLB %d file: %s", LINK_VERSION, what);
	else {
		link_text p = L->sections[L->cur].path;
		link_fail(L, "Malformed section `%.*s`: %s", p.len, p.s, what);
	}
}

/* A key as messages show it: `module.member`, or the member alone for an empty module. */
#define KEY_FMT "%.*s%s%.*s"
#define KEY_ARGS(m,n) (m).len, (m).s, (m).len ? "." : "", (n).len, (n).s
#define PATH_ARGS(section) (section)->path.len, (section)->path.s

// ---- reading

static int rd_byte( link_ctx *L ) {
	if( L->pos >= L->size ) { malformed(L, "no more data"); return 0; }
	return L->b[L->pos++];
}

static int rd_index( link_ctx *L ) {
	int b = rd_byte(L);
	if( (b & 0x80) == 0 ) return b & 0x7F;
	if( (b & 0x40) == 0 ) {
		int v = rd_byte(L) | ((b & 31) << 8);
		return (b & 0x20) == 0 ? v : -v;
	}
	{
		int c = rd_byte(L), d = rd_byte(L), e = rd_byte(L);
		int v = ((b & 31) << 24) | (c << 16) | (d << 8) | e;
		return (b & 0x20) == 0 ? v : -v;
	}
}

static int rd_uindex( link_ctx *L ) {
	int i = rd_index(L);
	if( i < 0 ) { malformed(L, "negative index"); return 0; }
	return i;
}

/* A table size: every entry takes at least a byte, which bounds what a corrupt count can make us allocate. */
static int rd_count( link_ctx *L ) {
	int n = rd_uindex(L);
	if( n > L->size ) { malformed(L, "a table count exceeds the data"); return 0; }
	return n;
}

static int rd_i32( link_ctx *L ) {
	const unsigned char *p;
	if( L->size - L->pos < 4 ) { malformed(L, "no more data"); return 0; }
	p = L->b + L->pos;
	L->pos += 4;
	return (int)((unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24));
}

static const unsigned char *rd_raw( link_ctx *L, int size ) {
	const unsigned char *p;
	if( size < 0 || L->size - L->pos < size ) { malformed(L, "no more data"); return NULL; }
	p = L->b + L->pos;
	L->pos += size;
	return p;
}

/* A length-prefixed text, as the directory and the program record hold. */
static link_text rd_text( link_ctx *L ) {
	link_text t;
	t.len = rd_uindex(L);
	t.s = (const char*)rd_raw(L, t.len);
	if( t.s == NULL ) { t.s = ""; t.len = 0; }
	return t;
}

/* A string table as HLB 8 encodes one: the byte size, the NUL-terminated strings, then each length. */
static link_text *rd_string_table( link_ctx *L, int count ) {
	int size = rd_i32(L);
	const char *base = (const char*)rd_raw(L, size);
	link_text *out = (link_text*)hl_malloc(&L->tmp, sizeof(link_text) * (count ? count : 1));
	int offset = 0;
	if( base == NULL ) return out;
	for(int i=0;i<count;i++) {
		int len = rd_uindex(L);
		if( L->error ) return out;
		if( len >= size - offset || base[offset + len] != 0 ) { malformed(L, "invalid string"); return out; }
		out[i].s = base + offset;
		out[i].len = len;
		offset += len + 1;
	}
	return out;
}

static int rd_local( link_ctx *L, int count, const char *what ) {
	int i = rd_uindex(L);
	if( i >= count ) { if( !L->error ) malformed(L, what); return 0; }
	return i;
}

// ---- tables

static unsigned int hash_mix( unsigned int h, unsigned int v ) {
	h ^= v;
	h *= 0x01000193;
	return h ^ (h >> 15);
}

/* Eight bytes a step: the text of keys and strings is most of what a link hashes. */
static unsigned int hash_text( unsigned int h, const char *s, int len ) {
	unsigned long long x = h;
	int i = 0;
	for(;i+8<=len;i+=8) {
		unsigned long long w;
		memcpy(&w, s + i, 8);
		x = (x ^ w) * 0x100000001B3ULL;
		x ^= x >> 29;
	}
	for(;i<len;i++) x = (x ^ (unsigned char)s[i]) * 0x100000001B3ULL;
	return hash_mix((unsigned int)(x ^ (x >> 32)), (unsigned int)len);
}

static void table_init( link_table *t, int expected ) {
	int capacity = 16;
	while( capacity < expected * 2 ) capacity <<= 1;
	t->ids = (int*)malloc(sizeof(int) * capacity);
	t->hashes = (unsigned int*)malloc(sizeof(unsigned int) * capacity);
	memset(t->ids, 0xFF, sizeof(int) * capacity);
	t->mask = capacity - 1;
	t->count = 0;
}

static void table_free( link_table *t ) {
	free(t->ids);
	free(t->hashes);
	t->ids = NULL;
	t->hashes = NULL;
}

static int table_find( link_ctx *L, link_table *t, unsigned int h, link_equal eq, const void *key ) {
	int slot = (int)(h & (unsigned int)t->mask);
	while( t->ids[slot] >= 0 ) {
		if( t->hashes[slot] == h && eq(L, t->ids[slot], key) ) return t->ids[slot];
		slot = (slot + 1) & t->mask;
	}
	return -1;
}

static void table_add( link_table *t, unsigned int h, int id ) {
	int slot;
	if( (t->count + 1) * 2 > t->mask + 1 ) {
		link_table bigger;
		table_init(&bigger, t->mask + 1);
		for(int i=0;i<=t->mask;i++)
			if( t->ids[i] >= 0 ) table_add(&bigger, t->hashes[i], t->ids[i]);
		table_free(t);
		*t = bigger;
	}
	slot = (int)(h & (unsigned int)t->mask);
	while( t->ids[slot] >= 0 ) slot = (slot + 1) & t->mask;
	t->ids[slot] = id;
	t->hashes[slot] = h;
	t->count++;
}

// ---- keys

typedef struct {
	link_key_kind kind;
	link_text module;
	link_text member;
} link_key;

static bool same_text( link_text a, link_text b ) {
	return a.len == b.len && memcmp(a.s, b.s, a.len) == 0;
}

static unsigned int key_hash( link_key_kind kind, link_text module, link_text member ) {
	return hash_text(hash_text(hash_mix(0x811C9DC5, (unsigned int)kind), module.s, module.len), member.s, member.len);
}

static bool key_equal( link_ctx *L, int id, const void *key ) {
	const link_key *k = (const link_key*)key;
	link_entry *e = L->entries + id;
	return e->kind == k->kind && same_text(e->module, k->module) && same_text(e->member, k->member);
}

static int key_find_hashed( link_ctx *L, unsigned int h, link_key_kind kind, link_text module, link_text member ) {
	link_key k = { kind, module, member };
	return table_find(L, &L->keys, h, key_equal, &k);
}

static int key_find( link_ctx *L, link_key_kind kind, link_text module, link_text member ) {
	return key_find_hashed(L, key_hash(kind, module, member), kind, module, member);
}

/* Enters a key; returns its entry, or -1 when it is already taken. */
static int key_add( link_ctx *L, link_key_kind kind, link_text module, link_text member, int value, int extra ) {
	link_entry *e;
	unsigned int h = key_hash(kind, module, member);
	if( key_find_hashed(L, h, kind, module, member) >= 0 ) return -1;
	if( L->nentries == L->entries_capacity ) {
		L->entries_capacity = L->entries_capacity ? L->entries_capacity * 2 : 1024;
		L->entries = (link_entry*)realloc(L->entries, sizeof(link_entry) * L->entries_capacity);
	}
	e = L->entries + L->nentries;
	e->kind = kind;
	e->module = module;
	e->member = member;
	e->value = value;
	e->section = L->cur;
	e->extra = extra;
	table_add(&L->keys, h, L->nentries);
	return L->nentries++;
}

// ---- literal tables, deduplicated by content

static bool string_equal( link_ctx *L, int id, const void *key ) {
	const link_text *t = (const link_text*)key;
	return L->c->strings_lens[id] == t->len && memcmp(L->c->strings[id], t->s, t->len) == 0;
}

static int intern_string( link_ctx *L, link_text t ) {
	hl_code *c = L->c;
	unsigned int h = hash_text(0x811C9DC5, t.s, t.len);
	int id = table_find(L, &L->strings, h, string_equal, &t);
	char *copy;
	if( id >= 0 ) return id;
	copy = (char*)hl_malloc(&c->alloc, t.len + 1);
	memcpy(copy, t.s, t.len);
	copy[t.len] = 0;
	id = c->nstrings++;
	c->strings[id] = copy;
	c->strings_lens[id] = t.len;
	table_add(&L->strings, h, id);
	return id;
}

static bool file_equal( link_ctx *L, int id, const void *key ) {
	const link_text *t = (const link_text*)key;
	return L->c->debugfiles_lens[id] == t->len && memcmp(L->c->debugfiles[id], t->s, t->len) == 0;
}

static int intern_file( link_ctx *L, link_text t ) {
	hl_code *c = L->c;
	unsigned int h = hash_text(0x811C9DC5, t.s, t.len);
	int id = table_find(L, &L->files, h, file_equal, &t);
	char *copy;
	if( id >= 0 ) return id;
	copy = (char*)hl_malloc(&c->alloc, t.len + 1);
	memcpy(copy, t.s, t.len);
	copy[t.len] = 0;
	id = c->ndebugfiles++;
	c->debugfiles[id] = copy;
	c->debugfiles_lens[id] = t.len;
	table_add(&L->files, h, id);
	return id;
}

static bool int_equal( link_ctx *L, int id, const void *key ) {
	return L->c->ints[id] == *(const int*)key;
}

static int intern_int( link_ctx *L, int v ) {
	unsigned int h = hash_mix(0x811C9DC5, (unsigned int)v);
	int id = table_find(L, &L->ints, h, int_equal, &v);
	if( id >= 0 ) return id;
	id = L->c->nints++;
	L->c->ints[id] = v;
	table_add(&L->ints, h, id);
	return id;
}

/* Floats are equal when their bits are: 0.0 and -0.0 stay apart, as do NaNs with different payloads. */
static bool float_equal( link_ctx *L, int id, const void *key ) {
	return memcmp(L->c->floats + id, key, sizeof(double)) == 0;
}

static int intern_float( link_ctx *L, const unsigned char *bits ) {
	unsigned int lo, hi, h;
	int id;
	memcpy(&lo, bits, 4);
	memcpy(&hi, bits + 4, 4);
	h = hash_mix(hash_mix(0x811C9DC5, lo), hi);
	id = table_find(L, &L->floats, h, float_equal, bits);
	if( id >= 0 ) return id;
	id = L->c->nfloats++;
	memcpy(L->c->floats + id, bits, sizeof(double));
	table_add(&L->floats, h, id);
	return id;
}

static int bytes_length( link_ctx *L, int id ) {
	return (id + 1 < L->c->nbytes ? L->c->bytes_pos[id + 1] : L->bytes_size) - L->c->bytes_pos[id];
}

static bool bytes_equal( link_ctx *L, int id, const void *key ) {
	const link_text *t = (const link_text*)key;
	return bytes_length(L, id) == t->len && memcmp(L->bytes_data + L->c->bytes_pos[id], t->s, t->len) == 0;
}

static int intern_bytes( link_ctx *L, link_text t ) {
	unsigned int h = hash_text(0x811C9DC5, t.s, t.len);
	int id = table_find(L, &L->bytes, h, bytes_equal, &t);
	if( id >= 0 ) return id;
	if( L->bytes_size + t.len > L->bytes_capacity ) {
		while( L->bytes_size + t.len > L->bytes_capacity ) L->bytes_capacity = L->bytes_capacity ? L->bytes_capacity * 2 : 4096;
		L->bytes_data = (unsigned char*)realloc(L->bytes_data, L->bytes_capacity);
	}
	memcpy(L->bytes_data + L->bytes_size, t.s, t.len);
	id = L->c->nbytes++;
	L->c->bytes_pos[id] = L->bytes_size;
	L->bytes_size += t.len;
	table_add(&L->bytes, h, id);
	return id;
}

// ---- types

static unsigned int type_ref( link_ctx *L, hl_type *t ) {
	return t == NULL ? 0xFFFFFFFFu : (unsigned int)(t - L->c->types);
}

static unsigned int hash_ptr( unsigned int h, const void *p ) {
	int_val v = (int_val)p;
	h = hash_mix(h, (unsigned int)v);
#	ifdef HL_64
	h = hash_mix(h, (unsigned int)((unsigned long long)v >> 32));
#	endif
	return h;
}

/* Field names and abstract names come from the deduplicated string table, so equal names are the same pointer. */
static unsigned int structural_hash( link_ctx *L, hl_type *t ) {
	unsigned int h = hash_mix(0x811C9DC5, (unsigned int)t->kind);
	switch( t->kind ) {
	case HFUN:
	case HMETHOD:
		h = hash_mix(h, (unsigned int)t->fun->nargs);
		for(int i=0;i<t->fun->nargs;i++) h = hash_mix(h, type_ref(L, t->fun->args[i]));
		h = hash_mix(h, type_ref(L, t->fun->ret));
		break;
	case HREF:
	case HNULL:
	case HPACKED:
		h = hash_mix(h, type_ref(L, t->tparam));
		break;
	case HABSTRACT:
		h = hash_ptr(h, t->abs_name);
		break;
	case HVIRTUAL:
		h = hash_ptr(h, t->virt->nominal_identity);
		h = hash_mix(h, (unsigned int)t->virt->nfields);
		for(int i=0;i<t->virt->nfields;i++) {
			h = hash_ptr(h, t->virt->fields[i].name);
			h = hash_mix(h, type_ref(L, t->virt->fields[i].t));
		}
		break;
	default:
		break;
	}
	return h;
}

static bool same_fields( hl_obj_field *a, hl_obj_field *b, int n ) {
	for(int i=0;i<n;i++)
		if( a[i].name != b[i].name || a[i].t != b[i].t ) return false;
	return true;
}

static bool same_structure( hl_type *a, hl_type *b ) {
	if( a->kind != b->kind ) return false;
	switch( a->kind ) {
	case HFUN:
	case HMETHOD:
		if( a->fun->nargs != b->fun->nargs || a->fun->ret != b->fun->ret ) return false;
		for(int i=0;i<a->fun->nargs;i++) if( a->fun->args[i] != b->fun->args[i] ) return false;
		return true;
	case HREF:
	case HNULL:
	case HPACKED:
		return a->tparam == b->tparam;
	case HABSTRACT:
		return a->abs_name == b->abs_name;
	case HVIRTUAL:
		return a->virt->nominal_identity == b->virt->nominal_identity && a->virt->nfields == b->virt->nfields
			&& same_fields(a->virt->fields, b->virt->fields, a->virt->nfields);
	default:
		return true;
	}
}

static bool structural_equal( link_ctx *L, int id, const void *key ) {
	return same_structure(L->c->types + id, (hl_type*)key);
}

/* A shared definition after mapping: everything but runtime state. */
static bool same_definition( hl_type *a, hl_type *b ) {
	if( a->kind != b->kind ) return false;
	switch( a->kind ) {
	case HOBJ:
	case HSTRUCT:
		{
			hl_type_obj *x = a->obj, *y = b->obj;
			if( x->name != y->name || x->super != y->super || x->global_value != y->global_value || x->nfields != y->nfields
				|| x->nproto != y->nproto || x->nbindings != y->nbindings || !same_fields(x->fields, y->fields, x->nfields) )
				return false;
			for(int i=0;i<x->nproto;i++)
				if( x->proto[i].name != y->proto[i].name || x->proto[i].findex != y->proto[i].findex || x->proto[i].pindex != y->proto[i].pindex )
					return false;
			return memcmp(x->bindings, y->bindings, sizeof(int) * 2 * x->nbindings) == 0;
		}
	case HENUM:
		{
			hl_type_enum *x = a->tenum, *y = b->tenum;
			if( x->name != y->name || x->global_value != y->global_value || x->nconstructs != y->nconstructs ) return false;
			for(int i=0;i<x->nconstructs;i++) {
				hl_enum_construct *p = x->constructs + i, *q = y->constructs + i;
				if( p->name != q->name || p->nparams != q->nparams ) return false;
				for(int k=0;k<p->nparams;k++) if( p->params[k] != q->params[k] ) return false;
			}
			return true;
		}
	default:
		return same_structure(a, b);
	}
}

static bool nominal_kind( int kind ) {
	return kind == HOBJ || kind == HSTRUCT || kind == HENUM || kind == HENUMTAG;
}

static hl_type *map_type( link_ctx *L, link_section *s ) {
	int i = rd_index(L);
	if( i < 0 || i >= s->ntimports + s->ntypes ) { malformed(L, "invalid type index"); return L->c->types; }
	if( s->tmap[i] < 0 ) { malformed(L, "a structural type refers to a later one"); return L->c->types; }
	return L->c->types + s->tmap[i];
}

static const uchar *map_ustring( link_ctx *L, link_section *s ) {
	int i = rd_local(L, s->nstrings, "invalid string index");
	if( L->error ) return USTR("");
	return hl_get_ustring(L->c, s->smap[i]);
}

/* A global a type refers to: imported or owned, never a constant, which pass 3 reads. */
static int map_type_global( link_ctx *L, link_section *s ) {
	int i = rd_local(L, s->ngimports + s->nglobals, "invalid global index in a type");
	return L->error ? 0 : s->gmap[i];
}

static int map_function( link_ctx *L, link_section *s, int i ) {
	if( i < 0 || i >= s->nfimports + s->nnatives + s->nfunctions ) { malformed(L, "invalid function index"); return 0; }
	return s->fmap[i];
}

static void read_fields( link_ctx *L, link_section *s, hl_obj_field *fields, int n ) {
	for(int i=0;i<n;i++) {
		fields[i].name = map_ustring(L, s);
		fields[i].hashed_name = hl_hash_gen(fields[i].name, true);
		fields[i].t = map_type(L, s);
	}
}

/* Reads one type of the section's table into `t`, as hl_read_type does, through the section's maps. */
static void read_type( link_ctx *L, link_section *s, hl_type *t, hl_alloc *alloc ) {
	t->kind = (hl_type_kind)rd_byte(L);
	switch( (int)t->kind ) {
	case HFUN:
	case HMETHOD:
		{
			int nargs = rd_byte(L);
			t->fun = (hl_type_fun*)hl_zalloc(alloc, sizeof(hl_type_fun));
			t->fun->nargs = nargs;
			t->fun->args = (hl_type**)hl_malloc(alloc, sizeof(hl_type*) * nargs);
			for(int i=0;i<nargs;i++) t->fun->args[i] = map_type(L, s);
			t->fun->ret = map_type(L, s);
		}
		break;
	case HOBJ:
	case HSTRUCT:
		{
			hl_type_obj *o = (hl_type_obj*)hl_zalloc(alloc, sizeof(hl_type_obj));
			int super, global;
			t->obj = o;
			o->name = map_ustring(L, s);
			super = rd_index(L);
			o->super = NULL;
			if( super >= 0 ) {
				if( super >= s->ntimports + s->ntypes || s->tmap[super] < 0 ) { malformed(L, "invalid super type"); return; }
				o->super = L->c->types + s->tmap[super];
			}
			global = rd_uindex(L);
			if( global > 0 ) {
				if( global - 1 >= s->ngimports + s->nglobals ) { malformed(L, "invalid global index in a type"); return; }
				global = s->gmap[global - 1] + 1;
			}
			o->global_value = (void**)(int_val)global;
			o->nfields = rd_count(L);
			o->nproto = rd_count(L);
			o->nbindings = rd_count(L);
			if( L->error ) return;
			o->fields = (hl_obj_field*)hl_malloc(alloc, sizeof(hl_obj_field) * o->nfields);
			o->proto = (hl_obj_proto*)hl_malloc(alloc, sizeof(hl_obj_proto) * o->nproto);
			o->bindings = (int*)hl_malloc(alloc, sizeof(int) * o->nbindings * 2);
			read_fields(L, s, o->fields, o->nfields);
			for(int i=0;i<o->nproto;i++) {
				hl_obj_proto *p = o->proto + i;
				p->name = map_ustring(L, s);
				p->hashed_name = hl_hash_gen(p->name, true);
				p->findex = map_function(L, s, rd_uindex(L));
				p->pindex = rd_index(L);
			}
			for(int i=0;i<o->nbindings;i++) {
				o->bindings[i<<1] = rd_uindex(L);
				o->bindings[(i<<1)|1] = map_function(L, s, rd_uindex(L));
			}
		}
		break;
	case HVIRTUAL:
		{
			const uchar *identity = map_ustring(L, s);
			int nfields = rd_count(L);
			if( L->error ) return;
			t->virt = (hl_type_virtual*)hl_zalloc(alloc, sizeof(hl_type_virtual));
			t->virt->nominal_identity = identity;
			t->virt->nfields = nfields;
			t->virt->fields = (hl_obj_field*)hl_malloc(alloc, sizeof(hl_obj_field) * nfields);
			read_fields(L, s, t->virt->fields, nfields);
		}
		break;
	case HABSTRACT:
		t->abs_name = map_ustring(L, s);
		break;
	case HENUM:
		{
			hl_type_enum *e = (hl_type_enum*)hl_zalloc(alloc, sizeof(hl_type_enum));
			int global;
			t->tenum = e;
			e->name = map_ustring(L, s);
			global = rd_uindex(L);
			if( global > 0 ) {
				if( global - 1 >= s->ngimports + s->nglobals ) { malformed(L, "invalid global index in a type"); return; }
				global = s->gmap[global - 1] + 1;
			}
			e->global_value = (void**)(int_val)global;
			e->nconstructs = rd_count(L);
			if( L->error ) return;
			e->constructs = (hl_enum_construct*)hl_zalloc(alloc, sizeof(hl_enum_construct) * e->nconstructs);
			for(int i=0;i<e->nconstructs;i++) {
				hl_enum_construct *k = e->constructs + i;
				k->name = map_ustring(L, s);
				k->nparams = rd_count(L);
				if( L->error ) return;
				k->params = (hl_type**)hl_malloc(alloc, sizeof(hl_type*) * k->nparams);
				k->offsets = (int*)hl_malloc(alloc, sizeof(int) * k->nparams);
				for(int j=0;j<k->nparams;j++) k->params[j] = map_type(L, s);
			}
		}
		break;
	case HENUMTAG:
		t->tenumtag = (hl_type_enum_tag*)hl_zalloc(alloc, sizeof(hl_type_enum_tag));
		t->tenumtag->boxed_type = map_type(L, s);
		t->tenumtag->ncases = rd_count(L);
		if( L->error ) return;
		t->tenumtag->cache_globals = (int*)hl_malloc(alloc, sizeof(int) * t->tenumtag->ncases);
		for(int i=0;i<t->tenumtag->ncases;i++) t->tenumtag->cache_globals[i] = map_type_global(L, s);
		break;
	case HREF:
	case HNULL:
	case HPACKED:
		t->tparam = map_type(L, s);
		break;
	default:
		if( t->kind >= HLAST ) malformed(L, "invalid type kind");
		break;
	}
}

/* Steps over one type of the table, so pass 2 can read the structural types before the definitions that refer to them. */
static void skip_type( link_ctx *L ) {
	int kind = rd_byte(L);
	switch( kind ) {
	case HFUN:
	case HMETHOD:
		{
			int nargs = rd_byte(L);
			for(int i=0;i<=nargs && !L->error;i++) rd_index(L);
		}
		break;
	case HOBJ:
	case HSTRUCT:
		{
			int nfields, nproto, nbindings;
			rd_index(L);
			rd_index(L);
			rd_index(L);
			nfields = rd_count(L);
			nproto = rd_count(L);
			nbindings = rd_count(L);
			for(int i=0;i<nfields && !L->error;i++) { rd_index(L); rd_index(L); }
			for(int i=0;i<nproto && !L->error;i++) { rd_index(L); rd_index(L); rd_index(L); }
			for(int i=0;i<nbindings && !L->error;i++) { rd_index(L); rd_index(L); }
		}
		break;
	case HVIRTUAL:
		{
			int nfields;
			rd_index(L);
			nfields = rd_count(L);
			for(int i=0;i<nfields && !L->error;i++) { rd_index(L); rd_index(L); }
		}
		break;
	case HENUM:
		{
			int nconstructs;
			rd_index(L);
			rd_index(L);
			nconstructs = rd_count(L);
			for(int i=0;i<nconstructs && !L->error;i++) {
				int nparams;
				rd_index(L);
				nparams = rd_count(L);
				for(int j=0;j<nparams && !L->error;j++) rd_index(L);
			}
		}
		break;
	case HENUMTAG:
		{
			int ncases;
			rd_index(L);
			ncases = rd_count(L);
			for(int i=0;i<ncases && !L->error;i++) rd_index(L);
		}
		break;
	case HABSTRACT:
	case HREF:
	case HNULL:
	case HPACKED:
		rd_index(L);
		break;
	default:
		if( kind >= HLAST ) malformed(L, "invalid type kind");
		break;
	}
}

/* The global type equal to the structural type `t` (read into scratch memory), added when it is new. */
static int intern_structural( link_ctx *L, hl_type *t ) {
	hl_code *c = L->c;
	unsigned int h = structural_hash(L, t);
	int id = table_find(L, &L->types, h, structural_equal, t);
	hl_type *dst;
	if( id >= 0 ) return id;
	id = c->ntypes++;
	dst = c->types + id;
	*dst = *t;
	switch( t->kind ) {
	case HFUN:
	case HMETHOD:
		dst->fun = (hl_type_fun*)hl_zalloc(&c->alloc, sizeof(hl_type_fun));
		dst->fun->nargs = t->fun->nargs;
		dst->fun->ret = t->fun->ret;
		dst->fun->args = (hl_type**)hl_malloc(&c->alloc, sizeof(hl_type*) * t->fun->nargs);
		memcpy(dst->fun->args, t->fun->args, sizeof(hl_type*) * t->fun->nargs);
		break;
	case HVIRTUAL:
		dst->virt = (hl_type_virtual*)hl_zalloc(&c->alloc, sizeof(hl_type_virtual));
		dst->virt->nominal_identity = t->virt->nominal_identity;
		dst->virt->nfields = t->virt->nfields;
		dst->virt->fields = (hl_obj_field*)hl_malloc(&c->alloc, sizeof(hl_obj_field) * t->virt->nfields);
		memcpy(dst->virt->fields, t->virt->fields, sizeof(hl_obj_field) * t->virt->nfields);
		break;
	default:
		break;
	}
	table_add(&L->types, h, id);
	return id;
}

// ---- constants

typedef struct {
	hl_type *t;
	int nfields;
	int *fields;
} link_constant;

static bool constant_equal( link_ctx *L, int id, const void *key ) {
	const link_constant *k = (const link_constant*)key;
	hl_constant *c = L->c->constants + id;
	return L->c->globals[c->global] == k->t && c->nfields == k->nfields && memcmp(c->fields, k->fields, sizeof(int) * k->nfields) == 0;
}

// ---- pass 1: interfaces

static link_text name_at( link_ctx *L, link_section *s ) {
	int i = rd_local(L, s->nnames, "invalid name index");
	if( L->error ) { link_text none = { "", 0 }; return none; }
	return s->names[i];
}

static link_import *read_imports( link_ctx *L, link_section *s, int count, bool kinds ) {
	link_import *imports = (link_import*)hl_zalloc(&L->tmp, sizeof(link_import) * (count ? count : 1));
	for(int i=0;i<count && !L->error;i++) {
		imports[i].module = name_at(L, s);
		imports[i].member = name_at(L, s);
		if( kinds ) {
			imports[i].expected = rd_byte(L);
			if( !nominal_kind(imports[i].expected) && imports[i].expected != HVIRTUAL ) malformed(L, "an imported type is not nominal");
		} else
			imports[i].expected = rd_local(L, s->ntimports + s->ntypes, "invalid type index");
	}
	return imports;
}

static void duplicate_export( link_ctx *L, link_section *s, link_key_kind kind, link_text member ) {
	link_fail(L, "`%.*s` exports %s `" KEY_FMT "` twice", PATH_ARGS(s), key_kind_names[kind], KEY_ARGS(s->path, member));
}

static void read_interface( link_ctx *L, int si ) {
	link_section *s = L->sections + si;
	hl_code *c = L->c;
	static const link_text shared_module = { "", 0 };
	int kind, version, flags;
	L->cur = si;
	L->b = s->data;
	L->size = s->size;
	L->pos = 0;
	kind = rd_uindex(L);
	version = rd_uindex(L);
	flags = rd_uindex(L);
	if( L->error ) return;
	if( kind != LINK_SECTION_CODE || version != LINK_SECTION_CODE_VERSION ) {
		link_fail(L, "Malformed section `%.*s`: unsupported section kind %d:%d", PATH_ARGS(s), kind, version);
		return;
	}
	if( flags & ~LINK_SECTION_LZ4 ) { malformed(L, "unknown section flags"); return; }
	if( flags & LINK_SECTION_LZ4 ) {
		int size = rd_uindex(L);
		int packed = L->size - L->pos;
		if( L->error ) return;
		// LZ4 expands a block at most 255 times.
		if( size / 255 > packed ) { malformed(L, "invalid compressed data"); return; }
		s->decoded = (unsigned char*)malloc(size > 0 ? size : 1);
		if( LZ4_decompress_safe((const char*)L->b + L->pos, (char*)s->decoded, packed, size) != size ) { malformed(L, "invalid compressed data"); return; }
		s->data = s->decoded;
		s->size = size;
	} else {
		s->data += L->pos;
		s->size -= L->pos;
	}
	L->b = s->data;
	L->size = s->size;
	L->pos = 0;
	s->nnames = rd_count(L);
	s->nfimports = rd_count(L);
	s->ngimports = rd_count(L);
	s->ntimports = rd_count(L);
	s->nnatives = rd_count(L);
	s->ntypes = rd_count(L);
	s->nglobals = rd_count(L);
	s->nfunctions = rd_count(L);
	s->nints = rd_count(L);
	s->nfloats = rd_count(L);
	s->nstrings = rd_count(L);
	s->nbytes = rd_count(L);
	s->nconstants = rd_count(L);
	s->ndebugfiles = rd_count(L);
	if( L->error ) return;
	if( s->ndebugfiles > 0 && !c->hasdebug ) { malformed(L, "debug files in a file without debug information"); return; }
	s->names = rd_string_table(L, s->nnames);
	s->fimports = read_imports(L, s, s->nfimports, false);
	s->gimports = read_imports(L, s, s->ngimports, false);
	s->timports = read_imports(L, s, s->ntimports, true);
	s->natives = read_imports(L, s, s->nnatives, false);
	if( L->error ) return;

	s->type_roles = (unsigned char*)hl_malloc(&L->tmp, s->ntypes + 1);
	s->type_kinds = (unsigned char*)hl_malloc(&L->tmp, s->ntypes + 1);
	s->type_keys = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->ntypes + 1));
	s->tmap = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->ntimports + s->ntypes + 1));
	for(int i=0;i<s->ntimports + s->ntypes;i++) s->tmap[i] = -1;
	for(int i=0;i<s->ntypes && !L->error;i++) {
		int role = rd_byte(L), tkind = rd_byte(L);
		link_text key;
		s->type_roles[i] = (unsigned char)role;
		s->type_kinds[i] = (unsigned char)tkind;
		s->type_keys[i] = -1;
		if( L->error ) return;
		if( role > ROLE_SHARED || tkind >= HLAST ) { malformed(L, "invalid type head"); return; }
		if( role == ROLE_STRUCTURAL ) {
			if( nominal_kind(tkind) ) { malformed(L, "a nominal type without a key"); return; }
			continue;
		}
		if( !nominal_kind(tkind) && tkind != HVIRTUAL ) { malformed(L, "a structural type with a key"); return; }
		s->type_keys[i] = rd_local(L, s->nnames, "invalid name index");
		if( L->error ) return;
		key = s->names[s->type_keys[i]];
		if( role == ROLE_OWNED ) {
			if( key_add(L, KEY_TYPE, s->path, key, L->nowned_types, tkind) < 0 ) { duplicate_export(L, s, KEY_TYPE, key); return; }
			s->tmap[s->ntimports + i] = L->nowned_types++;
		} else {
			int id = key_find(L, KEY_TYPE, shared_module, key);
			if( id < 0 ) {
				key_add(L, KEY_TYPE, shared_module, key, L->nowned_types, tkind);
				s->tmap[s->ntimports + i] = L->nowned_types++;
			} else if( L->entries[id].section == si ) {
				link_fail(L, "`%.*s` defines shared type `%.*s` twice", PATH_ARGS(s), key.len, key.s);
				return;
			} else if( L->entries[id].extra != tkind ) {
				link_section *o = L->sections + L->entries[id].section;
				link_fail(L, "`%.*s` defines shared type `%.*s` differently from `%.*s`", PATH_ARGS(s), key.len, key.s, PATH_ARGS(o));
				return;
			} else
				s->tmap[s->ntimports + i] = L->entries[id].value;
		}
	}

	s->global_keys = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nglobals + 1));
	s->global_types = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nglobals + 1));
	s->first_global = c->nglobals;
	for(int i=0;i<s->nglobals && !L->error;i++) {
		s->global_keys[i] = rd_local(L, s->nnames, "invalid name index");
		s->global_types[i] = rd_local(L, s->ntimports + s->ntypes, "invalid type index");
		if( L->error ) return;
		if( key_add(L, KEY_GLOBAL, s->path, s->names[s->global_keys[i]], c->nglobals++, 0) < 0 ) {
			duplicate_export(L, s, KEY_GLOBAL, s->names[s->global_keys[i]]);
			return;
		}
	}
	s->function_keys = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nfunctions + 1));
	s->function_types = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nfunctions + 1));
	s->first_function = c->nfunctions;
	for(int i=0;i<s->nfunctions && !L->error;i++) {
		s->function_keys[i] = rd_local(L, s->nnames, "invalid name index");
		s->function_types[i] = rd_local(L, s->ntimports + s->ntypes, "invalid type index");
		if( L->error ) return;
		if( key_add(L, KEY_FUNCTION, s->path, s->names[s->function_keys[i]], c->nfunctions++, 0) < 0 ) {
			duplicate_export(L, s, KEY_FUNCTION, s->names[s->function_keys[i]]);
			return;
		}
	}
	// Natives are deduplicated by (lib, name) and numbered in order of first declaration; their slots follow all functions.
	for(int i=0;i<s->nnatives;i++) {
		link_import *n = s->natives + i;
		int id = key_find(L, KEY_NATIVE, n->module, n->member);
		if( id < 0 ) id = key_add(L, KEY_NATIVE, n->module, n->member, c->nnatives++, -1);
		n->resolved = id;
	}
	s->types_pos = L->pos;
}

// ---- pass 2: types

static int resolve_import( link_ctx *L, link_section *s, link_import *im, link_key_kind kind ) {
	int id = key_find(L, kind, im->module, im->member);
	if( id < 0 ) {
		link_fail(L, "`%.*s` imports %s `" KEY_FMT "`, which no section defines", PATH_ARGS(s), key_kind_names[kind], KEY_ARGS(im->module, im->member));
		return -1;
	}
	im->resolved = id;
	return L->entries[id].value;
}

static void read_types( link_ctx *L, int si ) {
	link_section *s = L->sections + si;
	hl_code *c = L->c;
	static const link_text shared_module = { "", 0 };
	int nfun = s->nfimports + s->nnatives + s->nfunctions;
	int nglob = s->ngimports + s->nglobals + s->nconstants;
	int *positions, end;
	link_text *strings;
	L->cur = si;
	L->b = s->data;
	L->size = s->size;
	L->pos = s->types_pos;

	s->fmap = (int*)hl_malloc(&L->tmp, sizeof(int) * (nfun + 1));
	for(int i=0;i<s->nfimports;i++) {
		s->fmap[i] = resolve_import(L, s, s->fimports + i, KEY_FUNCTION);
		if( L->error ) return;
	}
	for(int i=0;i<s->nnatives;i++) s->fmap[s->nfimports + i] = c->nfunctions + L->entries[s->natives[i].resolved].value;
	for(int i=0;i<s->nfunctions;i++) s->fmap[s->nfimports + s->nnatives + i] = s->first_function + i;

	s->gmap = (int*)hl_malloc(&L->tmp, sizeof(int) * (nglob + 1));
	for(int i=0;i<s->ngimports;i++) {
		s->gmap[i] = resolve_import(L, s, s->gimports + i, KEY_GLOBAL);
		if( L->error ) return;
	}
	for(int i=0;i<s->nglobals;i++) s->gmap[s->ngimports + i] = s->first_global + i;
	for(int i=0;i<s->nconstants;i++) s->gmap[s->ngimports + s->nglobals + i] = -1;

	for(int i=0;i<s->ntimports;i++) {
		link_import *im = s->timports + i;
		link_entry *e;
		s->tmap[i] = resolve_import(L, s, im, KEY_TYPE);
		if( L->error ) return;
		e = L->entries + im->resolved;
		if( e->extra != im->expected ) {
			link_section *o = L->sections + e->section;
			link_fail(L, "`%.*s` imports type `" KEY_FMT "` as another kind than `%.*s` defines", PATH_ARGS(s), KEY_ARGS(im->module, im->member), PATH_ARGS(o));
			return;
		}
	}

	s->imap = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nints + 1));
	for(int i=0;i<s->nints && !L->error;i++) s->imap[i] = intern_int(L, rd_i32(L));
	s->flmap = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nfloats + 1));
	for(int i=0;i<s->nfloats && !L->error;i++) {
		const unsigned char *bits = rd_raw(L, 8);
		if( bits ) s->flmap[i] = intern_float(L, bits);
	}
	strings = rd_string_table(L, s->nstrings);
	s->smap = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nstrings + 1));
	for(int i=0;i<s->nstrings && !L->error;i++) s->smap[i] = intern_string(L, strings[i]);
	s->bmap = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nbytes + 1));
	for(int i=0;i<s->nbytes && !L->error;i++) {
		link_text b;
		b.len = rd_uindex(L);
		b.s = (const char*)rd_raw(L, b.len);
		if( b.s ) s->bmap[i] = intern_bytes(L, b);
	}
	strings = rd_string_table(L, s->ndebugfiles);
	s->dmap = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->ndebugfiles + 1));
	for(int i=0;i<s->ndebugfiles && !L->error;i++) s->dmap[i] = intern_file(L, strings[i]);
	if( L->error ) return;

	// A structural type refers only to the structural types before it and to definitions, whose slots are known: it is read in
	// table order. A definition can refer to a structural type after it, so it is stepped over and read once they all are.
	positions = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->ntypes + 1));
	hl_free(&L->scratch);
	hl_alloc_init(&L->scratch);
	for(int i=0;i<s->ntypes && !L->error;i++) {
		hl_type t;
		positions[i] = L->pos;
		if( s->type_roles[i] != ROLE_STRUCTURAL ) {
			skip_type(L);
			continue;
		}
		memset(&t, 0, sizeof(t));
		read_type(L, s, &t, &L->scratch);
		if( L->error ) return;
		if( (int)t.kind != s->type_kinds[i] ) { malformed(L, "a type differs from its head"); return; }
		s->tmap[s->ntimports + i] = intern_structural(L, &t);
	}
	end = L->pos;
	for(int i=0;i<s->ntypes && !L->error;i++) {
		int slot = s->tmap[s->ntimports + i];
		link_text key;
		int id = -1;
		if( s->type_roles[i] == ROLE_STRUCTURAL ) continue;
		key = s->names[s->type_keys[i]];
		L->pos = positions[i];
		if( s->type_roles[i] == ROLE_SHARED ) id = key_find(L, KEY_TYPE, shared_module, key);
		if( id < 0 || L->entries[id].section == si ) {
			read_type(L, s, c->types + slot, &c->alloc);
			if( !L->error && (int)c->types[slot].kind != s->type_kinds[i] ) malformed(L, "a type differs from its head");
		} else {
			hl_type t;
			memset(&t, 0, sizeof(t));
			read_type(L, s, &t, &L->scratch);
			if( L->error ) return;
			if( (int)t.kind != s->type_kinds[i] ) { malformed(L, "a type differs from its head"); return; }
			if( !same_definition(c->types + slot, &t) ) {
				link_section *o = L->sections + L->entries[id].section;
				link_fail(L, "`%.*s` defines shared type `%.*s` differently from `%.*s`", PATH_ARGS(s), key.len, key.s, PATH_ARGS(o));
				return;
			}
		}
	}
	if( L->error ) return;
	L->pos = end;

	for(int i=0;i<s->nglobals;i++) c->globals[s->first_global + i] = c->types + s->tmap[s->global_types[i]];
	for(int i=0;i<s->nfunctions;i++) {
		hl_type *t = c->types + s->tmap[s->function_types[i]];
		if( t->kind != HFUN && t->kind != HMETHOD ) { malformed(L, "a function's type is not a function type"); return; }
		L->ftypes[s->first_function + i] = t;
	}
	for(int i=0;i<s->nnatives;i++) {
		link_import *n = s->natives + i;
		link_entry *e = L->entries + n->resolved;
		hl_native *native = c->natives + e->value;
		hl_type *t = c->types + s->tmap[n->expected];
		if( t->kind != HFUN ) { malformed(L, "a native's type is not a function type"); return; }
		if( native->t == NULL ) {
			native->t = t;
			e->extra = si;
		} else if( native->t != t ) {
			link_section *o = L->sections + e->extra;
			link_fail(L, "`%.*s` declares native `%.*s@%.*s` with another type than `%.*s`", PATH_ARGS(s), n->module.len, n->module.s,
				n->member.len, n->member.s, PATH_ARGS(o));
			return;
		}
	}
	s->code_pos = L->pos;
}

/* After pass 2 every type is unified, so an import's expected type matches the definition's when the pointers are equal. */
static void check_imports( link_ctx *L ) {
	hl_code *c = L->c;
	for(int si=0;si<L->nsections && !L->error;si++) {
		link_section *s = L->sections + si;
		for(int k=0;k<s->nfimports + s->ngimports;k++) {
			bool function = k < s->nfimports;
			link_import *im = function ? s->fimports + k : s->gimports + (k - s->nfimports);
			link_entry *e = L->entries + im->resolved;
			hl_type *defined = function ? L->ftypes[e->value] : c->globals[e->value];
			if( c->types + s->tmap[im->expected] != defined ) {
				link_section *o = L->sections + e->section;
				link_fail(L, "`%.*s` imports %s `" KEY_FMT "` with another type than `%.*s` defines", PATH_ARGS(s),
					key_kind_names[function ? KEY_FUNCTION : KEY_GLOBAL], KEY_ARGS(im->module, im->member), PATH_ARGS(o));
				return;
			}
		}
	}
}

// ---- pass 3: code

static int map_local( link_ctx *L, const int *map, int count, int i, const char *what ) {
	if( i < 0 || i >= count ) { malformed(L, what); return 0; }
	return map[i];
}

static void read_constants( link_ctx *L, link_section *s ) {
	hl_code *c = L->c;
	for(int k=0;k<s->nconstants && !L->error;k++) {
		link_constant key;
		unsigned int h;
		int id;
		key.t = map_type(L, s);
		key.nfields = rd_count(L);
		if( L->error ) return;
		if( (key.t->kind != HOBJ && key.t->kind != HSTRUCT) || key.nfields > key.t->obj->nfields ) { malformed(L, "invalid constant"); return; }
		key.fields = (int*)hl_malloc(&L->scratch, sizeof(int) * (key.nfields + 1));
		for(int j=0;j<key.nfields && !L->error;j++) {
			int v = rd_uindex(L);
			switch( key.t->obj->fields[j].t->kind ) {
			case HI32: v = map_local(L, s->imap, s->nints, v, "invalid int index"); break;
			case HBOOL: break;
			case HF64: v = map_local(L, s->flmap, s->nfloats, v, "invalid float index"); break;
			case HBYTES: v = map_local(L, s->smap, s->nstrings, v, "invalid string index"); break;
			case HTYPE: v = map_local(L, s->tmap, s->ntimports + s->ntypes, v, "invalid type index"); break;
			default:
				v = map_local(L, s->gmap, s->ngimports + s->nglobals + s->nconstants, v, "invalid global index");
				if( v < 0 ) malformed(L, "a constant refers to a later one");
				break;
			}
			key.fields[j] = v;
		}
		if( L->error ) return;
		h = hash_mix(hash_mix(0x811C9DC5, type_ref(L, key.t)), (unsigned int)key.nfields);
		for(int j=0;j<key.nfields;j++) h = hash_mix(h, (unsigned int)key.fields[j]);
		id = table_find(L, &L->constants, h, constant_equal, &key);
		if( id < 0 ) {
			hl_constant *added = c->constants + c->nconstants;
			added->global = c->nglobals++;
			added->nfields = key.nfields;
			added->fields = (int*)hl_malloc(&c->alloc, sizeof(int) * (key.nfields + 1));
			memcpy(added->fields, key.fields, sizeof(int) * key.nfields);
			c->globals[added->global] = key.t;
			id = c->nconstants++;
			table_add(&L->constants, h, id);
		}
		s->gmap[s->ngimports + s->nglobals + k] = c->constants[id].global;
	}
}

static void read_opcode( link_ctx *L, link_section *s, hl_opcode *o ) {
	hl_alloc *falloc = &L->c->falloc;
	o->op = (hl_op)rd_byte(L);
	if( o->op >= OLast ) { malformed(L, "invalid opcode"); return; }
	switch( link_op_nargs[o->op] ) {
	case 0:
		break;
	case 1:
		o->p1 = rd_index(L);
		break;
	case 2:
		o->p1 = rd_index(L);
		o->p2 = rd_index(L);
		break;
	case 3:
		o->p1 = rd_index(L);
		o->p2 = rd_index(L);
		o->p3 = rd_index(L);
		break;
	case 4:
		o->p1 = rd_index(L);
		o->p2 = rd_index(L);
		o->p3 = rd_index(L);
		o->extra = (int*)(int_val)rd_index(L);
		break;
	case -1:
		switch( o->op ) {
		case OCallN:
		case OCallClosure:
		case OCallMethod:
		case OCallThis:
		case OMakeEnum:
			o->p1 = rd_index(L);
			o->p2 = rd_index(L);
			o->p3 = rd_byte(L);
			o->extra = (int*)hl_malloc(falloc, sizeof(int) * o->p3);
			for(int i=0;i<o->p3;i++) o->extra[i] = rd_index(L);
			break;
		case OSwitch:
			o->p1 = rd_uindex(L);
			o->p2 = rd_count(L);
			if( L->error ) return;
			o->extra = (int*)hl_malloc(falloc, sizeof(int) * o->p2);
			for(int i=0;i<o->p2;i++) o->extra[i] = rd_uindex(L);
			o->p3 = rd_uindex(L);
			break;
		default:
			malformed(L, "an opcode of unknown shape");
			break;
		}
		break;
	default:
		{
			int size = link_op_nargs[o->op] - 3;
			o->p1 = rd_index(L);
			o->p2 = rd_index(L);
			o->p3 = rd_index(L);
			o->extra = (int*)hl_malloc(falloc, sizeof(int) * size);
			for(int i=0;i<size;i++) o->extra[i] = rd_index(L);
		}
		break;
	}
	// The operands that index a table; field, prototype and constructor numbers are layout facts and stay as they are.
	switch( o->op ) {
	case OInt: o->p2 = map_local(L, s->imap, s->nints, o->p2, "invalid int index"); break;
	case OFloat: o->p2 = map_local(L, s->flmap, s->nfloats, o->p2, "invalid float index"); break;
	case OBytes: o->p2 = map_local(L, s->bmap, s->nbytes, o->p2, "invalid bytes index"); break;
	case OString: o->p2 = map_local(L, s->smap, s->nstrings, o->p2, "invalid string index"); break;
	case OType: o->p2 = map_local(L, s->tmap, s->ntimports + s->ntypes, o->p2, "invalid type index"); break;
	case OCall0: case OCall1: case OCall2: case OCall3: case OCall4: case OCallN: case OStaticClosure: case OInstanceClosure:
		o->p2 = map_function(L, s, o->p2);
		break;
	case OGetGlobal: o->p2 = map_local(L, s->gmap, s->ngimports + s->nglobals + s->nconstants, o->p2, "invalid global index"); break;
	case OSetGlobal: case OCatch: o->p1 = map_local(L, s->gmap, s->ngimports + s->nglobals + s->nconstants, o->p1, "invalid global index"); break;
	case ODynGet: o->p3 = map_local(L, s->smap, s->nstrings, o->p3, "invalid string index"); break;
	case ODynSet: o->p2 = map_local(L, s->smap, s->nstrings, o->p2, "invalid string index"); break;
	default: break;
	}
}

/* The opcode lines as HLB 8 encodes them, with the section's file indices mapped. */
static int *read_debug( link_ctx *L, link_section *s, int nops ) {
	int curfile = -1, curline = 0, i = 0;
	int *debug = (int*)hl_malloc(&L->c->alloc, sizeof(int) * (nops * 2 + 1));
	while( i < nops && !L->error ) {
		int b = rd_byte(L);
		if( b & 1 ) {
			int file = ((b >> 1) << 8) | rd_byte(L);
			if( file >= s->ndebugfiles ) { malformed(L, "invalid debug file"); break; }
			curfile = s->dmap[file];
		} else if( b & 2 ) {
			int delta = b >> 6;
			int count = (b >> 2) & 15;
			if( i + count > nops ) { malformed(L, "debug lines past the function's end"); break; }
			while( count-- ) {
				debug[i<<1] = curfile;
				debug[(i<<1)|1] = curline;
				i++;
			}
			curline += delta;
		} else {
			if( b & 4 )
				curline += b >> 3;
			else {
				int b2 = rd_byte(L);
				int b3 = rd_byte(L);
				curline = (b >> 3) | (b2 << 5) | (b3 << 13);
			}
			debug[i<<1] = curfile;
			debug[(i<<1)|1] = curline;
			i++;
		}
	}
	return debug;
}

static void read_function( link_ctx *L, link_section *s, int i ) {
	hl_code *c = L->c;
	hl_function *f = c->functions + s->first_function + i;
	const char *invalid;
	f->findex = s->first_function + i;
	f->type = L->ftypes[f->findex];
	f->nregs = rd_count(L);
	f->nops = rd_count(L);
	if( L->error ) return;
	f->regs = (hl_type**)hl_malloc(&c->falloc, sizeof(hl_type*) * f->nregs);
	for(int k=0;k<f->nregs && !L->error;k++) f->regs[k] = map_type(L, s);
	f->ops = (hl_opcode*)hl_zalloc(&c->falloc, sizeof(hl_opcode) * f->nops);
	for(int k=0;k<f->nops && !L->error;k++) read_opcode(L, s, f->ops + k);
	if( L->error ) return;
	invalid = hl_validate_function_control_flow(f);
	if( invalid ) {
		link_text name = s->names[s->function_keys[i]];
		link_fail(L, "Malformed section `%.*s`: function `" KEY_FMT "`: %s", PATH_ARGS(s), KEY_ARGS(s->path, name), invalid);
		return;
	}
	if( c->hasdebug ) {
		f->debug = read_debug(L, s, f->nops);
		f->nassigns = rd_count(L);
		if( L->error ) return;
		f->assigns = (int*)hl_malloc(&c->alloc, sizeof(int) * (f->nassigns * 3 + 1));
		for(int k=0;k<f->nassigns && !L->error;k++) {
			f->assigns[k*3] = s->smap[rd_local(L, s->nstrings, "invalid string index")];
			f->assigns[k*3+1] = rd_index(L) - 1;
			f->assigns[k*3+2] = rd_index(L) - 1;
		}
	}
}

/*
	The section's debug sub-sections (opcode source spans, source snapshots), each a kind, a version, flags, a size and a
	payload as HLB 8's debug sections are. Tools read them from the file; the loader only checks that they are well formed.
*/
static void skip_debug_sections( link_ctx *L ) {
	int count = rd_count(L);
	for(int i=0;i<count && !L->error;i++) {
		int kind = rd_uindex(L), version = rd_uindex(L), flags = rd_uindex(L), size = rd_uindex(L);
		if( L->error ) return;
		if( kind <= 0 || version <= 0 ) { malformed(L, "invalid debug section header"); return; }
		// The section's own compression covers them.
		if( flags != 0 ) { malformed(L, "a compressed debug section"); return; }
		rd_raw(L, size);
	}
}

static void read_code( link_ctx *L, int si ) {
	link_section *s = L->sections + si;
	L->cur = si;
	L->b = s->data;
	L->size = s->size;
	L->pos = s->code_pos;
	hl_free(&L->scratch);
	hl_alloc_init(&L->scratch);
	read_constants(L, s);
	for(int i=0;i<s->nfunctions && !L->error;i++) read_function(L, s, i);
	if( !L->error ) skip_debug_sections(L);
	if( !L->error && L->pos != L->size ) malformed(L, "trailing data");
}

// ---- the file

static void link_file( link_ctx *L, const unsigned char *data, int size ) {
	hl_code *c = L->c;
	link_text entry_module, entry_member;
	int flags, nsections, area, ntypes = 0, nints = 0, nfloats = 0, nstrings = 0, nbytes = 0, nconstants = 0, nfiles = 0;
	L->b = data;
	L->size = size;
	L->pos = 0;
	if( size < 4 || data[0] != 'H' || data[1] != 'L' || data[2] != 'B' || data[3] != LINK_VERSION ) { malformed(L, "invalid header"); return; }
	L->pos = 4;
	flags = rd_uindex(L);
	if( L->error ) return;
	if( flags & ~LINK_FILE_DEBUG ) { malformed(L, "unknown flags"); return; }
	c->version = LINK_VERSION;
	c->hasdebug = (flags & LINK_FILE_DEBUG) != 0;
	nsections = rd_count(L);
	if( L->error ) return;
	L->sections = (link_section*)hl_zalloc(&L->tmp, sizeof(link_section) * (nsections + 1));
	L->nsections = nsections;
	table_init(&L->keys, 1024);
	for(int i=0;i<L->nsections && !L->error;i++) {
		link_section *s = L->sections + i;
		static const link_text none = { "", 0 };
		s->path = rd_text(L);
		s->offset = rd_i32(L);
		s->size = rd_i32(L);
		rd_raw(L, 8); // the content digest, the compiler's reuse key
		if( L->error ) return;
		if( s->path.len == 0 ) { malformed(L, "a section without a module path"); return; }
		if( key_add(L, KEY_SECTION, s->path, none, i, 0) < 0 ) {
			link_fail(L, "Two sections are named `%.*s`", PATH_ARGS(s));
			return;
		}
	}
	entry_module = rd_text(L);
	entry_member = rd_text(L);
	if( L->error ) return;
	area = L->pos;
	for(int i=0;i<L->nsections;i++) {
		link_section *s = L->sections + i;
		if( s->offset < 0 || s->size < 0 || s->offset > size - area || s->size > size - area - s->offset ) { malformed(L, "a section lies outside the file"); return; }
		s->data = data + area + s->offset;
	}

	for(int i=0;i<L->nsections && !L->error;i++) read_interface(L, i);
	if( L->error ) return;
	L->cur = -1;
	for(int i=0;i<L->nsections;i++) {
		link_section *s = L->sections + i;
		ntypes += s->ntypes;
		nints += s->nints;
		nfloats += s->nfloats;
		nstrings += s->nstrings;
		nbytes += s->nbytes;
		nconstants += s->nconstants;
		nfiles += s->ndebugfiles;
	}
	c->types_capacity = ntypes > 0x7FFFFFFF - HL_PATCH_TYPE_RESERVE ? ntypes : ntypes + HL_PATCH_TYPE_RESERVE;
	c->types = (hl_type*)hl_zalloc(&c->alloc, sizeof(hl_type) * c->types_capacity);
	c->ntypes = L->nowned_types;
	c->globals = (hl_type**)hl_zalloc(&c->alloc, sizeof(hl_type*) * (c->nglobals + nconstants + 1));
	c->globals_capacity = c->nglobals + nconstants;
	c->constants = (hl_constant*)hl_zalloc(&c->alloc, sizeof(hl_constant) * (nconstants + 1));
	c->ints = (int*)hl_zalloc(&c->alloc, sizeof(int) * (nints + 1));
	c->floats = (double*)hl_zalloc(&c->alloc, sizeof(double) * (nfloats + 1));
	c->strings = (char**)hl_zalloc(&c->alloc, sizeof(char*) * (nstrings + 1));
	c->strings_lens = (int*)hl_zalloc(&c->alloc, sizeof(int) * (nstrings + 1));
	c->ustrings = (uchar**)hl_zalloc(&c->alloc, sizeof(uchar*) * (nstrings + 1));
	c->bytes_pos = (int*)hl_zalloc(&c->alloc, sizeof(int) * (nbytes + 1));
	c->debugfiles = (char**)hl_zalloc(&c->alloc, sizeof(char*) * (nfiles + 1));
	c->debugfiles_lens = (int*)hl_zalloc(&c->alloc, sizeof(int) * (nfiles + 1));
	c->natives = (hl_native*)hl_zalloc(&c->alloc, sizeof(hl_native) * (c->nnatives + 1));
	c->functions_capacity = c->nfunctions > 0x7FFFFFFF - HL_PATCH_FUNCTION_RESERVE - c->nnatives ? c->nfunctions : c->nfunctions + HL_PATCH_FUNCTION_RESERVE;
	c->functions = (hl_function*)hl_zalloc(&c->alloc, sizeof(hl_function) * c->functions_capacity);
	c->function_stable_ids = (int*)hl_zalloc(&c->alloc, sizeof(int) * c->functions_capacity);
	c->function_names = (char**)hl_zalloc(&c->alloc, sizeof(char*) * c->functions_capacity);
	c->function_names_lens = (int*)hl_zalloc(&c->alloc, sizeof(int) * c->functions_capacity);
	L->ftypes = (hl_type**)calloc(c->nfunctions + 1, sizeof(hl_type*));
	table_init(&L->strings, nstrings);
	table_init(&L->files, nfiles);
	table_init(&L->ints, nints);
	table_init(&L->floats, nfloats);
	table_init(&L->bytes, nbytes);
	table_init(&L->types, ntypes);
	table_init(&L->constants, nconstants);
	for(int i=0;i<L->nentries;i++) {
		link_entry *e = L->entries + i;
		char *text;
		if( e->kind == KEY_NATIVE ) {
			hl_native *n = c->natives + e->value;
			// Natives of one library share its name: the module resolves a library again whenever the pointer changes.
			for(int k=0;k<e->value && n->lib == NULL;k++)
				if( (int)strlen(c->natives[k].lib) == e->module.len && memcmp(c->natives[k].lib, e->module.s, e->module.len) == 0 )
					n->lib = c->natives[k].lib;
			if( n->lib == NULL ) {
				text = (char*)hl_malloc(&c->alloc, e->module.len + 1);
				memcpy(text, e->module.s, e->module.len);
				text[e->module.len] = 0;
				n->lib = text;
			}
			text = (char*)hl_malloc(&c->alloc, e->member.len + 1);
			memcpy(text, e->member.s, e->member.len);
			text[e->member.len] = 0;
			n->name = text;
			n->findex = c->nfunctions + e->value;
		} else if( e->kind == KEY_FUNCTION ) {
			// The key is the function's identity; its member is the name stack traces and profiles show.
			text = (char*)hl_malloc(&c->alloc, e->member.len + 1);
			memcpy(text, e->member.s, e->member.len);
			text[e->member.len] = 0;
			c->function_names[e->value] = text;
			c->function_names_lens[e->value] = e->member.len;
		}
	}

	for(int i=0;i<L->nsections && !L->error;i++) read_types(L, i);
	if( L->error ) return;
	L->cur = -1;
	check_imports(L);
	if( L->error ) return;
	for(int i=0;i<L->nsections && !L->error;i++) read_code(L, i);
	if( L->error ) return;
	L->cur = -1;

	c->bytes = (char*)hl_malloc(&c->alloc, L->bytes_size + 1);
	if( L->bytes_size ) memcpy(c->bytes, L->bytes_data, L->bytes_size);
	for(int i=0;i<c->nfunctions;i++) c->function_stable_ids[i] = i;
	{
		int id = key_find(L, KEY_FUNCTION, entry_module, entry_member);
		if( id < 0 ) {
			link_fail(L, "The entry function `" KEY_FMT "` is not defined by any section", KEY_ARGS(entry_module, entry_member));
			return;
		}
		c->entrypoint = L->entries[id].value;
	}
}

hl_code *hl_code_link( const unsigned char *data, int size, char **error_msg ) {
	link_ctx ctx;
	link_ctx *L = &ctx;
	hl_alloc alloc;
	hl_code *c;
	memset(L, 0, sizeof(link_ctx));
	hl_alloc_init(&alloc);
	c = (hl_code*)hl_zalloc(&alloc, sizeof(hl_code));
	c->alloc = alloc;
	hl_alloc_init(&c->falloc);
	hl_alloc_init(&L->tmp);
	hl_alloc_init(&L->scratch);
	L->c = c;
	L->cur = -1;
	link_file(L, data, size);
	for(int i=0;i<L->nsections;i++) free(L->sections[i].decoded);
	table_free(&L->keys);
	table_free(&L->strings);
	table_free(&L->files);
	table_free(&L->ints);
	table_free(&L->floats);
	table_free(&L->bytes);
	table_free(&L->types);
	table_free(&L->constants);
	free(L->entries);
	free(L->ftypes);
	free(L->bytes_data);
	hl_free(&L->scratch);
	hl_free(&L->tmp);
	if( L->error ) {
		hl_code_destroy(c);
		*error_msg = (char*)L->error;
		return NULL;
	}
	return c;
}
