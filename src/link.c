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

	A module loaded to take patches keeps what the link built (`hl_code_read_patchable`): the keys, the literal, structural
	and constant tables, and a digest of each function's code. An HLP 12 patch's sections are linked against that state by
	the same three passes (`hl_module_link_patch`), into the runtime's patch: a key the module has keeps its slot, a new key
	takes the next one, and every entry new to the module is staged after the module's tables until the patch commits.
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
	/* A patch's section: the global and the slot of each owned global and function, a known one or a new one. */
	int *global_slots, *function_slots;
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
	/* The patch that defined the key last (`hl_link_patch.stamp`), so a patch defines each key once. */
	int stamp;
} link_entry;

/* An open-addressed set of entry ids; the caller hashes and compares. */
typedef struct {
	int *ids;
	unsigned int *hashes;
	int mask;
	int count;
} link_table;

typedef struct hl_link_state link_ctx;
typedef struct hl_link_patch link_patch;
typedef bool (*link_equal)( link_ctx *L, int id, const void *key );

struct hl_link_state {
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
	/* Kept for patches (`hl_code_read_patchable`): the texts of the keys, and the constants patches added. */
	bool keep;
	hl_alloc kept;
	/* By slot, the digest of the function's linked code (`function_digest`). */
	unsigned long long *digests;
	int ndigests;
	/* The constants patches added, numbered after the module's own (`constant_at`). */
	hl_constant *more_constants;
	int nmore_constants, more_constants_capacity;
	int stamp;
	/* The patch being linked, with the module it patches. */
	link_patch *P;
	hl_module *m;
};

typedef struct {
	hl_type *t;
	int nfields;
	int *fields;
	/* A constant a patch stages: the global it is given. */
	int global;
} link_constant;

/* A function a patch replaces or adds: where its section has it, its slot, the digest the slot takes once the patch commits,
   and its line table, for the opcodes the section's spans leave out. */
typedef struct {
	int section, local, slot;
	unsigned long long digest;
	int *debug;
} link_changed;

/*
	What a patch adds while it is linked, past the module's tables: each entry's index is the module's count plus its place
	here, and the tables of the link state find it under that index until the patch commits or is dropped (`link_patch_end`).
*/
struct hl_link_patch {
	link_ctx *L;
	hl_patch *patch;
	int stamp;
	int base_entries, base_strings, base_ints, base_floats, base_files, base_types, base_constants, slots;
	link_text *strings; uchar **ustrings; int nstrings, cstrings, custrings;
	int *ints; int nints, cints;
	double *floats; int nfloats, cfloats;
	link_text *files; int nfiles, cfiles;
	/* Types: as read (for hashing and comparing) and as the patch carries them. */
	hl_type *types; hl_patch_type *ptypes; bool *structural; int ntypes, ctypes, cptypes, cstructural;
	link_constant *constants; int nconstants, cconstants;
	hl_patch_global *globals; int nglobals, cglobals;
	hl_patch_added_function *added; hl_type **added_types; int nadded, cadded;
	hl_patch_function *functions; link_changed *changed; int nfunctions, cfunctions, cchanged;
	hl_patch_object_field *fields; int nfields, cfields;
	/* Renamed entries and the members they had. */
	int *renamed; link_text *renamed_from; int nrenamed;
	/* The string indices the type being read names, in the order it names them (`read_type`). */
	int *trace; int ntrace, ctrace;
};

static void *grow( void *p, int count, int *capacity, int size ) {
	if( count < *capacity ) return p;
	*capacity = *capacity ? *capacity * 2 : 16;
	p = realloc(p, (size_t)*capacity * size);
	if( p == NULL ) hl_fatal("Out of memory linking a patch");
	memset((char*)p + (size_t)count * size, 0, (size_t)(*capacity - count) * size);
	return p;
}
/* Makes room for one more entry in a growable array of the patch. */
#define GROW(arr, n, cap) ((arr) = grow((arr), (n), &(cap), (int)sizeof(*(arr))))

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

static link_section running_module = { { "the running module", 18 } };
static const link_text no_module = { "", 0 };

/* The section that entered entry `id`'s key, or the running module for a key a patch links against. */
static link_section *entry_section( link_ctx *L, int id ) {
	int si = L->entries[id].section;
	return si < 0 ? &running_module : L->sections + si;
}

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
	e->stamp = L->P ? L->P->stamp : 0;
	table_add(&L->keys, h, L->nentries);
	return L->nentries++;
}

// ---- literal tables, deduplicated by content
//
// While a patch is linked, an entry past the module's count is the patch's: it is staged in the patch, and found there.

static bool string_equal( link_ctx *L, int id, const void *key ) {
	const link_text *t = (const link_text*)key;
	if( id >= L->c->nstrings ) return same_text(L->P->strings[id - L->c->nstrings], *t);
	return L->c->strings_lens[id] == t->len && memcmp(L->c->strings[id], t->s, t->len) == 0;
}

static int intern_string( link_ctx *L, link_text t ) {
	hl_code *c = L->c;
	unsigned int h = hash_text(0x811C9DC5, t.s, t.len);
	int id = table_find(L, &L->strings, h, string_equal, &t);
	char *copy;
	if( id >= 0 ) return id;
	if( L->P ) {
		link_patch *P = L->P;
		GROW(P->strings, P->nstrings, P->cstrings);
		id = c->nstrings + P->nstrings;
		P->strings[P->nstrings++] = t;
		table_add(&L->strings, h, id);
		return id;
	}
	copy = (char*)hl_malloc(&c->alloc, t.len + 1);
	memcpy(copy, t.s, t.len);
	copy[t.len] = 0;
	id = c->nstrings++;
	c->strings[id] = copy;
	c->strings_lens[id] = t.len;
	table_add(&L->strings, h, id);
	return id;
}

/* The UTF-16 text of string `id`, as type names and field names hold it; equal strings give the same pointer. */
static const uchar *link_ustring( link_ctx *L, int id ) {
	link_patch *P = L->P;
	int k;
	if( id < L->c->nstrings ) return hl_get_ustring(L->c, id);
	k = id - L->c->nstrings;
	if( k >= P->custrings ) {
		int before = P->custrings;
		P->custrings = P->cstrings;
		P->ustrings = (uchar**)realloc(P->ustrings, sizeof(uchar*) * P->custrings);
		if( P->ustrings == NULL ) hl_fatal("Out of memory linking a patch");
		memset(P->ustrings + before, 0, sizeof(uchar*) * (P->custrings - before));
	}
	if( P->ustrings[k] == NULL ) {
		link_text t = P->strings[k];
		char *copy = (char*)hl_malloc(&L->tmp, t.len + 1);
		int size;
		memcpy(copy, t.s, t.len);
		copy[t.len] = 0;
		size = hl_utf8_length((vbyte*)copy, 0);
		P->ustrings[k] = (uchar*)hl_malloc(&L->tmp, sizeof(uchar) * (size + 1));
		hl_from_utf8(P->ustrings[k], size, copy);
	}
	return P->ustrings[k];
}

static bool file_equal( link_ctx *L, int id, const void *key ) {
	const link_text *t = (const link_text*)key;
	if( id >= L->c->ndebugfiles ) return same_text(L->P->files[id - L->c->ndebugfiles], *t);
	return L->c->debugfiles_lens[id] == t->len && memcmp(L->c->debugfiles[id], t->s, t->len) == 0;
}

static int intern_file( link_ctx *L, link_text t ) {
	hl_code *c = L->c;
	unsigned int h = hash_text(0x811C9DC5, t.s, t.len);
	int id = table_find(L, &L->files, h, file_equal, &t);
	char *copy;
	if( id >= 0 ) return id;
	if( L->P ) {
		link_patch *P = L->P;
		GROW(P->files, P->nfiles, P->cfiles);
		id = c->ndebugfiles + P->nfiles;
		P->files[P->nfiles++] = t;
		table_add(&L->files, h, id);
		return id;
	}
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
	if( id >= L->c->nints ) return L->P->ints[id - L->c->nints] == *(const int*)key;
	return L->c->ints[id] == *(const int*)key;
}

static int intern_int( link_ctx *L, int v ) {
	unsigned int h = hash_mix(0x811C9DC5, (unsigned int)v);
	int id = table_find(L, &L->ints, h, int_equal, &v);
	if( id >= 0 ) return id;
	if( L->P ) {
		link_patch *P = L->P;
		GROW(P->ints, P->nints, P->cints);
		id = L->c->nints + P->nints;
		P->ints[P->nints++] = v;
	} else {
		id = L->c->nints++;
		L->c->ints[id] = v;
	}
	table_add(&L->ints, h, id);
	return id;
}

/* Floats are equal when their bits are: 0.0 and -0.0 stay apart, as do NaNs with different payloads. */
static bool float_equal( link_ctx *L, int id, const void *key ) {
	if( id >= L->c->nfloats ) return memcmp(L->P->floats + (id - L->c->nfloats), key, sizeof(double)) == 0;
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
	if( L->P ) {
		link_patch *P = L->P;
		GROW(P->floats, P->nfloats, P->cfloats);
		id = L->c->nfloats + P->nfloats;
		memcpy(P->floats + P->nfloats++, bits, sizeof(double));
	} else {
		id = L->c->nfloats++;
		memcpy(L->c->floats + id, bits, sizeof(double));
	}
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
	if( L->P ) {
		// The module's bytes are one blob the JIT addresses; a patch has no way to extend it.
		link_fail(L, "`%.*s` adds a bytes literal the running module does not have, which needs a reload", PATH_ARGS(L->sections + L->cur));
		return 0;
	}
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

/* Type `id`: the module's, or one a patch being linked stages after them. */
static hl_type *type_at( link_ctx *L, int id ) {
	return id < L->c->ntypes ? L->c->types + id : L->P->types + (id - L->c->ntypes);
}

static bool structural_equal( link_ctx *L, int id, const void *key ) {
	return same_structure(type_at(L, id), (hl_type*)key);
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
	if( L->P == NULL ) return hl_get_ustring(L->c, s->smap[i]);
	{
		// A patch carries a type with its names' string indices, which the type read here does not keep.
		link_patch *P = L->P;
		GROW(P->trace, P->ntrace, P->ctrace);
		P->trace[P->ntrace++] = s->smap[i];
	}
	return link_ustring(L, s->smap[i]);
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

/* A new type index for a patch, after the module's and the patch's other types; -1 when the module has no room for it. */
static int stage_type( link_ctx *L, bool structural ) {
	link_patch *P = L->P;
	int id = L->c->ntypes + P->ntypes;
	if( id >= L->c->types_capacity ) {
		link_fail(L, "`%.*s` adds more types than the running module has room for, which needs a reload", PATH_ARGS(L->sections + L->cur));
		return -1;
	}
	GROW(P->types, P->ntypes, P->ctypes);
	GROW(P->ptypes, P->ntypes, P->cptypes);
	GROW(P->structural, P->ntypes, P->cstructural);
	P->structural[P->ntypes] = structural;
	P->ntypes++;
	return id;
}

/* Patch type `k` as the patch carries it, from `t` as it was read and the string indices its reading named (`trace`). */
static void patch_type_of( link_ctx *L, int k, hl_type *t ) {
	link_patch *P = L->P;
	hl_patch_type *pt = P->ptypes + k;
	int *trace = P->trace, n = 0;
	pt->tag = t->kind;
	switch( t->kind ) {
	case HFUN:
	case HMETHOD:
		pt->data.fun.count = t->fun->nargs;
		pt->data.fun.arguments = (int*)malloc(sizeof(int) * (t->fun->nargs + 1));
		for(int i=0;i<t->fun->nargs;i++) pt->data.fun.arguments[i] = type_ref(L, t->fun->args[i]);
		pt->data.fun.result = type_ref(L, t->fun->ret);
		break;
	case HREF:
	case HNULL:
	case HPACKED:
		pt->data.parameter = type_ref(L, t->tparam);
		break;
	case HABSTRACT:
		pt->data.name = trace[0];
		break;
	case HVIRTUAL:
		{
			hl_patch_object_type *o = &pt->data.obj;
			o->name = trace[n++];
			o->super = -1;
			o->field_count = t->virt->nfields;
			o->fields = (hl_patch_type_field*)malloc(sizeof(hl_patch_type_field) * (o->field_count + 1));
			for(int i=0;i<o->field_count;i++) { o->fields[i].name = trace[n++]; o->fields[i].type = type_ref(L, t->virt->fields[i].t); }
		}
		break;
	case HOBJ:
	case HSTRUCT:
		{
			hl_patch_object_type *o = &pt->data.obj;
			hl_type_obj *obj = t->obj;
			o->name = trace[n++];
			o->super = obj->super ? type_ref(L, obj->super) : -1;
			o->global = (int)(int_val)obj->global_value;
			o->field_count = obj->nfields;
			o->fields = (hl_patch_type_field*)malloc(sizeof(hl_patch_type_field) * (o->field_count + 1));
			for(int i=0;i<obj->nfields;i++) { o->fields[i].name = trace[n++]; o->fields[i].type = type_ref(L, obj->fields[i].t); }
			o->proto_count = obj->nproto;
			o->protos = (hl_patch_type_method*)malloc(sizeof(hl_patch_type_method) * (o->proto_count + 1));
			for(int i=0;i<obj->nproto;i++) {
				o->protos[i].name = trace[n++];
				o->protos[i].findex = obj->proto[i].findex;
				o->protos[i].pindex = obj->proto[i].pindex;
			}
			o->binding_count = obj->nbindings;
			o->bindings = (hl_patch_type_binding*)malloc(sizeof(hl_patch_type_binding) * (o->binding_count + 1));
			for(int i=0;i<obj->nbindings;i++) { o->bindings[i].field = obj->bindings[i<<1]; o->bindings[i].findex = obj->bindings[(i<<1)|1]; }
		}
		break;
	default:
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
	if( L->P ) {
		id = stage_type(L, true);
		if( id < 0 ) return 0;
		dst = L->P->types + (id - c->ntypes);
		*dst = *t;
		// The scratch memory `t` lives in is reused by the next section; the staged copy lives with the patch.
		if( t->kind == HVIRTUAL ) {
			dst->virt = (hl_type_virtual*)hl_zalloc(&L->tmp, sizeof(hl_type_virtual));
			*dst->virt = *t->virt;
			dst->virt->fields = (hl_obj_field*)hl_malloc(&L->tmp, sizeof(hl_obj_field) * (t->virt->nfields + 1));
			memcpy(dst->virt->fields, t->virt->fields, sizeof(hl_obj_field) * t->virt->nfields);
		} else if( t->kind == HFUN || t->kind == HMETHOD ) {
			dst->fun = (hl_type_fun*)hl_zalloc(&L->tmp, sizeof(hl_type_fun));
			dst->fun->nargs = t->fun->nargs;
			dst->fun->ret = t->fun->ret;
			dst->fun->args = (hl_type**)hl_malloc(&L->tmp, sizeof(hl_type*) * (t->fun->nargs + 1));
			memcpy(dst->fun->args, t->fun->args, sizeof(hl_type*) * t->fun->nargs);
		}
		patch_type_of(L, id - c->ntypes, dst);
		table_add(&L->types, h, id);
		return id;
	}
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

/* Constant `id`: the module's, one an earlier patch added (`more_constants`), or one the patch being linked stages. */
static link_constant constant_at( link_ctx *L, int id ) {
	hl_code *c = L->c;
	link_constant k;
	if( id < c->nconstants + L->nmore_constants ) {
		hl_constant *x = id < c->nconstants ? c->constants + id : L->more_constants + (id - c->nconstants);
		k.t = c->globals[x->global];
		k.nfields = x->nfields;
		k.fields = x->fields;
		k.global = x->global;
		return k;
	}
	return L->P->constants[id - c->nconstants - L->nmore_constants];
}

static bool constant_equal( link_ctx *L, int id, const void *key ) {
	const link_constant *k = (const link_constant*)key;
	link_constant c = constant_at(L, id);
	return c.t == k->t && c.nfields == k->nfields && memcmp(c.fields, k->fields, sizeof(int) * k->nfields) == 0;
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
		if( role == ROLE_OWNED && L->P ) {
			// A patch redefines a type the module has, in the slot it has, or adds one after the module's.
			int id = key_find(L, KEY_TYPE, s->path, key);
			if( id >= 0 ) {
				link_entry *e = L->entries + id;
				if( e->stamp == L->P->stamp ) { duplicate_export(L, s, KEY_TYPE, key); return; }
				if( e->extra != tkind ) {
					link_fail(L, "`%.*s` redefines type `" KEY_FMT "` as another kind, which needs a reload", PATH_ARGS(s), KEY_ARGS(s->path, key));
					return;
				}
				e->stamp = L->P->stamp;
				s->tmap[s->ntimports + i] = e->value;
			} else {
				int slot = stage_type(L, false);
				if( slot < 0 ) return;
				key_add(L, KEY_TYPE, s->path, key, slot, tkind);
				s->tmap[s->ntimports + i] = slot;
			}
		} else if( role == ROLE_OWNED ) {
			if( key_add(L, KEY_TYPE, s->path, key, L->nowned_types, tkind) < 0 ) { duplicate_export(L, s, KEY_TYPE, key); return; }
			s->tmap[s->ntimports + i] = L->nowned_types++;
		} else {
			int id = key_find(L, KEY_TYPE, shared_module, key);
			if( id < 0 && L->P ) {
				int slot = stage_type(L, false);
				if( slot < 0 ) return;
				key_add(L, KEY_TYPE, shared_module, key, slot, tkind);
				s->tmap[s->ntimports + i] = slot;
			} else if( id < 0 ) {
				key_add(L, KEY_TYPE, shared_module, key, L->nowned_types, tkind);
				s->tmap[s->ntimports + i] = L->nowned_types++;
			} else if( L->entries[id].section == si ) {
				link_fail(L, "`%.*s` defines shared type `%.*s` twice", PATH_ARGS(s), key.len, key.s);
				return;
			} else if( L->entries[id].extra != tkind ) {
				link_section *o = entry_section(L, id);
				link_fail(L, "`%.*s` defines shared type `%.*s` differently from `%.*s`", PATH_ARGS(s), key.len, key.s, PATH_ARGS(o));
				return;
			} else
				s->tmap[s->ntimports + i] = L->entries[id].value;
		}
	}

	s->global_keys = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nglobals + 1));
	s->global_types = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nglobals + 1));
	s->first_global = c->nglobals;
	if( L->P ) s->global_slots = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nglobals + 1));
	for(int i=0;i<s->nglobals && !L->error;i++) {
		s->global_keys[i] = rd_local(L, s->nnames, "invalid name index");
		s->global_types[i] = rd_local(L, s->ntimports + s->ntypes, "invalid type index");
		if( L->error ) return;
		if( L->P ) {
			// A global the module has keeps its slot; a new one is a null slot after the module's globals.
			link_text member = s->names[s->global_keys[i]];
			int id = key_find(L, KEY_GLOBAL, s->path, member);
			if( id >= 0 ) {
				if( L->entries[id].stamp == L->P->stamp ) { duplicate_export(L, s, KEY_GLOBAL, member); return; }
				L->entries[id].stamp = L->P->stamp;
				s->global_slots[i] = L->entries[id].value;
			} else {
				link_patch *P = L->P;
				GROW(P->globals, P->nglobals, P->cglobals);
				P->globals[P->nglobals].field_count = -1;
				P->globals[P->nglobals].type = -1;
				s->global_slots[i] = c->nglobals + P->nglobals++;
				key_add(L, KEY_GLOBAL, s->path, member, s->global_slots[i], 0);
			}
			continue;
		}
		if( key_add(L, KEY_GLOBAL, s->path, s->names[s->global_keys[i]], c->nglobals++, 0) < 0 ) {
			duplicate_export(L, s, KEY_GLOBAL, s->names[s->global_keys[i]]);
			return;
		}
	}
	s->function_keys = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nfunctions + 1));
	s->function_types = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nfunctions + 1));
	s->first_function = c->nfunctions;
	if( L->P ) s->function_slots = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nfunctions + 1));
	for(int i=0;i<s->nfunctions && !L->error;i++) {
		s->function_keys[i] = rd_local(L, s->nnames, "invalid name index");
		s->function_types[i] = rd_local(L, s->ntimports + s->ntypes, "invalid type index");
		if( L->error ) return;
		if( L->P ) {
			// A function the module has keeps its slot, and its code unless the patch's differs; a new one takes the next slot.
			link_text member = s->names[s->function_keys[i]];
			int id = key_find(L, KEY_FUNCTION, s->path, member);
			if( id >= 0 ) {
				if( L->entries[id].stamp == L->P->stamp ) { duplicate_export(L, s, KEY_FUNCTION, member); return; }
				L->entries[id].stamp = L->P->stamp;
				s->function_slots[i] = L->entries[id].value;
			} else {
				link_patch *P = L->P;
				hl_patch_added_function *a;
				GROW(P->added, P->nadded, P->cadded);
				a = P->added + P->nadded;
				// The next slot, which is also the function's stable id.
				a->findex = P->slots + P->nadded;
				a->type = -1;
				a->name = (char*)malloc(member.len + 1);
				memcpy(a->name, member.s, member.len);
				a->name[member.len] = 0;
				P->nadded++;
				s->function_slots[i] = a->findex;
				key_add(L, KEY_FUNCTION, s->path, member, a->findex, 0);
			}
			continue;
		}
		if( key_add(L, KEY_FUNCTION, s->path, s->names[s->function_keys[i]], c->nfunctions++, 0) < 0 ) {
			duplicate_export(L, s, KEY_FUNCTION, s->names[s->function_keys[i]]);
			return;
		}
	}
	// Natives are deduplicated by (lib, name) and numbered in order of first declaration; their slots follow all functions.
	for(int i=0;i<s->nnatives;i++) {
		link_import *n = s->natives + i;
		int id = key_find(L, KEY_NATIVE, n->module, n->member);
		if( id < 0 && L->P ) {
			// Natives sit before every slot a patch adds.
			link_fail(L, "`%.*s` declares native `%.*s@%.*s`, which the running module does not have; a new native needs a reload",
				PATH_ARGS(s), n->module.len, n->module.s, n->member.len, n->member.s);
			return;
		}
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

/* The type of global `g` for a patch's sections: the module's, or the one the patch gives a global it adds. */
static hl_type *global_type( link_ctx *L, int g ) {
	hl_code *c = L->c;
	return g < c->nglobals ? c->globals[g] : c->types + L->P->globals[g - c->nglobals].type;
}

/* The type of the function in `slot`: the running module's, or an added function's. */
static hl_type *slot_type( link_ctx *L, int slot ) {
	link_patch *P = L->P;
	if( slot >= P->slots ) return P->added_types[slot - P->slots];
	return L->m->ctx.functions_types[slot];
}

/* A value global as a definition read from a patch holds it (the index plus one), as the running module holds it: a pointer. */
static void **live_global_value( link_ctx *L, void **read ) {
	int g = (int)(int_val)read;
	if( g == 0 ) return NULL;
	if( g - 1 >= L->c->nglobals ) return (void**)(int_val)-1;
	return (void**)(L->m->globals_data + L->m->globals_indexes[g - 1]);
}

/*
	A definition a patch's section gives for a type the running module has: equal after mapping, except that a class of the
	section's own may give its reserved slots (unnamed Dynamic fields) a name and a type, which the patch fills in place.
*/
static void redefine_type( link_ctx *L, link_section *s, int index, hl_type *t, link_text key, bool owned ) {
	hl_type *live = L->c->types + index;
	link_patch *P = L->P;
	bool same = true;
	if( t->kind == HOBJ || t->kind == HSTRUCT ) {
		hl_type_obj *x = live->obj, *y = t->obj;
		same = x->name == y->name && x->super == y->super && x->global_value == live_global_value(L, y->global_value)
			&& x->nfields == y->nfields && x->nproto == y->nproto && x->nbindings == y->nbindings
			&& memcmp(x->bindings, y->bindings, sizeof(int) * 2 * x->nbindings) == 0;
		for(int i=0;same && i<x->nproto;i++)
			same = x->proto[i].name == y->proto[i].name && x->proto[i].findex == y->proto[i].findex && x->proto[i].pindex == y->proto[i].pindex;
		for(int i=0;same && i<x->nfields;i++) {
			hl_obj_field *was = x->fields + i, *now = y->fields + i;
			if( was->name == now->name && was->t == now->t ) continue;
			if( owned && t->kind == HOBJ && was->name[0] == 0 && was->t->kind == HDYN && now->name[0] != 0 ) {
				hl_patch_object_field *f;
				GROW(P->fields, P->nfields, P->cfields);
				f = P->fields + P->nfields++;
				f->type = index;
				f->field = i;
				// The type's name comes first in the strings its reading named, then each field's.
				f->name = P->trace[1 + i];
				f->field_type = type_ref(L, now->t);
				continue;
			}
			same = false;
		}
	} else if( t->kind == HENUM ) {
		hl_type_enum mapped = *t->tenum;
		hl_type copy = *t;
		mapped.global_value = live_global_value(L, t->tenum->global_value);
		copy.tenum = &mapped;
		same = same_definition(live, &copy);
	} else
		same = same_definition(live, t);
	if( !same )
		link_fail(L, "`%.*s` redefines type `" KEY_FMT "` other than the running module has it, which needs a reload", PATH_ARGS(s),
			KEY_ARGS(owned ? s->path : no_module, key));
}

/* Definition `i` of a patch's section, in `slot`: a type the module has, one the patch adds, or a shared one another section of
   the patch added first. */
static void patch_definition( link_ctx *L, link_section *s, int i, int slot, link_text key, int shared ) {
	hl_code *c = L->c;
	link_patch *P = L->P;
	bool owned = s->type_roles[i] == ROLE_OWNED;
	hl_type t;
	if( slot >= c->ntypes && (owned || L->entries[shared].section == L->cur) ) {
		hl_type *dst = P->types + (slot - c->ntypes);
		P->ntrace = 0;
		read_type(L, s, dst, &L->tmp);
		if( L->error ) return;
		if( (int)dst->kind != s->type_kinds[i] ) { malformed(L, "a type differs from its head"); return; }
		if( dst->kind == HENUM || dst->kind == HENUMTAG ) {
			link_fail(L, "`%.*s` adds enum `" KEY_FMT "`, which needs a reload", PATH_ARGS(s), KEY_ARGS(owned ? s->path : no_module, key));
			return;
		}
		patch_type_of(L, slot - c->ntypes, dst);
		return;
	}
	memset(&t, 0, sizeof(t));
	P->ntrace = 0;
	read_type(L, s, &t, &L->scratch);
	if( L->error ) return;
	if( (int)t.kind != s->type_kinds[i] ) { malformed(L, "a type differs from its head"); return; }
	if( slot < c->ntypes )
		redefine_type(L, s, slot, &t, key, owned);
	else if( !same_definition(type_at(L, slot), &t) ) {
		link_section *o = entry_section(L, shared);
		link_fail(L, "`%.*s` defines shared type `%.*s` differently from `%.*s`", PATH_ARGS(s), key.len, key.s, PATH_ARGS(o));
	}
}

/* The types of a patch's section's globals, functions and natives, against the module's or as the patch gives them. */
static void patch_interface_types( link_ctx *L, link_section *s ) {
	hl_code *c = L->c;
	link_patch *P = L->P;
	for(int i=0;i<s->nglobals && !L->error;i++) {
		int g = s->global_slots[i], type = s->tmap[s->global_types[i]];
		link_text member = s->names[s->global_keys[i]];
		if( g >= c->nglobals ) P->globals[g - c->nglobals].type = type;
		else if( c->globals[g] != c->types + type )
			link_fail(L, "`%.*s` gives global `" KEY_FMT "` another type than the running module has, which needs a reload", PATH_ARGS(s), KEY_ARGS(s->path, member));
	}
	for(int i=0;i<s->nfunctions && !L->error;i++) {
		int slot = s->function_slots[i], type = s->tmap[s->function_types[i]];
		hl_type *t = type_at(L, type);
		link_text member = s->names[s->function_keys[i]];
		if( t->kind != HFUN && t->kind != HMETHOD ) { malformed(L, "a function's type is not a function type"); return; }
		if( slot >= P->slots ) {
			P->added[slot - P->slots].type = type;
			P->added_types[slot - P->slots] = c->types + type;
		} else if( slot_type(L, slot) != c->types + type )
			link_fail(L, "`%.*s` gives function `" KEY_FMT "` another type than the running module has; a changed signature is a renamed slot and a new function", PATH_ARGS(s), KEY_ARGS(s->path, member));
	}
	for(int i=0;i<s->nnatives && !L->error;i++) {
		link_import *n = s->natives + i;
		hl_native *native = c->natives + L->entries[n->resolved].value;
		if( native->t != c->types + s->tmap[n->expected] )
			link_fail(L, "`%.*s` declares native `%.*s@%.*s` with another type than the running module has", PATH_ARGS(s), n->module.len, n->module.s,
				n->member.len, n->member.s);
	}
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
	for(int i=0;i<s->nfunctions;i++) s->fmap[s->nfimports + s->nnatives + i] = L->P ? s->function_slots[i] : s->first_function + i;

	s->gmap = (int*)hl_malloc(&L->tmp, sizeof(int) * (nglob + 1));
	for(int i=0;i<s->ngimports;i++) {
		s->gmap[i] = resolve_import(L, s, s->gimports + i, KEY_GLOBAL);
		if( L->error ) return;
	}
	for(int i=0;i<s->nglobals;i++) s->gmap[s->ngimports + i] = L->P ? s->global_slots[i] : s->first_global + i;
	for(int i=0;i<s->nconstants;i++) s->gmap[s->ngimports + s->nglobals + i] = -1;

	for(int i=0;i<s->ntimports;i++) {
		link_import *im = s->timports + i;
		link_entry *e;
		s->tmap[i] = resolve_import(L, s, im, KEY_TYPE);
		if( L->error ) return;
		e = L->entries + im->resolved;
		if( e->extra != im->expected ) {
			link_section *o = entry_section(L, (int)(e - L->entries));
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
		if( L->P ) L->P->ntrace = 0;
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
		if( L->P ) {
			patch_definition(L, s, i, slot, key, id);
			continue;
		}
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
				link_section *o = entry_section(L, id);
				link_fail(L, "`%.*s` defines shared type `%.*s` differently from `%.*s`", PATH_ARGS(s), key.len, key.s, PATH_ARGS(o));
				return;
			}
		}
	}
	if( L->error ) return;
	L->pos = end;
	if( L->P ) {
		patch_interface_types(L, s);
		s->code_pos = L->pos;
		return;
	}

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
			link_section *o = e->extra < 0 ? &running_module : L->sections + e->extra;
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
			hl_type *defined = L->P ? (function ? slot_type(L, e->value) : global_type(L, e->value))
				: function ? L->ftypes[e->value] : c->globals[e->value];
			if( c->types + s->tmap[im->expected] != defined ) {
				link_section *o = entry_section(L, (int)(e - L->entries));
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
		if( L->P && type_ref(L, key.t) >= c->ntypes ) {
			link_fail(L, "`%.*s` adds a constant of a type the running module does not have, which needs a reload", PATH_ARGS(s));
			return;
		}
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
		if( id < 0 && L->P ) {
			link_patch *P = L->P;
			link_constant *x;
			hl_patch_global *g;
			GROW(P->constants, P->nconstants, P->cconstants);
			GROW(P->globals, P->nglobals, P->cglobals);
			x = P->constants + P->nconstants;
			*x = key;
			x->fields = (int*)hl_malloc(&L->tmp, sizeof(int) * (key.nfields + 1));
			memcpy(x->fields, key.fields, sizeof(int) * key.nfields);
			x->global = c->nglobals + P->nglobals;
			g = P->globals + P->nglobals++;
			g->type = type_ref(L, key.t);
			g->field_count = key.nfields;
			g->fields = (int*)malloc(sizeof(int) * (key.nfields + 1));
			memcpy(g->fields, key.fields, sizeof(int) * key.nfields);
			id = c->nconstants + L->nmore_constants + P->nconstants++;
			table_add(&L->constants, h, id);
		} else if( id < 0 ) {
			hl_constant *added = c->constants + c->nconstants;
			added->global = c->nglobals++;
			added->nfields = key.nfields;
			added->fields = (int*)hl_malloc(&c->alloc, sizeof(int) * (key.nfields + 1));
			memcpy(added->fields, key.fields, sizeof(int) * key.nfields);
			c->globals[added->global] = key.t;
			id = c->nconstants++;
			table_add(&L->constants, h, id);
		}
		s->gmap[s->ngimports + s->nglobals + k] = constant_at(L, id).global;
	}
}

/* Reads one opcode; `falloc` holds its extra operands (a patch's code lives with the patch until the runtime takes it). */
static void read_opcode( link_ctx *L, link_section *s, hl_opcode *o, hl_alloc *falloc ) {
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
	int *debug = (int*)hl_malloc(L->P ? &L->tmp : &L->c->alloc, sizeof(int) * (nops * 2 + 1));
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

/* The operands an opcode's extra array holds, as `read_opcode` reads them. */
static int extra_count( hl_opcode *o ) {
	switch( link_op_nargs[o->op] ) {
	case -1: return o->op == OSwitch ? o->p2 : o->p3;
	case 0: case 1: case 2: case 3: case 4: return 0;
	default: return link_op_nargs[o->op] - 3;
	}
}

static unsigned long long digest_mix( unsigned long long h, unsigned int v ) {
	h = (h ^ v) * 0x9E3779B97F4A7C15ULL;
	return h ^ (h >> 29);
}

/*
	A digest of a function's linked code: its type, registers and opcodes with every operand mapped, not its lines. A patch
	leaves a function whose code has the running one's digest as it runs, so a section re-encoded for one function's edit
	compiles that function alone.
*/
static unsigned long long function_digest( link_ctx *L, hl_function *f ) {
	unsigned long long h = digest_mix(0xCBF29CE484222325ULL, type_ref(L, f->type));
	h = digest_mix(h, (unsigned int)f->nregs);
	for(int k=0;k<f->nregs;k++) h = digest_mix(h, type_ref(L, f->regs[k]));
	h = digest_mix(h, (unsigned int)f->nops);
	for(int k=0;k<f->nops;k++) {
		hl_opcode *o = f->ops + k;
		int n = extra_count(o);
		h = digest_mix(h, (unsigned int)o->op);
		h = digest_mix(h, (unsigned int)o->p1);
		h = digest_mix(h, (unsigned int)o->p2);
		h = digest_mix(h, (unsigned int)o->p3);
		if( link_op_nargs[o->op] == 4 ) h = digest_mix(h, (unsigned int)(int_val)o->extra);
		for(int j=0;j<n;j++) h = digest_mix(h, (unsigned int)o->extra[j]);
	}
	return h;
}

/* The operands of `o` as an HLP function lists them (`hl_patch_read`), which the runtime checks and builds its opcode from. */
static void patch_instruction( hl_opcode *o, hl_patch_instruction *out ) {
	int n = link_op_nargs[o->op], *v;
	out->opcode = o->op;
	if( n == -1 && o->op == OSwitch ) {
		// The register, the table size, its offsets, the end offset.
		out->operand_count = 3 + o->p2;
		v = out->operands = (int*)malloc(sizeof(int) * out->operand_count);
		v[0] = o->p1;
		v[1] = o->p2;
		for(int j=0;j<o->p2;j++) v[2 + j] = o->extra[j];
		v[2 + o->p2] = o->p3;
		return;
	}
	out->operand_count = n == -1 ? 3 + o->p3 : n;
	v = out->operands = (int*)malloc(sizeof(int) * (out->operand_count + 1));
	if( out->operand_count > 0 ) v[0] = o->p1;
	if( out->operand_count > 1 ) v[1] = o->p2;
	if( out->operand_count > 2 ) v[2] = o->p3;
	if( n == 4 ) v[3] = (int)(int_val)o->extra;
	else for(int j=3;j<out->operand_count;j++) v[j] = o->extra[j - 3];
}

/* A function a patch's section defines: left as it runs when its code is the running one's, else carried by the patch. */
static void patch_function( link_ctx *L, link_section *s, int i, hl_function *f ) {
	link_patch *P = L->P;
	unsigned long long digest = function_digest(L, f);
	hl_patch_function *pf;
	link_changed *changed;
	int slot = f->findex;
	if( slot < P->slots && L->digests[slot] == digest ) return;
	GROW(P->functions, P->nfunctions, P->cfunctions);
	P->changed = (link_changed*)grow(P->changed, P->nfunctions, &P->cchanged, sizeof(link_changed));
	pf = P->functions + P->nfunctions;
	changed = P->changed + P->nfunctions++;
	pf->type = type_ref(L, f->type);
	pf->findex = slot;
	pf->register_count = f->nregs;
	pf->registers = (int*)malloc(sizeof(int) * (f->nregs + 1));
	for(int k=0;k<f->nregs;k++) pf->registers[k] = type_ref(L, f->regs[k]);
	pf->instruction_count = f->nops;
	pf->instructions = (hl_patch_instruction*)calloc(f->nops + 1, sizeof(hl_patch_instruction));
	for(int k=0;k<f->nops;k++) patch_instruction(f->ops + k, pf->instructions + k);
	changed->section = L->cur;
	changed->local = i;
	changed->slot = slot;
	changed->digest = digest;
	changed->debug = f->debug;
}

static void read_function( link_ctx *L, link_section *s, int i ) {
	hl_code *c = L->c;
	hl_function patched, *f;
	hl_alloc *falloc = L->P ? &L->tmp : &c->falloc;
	const char *invalid;
	if( L->P ) {
		memset(&patched, 0, sizeof(patched));
		f = &patched;
		f->findex = s->function_slots[i];
		f->type = slot_type(L, f->findex);
	} else {
		f = c->functions + s->first_function + i;
		f->findex = s->first_function + i;
		f->type = L->ftypes[f->findex];
	}
	f->nregs = rd_count(L);
	f->nops = rd_count(L);
	if( L->error ) return;
	f->regs = (hl_type**)hl_malloc(falloc, sizeof(hl_type*) * f->nregs);
	for(int k=0;k<f->nregs && !L->error;k++) f->regs[k] = map_type(L, s);
	f->ops = (hl_opcode*)hl_zalloc(falloc, sizeof(hl_opcode) * f->nops);
	for(int k=0;k<f->nops && !L->error;k++) read_opcode(L, s, f->ops + k, falloc);
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
		f->assigns = (int*)hl_malloc(L->P ? &L->tmp : &c->alloc, sizeof(int) * (f->nassigns * 3 + 1));
		for(int k=0;k<f->nassigns && !L->error;k++) {
			f->assigns[k*3] = s->smap[rd_local(L, s->nstrings, "invalid string index")];
			f->assigns[k*3+1] = rd_index(L) - 1;
			f->assigns[k*3+2] = rd_index(L) - 1;
		}
	}
	if( L->error ) return;
	if( L->P )
		patch_function(L, s, i, f);
	else if( L->keep )
		L->digests[f->findex] = function_digest(L, f);
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

/*
	A patch's section's debug sub-sections: the opcode source spans of the functions the patch carries (kind 2 version 2: by
	the function's index among the section's, each opcode's file, offsets, lines and columns, source hash and flags), and the
	source snapshots (kind 3 version 1), which the patch carries for the debugger.
*/
static void read_patch_debug_sections( link_ctx *L, link_section *s, int first ) {
	link_patch *P = L->P;
	hl_patch *patch = P->patch;
	int count = rd_count(L);
	int *carried = (int*)hl_malloc(&L->tmp, sizeof(int) * (s->nfunctions + 1));
	for(int i=0;i<s->nfunctions;i++) carried[i] = -1;
	for(int k=first;k<P->nfunctions;k++) carried[P->changed[k].local] = k;
	for(int i=0;i<count && !L->error;i++) {
		int kind = rd_uindex(L), version = rd_uindex(L), flags = rd_uindex(L), size = rd_uindex(L), end;
		if( L->error ) return;
		if( kind <= 0 || version <= 0 ) { malformed(L, "invalid debug section header"); return; }
		if( flags != 0 ) { malformed(L, "a compressed debug section"); return; }
		if( size < 0 || size > L->size - L->pos ) { malformed(L, "no more data"); return; }
		end = L->pos + size;
		if( kind == 2 && version == 2 ) {
			int nfiles = rd_count(L), ngroups;
			int *files = (int*)hl_malloc(&L->tmp, sizeof(int) * (nfiles + 1));
			for(int f=0;f<nfiles && !L->error;f++) files[f] = intern_file(L, rd_text(L));
			ngroups = rd_count(L);
			for(int g=0;g<ngroups && !L->error;g++) {
				int fn = rd_local(L, s->nfunctions, "invalid opcode source-span function"), n = rd_count(L);
				hl_patch_function *pf = NULL;
				if( L->error ) return;
				if( carried[fn] >= 0 ) {
					pf = P->functions + carried[fn];
					if( pf->debug_spans == NULL ) {
						pf->debug_count = pf->instruction_count;
						pf->debug_spans = (hl_source_span*)calloc(pf->instruction_count + 1, sizeof(hl_source_span));
						for(int k=0;k<pf->instruction_count;k++) pf->debug_spans[k].file = -1;
					}
				}
				for(int m=0;m<n && !L->error;m++) {
					hl_source_span span;
					int opcode = rd_uindex(L);
					span.file = files[rd_local(L, nfiles, "invalid opcode source-span file")];
					span.start = rd_index(L) - 1;
					span.end = rd_index(L) - 1;
					span.line = rd_uindex(L);
					span.column = rd_uindex(L);
					span.end_line = rd_uindex(L);
					span.end_column = rd_uindex(L);
					span.source_hash = rd_i32(L);
					span.flags = rd_uindex(L);
					if( L->error ) return;
					if( pf == NULL ) continue;
					if( opcode >= pf->instruction_count ) { malformed(L, "invalid opcode source-span opcode"); return; }
					// The runtime's spans start at line 1.
					if( span.line < 1 ) span.line = 1;
					if( span.end_line < span.line ) span.end_line = span.line;
					if( span.column < 1 ) span.column = 1;
					if( span.end_column < 1 ) span.end_column = 1;
					if( span.end_line == span.line && span.end_column < span.column ) span.end_column = span.column;
					pf->debug_spans[opcode] = span;
				}
			}
		} else if( kind == 3 && version == 1 ) {
			int n = rd_count(L);
			for(int k=0;k<n && !L->error;k++) {
				hl_source_snapshot snapshot;
				const unsigned char *content;
				bool known = false;
				snapshot.source_hash = rd_i32(L);
				snapshot.length = rd_uindex(L);
				content = rd_raw(L, snapshot.length);
				if( L->error ) return;
				for(int j=0;j<patch->source_snapshot_count;j++) if( patch->source_snapshots[j].source_hash == snapshot.source_hash ) known = true;
				if( known ) continue;
				snapshot.content = (unsigned char*)malloc(snapshot.length + 1);
				memcpy(snapshot.content, content, snapshot.length);
				patch->source_snapshots = (hl_source_snapshot*)realloc(patch->source_snapshots, sizeof(hl_source_snapshot) * (patch->source_snapshot_count + 1));
				patch->source_snapshots[patch->source_snapshot_count++] = snapshot;
			}
		}
		if( !L->error && L->pos > end ) { malformed(L, "invalid debug section size"); return; }
		L->pos = end;
	}
}

static void read_code( link_ctx *L, int si ) {
	link_section *s = L->sections + si;
	int first = L->P ? L->P->nfunctions : 0;
	L->cur = si;
	L->b = s->data;
	L->size = s->size;
	L->pos = s->code_pos;
	hl_free(&L->scratch);
	hl_alloc_init(&L->scratch);
	read_constants(L, s);
	for(int i=0;i<s->nfunctions && !L->error;i++) read_function(L, s, i);
	if( !L->error ) {
		if( L->P ) read_patch_debug_sections(L, s, first);
		else skip_debug_sections(L);
	}
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
	if( L->keep ) {
		// Slots: the functions, the natives, then the functions patches add.
		L->ndigests = c->nfunctions + c->nnatives + HL_PATCH_FUNCTION_RESERVE;
		L->digests = (unsigned long long*)calloc(L->ndigests, sizeof(unsigned long long));
	}
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

/* What only one link needs: the sections it read, their decoded payloads, and its scratch memory. */
static void link_release_sections( link_ctx *L ) {
	for(int i=0;i<L->nsections;i++) free(L->sections[i].decoded);
	L->sections = NULL;
	L->nsections = 0;
	free(L->ftypes);
	L->ftypes = NULL;
	hl_free(&L->scratch);
	hl_free(&L->tmp);
	hl_alloc_init(&L->scratch);
	hl_alloc_init(&L->tmp);
}

/* A copy of `t` that lives with the link state. */
static link_text keep_text( link_ctx *L, link_text t ) {
	link_text copy;
	char *s = (char*)hl_malloc(&L->kept, t.len + 1);
	memcpy(s, t.s, t.len);
	s[t.len] = 0;
	copy.s = s;
	copy.len = t.len;
	return copy;
}

/* Every key's text, which points into the sections, moves into the state; the keys then belong to the running module. */
static void keep_entries( link_ctx *L, int from ) {
	for(int i=from;i<L->nentries;i++) {
		link_entry *e = L->entries + i;
		e->module = keep_text(L, e->module);
		e->member = keep_text(L, e->member);
		e->section = -1;
		if( e->kind == KEY_NATIVE ) e->extra = -1;
	}
}

static void link_state_free( link_ctx *L ) {
	link_release_sections(L);
	table_free(&L->keys);
	table_free(&L->strings);
	table_free(&L->files);
	table_free(&L->ints);
	table_free(&L->floats);
	table_free(&L->bytes);
	table_free(&L->types);
	table_free(&L->constants);
	free(L->entries);
	free(L->bytes_data);
	free(L->digests);
	free(L->more_constants);
	hl_free(&L->kept);
	hl_free(&L->scratch);
	hl_free(&L->tmp);
	free(L);
}

void hl_code_link_state_free( hl_code *c ) {
	if( c == NULL || c->link_state == NULL ) return;
	link_state_free(c->link_state);
	c->link_state = NULL;
}

static hl_code *code_link( const unsigned char *data, int size, char **error_msg, bool keep ) {
	link_ctx *L = (link_ctx*)calloc(1, sizeof(link_ctx));
	hl_alloc alloc;
	hl_code *c;
	hl_alloc_init(&alloc);
	c = (hl_code*)hl_zalloc(&alloc, sizeof(hl_code));
	c->alloc = alloc;
	hl_alloc_init(&c->falloc);
	hl_alloc_init(&L->tmp);
	hl_alloc_init(&L->scratch);
	hl_alloc_init(&L->kept);
	L->c = c;
	L->cur = -1;
	L->keep = keep;
	link_file(L, data, size);
	if( L->error ) {
		hl_code_destroy(c);
		*error_msg = (char*)L->error;
		link_state_free(L);
		return NULL;
	}
	if( !keep ) {
		link_state_free(L);
		return c;
	}
	keep_entries(L, 0);
	link_release_sections(L);
	c->link_state = L;
	return c;
}

hl_code *hl_code_link( const unsigned char *data, int size, char **error_msg ) {
	return code_link(data, size, error_msg, false);
}

hl_code *hl_code_link_patchable( const unsigned char *data, int size, char **error_msg ) {
	return code_link(data, size, error_msg, true);
}

// ---- patches

/* Drops the ids from `limit` on from a table. */
static void table_drop_from( link_table *t, int limit ) {
	link_table kept;
	table_init(&kept, t->count);
	for(int i=0;i<=t->mask;i++)
		if( t->ids[i] >= 0 && t->ids[i] < limit ) table_add(&kept, t->hashes[i], t->ids[i]);
	table_free(t);
	*t = kept;
}

/* Enters every key again, as renames change them; the first entry whose key another already has, or -1. */
static int rebuild_keys( link_ctx *L ) {
	int duplicate = -1;
	table_free(&L->keys);
	table_init(&L->keys, L->nentries);
	for(int i=0;i<L->nentries;i++) {
		link_entry *e = L->entries + i;
		unsigned int h = key_hash(e->kind, e->module, e->member);
		if( duplicate < 0 && key_find_hashed(L, h, e->kind, e->module, e->member) >= 0 ) duplicate = i;
		table_add(&L->keys, h, i);
	}
	return duplicate;
}

static link_text text_of( const char *s ) {
	link_text t;
	t.s = s ? s : "";
	t.len = s ? (int)strlen(s) : 0;
	return t;
}

/* The patch's renames, before its sections are read, so they find each renamed function, type or global under its new key. */
static void apply_renames( link_ctx *L, hl_patch *patch ) {
	link_patch *P = L->P;
	int duplicate;
	if( patch->rename_count == 0 ) return;
	P->renamed = (int*)malloc(sizeof(int) * patch->rename_count);
	P->renamed_from = (link_text*)malloc(sizeof(link_text) * patch->rename_count);
	for(int k=0;k<patch->rename_count;k++) {
		hl_patch_rename *r = patch->renames + k;
		link_text module = text_of(r->module), from = text_of(r->from);
		int id = key_find(L, KEY_FUNCTION, module, from);
		bool function = id >= 0;
		if( !function ) id = key_find(L, KEY_TYPE, module, from);
		if( id < 0 ) id = key_find(L, KEY_GLOBAL, module, from);
		if( id < 0 ) {
			link_fail(L, "The patch renames `" KEY_FMT "`, which the running module has no function, type or global keyed by", KEY_ARGS(module, from));
			return;
		}
		for(int j=0;j<P->nrenamed;j++)
			if( P->renamed[j] == id ) {
				link_fail(L, "The patch renames `" KEY_FMT "` twice", KEY_ARGS(module, from));
				return;
			}
		P->renamed[P->nrenamed] = id;
		P->renamed_from[P->nrenamed++] = L->entries[id].member;
		r->slot = function ? L->entries[id].value : -1;
	}
	for(int k=0;k<P->nrenamed;k++) L->entries[P->renamed[k]].member = text_of(patch->renames[k].to);
	duplicate = rebuild_keys(L);
	if( duplicate >= 0 ) {
		link_entry *e = L->entries + duplicate;
		link_fail(L, "The patch renames to `" KEY_FMT "`, which another entry of the running module is keyed by", KEY_ARGS(e->module, e->member));
	}
}

/* The tables the patch's sections staged, as the patch carries them; the patch owns them from here, linked or not. */
static void move_to_patch( link_ctx *L, hl_patch *patch ) {
	hl_code *c = L->c;
	link_patch *P = L->P;
	patch->base_int_count = c->nints;
	patch->int_count = P->nints;
	patch->ints = P->ints;
	P->ints = NULL;
	patch->base_float_count = c->nfloats;
	patch->float_count = P->nfloats;
	patch->floats = P->floats;
	P->floats = NULL;
	patch->base_string_count = c->nstrings;
	patch->string_count = P->nstrings;
	patch->strings = (char**)calloc(P->nstrings + 1, sizeof(char*));
	patch->string_lens = (int*)calloc(P->nstrings + 1, sizeof(int));
	for(int k=0;k<P->nstrings;k++) {
		link_text t = P->strings[k];
		patch->strings[k] = (char*)malloc(t.len + 1);
		memcpy(patch->strings[k], t.s, t.len);
		patch->strings[k][t.len] = 0;
		patch->string_lens[k] = t.len;
	}
	patch->base_type_count = c->ntypes;
	patch->type_count = P->ntypes;
	patch->types = P->ptypes;
	P->ptypes = NULL;
	patch->function_count = P->nfunctions;
	patch->functions = P->functions;
	P->functions = NULL;
	patch->added_function_count = P->nadded;
	patch->added_functions = P->added;
	P->added = NULL;
	patch->base_global_count = c->nglobals;
	patch->global_count = P->nglobals;
	patch->globals = P->globals;
	P->globals = NULL;
	patch->object_field_count = P->nfields;
	patch->object_fields = P->fields;
	P->fields = NULL;
	// The patch's new debug files follow the module's; its spans name files by their index in the module (`hl_module_apply_patch`).
	patch->debug_file_count = P->nfiles;
	patch->debug_files = (char**)calloc(P->nfiles + 1, sizeof(char*));
	patch->debug_file_lens = (int*)calloc(P->nfiles + 1, sizeof(int));
	for(int k=0;k<P->nfiles;k++) {
		link_text t = P->files[k];
		patch->debug_files[k] = (char*)malloc(t.len + 1);
		memcpy(patch->debug_files[k], t.s, t.len);
		patch->debug_files[k][t.len] = 0;
		patch->debug_file_lens[k] = t.len;
	}
}

/* Spans for the opcodes the sections' spans leave out, from the functions' line tables. */
static void fill_spans( link_ctx *L, hl_patch *patch ) {
	link_patch *P = L->P;
	for(int k=0;k<patch->function_count;k++) {
		hl_patch_function *pf = patch->functions + k;
		int *debug = P->changed[k].debug;
		if( debug == NULL ) continue;
		if( pf->debug_spans == NULL ) {
			pf->debug_count = pf->instruction_count;
			pf->debug_spans = (hl_source_span*)calloc(pf->instruction_count + 1, sizeof(hl_source_span));
			for(int j=0;j<pf->instruction_count;j++) pf->debug_spans[j].file = -1;
		}
		for(int j=0;j<pf->instruction_count;j++) {
			hl_source_span *span = pf->debug_spans + j;
			if( span->file >= 0 ) continue;
			if( debug[j<<1] < 0 ) {
				// Code with no file at all carries no debug information.
				free(pf->debug_spans);
				pf->debug_spans = NULL;
				pf->debug_count = 0;
				break;
			}
			span->file = debug[j<<1];
			span->line = span->end_line = debug[(j<<1)|1] < 1 ? 1 : debug[(j<<1)|1];
			span->column = span->end_column = 1;
			span->source_hash = 0;
			span->start = span->end = -1;
			span->flags = 0;
		}
	}
}

/* The guards and migrations by key, and the names of the module's globals for a refusal to name a holder. */
static void resolve_patch_keys( link_ctx *L, hl_patch *patch ) {
	int nglobals = 0;
	for(int k=0;k<patch->guard_count && !L->error;k++) {
		hl_patch_guard *g = patch->guards + k;
		link_text module = text_of(g->module), member = text_of(g->member);
		int id = key_find(L, KEY_FUNCTION, module, member);
		if( id < 0 ) { link_fail(L, "The patch guards function `" KEY_FMT "`, which the running module does not have", KEY_ARGS(module, member)); return; }
		g->findex = L->entries[id].value;
	}
	for(int k=0;k<patch->migration_count && !L->error;k++) {
		hl_patch_migration *mg = patch->migrations + k;
		link_text tm = text_of(mg->type_module), tn = text_of(mg->type_member), fm = text_of(mg->function_module), fn = text_of(mg->function_member);
		int type = key_find(L, KEY_TYPE, tm, tn), function = key_find(L, KEY_FUNCTION, fm, fn);
		if( type < 0 ) { link_fail(L, "The patch migrates type `" KEY_FMT "`, which the running module does not have", KEY_ARGS(tm, tn)); return; }
		if( function < 0 ) { link_fail(L, "The patch migrates with function `" KEY_FMT "`, which no section defines", KEY_ARGS(fm, fn)); return; }
		mg->type = L->entries[type].value;
		mg->findex = L->entries[function].value;
	}
	if( patch->guard_count == 0 ) return;
	for(int i=0;i<L->nentries;i++) if( L->entries[i].kind == KEY_GLOBAL && L->entries[i].value < L->c->nglobals ) nglobals++;
	patch->global_name_count = nglobals;
	patch->global_names = (char**)calloc(nglobals + 1, sizeof(char*));
	patch->global_name_indexes = (int*)calloc(nglobals + 1, sizeof(int));
	nglobals = 0;
	for(int i=0;i<L->nentries;i++) {
		link_entry *e = L->entries + i;
		if( e->kind != KEY_GLOBAL || e->value >= L->c->nglobals ) continue;
		patch->global_names[nglobals] = (char*)malloc(e->member.len + 1);
		memcpy(patch->global_names[nglobals], e->member.s, e->member.len);
		patch->global_names[nglobals][e->member.len] = 0;
		patch->global_name_indexes[nglobals++] = e->value;
	}
}

h_bool hl_module_link_patch( hl_module *m, hl_patch *patch, const char **error_msg ) {
	link_ctx *L = m && m->code ? m->code->link_state : NULL;
	link_patch *P;
	hl_code *c;
	if( L == NULL ) { *error_msg = "The module was not loaded to take patches of sections"; return false; }
	if( patch == NULL || patch->linked ) { *error_msg = "No patch, or one already linked"; return false; }
	c = L->c;
	P = (link_patch*)calloc(1, sizeof(link_patch));
	if( P == NULL ) { *error_msg = "Out of memory linking a patch"; return false; }
	P->L = L;
	P->patch = patch;
	P->stamp = ++L->stamp;
	P->base_entries = L->nentries;
	P->base_strings = c->nstrings;
	P->base_ints = c->nints;
	P->base_floats = c->nfloats;
	P->base_files = c->ndebugfiles;
	P->base_types = c->ntypes;
	P->base_constants = c->nconstants + L->nmore_constants;
	P->slots = c->nfunctions + c->nnatives + c->npatchfunctions;
	patch->linked = P;
	L->P = P;
	L->m = m;
	L->error = NULL;
	L->cur = -1;
	L->nsections = patch->section_count;
	L->sections = (link_section*)hl_zalloc(&L->tmp, sizeof(link_section) * (L->nsections + 1));
	for(int i=0;i<L->nsections && !L->error;i++) {
		link_section *s = L->sections + i;
		s->path = text_of(patch->sections[i].path);
		s->data = patch->sections[i].data;
		s->size = patch->sections[i].size;
		if( s->path.len == 0 ) malformed(L, "a section without a module path");
		for(int j=0;j<i && !L->error;j++)
			if( same_text(L->sections[j].path, s->path) ) link_fail(L, "The patch replaces section `%.*s` twice", PATH_ARGS(s));
	}
	if( !L->error ) apply_renames(L, patch);
	for(int i=0;i<L->nsections && !L->error;i++) read_interface(L, i);
	L->cur = -1;
	if( !L->error ) P->added_types = (hl_type**)calloc(P->nadded + 1, sizeof(hl_type*));
	for(int i=0;i<L->nsections && !L->error;i++) read_types(L, i);
	L->cur = -1;
	if( !L->error ) check_imports(L);
	for(int i=0;i<L->nsections && !L->error;i++) read_code(L, i);
	L->cur = -1;
	move_to_patch(L, patch);
	if( !L->error && c->hasdebug ) fill_spans(L, patch);
	if( !L->error ) resolve_patch_keys(L, patch);
	L->P = NULL;
	if( L->error ) {
		*error_msg = L->error;
		hl_link_patch_end(patch, false);
		return false;
	}
	*error_msg = NULL;
	return true;
}

void hl_link_patch_end( hl_patch *patch, bool applied ) {
	link_patch *P = patch ? patch->linked : NULL;
	link_ctx *L;
	hl_code *c;
	if( P == NULL ) return;
	L = P->L;
	c = L->c;
	patch->linked = NULL;
	if( applied ) {
		// The module now holds what the patch staged, under the indices the tables found it at.
		keep_entries(L, P->base_entries);
		for(int k=0;k<P->nrenamed;k++) L->entries[P->renamed[k]].member = keep_text(L, L->entries[P->renamed[k]].member);
		// A structural type naming strings was hashed with the staged names, which the module holds elsewhere now.
		table_drop_from(&L->types, P->base_types);
		for(int k=0;k<P->ntypes;k++)
			if( P->structural[k] ) table_add(&L->types, structural_hash(L, c->types + P->base_types + k), P->base_types + k);
		for(int k=0;k<P->nconstants;k++) {
			link_constant *x = P->constants + k;
			hl_constant *added;
			L->more_constants = (hl_constant*)grow(L->more_constants, L->nmore_constants, &L->more_constants_capacity, sizeof(hl_constant));
			added = L->more_constants + L->nmore_constants++;
			added->global = x->global;
			added->nfields = x->nfields;
			added->fields = (int*)hl_malloc(&L->kept, sizeof(int) * (x->nfields + 1));
			memcpy(added->fields, x->fields, sizeof(int) * x->nfields);
		}
		for(int k=0;k<P->nfunctions;k++)
			if( P->changed[k].slot < L->ndigests ) L->digests[P->changed[k].slot] = P->changed[k].digest;
		if( P->nrenamed ) rebuild_keys(L);
	} else {
		table_drop_from(&L->strings, P->base_strings);
		table_drop_from(&L->ints, P->base_ints);
		table_drop_from(&L->floats, P->base_floats);
		table_drop_from(&L->files, P->base_files);
		table_drop_from(&L->types, P->base_types);
		table_drop_from(&L->constants, P->base_constants);
		for(int k=0;k<P->nrenamed;k++) L->entries[P->renamed[k]].member = P->renamed_from[k];
		L->nentries = P->base_entries;
		rebuild_keys(L);
	}
	free(P->strings);
	free(P->ustrings);
	free(P->ints);
	free(P->floats);
	free(P->files);
	free(P->types);
	free(P->ptypes);
	free(P->structural);
	free(P->constants);
	free(P->globals);
	if( P->added ) for(int k=0;k<P->nadded;k++) free(P->added[k].name);
	free(P->added);
	free(P->added_types);
	free(P->functions);
	free(P->changed);
	free(P->fields);
	free(P->renamed);
	free(P->renamed_from);
	free(P->trace);
	free(P);
	link_release_sections(L);
}
