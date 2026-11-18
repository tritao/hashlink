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
#include <hl.h>
#ifdef HL_VCC
#	pragma warning(disable:4034) // sizeof(void) == 0
#endif

#define H_SIZE_INIT 3

// successive primes that double every time
static int H_PRIMES[] = {
	7,17,37,79,163,331,673,1361,2729,5471,10949,21911,43853,87613,175229,350459,700919,1401857,2803727,5607457,11214943,22429903,44859823,89719661,179424673,373587883,776531401,1611623773
};

#define _MVAL_TYPE vdynamic*

// ----- INT MAP ---------------------------------

typedef struct {
	int key;
} hl_hi_entry;

typedef struct {
	vdynamic *value;
} hl_hi_value;

#define hlt_key		hlt_i32
#define hl_hifilter(key) key
#define hl_hihash(h)	((unsigned)(h))
#define _MKEY_TYPE	int
#define _MNAME(n)	hl_hi##n
#define _MMATCH(c)	m->entries[c].key == key
#define _MKEY(m,c)	m->entries[c].key
#define	_MSET(c)	m->entries[c].key = key
#define _MERASE(c)

#include "maps.h"


// ----- INT64 MAP ---------------------------------

typedef struct {
	int64 key;
} hl_hi64_entry;

typedef struct {
	vdynamic *value;
} hl_hi64_value;

#define hlt_key		hlt_i64
#define hl_hi64filter(key) key
#define hl_hi64hash(h)	(((unsigned int)h) ^ ((unsigned int)(h>>32)))
#define _MKEY_TYPE	int64
#define _MNAME(n)	hl_hi64##n
#define _MMATCH(c)	m->entries[c].key == key
#define _MKEY(m,c)	m->entries[c].key
#define	_MSET(c)	m->entries[c].key = key
#define _MERASE(c)

#include "maps.h"

// ----- BYTES MAP ---------------------------------

// A null key has length -1, so it never matches a string, not even the empty one.
typedef struct {
	unsigned int hash;
	int len;
} hl_hb_entry;

typedef struct {
	uchar *key;
	vdynamic *value;
} hl_hb_value;

#define hlt_key		hlt_bytes
#define hl_hbfilter(key) key
// String keys are hashed with rapidhash over their UTF-16 code units. Maps iterate in insertion order, so the hash
// never shows in a program's behaviour and may change between versions or platforms.
#include "../../include/rapidhash/rapidhash.h"

#if defined(_MSC_VER)
#	include <intrin.h>
static inline int hb_ctz64( uint64_t v ) { unsigned long i; _BitScanForward64(&i,v); return (int)i; }
#else
#	define hb_ctz64(v) __builtin_ctzll(v)
#endif

#if defined(__clang__) || defined(__GNUC__)
#	define HB_NO_ASAN __attribute__((no_sanitize_address))
#else
#	define HB_NO_ASAN
#endif

// The number of code units before the terminating 0, four at a time. Each load is an aligned 8 bytes, which never
// crosses a page boundary, so reading past the terminator inside that word is safe.
static inline HB_NO_ASAN size_t hb_ulen( const uchar *s ) {
#if defined(RAPIDHASH_LITTLE_ENDIAN) && (defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
	const uint64_t ones = 0x0001000100010001ull, highs = 0x8000800080008000ull;
	uintptr_t at = (uintptr_t)s;
	const uint64_t *w = (const uint64_t*)(at & ~(uintptr_t)7);
	// mark the code units before `s` in the first word as non-zero
	uint64_t v;
	memcpy(&v,w,8);
	v |= (1ull << ((at & 7) * 8)) - 1;
	uint64_t zero = (v - ones) & ~v & highs;
	while( !zero ) {
		memcpy(&v,++w,8);
		zero = (v - ones) & ~v & highs;
	}
	return (size_t)(((const char*)w + (hb_ctz64(zero) >> 3) - 1 - (const char*)s) / sizeof(uchar));
#else
	const uchar *p = s;
	while( *p ) p++;
	return (size_t)(p - s);
#endif
}

static unsigned hl_hbhash_n( const uchar *key, int len ) {
	if( len < 0 ) return 0u;
	uint64_t h = rapidhash(key,(size_t)len * sizeof(uchar));
	return (unsigned)(h ^ (h >> 32));
}

#define _MKLEN(key)	((key) == NULL ? -1 : (int)hb_ulen(key))
#define _MHASHN(key,klen)	hl_hbhash_n(key,klen)
#define _MKEY_TYPE	uchar*
#define _MNAME(n)	hl_hb##n
#define _MMATCH(c)	(m->entries[c].hash == hash && m->entries[c].len == klen && (m->values[c].key == key || memcmp(m->values[c].key,key,(size_t)klen * sizeof(uchar)) == 0))
#define _MKEY(m,c)	m->values[c].key
#define	_MSET(c)	m->entries[c].hash = hash; m->entries[c].len = klen; hl_gc_store_ref(&m->values[c].key,key,&hlt_key)
#define _MREHASH(m,c)	((m)->entries[c].hash)
#define _MERASE(c)  hl_gc_store_ref(&m->values[c].key,NULL,&hlt_key)

#include "maps.h"

/*
	The same operations for a caller that already knows the key's length in code units, as a String does: the key is
	neither scanned for its terminator nor compared past it. `key` must still be 0-terminated, since the map keeps it.
*/
#define HB_LEN(key,len) ((key) == NULL ? -1 : (len))

HL_API void hl_hbset_n( void *m, uchar *key, int len, vdynamic *value ) {
	len = HB_LEN(key,len);
	hl_hbprobe_set((hl_hb_map*)m,key,hl_hbhash_n(key,len),len,value);
}

HL_API bool hl_hbexists_n( void *m, uchar *key, int len ) {
	len = HB_LEN(key,len);
	return hl_hbprobe_find((hl_hb_map*)m,key,hl_hbhash_n(key,len),len) != NULL;
}

HL_API vdynamic *hl_hbget_n( void *m, uchar *key, int len ) {
	len = HB_LEN(key,len);
	vdynamic **v = hl_hbprobe_find((hl_hb_map*)m,key,hl_hbhash_n(key,len),len);
	return v == NULL ? NULL : *v;
}

HL_API bool hl_hbremove_n( void *m, uchar *key, int len ) {
	len = HB_LEN(key,len);
	return hl_hbprobe_remove((hl_hb_map*)m,key,hl_hbhash_n(key,len),len);
}

#undef HB_LEN

// ----- OBJECT MAP ---------------------------------

typedef void hl_ho_entry;

typedef struct {
	vdynamic *key;
	vdynamic *value;
} hl_ho_value;

static vdynamic *hl_hofilter( vdynamic *key ) {
	if( key )
		switch( key->t->kind ) {
		// erase virtual (prevent mismatch once virtualized)
		case HVIRTUAL:
			key = hl_virtual_make_value((vvirtual*)key);
			break;
		// store real pointer instead of dynamic wrapper
		case HBYTES:
		case HTYPE:
		case HABSTRACT:
		case HREF:
			key = (vdynamic*)key->v.ptr;
			break;
		default:
			break;
		}
	return key;
}

#define hlt_key		hlt_dyn
#define hl_hohash(key)	((unsigned int)(int_val)(key))
#define _MKEY_TYPE	vdynamic*
#define _MNAME(n)	hl_ho##n
#define _MMATCH(c)	m->values[c].key == key
#define _MKEY(m,c)	m->values[c].key
#define	_MSET(c)	hl_gc_store_ref(&m->values[c].key,key,&hlt_key)
#define _MERASE(c)  hl_gc_store_ref(&m->values[c].key,NULL,&hlt_key)

#include "maps.h"

// ----- LOOKUP MAP ---------------------------------

#undef _MVAL_TYPE
#define _MVAL_TYPE int

typedef struct {
	void *key;
} hl_mlookup__entry;

typedef struct {
	int value;
} hl_mlookup__value;

#define hl_mlookup_hash(h) ((unsigned int)(int_val)(h))
#define _MKEY_TYPE	void*
#define _MNAME(n)	hl_mlookup_##n
#define _MMATCH(c)	m->entries[c].key == key
#define _MKEY(m,c)	m->entries[c].key
#define	_MSET(c)	m->entries[c].key = key
#define _MERASE(c)
#define _MNO_EXPORTS

#include "maps.h"

/// ----------------------------------------------

#define _IMAP _ABSTRACT(hl_int_map)
DEFINE_PRIM( _IMAP, hialloc, _NO_ARG );
DEFINE_PRIM( _VOID, hiset, _IMAP _I32 _DYN );
DEFINE_PRIM( _BOOL, hiexists, _IMAP _I32 );
DEFINE_PRIM( _DYN, higet, _IMAP _I32 );
DEFINE_PRIM( _BOOL, hiremove, _IMAP _I32 );
DEFINE_PRIM( _ARR, hikeys, _IMAP );
DEFINE_PRIM( _ARR, hivalues, _IMAP );
DEFINE_PRIM( _VOID, hiclear, _IMAP );
DEFINE_PRIM( _IMAP, hicopy, _IMAP );
DEFINE_PRIM( _I32, hisize, _IMAP );

#define _I64MAP _ABSTRACT(hl_int64_map)
DEFINE_PRIM( _I64MAP, hi64alloc, _NO_ARG );
DEFINE_PRIM( _VOID, hi64set, _I64MAP _I64 _DYN );
DEFINE_PRIM( _BOOL, hi64exists, _I64MAP _I64 );
DEFINE_PRIM( _DYN, hi64get, _I64MAP _I64 );
DEFINE_PRIM( _BOOL, hi64remove, _I64MAP _I64 );
DEFINE_PRIM( _ARR, hi64keys, _I64MAP );
DEFINE_PRIM( _ARR, hi64values, _I64MAP );
DEFINE_PRIM( _VOID, hi64clear, _I64MAP );
DEFINE_PRIM( _I64MAP, hi64copy, _I64MAP );
DEFINE_PRIM( _I32, hi64size, _I64MAP );

#define _BMAP _ABSTRACT(hl_bytes_map)
DEFINE_PRIM( _BMAP, hballoc, _NO_ARG );
DEFINE_PRIM( _VOID, hbset, _BMAP _BYTES _DYN );
DEFINE_PRIM( _BOOL, hbexists, _BMAP _BYTES );
DEFINE_PRIM( _DYN, hbget, _BMAP _BYTES );
DEFINE_PRIM( _BOOL, hbremove, _BMAP _BYTES );
DEFINE_PRIM( _ARR, hbkeys, _BMAP );
DEFINE_PRIM( _ARR, hbvalues, _BMAP );
DEFINE_PRIM( _VOID, hbclear, _BMAP );
DEFINE_PRIM( _BMAP, hbcopy, _BMAP );
DEFINE_PRIM( _I32, hbsize, _BMAP );

#define _OMAP _ABSTRACT(hl_obj_map)
DEFINE_PRIM( _OMAP, hoalloc, _NO_ARG );
DEFINE_PRIM( _VOID, hoset, _OMAP _DYN _DYN );
DEFINE_PRIM( _BOOL, hoexists, _OMAP _DYN );
DEFINE_PRIM( _DYN, hoget, _OMAP _DYN );
DEFINE_PRIM( _BOOL, horemove, _OMAP _DYN );
DEFINE_PRIM( _ARR, hokeys, _OMAP );
DEFINE_PRIM( _ARR, hovalues, _OMAP );
DEFINE_PRIM( _VOID, hoclear, _OMAP );
DEFINE_PRIM( _OMAP, hocopy, _OMAP );
DEFINE_PRIM( _I32, hosize, _OMAP );
