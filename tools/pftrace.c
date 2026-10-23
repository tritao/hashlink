/*
 * pftrace - minimal streaming writer for Perfetto native-protobuf trace files.
 * See pftrace.h for the API. Packet layout mirrors a trace verified to load in
 * trace_processor v58.2:
 *   TracePacket: timestamp=8, trusted_packet_sequence_id=10, track_event=11,
 *                interned_data=12, sequence_flags=13, trace_packet_defaults=59,
 *                track_descriptor=60, stack_sample=135
 */
#include "pftrace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- protobuf field numbers ------------------------------------------- */

#define F_PKT_TIMESTAMP		8
#define F_PKT_SEQ_ID		10
#define F_PKT_TRACK_EVENT	11
#define F_PKT_INTERNED		12
#define F_PKT_SEQ_FLAGS		13
#define F_PKT_DEFAULTS		59
#define F_PKT_TRACK_DESC	60
#define F_PKT_STACK_SAMPLE	135

#define F_IN_EVENT_NAMES	2
#define F_IN_FUNCTION_NAMES	5
#define F_IN_FRAMES			6
#define F_IN_CALLSTACKS		7
#define F_IN_MAPPING_PATHS	17
#define F_IN_SOURCE_PATHS	18
#define F_IN_MAPPINGS		19
#define F_IN_TASK_CONTEXTS	48

#define SEQ_ID				1
#define SEQ_CLEARED_NEEDS	3
#define SEQ_NEEDS			2

#define PROCESS_UUID		1

/* ---- growable byte buffer ---------------------------------------------- */

typedef struct {
	uint8_t *p;
	size_t len;
	size_t cap;
	int fail;
} pbuf;

static void pb_reserve( pbuf *b, size_t n ) {
	size_t nc;
	uint8_t *np;
	if( b->fail || b->len + n <= b->cap )
		return;
	nc = b->cap ? b->cap : 256;
	while( nc < b->len + n ) {
		if( nc > ((size_t)-1) / 2 ) { b->fail = 1; return; }
		nc *= 2;
	}
	np = (uint8_t*)realloc(b->p, nc);
	if( !np ) { b->fail = 1; return; }
	b->p = np;
	b->cap = nc;
}

static void pb_byte( pbuf *b, unsigned c ) {
	pb_reserve(b, 1);
	if( !b->fail )
		b->p[b->len++] = (uint8_t)c;
}

static void pb_varint( pbuf *b, uint64_t v ) {
	pb_reserve(b, 10);
	if( b->fail ) return;
	while( v >= 0x80 ) {
		b->p[b->len++] = (uint8_t)(v | 0x80);
		v >>= 7;
	}
	b->p[b->len++] = (uint8_t)v;
}

static void pb_bytes( pbuf *b, const void *data, size_t n ) {
	pb_reserve(b, n);
	if( b->fail || n == 0 ) return;
	memcpy(b->p + b->len, data, n);
	b->len += n;
}

static void pb_tag( pbuf *b, unsigned field, unsigned wt ) {
	pb_varint(b, ((uint64_t)field << 3) | wt);
}

/* varint field */
static void pb_vi( pbuf *b, unsigned field, uint64_t v ) {
	pb_tag(b, field, 0);
	pb_varint(b, v);
}

/* length-delimited string/bytes field */
static void pb_str( pbuf *b, unsigned field, const char *s, size_t len ) {
	pb_tag(b, field, 2);
	pb_varint(b, len);
	pb_bytes(b, s, len);
}

/* double field (wire type 1, little endian) */
static void pb_dbl( pbuf *b, unsigned field, double d ) {
	uint64_t u;
	int i;
	memcpy(&u, &d, 8);
	pb_tag(b, field, 1);
	pb_reserve(b, 8);
	if( b->fail ) return;
	for( i = 0; i < 8; i++ )
		b->p[b->len++] = (uint8_t)(u >> (8 * i));
}

/* Nested message: pb_begin writes tag + a 1 byte length placeholder, pb_end patches
   the real (minimal) varint length, shifting the body when it needs more than 1 byte. */
static size_t pb_begin( pbuf *b, unsigned field ) {
	pb_tag(b, field, 2);
	pb_byte(b, 0);
	return b->len ? b->len - 1 : 0;
}

static void pb_end( pbuf *b, size_t at ) {
	size_t n, k, x, i;
	if( b->fail ) return;
	n = b->len - at - 1;
	if( n < 128 ) {
		b->p[at] = (uint8_t)n;
		return;
	}
	k = 1;
	for( x = n >> 7; x; x >>= 7 ) k++;
	pb_reserve(b, k - 1);
	if( b->fail ) return;
	memmove(b->p + at + k, b->p + at + 1, n);
	x = n;
	for( i = 0; i < k; i++ ) {
		b->p[at + i] = (uint8_t)((x & 0x7f) | (i + 1 < k ? 0x80 : 0));
		x >>= 7;
	}
	b->len += k - 1;
}

/* ---- hashing and hash index -------------------------------------------- */

static uint64_t h_final( uint64_t h ) {
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;
	return h;
}

static uint64_t h_bytes( const void *p, size_t n ) {
	const uint8_t *s = (const uint8_t*)p;
	uint64_t h = 0xcbf29ce484222325ULL;
	size_t i;
	for( i = 0; i < n; i++ ) {
		h ^= s[i];
		h *= 0x100000001b3ULL;
	}
	return h_final(h);
}

static uint64_t h_mix( uint64_t h, uint64_t v ) {
	h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h *= 0xff51afd7ed558ccdULL;
	return h ^ (h >> 31);
}

/* Open addressing table of 1-based indexes into an entry array whose entries all
   start with a uint64_t hash. */
typedef struct {
	uint32_t *slot;
	size_t cap;
} hidx;

typedef struct {
	void *p;
	size_t n;
	size_t cap;
} vec;

typedef int (*eq_fn)( const void *entry, const void *key );

static uint64_t entry_hash( const void *base, size_t stride, size_t i ) {
	uint64_t h;
	memcpy(&h, (const char*)base + i * stride, 8);
	return h;
}

/* Returns 1-based index of the matching entry, or 0. */
static size_t hidx_find( const hidx *h, const vec *v, size_t stride, uint64_t hash, eq_fn eq, const void *key ) {
	size_t m, i, k;
	if( !h->cap ) return 0;
	m = h->cap - 1;
	i = (size_t)hash & m;
	while( (k = h->slot[i]) != 0 ) {
		const char *e = (const char*)v->p + (k - 1) * stride;
		if( entry_hash(v->p, stride, k - 1) == hash && eq(e, key) )
			return k;
		i = (i + 1) & m;
	}
	return 0;
}

/* Appends a zeroed entry to v and returns it (NULL on OOM). Index it with hidx_commit. */
static void *vec_push( vec *v, size_t stride ) {
	if( v->n == v->cap ) {
		size_t nc = v->cap ? v->cap * 2 : 64;
		void *np = realloc(v->p, nc * stride);
		if( !np ) return NULL;
		v->p = np;
		v->cap = nc;
	}
	memset((char*)v->p + v->n * stride, 0, stride);
	return (char*)v->p + v->n++ * stride;
}

/* Indexes the entry that was just pushed (the last one). Returns 0 on OOM. */
static int hidx_commit( hidx *h, const vec *v, size_t stride ) {
	size_t n = v->n, m, i, p;
	if( n * 2 > h->cap ) {
		size_t nc = h->cap ? h->cap : 64;
		uint32_t *ns;
		while( nc < n * 2 ) nc <<= 1;
		ns = (uint32_t*)calloc(nc, sizeof(uint32_t));
		if( !ns ) return 0;
		m = nc - 1;
		for( i = 0; i < n; i++ ) {
			p = (size_t)entry_hash(v->p, stride, i) & m;
			while( ns[p] ) p = (p + 1) & m;
			ns[p] = (uint32_t)(i + 1);
		}
		free(h->slot);
		h->slot = ns;
		h->cap = nc;
		return 1;
	}
	m = h->cap - 1;
	p = (size_t)entry_hash(v->p, stride, n - 1) & m;
	while( h->slot[p] ) p = (p + 1) & m;
	h->slot[p] = (uint32_t)n;
	return 1;
}

/* ---- interning tables ---------------------------------------------------- */

typedef struct {
	uint64_t hash;
	char *s;
	size_t len;
} str_entry;

typedef struct { const char *s; size_t len; } str_key;

typedef struct { vec v; hidx h; } strtab;

typedef struct {
	uint64_t hash;
	uint64_t fn, mapping, rel_pc, src;
	uint32_t line;
} frame_entry;

typedef struct {
	uint64_t hash;
	uint64_t path, start, end;
} mapping_entry;

typedef struct {
	uint64_t hash;
	size_t off;
	size_t count;
} stack_entry;

typedef struct { const uint64_t *f; size_t count; } stack_key;

typedef struct {
	uint64_t hash;
	uint64_t uuid;
	uint64_t tc_iid;
	uint64_t stack_uuid;	/* the thread's call-stack track, 0 until used */
	uint32_t tid;
	int emitted;
	char *name;
} thread_entry;

typedef struct {
	uint64_t hash;
	uint64_t uuid;
	char *name;
	size_t len;
} counter_entry;

struct pftrace {
	FILE *f;
	int failed;
	uint32_t pid;
	char *process_name;
	uint64_t last_ts;
	int proc_emitted;
	int seq_started;
	uint64_t next_uuid;
	pbuf pk;	/* packet being built */
	pbuf in;	/* pending InternedData entries */
	strtab event_names, function_names, source_paths, mapping_paths;
	vec frames;		hidx frames_h;
	vec mappings;	hidx mappings_h;
	vec stacks;		hidx stacks_h;
	uint64_t *pool;	size_t pool_n, pool_cap;	/* callstack frame id storage */
	vec threads;	hidx threads_h;
	vec counters;	hidx counters_h;
	uint64_t next_tc_iid;
};

static void fail( pftrace *t ) {
	t->failed = 1;
}

static char *dup_bytes( const char *s, size_t len ) {
	char *r = (char*)malloc(len + 1);
	if( !r ) return NULL;
	if( len ) memcpy(r, s, len);
	r[len] = 0;
	return r;
}

static int eq_str( const void *e, const void *k ) {
	const str_entry *a = (const str_entry*)e;
	const str_key *b = (const str_key*)k;
	return a->len == b->len && (b->len == 0 || memcmp(a->s, b->s, b->len) == 0);
}

/* Interns a string in tab. When new, the InternedString is appended to t->in under
   the given InternedData field. Returns the (nonzero) iid, or 0 on failure. */
static uint64_t intern_str( pftrace *t, strtab *tab, unsigned field, const char *s ) {
	str_key key;
	uint64_t h;
	size_t k;
	str_entry *e;
	size_t at;
	if( !s ) s = "";
	key.s = s;
	key.len = strlen(s);
	h = h_bytes(s, key.len);
	k = hidx_find(&tab->h, &tab->v, sizeof(str_entry), h, eq_str, &key);
	if( k ) return k;
	e = (str_entry*)vec_push(&tab->v, sizeof(str_entry));
	if( !e ) { fail(t); return 0; }
	e->hash = h;
	e->len = key.len;
	e->s = dup_bytes(s, key.len);
	if( !e->s || !hidx_commit(&tab->h, &tab->v, sizeof(str_entry)) ) { fail(t); return 0; }
	at = pb_begin(&t->in, field);
	pb_vi(&t->in, 1, tab->v.n);
	pb_str(&t->in, 2, s, key.len);
	pb_end(&t->in, at);
	return tab->v.n;
}

static void strtab_free( strtab *tab ) {
	size_t i;
	str_entry *e = (str_entry*)tab->v.p;
	for( i = 0; i < tab->v.n; i++ )
		free(e[i].s);
	free(tab->v.p);
	free(tab->h.slot);
}

/* ---- packet emission ------------------------------------------------------ */

static void pkt_begin( pftrace *t, uint64_t ts ) {
	t->pk.len = 0;
	pb_vi(&t->pk, F_PKT_TIMESTAMP, ts);
	t->last_ts = ts;
}

static void write_packet( pftrace *t ) {
	uint8_t hb[16];
	size_t n = 0;
	uint64_t v = t->pk.len;
	if( t->pk.fail || t->in.fail ) { fail(t); return; }
	hb[n++] = 0x0A;
	while( v >= 0x80 ) {
		hb[n++] = (uint8_t)(v | 0x80);
		v >>= 7;
	}
	hb[n++] = (uint8_t)v;
	if( fwrite(hb, 1, n, t->f) != n || fwrite(t->pk.p, 1, t->pk.len, t->f) != t->pk.len )
		fail(t);
}

/* Finishes the packet in t->pk. seq=1 attaches the sequence id/flags, pending interned
   data and (once) the stack sample defaults. */
static void pkt_finish( pftrace *t, int seq ) {
	if( seq ) {
		size_t a;
		if( t->in.len ) {
			a = pb_begin(&t->pk, F_PKT_INTERNED);
			pb_bytes(&t->pk, t->in.p, t->in.len);
			pb_end(&t->pk, a);
			t->in.len = 0;
		}
		if( !t->seq_started ) {
			/* TracePacketDefaults{ stack_sample_defaults(100){ source, primary_descriptor{name, unit} } } */
			size_t d = pb_begin(&t->pk, F_PKT_DEFAULTS);
			size_t s = pb_begin(&t->pk, 100);
			size_t p;
			pb_str(&t->pk, 1, "haxeon", 6);
			p = pb_begin(&t->pk, 2);
			pb_str(&t->pk, 2, "wall-time", 9);
			pb_vi(&t->pk, 3, 1);	/* UNIT_NANOSECONDS */
			pb_end(&t->pk, p);
			pb_end(&t->pk, s);
			pb_end(&t->pk, d);
		}
		pb_vi(&t->pk, F_PKT_SEQ_ID, SEQ_ID);
		pb_vi(&t->pk, F_PKT_SEQ_FLAGS, t->seq_started ? SEQ_NEEDS : SEQ_CLEARED_NEEDS);
		t->seq_started = 1;
	}
	write_packet(t);
}

static void emit_process( pftrace *t, uint64_t ts ) {
	size_t a, p;
	t->proc_emitted = 1;
	pkt_begin(t, ts);
	a = pb_begin(&t->pk, F_PKT_TRACK_DESC);
	pb_vi(&t->pk, 1, PROCESS_UUID);
	p = pb_begin(&t->pk, 3);
	pb_vi(&t->pk, 1, t->pid);
	pb_str(&t->pk, 6, t->process_name, strlen(t->process_name));
	pb_end(&t->pk, p);
	pb_end(&t->pk, a);
	pkt_finish(t, 0);
}

static void ensure_process( pftrace *t, uint64_t ts ) {
	if( !t->proc_emitted )
		emit_process(t, ts);
}

static void emit_thread( pftrace *t, thread_entry *th, uint64_t ts ) {
	size_t a, p;
	ensure_process(t, ts);
	th->emitted = 1;
	pkt_begin(t, ts);
	a = pb_begin(&t->pk, F_PKT_TRACK_DESC);
	pb_vi(&t->pk, 1, th->uuid);
	p = pb_begin(&t->pk, 4);
	pb_vi(&t->pk, 1, t->pid);
	pb_vi(&t->pk, 2, th->tid);
	pb_str(&t->pk, 5, th->name, strlen(th->name));
	pb_end(&t->pk, p);
	pb_vi(&t->pk, 5, PROCESS_UUID);
	pb_end(&t->pk, a);
	pkt_finish(t, 0);
}

/* ---- threads ------------------------------------------------------------------ */

static int eq_thread( const void *e, const void *k ) {
	return ((const thread_entry*)e)->tid == *(const uint32_t*)k;
}

static thread_entry *thread_get( pftrace *t, uint32_t tid, int create ) {
	uint64_t h = h_final(tid);
	size_t k = hidx_find(&t->threads_h, &t->threads, sizeof(thread_entry), h, eq_thread, &tid);
	thread_entry *e;
	if( k ) return (thread_entry*)t->threads.p + (k - 1);
	if( !create ) return NULL;
	e = (thread_entry*)vec_push(&t->threads, sizeof(thread_entry));
	if( !e ) { fail(t); return NULL; }
	e->hash = h;
	e->tid = tid;
	e->uuid = t->next_uuid++;
	if( !hidx_commit(&t->threads_h, &t->threads, sizeof(thread_entry)) ) { fail(t); return NULL; }
	return e;
}

/* Returns the thread entry with its descriptor emitted (named "Thread <tid>" if needed). */
static thread_entry *thread_ready( pftrace *t, uint32_t tid, uint64_t ts ) {
	thread_entry *e = thread_get(t, tid, 1);
	if( !e ) return NULL;
	if( !e->name ) {
		char buf[32];
		snprintf(buf, sizeof(buf), "Thread %lu", (unsigned long)tid);
		e->name = dup_bytes(buf, strlen(buf));
		if( !e->name ) { fail(t); return NULL; }
	}
	if( !e->emitted )
		emit_thread(t, e, ts);
	return t->failed ? NULL : e;
}

/* ---- public API ------------------------------------------------------------------- */

pftrace *pftrace_open( const char *path, uint32_t pid, const char *process_name ) {
	pftrace *t;
	if( !path || !pid )
		return NULL;
	t = (pftrace*)calloc(1, sizeof(pftrace));
	if( !t ) return NULL;
	t->pid = pid;
	t->process_name = dup_bytes(process_name ? process_name : "", process_name ? strlen(process_name) : 0);
#if defined(_MSC_VER)
	if( fopen_s(&t->f, path, "wb") != 0 )
		t->f = NULL;
#else
	t->f = fopen(path, "wb");
#endif
	if( !t->process_name || !t->f ) {
		if( t->f ) fclose(t->f);
		free(t->process_name);
		free(t);
		return NULL;
	}
	setvbuf(t->f, NULL, _IOFBF, 1 << 20);
	t->next_uuid = PROCESS_UUID + 1;
	t->next_tc_iid = 1;
	return t;
}

int pftrace_close( pftrace *t ) {
	size_t i;
	int ok;
	if( !t ) return 0;
	if( !t->failed ) {
		/* make sure named-but-unused threads and the process still appear */
		ensure_process(t, t->last_ts);
		for( i = 0; i < t->threads.n && !t->failed; i++ ) {
			thread_entry *e = (thread_entry*)t->threads.p + i;
			if( e->name && !e->emitted )
				emit_thread(t, e, t->last_ts);
		}
	}
	ok = !t->failed;
	if( fflush(t->f) != 0 ) ok = 0;
	if( fclose(t->f) != 0 ) ok = 0;
	for( i = 0; i < t->threads.n; i++ )
		free(((thread_entry*)t->threads.p)[i].name);
	for( i = 0; i < t->counters.n; i++ )
		free(((counter_entry*)t->counters.p)[i].name);
	strtab_free(&t->event_names);
	strtab_free(&t->function_names);
	strtab_free(&t->source_paths);
	strtab_free(&t->mapping_paths);
	free(t->frames.p);		free(t->frames_h.slot);
	free(t->mappings.p);	free(t->mappings_h.slot);
	free(t->stacks.p);		free(t->stacks_h.slot);
	free(t->pool);
	free(t->threads.p);		free(t->threads_h.slot);
	free(t->counters.p);	free(t->counters_h.slot);
	free(t->pk.p);
	free(t->in.p);
	free(t->process_name);
	free(t);
	return ok;
}

void pftrace_thread( pftrace *t, uint32_t tid, const char *name ) {
	thread_entry *e;
	char *nn;
	if( !t || t->failed || !tid ) return;
	if( !name ) name = "";
	e = thread_get(t, tid, 1);
	if( !e ) return;
	if( e->name && strcmp(e->name, name) == 0 )
		return;
	nn = dup_bytes(name, strlen(name));
	if( !nn ) { fail(t); return; }
	free(e->name);
	e->name = nn;
	/* first emission is lazy (stamped with the first event); a rename re-emits right away */
	if( e->emitted )
		emit_thread(t, e, t->last_ts);
}

static uint64_t track_for( pftrace *t, uint32_t tid, uint64_t ts ) {
	thread_entry *e;
	if( !tid ) {
		ensure_process(t, ts);
		return PROCESS_UUID;
	}
	e = thread_ready(t, tid, ts);
	return e ? e->uuid : 0;
}

/* The thread's call-stack track: a child of its thread track, so it shows inside the thread's group. */
static uint64_t stack_track_for( pftrace *t, uint32_t tid, uint64_t ts ) {
	thread_entry *e = thread_ready(t, tid, ts);
	size_t a;
	if( !e ) return 0;
	if( !e->stack_uuid ) {
		e->stack_uuid = t->next_uuid++;
		pkt_begin(t, ts);
		a = pb_begin(&t->pk, F_PKT_TRACK_DESC);
		pb_vi(&t->pk, 1, e->stack_uuid);
		pb_str(&t->pk, 2, "Call stacks", 11);
		pb_vi(&t->pk, 5, e->uuid);
		pb_end(&t->pk, a);
		pkt_finish(t, 0);
	}
	return e->stack_uuid;
}

static void slice_begin( pftrace *t, uint64_t ts_ns, uint64_t uuid, const char *name, const char *category ) {
	uint64_t nid;
	size_t a;
	nid = intern_str(t, &t->event_names, F_IN_EVENT_NAMES, name);
	if( t->failed ) return;
	pkt_begin(t, ts_ns);
	a = pb_begin(&t->pk, F_PKT_TRACK_EVENT);
	pb_vi(&t->pk, 9, 1);	/* TYPE_SLICE_BEGIN */
	pb_vi(&t->pk, 11, uuid);
	pb_vi(&t->pk, 10, nid);
	if( category )
		pb_str(&t->pk, 22, category, strlen(category));
	pb_end(&t->pk, a);
	pkt_finish(t, 1);
}

static void slice_end( pftrace *t, uint64_t ts_ns, uint64_t uuid ) {
	size_t a;
	pkt_begin(t, ts_ns);
	a = pb_begin(&t->pk, F_PKT_TRACK_EVENT);
	pb_vi(&t->pk, 9, 2);	/* TYPE_SLICE_END */
	pb_vi(&t->pk, 11, uuid);
	pb_end(&t->pk, a);
	pkt_finish(t, 1);
}

void pftrace_slice_begin( pftrace *t, uint64_t ts_ns, uint32_t tid, const char *name, const char *category ) {
	uint64_t uuid;
	if( !t || t->failed ) return;
	uuid = track_for(t, tid, ts_ns);
	if( !t->failed ) slice_begin(t, ts_ns, uuid, name, category);
}

void pftrace_slice_end( pftrace *t, uint64_t ts_ns, uint32_t tid ) {
	uint64_t uuid;
	if( !t || t->failed ) return;
	uuid = track_for(t, tid, ts_ns);
	if( !t->failed ) slice_end(t, ts_ns, uuid);
}

void pftrace_stack_begin( pftrace *t, uint64_t ts_ns, uint32_t tid, const char *name ) {
	uint64_t uuid;
	if( !t || t->failed || !tid ) return;
	uuid = stack_track_for(t, tid, ts_ns);
	if( !t->failed ) slice_begin(t, ts_ns, uuid, name, "hl.stack");
}

void pftrace_stack_end( pftrace *t, uint64_t ts_ns, uint32_t tid ) {
	uint64_t uuid;
	if( !t || t->failed || !tid ) return;
	uuid = stack_track_for(t, tid, ts_ns);
	if( !t->failed ) slice_end(t, ts_ns, uuid);
}

void pftrace_instant( pftrace *t, uint64_t ts_ns, uint32_t tid, const char *name ) {
	uint64_t uuid, nid;
	size_t a;
	if( !t || t->failed ) return;
	uuid = track_for(t, tid, ts_ns);
	nid = intern_str(t, &t->event_names, F_IN_EVENT_NAMES, name);
	if( t->failed ) return;
	pkt_begin(t, ts_ns);
	a = pb_begin(&t->pk, F_PKT_TRACK_EVENT);
	pb_vi(&t->pk, 9, 3);	/* TYPE_INSTANT */
	pb_vi(&t->pk, 11, uuid);
	pb_vi(&t->pk, 10, nid);
	pb_end(&t->pk, a);
	pkt_finish(t, 1);
}

static int eq_counter( const void *e, const void *k ) {
	const counter_entry *a = (const counter_entry*)e;
	const str_key *b = (const str_key*)k;
	return a->len == b->len && (b->len == 0 || memcmp(a->name, b->s, b->len) == 0);
}

void pftrace_counter( pftrace *t, uint64_t ts_ns, const char *track_name, const char *unit, double value ) {
	str_key key;
	uint64_t h;
	size_t k, a, c;
	counter_entry *e;
	uint64_t uuid;
	if( !t || t->failed ) return;
	if( !track_name ) track_name = "";
	key.s = track_name;
	key.len = strlen(track_name);
	h = h_bytes(track_name, key.len);
	ensure_process(t, ts_ns);
	k = hidx_find(&t->counters_h, &t->counters, sizeof(counter_entry), h, eq_counter, &key);
	if( k ) {
		uuid = ((counter_entry*)t->counters.p)[k - 1].uuid;
	} else {
		e = (counter_entry*)vec_push(&t->counters, sizeof(counter_entry));
		if( !e ) { fail(t); return; }
		e->hash = h;
		e->len = key.len;
		e->uuid = uuid = t->next_uuid++;
		e->name = dup_bytes(track_name, key.len);
		if( !e->name || !hidx_commit(&t->counters_h, &t->counters, sizeof(counter_entry)) ) { fail(t); return; }
		/* counter track descriptor: parent = process track */
		pkt_begin(t, ts_ns);
		a = pb_begin(&t->pk, F_PKT_TRACK_DESC);
		pb_vi(&t->pk, 1, uuid);
		pb_str(&t->pk, 2, track_name, key.len);
		pb_vi(&t->pk, 5, PROCESS_UUID);
		c = pb_begin(&t->pk, 8);
		if( unit ) {
			if( strcmp(unit, "bytes") == 0 ) pb_vi(&t->pk, 3, 3);		/* UNIT_SIZE_BYTES */
			else if( strcmp(unit, "ns") == 0 ) pb_vi(&t->pk, 3, 1);	/* UNIT_TIME_NS */
			pb_str(&t->pk, 6, unit, strlen(unit));
		}
		pb_end(&t->pk, c);
		pb_end(&t->pk, a);
		pkt_finish(t, 0);
	}
	if( t->failed ) return;
	pkt_begin(t, ts_ns);
	a = pb_begin(&t->pk, F_PKT_TRACK_EVENT);
	pb_vi(&t->pk, 9, 4);	/* TYPE_COUNTER */
	pb_vi(&t->pk, 11, uuid);
	pb_dbl(&t->pk, 44, value);
	pb_end(&t->pk, a);
	pkt_finish(t, 1);
}

static int eq_mapping( const void *e, const void *k ) {
	const mapping_entry *a = (const mapping_entry*)e;
	const mapping_entry *b = (const mapping_entry*)k;
	return a->path == b->path && a->start == b->start;
}

uint64_t pftrace_mapping( pftrace *t, const char *path, uint64_t start, uint64_t end ) {
	mapping_entry key, *e;
	size_t k, a;
	uint64_t pid;
	if( !t || t->failed ) return 0;
	pid = intern_str(t, &t->mapping_paths, F_IN_MAPPING_PATHS, path);
	if( !pid ) return 0;
	key.path = pid;
	key.start = start;
	key.hash = h_mix(h_mix(0x1234, pid), start);
	k = hidx_find(&t->mappings_h, &t->mappings, sizeof(mapping_entry), key.hash, eq_mapping, &key);
	if( k ) return k;
	e = (mapping_entry*)vec_push(&t->mappings, sizeof(mapping_entry));
	if( !e ) { fail(t); return 0; }
	*e = key;
	e->end = end;
	if( !hidx_commit(&t->mappings_h, &t->mappings, sizeof(mapping_entry)) ) { fail(t); return 0; }
	a = pb_begin(&t->in, F_IN_MAPPINGS);
	pb_vi(&t->in, 1, t->mappings.n);
	pb_vi(&t->in, 4, start);
	pb_vi(&t->in, 5, end);
	pb_vi(&t->in, 7, pid);
	pb_end(&t->in, a);
	return t->mappings.n;
}

static int eq_frame( const void *e, const void *k ) {
	const frame_entry *a = (const frame_entry*)e;
	const frame_entry *b = (const frame_entry*)k;
	return a->fn == b->fn && a->mapping == b->mapping && a->rel_pc == b->rel_pc && a->src == b->src && a->line == b->line;
}

uint64_t pftrace_frame( pftrace *t, const char *function, uint64_t mapping_id, uint64_t rel_pc, const char *source_file, uint32_t line ) {
	frame_entry key, *e;
	size_t k, a;
	if( !t || t->failed ) return 0;
	memset(&key, 0, sizeof(key));
	if( mapping_id > t->mappings.n ) mapping_id = 0;
	key.fn = intern_str(t, &t->function_names, F_IN_FUNCTION_NAMES, function ? function : "<unknown>");
	if( source_file )
		key.src = intern_str(t, &t->source_paths, F_IN_SOURCE_PATHS, source_file);
	if( t->failed ) return 0;
	key.mapping = mapping_id;
	key.rel_pc = mapping_id ? rel_pc : 0;
	key.line = source_file ? line : 0;
	key.hash = h_mix(h_mix(h_mix(h_mix(key.fn, key.mapping), key.rel_pc), key.src), key.line);
	k = hidx_find(&t->frames_h, &t->frames, sizeof(frame_entry), key.hash, eq_frame, &key);
	if( k ) return k;
	e = (frame_entry*)vec_push(&t->frames, sizeof(frame_entry));
	if( !e ) { fail(t); return 0; }
	*e = key;
	if( !hidx_commit(&t->frames_h, &t->frames, sizeof(frame_entry)) ) { fail(t); return 0; }
	a = pb_begin(&t->in, F_IN_FRAMES);
	pb_vi(&t->in, 1, t->frames.n);
	pb_vi(&t->in, 2, key.fn);
	if( key.mapping ) {
		pb_vi(&t->in, 3, key.mapping);
		pb_vi(&t->in, 4, key.rel_pc);	/* must be present whenever mapping_id is set */
	}
	if( key.src ) {
		pb_vi(&t->in, 5, key.src);
		pb_vi(&t->in, 6, key.line);
	}
	pb_end(&t->in, a);
	return t->frames.n;
}

static size_t stack_find( pftrace *t, uint64_t hash, const stack_key *key ) {
	size_t m, i, k;
	if( !t->stacks_h.cap ) return 0;
	m = t->stacks_h.cap - 1;
	i = (size_t)hash & m;
	while( (k = t->stacks_h.slot[i]) != 0 ) {
		const stack_entry *e = (const stack_entry*)t->stacks.p + (k - 1);
		if( e->hash == hash && e->count == key->count && memcmp(t->pool + e->off, key->f, key->count * sizeof(uint64_t)) == 0 )
			return k;
		i = (i + 1) & m;
	}
	return 0;
}

static uint64_t intern_stack( pftrace *t, const uint64_t *frames, size_t count ) {
	stack_key key;
	stack_entry *e;
	uint64_t h = 0x57ac;
	size_t i, k, a;
	key.f = frames;
	key.count = count;
	for( i = 0; i < count; i++ )
		h = h_mix(h, frames[i]);
	h = h_mix(h, count);
	k = stack_find(t, h, &key);
	if( k ) return k;
	if( t->pool_n + count > t->pool_cap ) {
		size_t nc = t->pool_cap ? t->pool_cap : 1024;
		uint64_t *np;
		while( nc < t->pool_n + count ) nc *= 2;
		np = (uint64_t*)realloc(t->pool, nc * sizeof(uint64_t));
		if( !np ) { fail(t); return 0; }
		t->pool = np;
		t->pool_cap = nc;
	}
	e = (stack_entry*)vec_push(&t->stacks, sizeof(stack_entry));
	if( !e ) { fail(t); return 0; }
	e->hash = h;
	e->off = t->pool_n;
	e->count = count;
	memcpy(t->pool + t->pool_n, frames, count * sizeof(uint64_t));
	t->pool_n += count;
	if( !hidx_commit(&t->stacks_h, &t->stacks, sizeof(stack_entry)) ) { fail(t); return 0; }
	a = pb_begin(&t->in, F_IN_CALLSTACKS);
	pb_vi(&t->in, 1, t->stacks.n);
	for( i = 0; i < count; i++ )
		pb_vi(&t->in, 2, frames[i]);	/* unpacked repeated, root first */
	pb_end(&t->in, a);
	return t->stacks.n;
}

void pftrace_sample( pftrace *t, uint64_t ts_ns, uint32_t tid, const uint64_t *frames_root_first, uint32_t count, uint64_t weight_ns ) {
	thread_entry *th;
	uint64_t cs;
	uint32_t i;
	size_t a;
	if( !t || t->failed || !tid || !count || !frames_root_first ) return;
	for( i = 0; i < count; i++ )
		if( frames_root_first[i] == 0 || frames_root_first[i] > t->frames.n )
			return;	/* unknown frame id: drop the sample */
	th = thread_ready(t, tid, ts_ns);
	if( !th ) return;
	if( !th->tc_iid ) {
		th->tc_iid = t->next_tc_iid++;
		a = pb_begin(&t->in, F_IN_TASK_CONTEXTS);
		pb_vi(&t->in, 1, th->tc_iid);
		pb_vi(&t->in, 2, t->pid);
		pb_vi(&t->in, 3, tid);
		pb_end(&t->in, a);
	}
	cs = intern_stack(t, frames_root_first, count);
	if( !cs ) return;
	pkt_begin(t, ts_ns);
	a = pb_begin(&t->pk, F_PKT_STACK_SAMPLE);
	pb_vi(&t->pk, 2, th->tc_iid);
	pb_vi(&t->pk, 6, cs);
	pb_vi(&t->pk, 11, weight_ns);
	pb_end(&t->pk, a);
	pkt_finish(t, 1);
}
