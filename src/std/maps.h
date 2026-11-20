#ifdef _MNO_EXPORTS
#define _MVALUE_LAYOUT hlt_i32
#else
#define _MVALUE_LAYOUT hlt_dyn
#endif

/*
	Entries live in insertion order in `entries`/`values`, appended at `nused`. Each hash cell heads a chain
	through `nexts`. A removed entry stays in place as a tombstone (`nexts[c] == _MDEAD`) until the next
	rebuild compacts the storage, so iteration order is insertion order and never depends on the hash.
*/

#undef t_map
#undef t_entry
#undef t_value
#undef t_key
#define t_key _MKEY_TYPE
#define t_map _MNAME(_map)
#define t_entry _MNAME(_entry)
#define t_value _MNAME(_value)
#define _MLIMIT 128
#define _MDEAD (-2)
#define _MSMALL(m) ((m)->maxentries < _MLIMIT)
#define _MINDEX(m,ckey) (_MSMALL(m) ? (int)((signed char*)(m)->cells)[ckey] : ((int*)(m)->cells)[ckey])
#define _MNEXT(m,c) (_MSMALL(m) ? (int)((signed char*)(m)->nexts)[c] : ((int*)(m)->nexts)[c])
#define _MSETINDEX(m,ckey,v) if( _MSMALL(m) ) ((signed char*)(m)->cells)[ckey] = (signed char)(v); else ((int*)(m)->cells)[ckey] = (v)
#define _MSETNEXT(m,c,v) if( _MSMALL(m) ) ((signed char*)(m)->nexts)[c] = (signed char)(v); else ((int*)(m)->nexts)[c] = (v)
#define _MLIVE(m,c) (_MNEXT(m,c) != _MDEAD)
#ifndef _MREHASH
#define _MREHASH(m,c) _MNAME(hash)(_MKEY(m,c))
#endif
/*
	A probe carries the key, its hash and its length. Only string keys have a length: `_MKLEN` measures it once per
	operation, `_MHASHN` hashes with it and `_MMATCH`/`_MSET` may read it as `klen`. Other keys leave it 0.
*/
#ifndef _MKLEN
#define _MKLEN(key) 0
#endif
#ifndef _MHASHN
#define _MHASHN(key,klen) _MNAME(hash)(key)
#endif
#ifdef _MNO_EXPORTS
#define _MSTATIC
#else
#define _MSTATIC static
#endif

typedef struct {
	void *cells;
	void *nexts;
	t_entry *entries;
	t_value *values;
	int ncells;
	int nentries;	// live entries
	int nused;		// entries and tombstones, in insertion order
	int maxentries;
} t_map;

#ifndef _MNO_EXPORTS
HL_PRIM
#endif
t_map *_MNAME(alloc)() {
	t_map *m = (t_map*)hl_gc_alloc_raw(sizeof(t_map));
	hl_gc_clear_values(m,sizeof(t_map),&hlt_bytes);
	return m;
}

static _MVAL_TYPE *_MNAME(probe_find)( t_map *m, t_key key, unsigned int hash, int klen ) {
	int c, ckey;
	(void)klen;
	if( !m->values ) return NULL;
	ckey = hash % ((unsigned)m->ncells);
	c = _MINDEX(m,ckey);
	while( c >= 0 ) {
		if( _MMATCH(c) )
			return &m->values[c].value;
		c = _MNEXT(m,c);
	}
	return NULL;
}

_MSTATIC _MVAL_TYPE *_MNAME(find)( t_map *m, t_key key ) {
	int klen = _MKLEN(key);
	return _MNAME(probe_find)(m,key,_MHASHN(key,klen),klen);
}

// Moves the live entries, in order, into storage for `maxentries` entries and relinks the chains.
static void _MNAME(rebuild)( t_map *m, int maxentries ) {
	t_map old = *m, *o = &old;
	int i = 0, n = 0, c;
	int ncells = maxentries;
	while( H_PRIMES[i] < ncells ) i++;
	ncells = H_PRIMES[i];

	int ksize = maxentries < _MLIMIT ? 1 : sizeof(int);
	// The storage goes where the map is, not to the current arena: a map that outlives an arena can grow inside one.
	void *home = hl_gc_arena_owner_of(m);
	hl_gc_store_ref(&m->entries,(t_entry*)hl_gc_alloc_gen_owner(&hlt_bytes,maxentries * sizeof(t_entry),MEM_KIND_NOPTR,home),&hlt_bytes);
	hl_gc_store_ref(&m->values,(t_value*)hl_gc_alloc_gen_owner(&hlt_abstract,maxentries * sizeof(t_value),MEM_KIND_RAW,home),&hlt_bytes);
	hl_gc_store_ref(&m->cells,hl_gc_alloc_gen_owner(&hlt_bytes,(ncells + maxentries) * ksize,MEM_KIND_NOPTR,home),&hlt_bytes);
	hl_gc_store_ref(&m->nexts,(signed char*)m->cells + ncells * ksize,&hlt_bytes);
	m->ncells = ncells;
	m->maxentries = maxentries;
	memset(m->cells,0xFF,ncells * ksize);
	memset(m->values,0,maxentries * sizeof(t_value));
	for(c=0;c<o->nused;c++) {
		if( !_MLIVE(o,c) ) continue;
		unsigned int hash = _MREHASH(o,c);
		int ckey = hash % ((unsigned)ncells);
		memcpy((char*)m->entries + n * sizeof(t_entry),(char*)o->entries + c * sizeof(t_entry),sizeof(t_entry));
		m->values[n] = o->values[c];
		_MSETNEXT(m,n,_MINDEX(m,ckey));
		_MSETINDEX(m,ckey,n);
		n++;
	}
	hl_gc_record_write(m->values,maxentries * sizeof(t_value));
	m->nused = n;
	m->nentries = n;
}

// Called when every slot is used: compacts if enough are tombstones, grows otherwise.
static void _MNAME(make_room)( t_map *m ) {
	int max = m->maxentries;
	if( max == 0 )
		max = H_SIZE_INIT;
	else if( m->nentries * 4 > max * 3 )
		max = ((max * 3) + 1) >> 1;
	_MNAME(rebuild)(m,max);
}

static void _MNAME(probe_set)( t_map *m, t_key key, unsigned int hash, int klen, _MVAL_TYPE value ) {
	int c, ckey;
	(void)klen;
	if( m->values ) {
		ckey = hash % ((unsigned)m->ncells);
		c = _MINDEX(m,ckey);
		while( c >= 0 ) {
			if( _MMATCH(c) ) {
				hl_gc_copy_values(&m->values[c].value,&value,sizeof(value),&_MVALUE_LAYOUT);
				return;
			}
			c = _MNEXT(m,c);
		}
	}
	if( m->nused == m->maxentries )
		_MNAME(make_room)(m);
	ckey = hash % ((unsigned)m->ncells);
	c = m->nused++;
	_MSET(c);
	_MSETNEXT(m,c,_MINDEX(m,ckey));
	_MSETINDEX(m,ckey,c);
	hl_gc_copy_values(&m->values[c].value,&value,sizeof(value),&_MVALUE_LAYOUT);
	m->nentries++;
}

_MSTATIC void _MNAME(set_impl)( t_map *m, t_key key, _MVAL_TYPE value ) {
	int klen = _MKLEN(key);
	_MNAME(probe_set)(m,key,_MHASHN(key,klen),klen,value);
}

static bool _MNAME(probe_remove)( t_map *m, t_key key, unsigned int hash, int klen ) {
	int c, prev = -1, ckey;
	(void)klen;
	if( !m->cells ) return false;
	ckey = hash % ((unsigned)m->ncells);
	c = _MINDEX(m,ckey);
	while( c >= 0 ) {
		if( _MMATCH(c) ) {
			int next = _MNEXT(m,c);
			if( prev >= 0 ) {
				_MSETNEXT(m,prev,next);
			} else {
				_MSETINDEX(m,ckey,next);
			}
			_MSETNEXT(m,c,_MDEAD);
			m->nentries--;
			_MERASE(c);
			hl_gc_store_ref(&m->values[c].value,NULL,&hlt_dyn);
			// a tombstone at the end is simply given back
			while( m->nused > 0 && !_MLIVE(m,m->nused - 1) ) m->nused--;
			return true;
		}
		prev = c;
		c = _MNEXT(m,c);
	}
	return false;
}

#ifndef _MNO_EXPORTS

HL_PRIM void _MNAME(set)( t_map *m, t_key key, _MVAL_TYPE value ) {
	_MNAME(set_impl)(m,_MNAME(filter)(key),value);
}

HL_PRIM bool _MNAME(exists)( t_map *m, t_key key ) {
	return _MNAME(find)(m,_MNAME(filter)(key)) != NULL;
}

HL_PRIM vdynamic* _MNAME(get)( t_map *m, t_key key ) {
	vdynamic **v = _MNAME(find)(m,_MNAME(filter)(key));
	if( v == NULL ) return NULL;
	return *v;
}

HL_PRIM bool _MNAME(remove)( t_map *m, t_key key ) {
	int klen;
	key = _MNAME(filter)(key);
	klen = _MKLEN(key);
	return _MNAME(probe_remove)(m,key,_MHASHN(key,klen),klen);
}

HL_PRIM varray* _MNAME(keys)( t_map *m ) {
	varray *a = hl_alloc_array(&hlt_key,m->nentries);
	t_key *keys = hl_aptr(a,t_key);
	int p = 0;
	int c;
	for(c=0;c<m->nused;c++) {
		if( !_MLIVE(m,c) ) continue;
		t_key key = _MKEY(m,c);
		hl_gc_copy_values(&keys[p++],&key,sizeof(key),&hlt_key);
	}
	return a;
}

HL_PRIM varray* _MNAME(values)( t_map *m ) {
	varray *a = hl_alloc_array(&hlt_dyn,m->nentries);
	vdynamic **values = hl_aptr(a,vdynamic*);
	int p = 0;
	int c;
	for(c=0;c<m->nused;c++) {
		if( !_MLIVE(m,c) ) continue;
		hl_gc_store_ref(&values[p++],m->values[c].value,&hlt_dyn);
	}
	return a;
}

// Maps that are cleared and refilled every frame would otherwise regrow through the whole size ladder each time,
// so a cleared map of moderate size keeps its storage and only forgets its entries.
#define _MCLEAR_KEEP_ENTRIES 65536

HL_PRIM void _MNAME(clear)( t_map *m ) {
	if( m->values && m->maxentries <= _MCLEAR_KEEP_ENTRIES ) {
		int ksize = _MSMALL(m) ? 1 : sizeof(int);
		memset(m->cells,0xFF,m->ncells * ksize);
		memset(m->entries,0,m->maxentries * sizeof(t_entry));
		memset(m->values,0,m->maxentries * sizeof(t_value));
		hl_gc_record_write(m->values,m->maxentries * sizeof(t_value));
		m->nentries = 0;
		m->nused = 0;
		return;
	}
	hl_gc_clear_values(m,sizeof(t_map),&hlt_bytes);
}

// A structural copy: same entries in the same order, tombstones included, no rehash.
HL_PRIM t_map *_MNAME(copy)( t_map *m ) {
	t_map *c = (t_map*)hl_gc_alloc_raw(sizeof(t_map));
	*c = *m;
	hl_gc_record_write(c,sizeof(t_map));
	if( !m->values )
		return c;
	int ksize = _MSMALL(m) ? 1 : sizeof(int);
	hl_gc_store_ref(&c->entries,(t_entry*)hl_gc_alloc_noptr(m->maxentries * sizeof(t_entry)),&hlt_bytes);
	memcpy(c->entries,m->entries,m->maxentries * sizeof(t_entry));
	hl_gc_store_ref(&c->values,(t_value*)hl_gc_alloc_raw(m->maxentries * sizeof(t_value)),&hlt_bytes);
	memcpy(c->values,m->values,m->maxentries * sizeof(t_value));
	hl_gc_record_write(c->values,m->maxentries * sizeof(t_value));
	hl_gc_store_ref(&c->cells,hl_gc_alloc_noptr((m->ncells + m->maxentries) * ksize),&hlt_bytes);
	hl_gc_store_ref(&c->nexts,(signed char*)c->cells + m->ncells * ksize,&hlt_bytes);
	memcpy(c->cells,m->cells,m->ncells * ksize);
	memcpy(c->nexts,m->nexts,m->maxentries * ksize);
	return c;
}

HL_PRIM int _MNAME(size)( t_map *m ) {
	return m->nentries;
}


#endif

#undef hlt_key
#undef _MKEY_TYPE
#undef _MNAME
#undef _MMATCH
#undef _MKEY
#undef _MSET
#undef _MERASE
#undef _MREHASH
#undef _MOLD_KEY
#undef _MINDEX
#undef _MNEXT
#undef _MSETINDEX
#undef _MSETNEXT
#undef _MLIVE
#undef _MSMALL
#undef _MDEAD
#undef _MSTATIC
#undef _MKLEN
#undef _MHASHN

#undef _MVALUE_LAYOUT
