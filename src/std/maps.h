#ifdef _MNO_EXPORTS
#define _MVALUE_LAYOUT hlt_i32
#else
#define _MVALUE_LAYOUT hlt_dyn
#endif

#undef t_map
#undef t_entry
#undef t_value
#undef t_key
#define t_key _MKEY_TYPE
#define t_map _MNAME(_map)
#define t_entry _MNAME(_entry)
#define t_value _MNAME(_value)
#define _MLIMIT 128
#define _MINDEX(m,ckey) ((m)->maxentries < _MLIMIT ? (int)((signed char*)(m)->cells)[ckey] : ((int*)(m)->cells)[ckey])
#define _MNEXT(m,ckey) ((m)->maxentries < _MLIMIT ? (int)((signed char*)(m)->nexts)[ckey] : ((int*)(m)->nexts)[ckey])
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
	hl_free_list lfree;
	int ncells;
	int nentries;
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

_MSTATIC _MVAL_TYPE *_MNAME(find)( t_map *m, t_key key ) {
	int c, ckey;
	unsigned int hash;

	if( !m->values ) return NULL;
	hash = _MNAME(hash)(key);
	ckey = hash % ((unsigned)m->ncells);
	c = _MINDEX(m,ckey);
	while( c >= 0 ) {
		if( _MMATCH(c) )
			return &m->values[c].value;
		c = _MNEXT(m,c);
	}
	return NULL;
}

static void _MNAME(resize)( t_map *m );

_MSTATIC void _MNAME(set_impl)( t_map *m, t_key key, _MVAL_TYPE value ) {
	int c, ckey = 0;
	unsigned int hash = _MNAME(hash)(key);
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
	c = hl_freelist_get(&m->lfree);
	if( c < 0 ) {
		_MNAME(resize)(m);
		ckey = hash % ((unsigned)m->ncells);
		c = hl_freelist_get(&m->lfree);
	}
	_MSET(c);
	if( m->maxentries < _MLIMIT ) {
		((signed char*)m->nexts)[c] = ((signed char*)m->cells)[ckey];
		((signed char*)m->cells)[ckey] = (signed char)c;
	} else {
		((int*)m->nexts)[c] = ((int*)m->cells)[ckey];
		((int*)m->cells)[ckey] = c;
	}
	hl_gc_copy_values(&m->values[c].value,&value,sizeof(value),&_MVALUE_LAYOUT);
	m->nentries++;
}

static void _MNAME(resize)( t_map *m ) {
	// save
	t_map old = *m;

	if( m->nentries != m->maxentries ) hl_error("assert");

	// resize
	int i = 0;
	int nentries = m->maxentries ? ((m->maxentries * 3) + 1) >> 1 : H_SIZE_INIT;
	int ncells = nentries >> 2;

	while( H_PRIMES[i] < ncells ) i++;
	ncells = H_PRIMES[i];

	int ksize = nentries < _MLIMIT ? 1 : sizeof(int);
	hl_gc_store_ref(&m->entries,(t_entry*)hl_gc_alloc_noptr(nentries * sizeof(t_entry)),&hlt_bytes);
	hl_gc_store_ref(&m->values,(t_value*)hl_gc_alloc_raw(nentries * sizeof(t_value)),&hlt_bytes);
	m->maxentries = nentries;

	if( old.ncells == ncells && (nentries < _MLIMIT || old.maxentries >= _MLIMIT) ) {
		// simply expand
		hl_gc_store_ref(&m->nexts,hl_gc_alloc_noptr(nentries * ksize),&hlt_bytes);
		memcpy(m->entries,old.entries,old.maxentries * sizeof(t_entry));
		memcpy(m->values,old.values,old.maxentries * sizeof(t_value));
		hl_gc_record_write(m->values,old.maxentries * sizeof(t_value));
		memcpy(m->nexts,old.nexts,old.maxentries * ksize);
		memset(m->values + old.maxentries, 0, (nentries - old.maxentries) * sizeof(t_value));
		hl_gc_record_write(m->values,nentries * sizeof(t_value));
		hl_freelist_add_range(&m->lfree,old.maxentries,m->maxentries - old.maxentries);
	} else {
		// expand and remap
		hl_gc_store_ref(&m->cells,hl_gc_alloc_noptr((ncells + nentries) * ksize),&hlt_bytes);
		hl_gc_store_ref(&m->nexts,(signed char*)m->cells + ncells * ksize,&hlt_bytes);
		m->ncells = ncells;
		m->nentries = 0;
		memset(m->cells,0xFF,ncells * ksize);
		memset(m->values, 0, nentries * sizeof(t_value));
		hl_gc_record_write(m->values,nentries * sizeof(t_value));
		hl_freelist_init(&m->lfree);
		hl_freelist_add_range(&m->lfree,0,m->maxentries);
		for(i=0;i<old.ncells;i++) {
			int c = old.maxentries < _MLIMIT ? ((signed char*)old.cells)[i] : ((int*)old.cells)[i];
			while( c >= 0 ) {
				_MNAME(set_impl)(m,_MKEY((&old),c),old.values[c].value);
				c = _MNEXT(&old,c);
			}
		}
	}
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
	int c, prev = -1, ckey;
	unsigned int hash;
	if( !m->cells ) return false;
	key = _MNAME(filter)(key);
	hash = _MNAME(hash)(key);
	ckey = hash % ((unsigned)m->ncells);
	c = _MINDEX(m,ckey);
	while( c >= 0 ) {
		if( _MMATCH(c) ) {
			hl_freelist_add(&m->lfree,c);
			m->nentries--;
			_MERASE(c);
			hl_gc_store_ref(&m->values[c].value,NULL,&hlt_dyn);
			if( m->maxentries < _MLIMIT ) {
				if( prev >= 0 )
					((signed char*)m->nexts)[prev] = ((signed char*)m->nexts)[c];
				else
					((signed char*)m->cells)[ckey] = ((signed char*)m->nexts)[c];
			} else {
				if( prev >= 0 )
					((int*)m->nexts)[prev] = ((int*)m->nexts)[c];
				else
					((int*)m->cells)[ckey] = ((int*)m->nexts)[c];
			}
			return true;
		}
		prev = c;
		c = _MNEXT(m,c);
	}
	return false;
}

HL_PRIM varray* _MNAME(keys)( t_map *m ) {
	varray *a = hl_alloc_array(&hlt_key,m->nentries);
	t_key *keys = hl_aptr(a,t_key);
	int p = 0;
	int i;
	for(i=0;i<m->ncells;i++) {
		int c = _MINDEX(m,i);
		while( c >= 0 ) {
			t_key key = _MKEY(m,c);
			hl_gc_copy_values(&keys[p++],&key,sizeof(key),&hlt_key);
			c = _MNEXT(m,c);
		}
	}
	return a;
}

HL_PRIM varray* _MNAME(values)( t_map *m ) {
	varray *a = hl_alloc_array(&hlt_dyn,m->nentries);
	vdynamic **values = hl_aptr(a,vdynamic*);
	int p = 0;
	int i;
	for(i=0;i<m->ncells;i++) {
		int c = _MINDEX(m,i);
		while( c >= 0 ) {
			hl_gc_store_ref(&values[p++],m->values[c].value,&hlt_dyn);
			c = _MNEXT(m,c);
		}
	}
	return a;
}

// Maps that are cleared and refilled every frame would otherwise regrow through the whole size ladder each time,
// so a cleared map of moderate size keeps its storage and only forgets its entries.
#define _MCLEAR_KEEP_ENTRIES 65536

HL_PRIM void _MNAME(clear)( t_map *m ) {
	if( m->values && m->maxentries <= _MCLEAR_KEEP_ENTRIES ) {
		int ksize = m->maxentries < _MLIMIT ? 1 : sizeof(int);
		memset(m->cells,0xFF,m->ncells * ksize);
		memset(m->entries,0,m->maxentries * sizeof(t_entry));
		memset(m->values,0,m->maxentries * sizeof(t_value));
		hl_gc_record_write(m->values,m->maxentries * sizeof(t_value));
		m->nentries = 0;
		hl_freelist_init(&m->lfree);
		hl_freelist_add_range(&m->lfree,0,m->maxentries);
		return;
	}
	hl_gc_clear_values(m,sizeof(t_map),&hlt_bytes);
}

// A structural copy: same entries, no rehash. Every buffer is duplicated on its own, since `nexts` is either
// part of the `cells` allocation or a separate one depending on how the map last grew.
HL_PRIM t_map *_MNAME(copy)( t_map *m ) {
	t_map *c = (t_map*)hl_gc_alloc_raw(sizeof(t_map));
	*c = *m;
	hl_gc_record_write(c,sizeof(t_map));
	if( !m->values )
		return c;
	int ksize = m->maxentries < _MLIMIT ? 1 : sizeof(int);
	hl_gc_store_ref(&c->entries,(t_entry*)hl_gc_alloc_noptr(m->maxentries * sizeof(t_entry)),&hlt_bytes);
	memcpy(c->entries,m->entries,m->maxentries * sizeof(t_entry));
	hl_gc_store_ref(&c->values,(t_value*)hl_gc_alloc_raw(m->maxentries * sizeof(t_value)),&hlt_bytes);
	memcpy(c->values,m->values,m->maxentries * sizeof(t_value));
	hl_gc_record_write(c->values,m->maxentries * sizeof(t_value));
	hl_gc_store_ref(&c->cells,hl_gc_alloc_noptr(m->ncells * ksize),&hlt_bytes);
	memcpy(c->cells,m->cells,m->ncells * ksize);
	hl_gc_store_ref(&c->nexts,hl_gc_alloc_noptr(m->maxentries * ksize),&hlt_bytes);
	memcpy(c->nexts,m->nexts,m->maxentries * ksize);
	if( m->lfree.buckets ) {
		hl_gc_store_ref(&c->lfree.buckets,(hl_free_bucket*)hl_gc_alloc_noptr(sizeof(hl_free_bucket) * m->lfree.nbuckets),&hlt_bytes);
		memcpy(c->lfree.buckets,m->lfree.buckets,m->lfree.head * sizeof(hl_free_bucket));
	}
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
#undef _MOLD_KEY
#undef _MINDEX
#undef _MNEXT
#undef _MSTATIC

#undef _MVALUE_LAYOUT
