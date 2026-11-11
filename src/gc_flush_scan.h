// The free runs of a fixed-class page after a collection, found a word of the mark bitmap at a time.
//
// A page of one block size has every block of the same size, so the free list it needs after marking is exactly the runs of
// unmarked blocks, plus the runs the old free list already held (a block of an old run is free whatever its mark says: a mark
// inside one can only be a stale false positive). `flush_free_list` used to find those runs with one bit test per block of the
// page, on every page it reached after every collection; here a run of 64 equal bits is one comparison. The result is the same
// list, run for run: tests/native/gc_flush_scan.c checks it against the one-block-at-a-time reference on random pages.
#ifndef HL_GC_FLUSH_SCAN_H
#define HL_GC_FLUSH_SCAN_H

#include <stdint.h>
#include <string.h>
#include "allocator.h"

#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_WIN32)
#	define GC_FLUSH_SCAN_WORDS 1
#endif

#if defined(_MSC_VER)
#	include <intrin.h>
static inline int gc_scan_ctz64( uint64_t x ) {
	unsigned long index = 0;
	_BitScanForward64(&index,x);
	return (int)index;
}
#else
static inline int gc_scan_ctz64( uint64_t x ) {
	return __builtin_ctzll(x);
}
#endif

/* The first block in [from, limit) whose mark equals `want` (0 or 1), or `limit` when there is none. Bit b of the bitmap is
   bit (b & 7) of byte (b >> 3), as the marker writes it. Bits at or after `limit` are never read. */
static inline int gc_bitmap_next( const unsigned char *bmp, int from, int limit, int want ) {
	int bid = from;
	while( bid < limit && (bid & 7) ) {
		if( ((bmp[bid >> 3] >> (bid & 7)) & 1) == want ) return bid;
		bid++;
	}
#	ifdef GC_FLUSH_SCAN_WORDS
	{
		uint64_t invert = want ? 0 : ~(uint64_t)0;
		while( bid + 64 <= limit ) {
			uint64_t word;
			memcpy(&word,bmp + (bid >> 3),sizeof(word));
			word ^= invert;
			if( word ) return bid + gc_scan_ctz64(word);
			bid += 64;
		}
	}
#	endif
	while( bid < limit ) {
		if( ((bmp[bid >> 3] >> (bid & 7)) & 1) == want ) return bid;
		bid++;
	}
	return limit;
}

typedef void (*gc_run_emit)( void *context, int pos, int count );

/* Calls `emit` for each free run of a fixed-class page, in position order, with adjacent runs joined: the blocks of
   [first, last) that are unmarked, together with the `old_count` runs of `old` (in position order). */
static inline void gc_fixed_free_runs( const unsigned char *bmp, int first, int last, const gc_fl *old, int old_count, gc_run_emit emit, void *context ) {
	int bid = first, next_old = 0, have = 0, start = 0, length = 0;
	const gc_fl *reuse = next_old < old_count ? old + next_old++ : NULL;
	int next_bid = reuse ? (int)reuse->pos : -1;
	while( bid < last ) {
		if( bid == next_bid ) {
			if( have && start + length == bid )
				length += (int)reuse->count;
			else {
				if( have ) emit(context,start,length);
				have = 1;
				start = (int)reuse->pos;
				length = (int)reuse->count;
			}
			reuse = next_old < old_count ? old + next_old++ : NULL;
			bid = start + length;
			next_bid = reuse ? (int)reuse->pos : -1;
			continue;
		}
		{
			int limit = next_bid >= bid && next_bid < last ? next_bid : last;
			int marked = gc_bitmap_next(bmp,bid,limit,1);
			if( marked > bid ) {
				if( have && start + length == bid )
					length += marked - bid;
				else {
					if( have ) emit(context,start,length);
					have = 1;
					start = bid;
					length = marked - bid;
				}
			}
			bid = marked < limit ? gc_bitmap_next(bmp,marked,limit,0) : limit;
		}
	}
	if( have ) emit(context,start,length);
}

#endif
