
// Positions and lengths of free-block runs in a page. A page holds up to GC_PAGE_SIZE blocks, and a run that ends
// at the last block has its end position equal to that count, so 16 bits are not enough.
typedef unsigned int fl_cursor;

typedef struct {
	fl_cursor pos;
	fl_cursor count;
} gc_fl;

typedef struct _gc_freelist {
	int current;
	int count;
	int size_bits;
	gc_fl *data;
} gc_freelist;

#define SIZES_PADDING 8

typedef struct {
	int block_size;
	unsigned char size_bits;
	unsigned char need_flush;
	short first_block;
	int max_blocks;
	// mutable
	gc_freelist free;
	unsigned char *sizes;
	char sizes_ref[SIZES_PADDING];
} gc_allocator_page_data;

