#ifndef HL_GC_WRITE_H
#define HL_GC_WRITE_H
/* Included by hl.h after the runtime type declarations. */
#include <string.h>

HL_API int hl_gc_write_barrier_active;
HL_API void hl_gc_write_barrier(void *address, size_t bytes);
static HL_INLINE void hl_gc_record_write(void *address, size_t bytes) {
#if defined(__GNUC__)
	if( __atomic_load_n(&hl_gc_write_barrier_active,__ATOMIC_RELAXED) )
#else
	if( hl_gc_write_barrier_active )
#endif
		hl_gc_write_barrier(address,bytes);
}


/* Typed mutation boundaries record destination pages during incremental marking.
 * Ownership bookkeeping is not enabled here. Preserve the destination, source and layout
 * until the write, so a future implementation can inspect overwritten values.
 * These helpers never allocate, lock or introduce a safepoint. Callers must
 * evaluate allocating conversions before entering a mutation operation.
 *
 * copy/move/clear_values describe ordinary value slots of `type`; packed copies
 * describe inline object/struct payloads, NOT pointers to those objects.
 * move_values has memmove semantics: the source is copied, not consumed. A
 * future RC implementation must retain incoming references before releasing
 * overwritten references, including self-assignment and overlapping ranges.
 * This is only a migration boundary, not a complete native ownership contract.
 */
static HL_INLINE void hl_gc_store_ref(void *slot, void *value, hl_type *type) {
	(void)type;
	memcpy(slot,&value,sizeof(value));
	hl_gc_record_write(slot,sizeof(value));
}
static HL_INLINE void hl_gc_copy_values(void *dst, const void *src, size_t bytes, hl_type *type) {
	(void)type;
	memcpy(dst,src,bytes);
	hl_gc_record_write(dst,bytes);
}
static HL_INLINE void hl_gc_move_values(void *dst, const void *src, size_t bytes, hl_type *type) {
	(void)type;
	memmove(dst,src,bytes);
	hl_gc_record_write(dst,bytes);
}
static HL_INLINE void hl_gc_clear_values(void *dst, size_t bytes, hl_type *type) {
	(void)type;
	memset(dst,0,bytes);
	hl_gc_record_write(dst,bytes);
}
/* Swap is a single mutation operation: neither side is a consumed temporary. */
static HL_INLINE void hl_gc_swap_values(void *left, void *right, size_t bytes, hl_type *type) {
	(void)type;
	unsigned char *a = (unsigned char*)left, *b = (unsigned char*)right;
	for(size_t i = 0; i < bytes; i++) {
		unsigned char value = a[i]; a[i] = b[i]; b[i] = value;
	}
	hl_gc_record_write(left,bytes);
	hl_gc_record_write(right,bytes);
}
static HL_INLINE void hl_gc_copy_packed(void *dst, const void *src, size_t bytes, hl_type *layout) {
	(void)layout;
	memcpy(dst,src,bytes);
	hl_gc_record_write(dst,bytes);
}
static HL_INLINE void hl_gc_move_packed(void *dst, const void *src, size_t bytes, hl_type *layout) {
	(void)layout;
	memmove(dst,src,bytes);
	hl_gc_record_write(dst,bytes);
}
#endif
