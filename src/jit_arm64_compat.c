/*
 * Platform-independent entry points used by Haxeon's integrated runtime.
 *
 * The upstream AArch64 backend is intentionally self-contained and does not
 * include the legacy x86 emitter/debugger glue. Keep the integration hooks in
 * this small translation unit so the backend can share Haxeon's module and
 * patching code without linking the x86 JIT.
 */
#include <jit.h>
#include <stdio.h>

int hl_jit_trampoline = -1;

void hl_jit_tag_callback( void *native ) {
	(void)native;
}

bool hl_jit_is_callback( void *native ) {
	(void)native;
	return false;
}

void hl_jit_error( const char *msg, const char *func, int line ) {
	fprintf(stderr, "*** JIT ERROR %s:%d (%s) ***\n", func, line, msg);
}

void hl_emit_dump( jit_ctx *ctx ) {
	/* The AArch64 backend has its own optional HL_JIT_DUMP output. */
	(void)ctx;
}

void *hl_jit_patch_code( jit_ctx *ctx, hl_module *m, int *codesize, hl_debug_infos **debug ) {
	/* AArch64 emits the same contiguous code image for initial and patch JITs. */
	return hl_jit_code(ctx, m, codesize, debug, NULL);
}
