/*
	The JIT's entry points in a VM built without the JIT (HL_NO_JIT_SOURCES in cmake/hl-sources.cmake), for executables whose
	functions were compiled ahead of time and are initialized by hl_module_init_aot. Nothing here compiles code: a module
	cannot be initialized for the JIT (hl_module_init fails, as when the JIT cannot allocate), nor patched.
*/
#include <hlmodule.h>
#include "jit.h"
#include "jit_gdb.h"

int hl_jit_trampoline = -1;

jit_ctx *hl_jit_alloc() {
	return NULL;
}

void hl_jit_free( jit_ctx *ctx, h_bool can_reset ) {
}

void hl_jit_reset( jit_ctx *ctx, hl_module *m ) {
}

void hl_jit_init( jit_ctx *ctx, hl_module *m ) {
}

int hl_jit_function( jit_ctx *ctx, hl_module *m, hl_function *f ) {
	return -1;
}

void hl_emit_dump( jit_ctx *ctx ) {
}

void *hl_jit_code( jit_ctx *ctx, hl_module *m, int *codesize, hl_debug_infos **debug, hl_module *previous ) {
	return NULL;
}

void *hl_jit_patch_code( jit_ctx *ctx, hl_module *m, int *codesize, hl_debug_infos **debug ) {
	return NULL;
}

void hl_jit_patch_method( void *old_fun, void **new_fun_table ) {
	hl_fatal("hl_jit_patch_method: this VM has no JIT");
}

bool hl_jit_patch_entry_jump( void *entry, void *stub ) {
	return false;
}

void hl_jit_tag_callback( void *native ) {
}

const char *hl_jit_support_symbol( void *addr, void **start, void **base, int *size ) {
	return NULL;
}

void hl_gdb_jit_register( hl_module *m ) {
}

void hl_gdb_jit_register_patch( hl_module *m ) {
}

void hl_gdb_jit_unregister( hl_module *m ) {
}
