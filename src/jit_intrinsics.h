/* Native intrinsics are exact (library, name, signature) matches, never pointer
 * guesses. Add a table row, a JIT-only tag in jit.h and a branch-free x86-64
 * emitter, then test native parity and mutate that emitter. Other architectures
 * use the native ABI call. Feature-dependent entries must check the host CPU.
 *
 * min/max stay native: MINSD/MAXSD do not implement Haxe's NaN/signed-zero
 * rules. char_code_at stays native: null and out-of-range inputs return -1;
 * addChar also needs bounds/allocation branches. Neither is a plain load/store.
 */
#ifndef JIT_INTRINSICS_H
#define JIT_INTRINSICS_H

#if defined(__x86_64__) || defined(_M_X64)
typedef enum { INTR_SQRT, INTR_ABS, INTR_FLOOR, INTR_CEIL } jit_intrinsic;
typedef struct {
	const char *library;
	const char *name;
	jit_intrinsic intrinsic;
	int nargs;
	emit_mode argument;
	emit_mode result;
	bool sse41;
} jit_intrinsic_entry;

static const jit_intrinsic_entry jit_intrinsics[] = {
	{ "haxeon_runtime", "__math_sqrt", INTR_SQRT, 1, M_F64, M_F64, false },
	{ "haxeon_runtime", "__math_abs", INTR_ABS, 1, M_F64, M_F64, false },
	{ "haxeon_runtime", "__math_floor", INTR_FLOOR, 1, M_F64, M_I32, true },
	{ "haxeon_runtime", "__math_ceil", INTR_CEIL, 1, M_F64, M_I32, true },
};

bool hl_jit_has_sse41(void);

static const jit_intrinsic_entry *jit_intrinsic_lookup(hl_native *native) {
	if( native->lib == NULL ) return NULL;
	for(unsigned int i = 0; i < sizeof(jit_intrinsics)/sizeof(*jit_intrinsics); i++) {
		const jit_intrinsic_entry *entry = jit_intrinsics + i;
		if( strcmp(native->lib,entry->library) || strcmp(native->name,entry->name) ) continue;
		hl_type_fun *signature = native->t->fun;
		if( signature->nargs != entry->nargs || hl_type_mode(signature->ret) != entry->result ) return NULL;
		for(int a = 0; a < entry->nargs; a++)
			if( hl_type_mode(signature->args[a]) != entry->argument ) return NULL;
		return entry->sse41 && !hl_jit_has_sse41() ? NULL : entry;
	}
	return NULL;
}
#endif
#endif
