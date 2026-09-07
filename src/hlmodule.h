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
#ifndef HL_MODULE_H
#define HL_MODULE_H

#include <hl.h>
#include <hlsystem.h>
#include "opcodes.h"

typedef struct {
	const char *lib;
	const char *name;
	hl_type *t;
	int findex;
} hl_native;

typedef struct {
	hl_op op;
	int p1;
	int p2;
	int p3;
	int *extra;
} hl_opcode;

typedef struct hl_function hl_function;

struct hl_function {
	int findex;
	int nregs;
	int nops;
	int ref;
	int nassigns;
	hl_type *type;
	hl_type **regs;
	hl_opcode *ops;
	int *debug;
	int *assigns;
#	define ASSIGN_NAME(f,i)		((f)->assigns[(i)*3])
#	define ASSIGN_POS(f,i)		((f)->assigns[(i)*3+1])
#	define ASSIGN_SCOPE_END(f,i)	((f)->assigns[(i)*3+2])

	hl_type_obj *obj;
	union {
		const uchar *name;
		hl_function *ref; // obj = NULL
	} field;
};

#define fun_obj(f) ((f)->obj ? (f)->obj : (f)->field.ref ? (f)->field.ref->obj : NULL)
#define fun_field_name(f) ((f)->obj ? (f)->field.name : (f)->field.ref ? (f)->field.ref->field.name : NULL)

typedef struct {
	int global;
	int nfields;
	int *fields;
} hl_constant;

/* Extra contiguous type slots reserved at load time for non-moving patch metadata. */
#define HL_PATCH_TYPE_RESERVE 65536

typedef struct {
	int version;
	int nints;
	int nfloats;
	int nstrings;
	int nbytes;
	int ntypes;
	int types_capacity;
	int nglobals;
	int nnatives;
	int nfunctions;
	int nconstants;
	int entrypoint;
	int ndebugfiles;
	bool hasdebug;
	int*		ints;
	double*		floats;
	char**		strings;
	int*		strings_lens;
	char*		bytes;
	int*		bytes_pos;
	char**		debugfiles;
	int*		debugfiles_lens;
	uchar**		ustrings;
	hl_type*	types;
	hl_type**	globals;
	hl_native*	natives;
	hl_function*functions;
	hl_constant*constants;
	hl_alloc	alloc;
	hl_alloc	falloc;
} hl_code;

typedef struct {
	int opcode;
	int operand_count;
	int *operands;
} hl_patch_instruction;

typedef struct {
	int tag;
	union {
		struct {
			int count;
			int *arguments;
			int result;
		} fun;
		int name;
		int parameter;
	} data;
} hl_patch_type;

typedef struct {
	int type;
	int stable_id;
	int findex;
	int register_count;
	int *registers;
	int instruction_count;
	hl_patch_instruction *instructions;
	int relocation_count;
	int *relocation_instructions;
	int *relocation_stable_ids;
	int debug_count;
	int *debug_files;
	int *debug_lines;
} hl_patch_function;

typedef struct {
	unsigned char module_id[16];
	int base_revision;
	int revision;
	unsigned int int_prefix_hash, float_prefix_hash, string_prefix_hash, type_prefix_hash;
	int base_int_count;
	int int_count;
	int *ints;
	int float_count;
	int base_float_count;
	double *floats;
	int string_count;
	int base_string_count;
	char **strings;
	int *string_lens;
	int type_count;
	int base_type_count;
	hl_patch_type *types;
	int function_count;
	hl_patch_function *functions;
	int debug_file_count;
	char **debug_files;
	int *debug_file_lens;
} hl_patch;

HL_EXTERN_C HL_EXPORT hl_patch *hl_patch_read( const unsigned char *data, int size, const char **error_msg );
HL_EXTERN_C HL_EXPORT void hl_patch_free( hl_patch *patch );

typedef struct {
	void *offsets;
	void *vars;
	unsigned char *opcodes;
	int start;
	int vars_size;
	bool large;
} hl_debug_infos;

typedef struct {
	hl_code *code;
	int *types_hashes;
	int *globals_signs;
	int *functions_signs;
	int *functions_hashes;
	int *functions_indexes;
} hl_code_hash;

#if defined(HL_64) && defined(HL_WIN)
//	always enable custom longjmp (Intel CET)
#	define JIT_CUSTOM_LONGJUMP
#	if !defined(HL_CONSOLE)
#		define WIN64_UNWIND_TABLES
#	endif
#endif

typedef struct _jit_ctx jit_ctx;
typedef struct _hl_patch_code hl_patch_code;

typedef struct {
	hl_code *code;
	int codesize;
	int globals_size;
	int *globals_indexes;
	unsigned char *globals_data;
	void **functions_ptrs;
	int *functions_indexes;
	void *jit_code;
	hl_code_hash *hash;
	hl_debug_infos *jit_debug;
	jit_ctx *jit_ctx;
	bool debug;
	bool patchable;
	bool staging_patch;
	int revision;
	int patch_jit_count;
	hl_patch_code **patch_owners;
	hl_patch_code *retired_patch_code;
	void **patch_targets;
	void *patch_entry_code;
	int patch_entry_code_size;
	int *patch_ints;
	double *patch_floats;
	char **patch_strings;
	int *patch_string_lens;
	uchar **patch_ustrings;
	char *patch_string_data;
	int patch_initial_string_count;
	void **patch_type_allocations;
	int patch_type_allocation_count;
	int patch_type_allocation_capacity;
	int patch_failure_stage;
	int registry_readers;
	unsigned long long diagnostics_id;
	bool retiring;
	bool roots_detached;
	unsigned char *debug_hlb;
	int debug_hlb_size;
	hl_module_context ctx;
#ifdef WIN64_UNWIND_TABLES
	int unwind_table_size;
	PRUNTIME_FUNCTION unwind_table;
#endif
#ifdef HL_VTUNE
	unsigned int *vtune_method_ids;
#endif
} hl_module;

HL_EXTERN_C HL_EXPORT hl_code *hl_code_read( const unsigned char *data, int size, char **error_msg );

hl_code_hash *hl_code_hash_alloc( hl_code *c );
void hl_code_hash_finalize( hl_code_hash *h );
void hl_code_hash_free( hl_code_hash *h );
HL_EXTERN_C HL_EXPORT void hl_code_free( hl_code *c );
int hl_code_hash_type( hl_code_hash *h, hl_type *t );
void hl_code_hash_remap_globals( hl_code_hash *hnew, hl_code_hash *hold );

const uchar *hl_get_ustring( hl_code *c, int index );
const char* hl_op_name( int op );

typedef unsigned char h_bool;

#define HL_MODULE_HOT_RELOAD 1
#define HL_MODULE_DUMP 2
#define HL_MODULE_DEBUG 4
#define HL_MODULE_PATCHABLE 8

extern int hl_jit_trampoline;
void hl_jit_tag_callback( void *native );

HL_EXTERN_C HL_EXPORT hl_module *hl_module_alloc( hl_code *code );
HL_EXTERN_C HL_EXPORT int hl_module_init( hl_module *m, int flags );
h_bool hl_module_patch( hl_module *m, hl_code *code );
/** Atomically redirect compatible function indices to an initialized generation. */
HL_EXTERN_C HL_EXPORT h_bool hl_module_patch_slots( hl_module *target, hl_module *generation, const int *indices, int count );
/** Validate and redirect every bytecode function to a complete generation. */
HL_EXTERN_C HL_EXPORT h_bool hl_module_patch_generation( hl_module *target, hl_module *generation );
HL_EXTERN_C HL_EXPORT h_bool hl_module_apply_patch( hl_module *module, hl_patch *patch, const char **error_msg );
HL_EXTERN_C HL_EXPORT int hl_module_patch_allocation_count( hl_module *module );
HL_EXTERN_C HL_EXPORT int hl_module_patch_retired_allocation_count( hl_module *module );
/** Resolve a program counter owned by a live or retained hot-reload JIT block. */
bool hl_module_patch_resolve_pos( hl_module *module, void *addr, hl_function **function, int *opcode );
/** Test whether a program counter belongs to a live or retained hot-reload JIT block. */
bool hl_module_patch_contains_address( hl_module *module, void *addr );
typedef struct {
	void *code;
	int code_size;
	int function_count;
	int revision;
	bool retired;
} hl_patch_debug_region;
int hl_module_patch_debug_region_count( hl_module *module );
bool hl_module_patch_debug_region_get( hl_module *module, int region, hl_patch_debug_region *out );
bool hl_module_patch_debug_function_get( hl_module *module, int region, int function, int *function_index, hl_function **bytecode, hl_debug_infos **debug );
void hl_module_patch_release_all( hl_module *module );
/** Force teardown during initialization failure or process shutdown only. */
HL_EXTERN_C HL_EXPORT void hl_module_free_shutdown( hl_module *m );
/** Retire an initialized module only when tracked borrowers have cleared. */
HL_EXTERN_C HL_EXPORT h_bool hl_module_unload( hl_module *m );
HL_EXTERN_C HL_EXPORT int hl_module_live_allocation_count( hl_module *m );
HL_EXTERN_C HL_EXPORT int hl_module_native_root_count( hl_module *m );
typedef enum {
	HL_MODULE_RETIRE_LIVE_MANAGED = 1,
	HL_MODULE_RETIRE_OWNED_ROOTS = 2,
	HL_MODULE_RETIRE_REGISTRY_READERS = 4
} hl_module_retirement_flags;
typedef struct {
	int live_managed_allocations;
	int owned_native_roots;
	int registry_readers;
	int flags;
} hl_module_retirement_status;
/** Unpublish a module and detach its owned roots. Safe to call repeatedly. */
HL_EXTERN_C HL_EXPORT void hl_module_retire_prepare( hl_module *m );
/** Reclaim a prepared module when no tracked borrower remains. */
HL_EXTERN_C HL_EXPORT h_bool hl_module_retire_try( hl_module *m, hl_module_retirement_status *status );
/** Snapshot known module-owned resources and borrowers. The caller must quiesce calls. */
HL_EXTERN_C HL_EXPORT void hl_module_retirement_status_get( hl_module *m, hl_module_retirement_status *out );
h_bool hl_module_debug( hl_module *m, int port, h_bool wait );
bool hl_diagnostics_start( int port, bool public_bind );
void hl_diagnostics_stop( void );
void hl_profile_stream_status( unsigned long long *first, unsigned long long *next, unsigned long long *dropped, int *sample_rate, int *paused, unsigned long long *consumer, int *requested_rate, unsigned long long *sample_records, unsigned long long *sample_nanos, unsigned long long *generated_bytes );
#define HL_PROFILE_STREAM_SIZE (8 << 20)
unsigned int hl_profile_stream_read( unsigned long long cursor, void *output, unsigned int capacity, unsigned long long *next, unsigned long long *dropped );
bool hl_profile_stream_configure( int sample_rate, bool enabled );
void hl_profile_stream_notify_revision( unsigned long long module_id, int revision );
hl_type *hl_module_resolve_type( hl_module *m, hl_type *t, bool err );
HL_EXTERN_C HL_EXPORT hl_module **hl_module_registry_snapshot( int *count );
HL_EXTERN_C HL_EXPORT void hl_module_registry_snapshot_free( hl_module **modules, int count );
/* Resolve a JIT program counter without requiring HLB source debug tables. */
HL_EXTERN_C HL_EXPORT const char *hl_module_resolve_jit_location( void *addr );

typedef struct _hl_runtime_module hl_runtime_module;
typedef enum {
	HL_RUNTIME_OK = 0, HL_RUNTIME_BAD_ARGUMENT, HL_RUNTIME_BAD_FORMAT,
	HL_RUNTIME_STALE_PATCH, HL_RUNTIME_INCOMPATIBLE, HL_RUNTIME_JIT_FAILED,
	HL_RUNTIME_BAD_FUNCTION, HL_RUNTIME_EXCEPTION, HL_RUNTIME_RETIRE_BLOCKED
} hl_runtime_status;
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_load( const unsigned char *bytes, int length, const unsigned char *identity, int identity_length, hl_runtime_module **out );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_i32( hl_runtime_module *runtime, int stable_id, int *result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_void( hl_runtime_module *runtime, int stable_id, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_bytes( hl_runtime_module *runtime, int stable_id, vbyte **result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_bytes1( hl_runtime_module *runtime, int stable_id, vbyte *argument, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_closure( hl_runtime_module *runtime, int stable_id, vclosure **result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_retained_closure_i32( hl_runtime_module *runtime, vclosure *closure, int *result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_object( hl_runtime_module *runtime, int stable_id, vdynamic **result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_i32_object( hl_runtime_module *runtime, int stable_id, vdynamic *argument, int *result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_validate_call( hl_runtime_module *runtime, int stable_id, int shape );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_apply_hlp( hl_runtime_module *runtime, const unsigned char *bytes, int length );
HL_EXTERN_C HL_EXPORT const char *hl_runtime_module_resolve_jit_location( hl_runtime_module *runtime, int stable_id );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_debug_region_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_hlp_summary( const unsigned char *bytes, int length, int *base_revision, int *revision, int *function_count );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_revision( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_jit_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_allocation_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_retired_allocation_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_type_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_type_capacity( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_live_allocation_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_native_root_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT void hl_runtime_module_retirement_status_get( hl_runtime_module *runtime, hl_module_retirement_status *out );
/** Test hook: fail the next patch at a staging boundary (1..3), or disable with 0. */
HL_EXTERN_C HL_EXPORT void hl_runtime_module_set_patch_failure_stage( hl_runtime_module *runtime, int stage );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_release( hl_runtime_module *runtime );
/** Retry internally owned failed-load retirements and return the pending count. */
HL_EXTERN_C HL_EXPORT int hl_runtime_failed_retirements_retry();
HL_EXTERN_C HL_EXPORT int hl_runtime_failed_retirements_count();

void hl_profile_setup( int sample_count );
void hl_profile_end();

#endif
