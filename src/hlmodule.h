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

typedef struct {
	int version;
	int nints;
	int nfloats;
	int nstrings;
	int nbytes;
	int ntypes;
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
	int function_count;
	hl_patch_function *functions;
} hl_patch;

HL_EXTERN_C HL_EXPORT hl_patch *hl_patch_read( const unsigned char *data, int size, const char **error_msg );
HL_EXTERN_C HL_EXPORT void hl_patch_free( hl_patch *patch );

typedef struct {
	void *offsets;
	void *vars;
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
	int revision;
	int patch_jit_count;
	hl_patch_code **patch_owners;
	int *patch_ints;
	double *patch_floats;
	char **patch_strings;
	int *patch_string_lens;
	uchar **patch_ustrings;
	char *patch_string_data;
	int patch_initial_string_count;
	hl_module_context ctx;
#ifdef WIN64_UNWIND_TABLES
	int unwind_table_size;
	PRUNTIME_FUNCTION unwind_table;
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
void hl_module_patch_release_all( hl_module *module );
HL_EXTERN_C HL_EXPORT void hl_module_free( hl_module *m );
/** Remove an initialized module from runtime discovery and release its JIT data. */
HL_EXTERN_C HL_EXPORT h_bool hl_module_unload( hl_module *m );
h_bool hl_module_debug( hl_module *m, int port, h_bool wait );
hl_type *hl_module_resolve_type( hl_module *m, hl_type *t, bool err );
hl_module **hl_get_modules( int *count );

typedef struct _hl_runtime_module hl_runtime_module;
typedef enum {
	HL_RUNTIME_OK = 0, HL_RUNTIME_BAD_ARGUMENT, HL_RUNTIME_BAD_FORMAT,
	HL_RUNTIME_STALE_PATCH, HL_RUNTIME_INCOMPATIBLE, HL_RUNTIME_JIT_FAILED,
	HL_RUNTIME_BAD_FUNCTION, HL_RUNTIME_EXCEPTION
} hl_runtime_status;
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_load( const unsigned char *bytes, int length, const unsigned char *identity, int identity_length, hl_runtime_module **out );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_i32( hl_runtime_module *runtime, int stable_id, int *result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_void( hl_runtime_module *runtime, int stable_id, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_bytes( hl_runtime_module *runtime, int stable_id, vbyte **result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_bytes1( hl_runtime_module *runtime, int stable_id, vbyte *argument, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_apply_hlp( hl_runtime_module *runtime, const unsigned char *bytes, int length );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_hlp_summary( const unsigned char *bytes, int length, int *base_revision, int *revision, int *function_count );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_revision( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_jit_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_allocation_count( hl_runtime_module *runtime );
HL_EXTERN_C HL_EXPORT void hl_runtime_module_release( hl_runtime_module *runtime );

void hl_profile_setup( int sample_count );
void hl_profile_end();

#endif
