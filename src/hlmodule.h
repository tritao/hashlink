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

/* Size reserved for each stable function entry used by patchable modules. */
#if defined(__aarch64__)
#define HL_JIT_PATCH_ENTRY_STRIDE 24
#else
#define HL_JIT_PATCH_ENTRY_STRIDE 16
#endif

/* On x86-64 a patchable module's own bytecode calls its functions directly (a plain call rel32, as in a normal module)
   instead of through the stub table. The first patch of a function then redirects callers by rewriting its original
   entry, so each function of such a module starts with an HL_JIT_ENTRY_PAD byte nop that one aligned store turns into
   a jmp rel32 to the slot's stub. Patch generations keep calling through the table. */
#if defined(HL_64) && !defined(__aarch64__) && !defined(_M_ARM64)
#define HL_JIT_DIRECT_PATCHABLE_CALLS
#define HL_JIT_ENTRY_PAD 8
#endif

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
	int kind;
	int version;
	int flags;
	int size;
	unsigned char *data;
} hl_debug_section;

/* Extra contiguous type slots reserved at load time for non-moving patch metadata. */
#define HL_PATCH_TYPE_RESERVE 65536
/* Function slots reserved at load time for functions that patches add. */
#define HL_PATCH_FUNCTION_RESERVE 4096
/* Pointer globals reserved at load time, in a patchable module only, for the String constants that patches add. A patch
   cannot move the globals once the JIT has baked their addresses into code, so the room is allocated up front. */
#define HL_PATCH_GLOBAL_RESERVE 16384

typedef struct {
	int version;
	int nints;
	int nfloats;
	int nstrings;
	int nbytes;
	int ntypes;
	int types_capacity;
	int nglobals;
	/* Entries allocated in `globals`; patches add constant globals after the loaded ones. */
	int globals_capacity;
	/* How many of the globals a patch added; the loaded ones come first and stay writable. */
	int npatchglobals;
	int nnatives;
	int nfunctions;
	/* Functions added by patches follow the loaded ones in `functions` and the tables beside it; their slots follow the
	   natives. `nfunctions` stays the count compiled at load, which the module's own JIT tables are sized by. */
	int npatchfunctions;
	int functions_capacity;
	int nconstants;
	int ndebugsections;
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
	int*        function_stable_ids;
	char**      function_names;
	int*        function_names_lens;
	hl_constant*constants;
	hl_debug_section*debugsections;
	hl_alloc	alloc;
	hl_alloc	falloc;
} hl_code;

typedef struct {
	int opcode;
	int operand_count;
	int *operands;
} hl_patch_instruction;

typedef struct {
	int file, line, column, end_line, end_column;
	int source_hash;
	int start, end, flags;
} hl_source_span;

typedef struct {
	int source_hash;
	int length;
	unsigned char *content;
} hl_source_snapshot;

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
	hl_source_span *debug_spans;
} hl_patch_function;

typedef struct {
	int stable_id;
	int findex;
	int type;
	char *name;
} hl_patch_added_function;

/* A global a patch adds: a constant object of `type`, built from `fields` as an HLB constant is. */
typedef struct {
	int type;
	int field_count;
	int *fields;
} hl_patch_global;

/*
 * A field a patch adds to an existing class, in one of the class's reserved slots: an unnamed field of type Dynamic that
 * a live build appends to the class's own fields. The slot keeps its offset, so instances made before the patch already
 * have room for the field; the patch gives it a name and a type. `field` indexes the class's own fields, not the
 * inherited ones.
 */
typedef struct {
	int type;
	int field;
	int name;
	int field_type;
} hl_patch_object_field;

/*
 * Runs `findex`, a function of one argument returning Void, on every live instance of `type` and of its subclasses once
 * the patch commits: it evaluates the declaration initializers of the fields the patch adds, which constructors already
 * run for instances made later. The runtime resolves `stable_id` to `findex` before applying the patch.
 */
typedef struct {
	int type;
	int stable_id;
	int findex;
} hl_patch_migration;

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
	int added_function_count;
	hl_patch_added_function *added_functions;
	int debug_file_count;
	char **debug_files;
	int *debug_file_lens;
	int source_snapshot_count;
	hl_source_snapshot *source_snapshots;
	unsigned int global_prefix_hash;
	int base_global_count;
	int global_count;
	hl_patch_global *globals;
	int object_field_count;
	hl_patch_object_field *object_fields;
	int migration_count;
	hl_patch_migration *migrations;
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
typedef struct _hl_patch_live hl_patch_live;

typedef struct {
	hl_code *code;
	int codesize;
	int globals_size;
	/* Bytes allocated in globals_data, which the globals a patch adds are laid out in after globals_size. */
	int globals_data_capacity;
	int *globals_indexes;
	unsigned char *globals_data;
	void **functions_ptrs;
	/* Indexed by code->natives, resolved independently for every module generation. */
	unsigned char *native_noreturn;
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
	/* The original code entry of each slot of the base module (NULL for slots that only patches add). */
	void **patch_origin;
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
	void *gdb_jit_entry;
	hl_module_context ctx;
#ifdef WIN64_UNWIND_TABLES
	int unwind_table_size;
	PRUNTIME_FUNCTION unwind_table;
#endif
#ifdef HL_VTUNE
	unsigned int *vtune_method_ids;
#endif
	/* Bounds of every patch code region ever installed (retired ones included), so an address outside them is not patch code. */
	void *patch_lo;
	void *patch_hi;
	/* The distinct allocations patch_owners refers to, ordered by code address; replaced when a patch commits. */
	hl_patch_live *patch_live;
} hl_module;

HL_EXTERN_C HL_EXPORT hl_code *hl_code_read( const unsigned char *data, int size, char **error_msg );

hl_code_hash *hl_code_hash_alloc( hl_code *c );
void hl_code_hash_finalize( hl_code_hash *h );
void hl_code_hash_free( hl_code_hash *h );
/* Releases temporary decoded function bodies after module initialization.
	The hl_code object and its persistent metadata remain alive. */
HL_EXTERN_C HL_EXPORT void hl_code_free_function_data( hl_code *c );
/* Legacy name retained for source and ABI compatibility. */
HL_EXTERN_C HL_EXPORT void hl_code_free( hl_code *c );
/* Releases both temporary function data and persistent hl_code storage.
	No module may still reference the code. */
HL_EXTERN_C HL_EXPORT void hl_code_destroy( hl_code *c );
int hl_code_hash_type( hl_code_hash *h, hl_type *t );
void hl_code_hash_remap_globals( hl_code_hash *hnew, hl_code_hash *hold );

const uchar *hl_get_ustring( hl_code *c, int index );
const char* hl_op_name( int op );
const char *hl_code_function_name( hl_code *code, hl_function *function );

typedef unsigned char h_bool;

#define HL_MODULE_HOT_RELOAD 1
#define HL_MODULE_DUMP 2
#define HL_MODULE_DEBUG 4
#define HL_MODULE_PATCHABLE 8

extern int hl_jit_trampoline;
void hl_jit_tag_callback( void *native );
/* Names the shared JIT support stub containing addr, for profilers; NULL when addr is not in one. */
const char *hl_jit_support_symbol( void *addr, void **start, void **base, int *size );

HL_EXTERN_C HL_EXPORT hl_module *hl_module_alloc( hl_code *code );
HL_EXTERN_C HL_EXPORT int hl_module_init( hl_module *m, int flags );
h_bool hl_module_patch( hl_module *m, hl_code *code );
/** Atomically redirect compatible function indices to an initialized generation. */
HL_EXTERN_C HL_EXPORT h_bool hl_module_patch_slots( hl_module *target, hl_module *generation, const int *indices, int count );
/** Points a function slot at new code: every caller, direct or through the table or a closure, reaches it afterwards. */
HL_EXTERN_C void hl_module_redirect_slot( hl_module *m, int slot, void *code );
/** True when pc lies in a patchable module's stub for a slot with an original entry; origin receives that entry. */
HL_EXTERN_C bool hl_module_patch_entry_origin( void *pc, void **origin );
/** Validate and redirect every bytecode function to a complete generation. */
HL_EXTERN_C HL_EXPORT h_bool hl_module_patch_generation( hl_module *target, hl_module *generation );
/* Builds the object of a constant in the module's arena and stores it in the constant's global; `code` supplies the tables
   its fields index. Does not touch the GC roots. */
HL_EXTERN_C vdynamic *hl_module_build_constant( hl_module *module, hl_code *code, hl_constant *constant );
HL_EXTERN_C HL_EXPORT h_bool hl_module_apply_patch( hl_module *module, hl_patch *patch, const char **error_msg );
/**
 * Runs the migrations of a patch `module` has committed (see `hl_patch_migration`), returning how many instances were
 * migrated. Exceptions do not propagate: each failed call counts in `failures`, its instance keeps zero values in the
 * added fields, and `first_exception` receives the first exception thrown. Call it after `hl_module_apply_patch`
 * succeeds, before the module runs other code.
 */
HL_EXTERN_C HL_EXPORT int hl_module_patch_migrate( hl_module *module, hl_patch *patch, int *failures, vdynamic **first_exception );
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
bool hl_module_patch_debug_source_span_get( hl_module *module, int region, int function, int opcode, hl_source_span *out );
int hl_module_patch_debug_source_snapshot_count( hl_module *module, int region );
bool hl_module_patch_debug_source_snapshot_get( hl_module *module, int region, int snapshot, hl_source_snapshot *out );
void hl_module_patch_release_all( hl_module *module );
/* Registers (+1) or unregisters (-1) a thread that reads patch code concurrently with commits; see hlpatch.c. */
void hl_module_patch_readers( int delta );
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
/** Ends the streaming session, if any, after pushing every record to the client. */
void hl_diagnostics_finish( void );
/** Starts the sampler and allocation sampling a session asks for (HL_PROF_SOURCE_*), and releases --diagnostics-wait. */
bool hl_profile_session_start( int sources, int sample_rate, int allocation_interval );
void hl_profile_session_stop( void );
/** Consumer: streams the names of native call keys first recorded since the last call (see hl_prof_enter_native). */
void hl_profile_name_native_keys( void );
/** Installs the boundary hooks HL_PROF_BOUNDARY asks for (Windows x64; see prof_boundary.c). */
void hl_prof_boundary_install( void );
/** The calling thread's boundary calls are never recorded: the profiler's own threads. */
void hl_prof_boundary_ignore_thread( void );
/** The name of a boundary hook's key, or NULL when the key is not one. */
const char *hl_prof_boundary_name( unsigned long long key );
/** True once a module load or patch changed the symbol metadata since the last call. */
bool hl_profile_metadata_changed( void );
void hl_profile_stream_notify_revision( unsigned long long module_id, int revision );
void hl_profile_stream_notify_module( unsigned long long module_id );
HL_API void hl_gc_profile_stats( unsigned long long *allocated, unsigned long long *allocations, unsigned long long *heap, unsigned long long *collections, unsigned long long *mark_micros );
hl_type *hl_module_resolve_type( hl_module *m, hl_type *t, bool err );
/* What hl_module_capture_stack_from_frame found at each captured frame. */
typedef enum {
	HL_CAPTURE_JIT,     /* a return address into JIT code */
	HL_CAPTURE_NATIVE,  /* a return address the profiler checks is native code before keeping it */
	HL_CAPTURE_GAP      /* frames skipped where the frame-pointer chain broke */
} hl_capture_kind;

HL_EXTERN_C HL_EXPORT hl_module **hl_module_registry_snapshot( int *count );
HL_EXTERN_C HL_EXPORT void hl_module_registry_snapshot_free( hl_module **modules, int count );
/* Resolve a JIT program counter without requiring HLB source debug tables. */
HL_EXTERN_C HL_EXPORT const char *hl_module_resolve_jit_location( void *addr );
// Serialize crash readers with module/patch metadata publication.
HL_EXTERN_C void hl_module_crash_write_lock( void );
HL_EXTERN_C void hl_module_crash_write_unlock( void );
#if defined(HL_LINUX) || defined(HL_MAC)
HL_EXTERN_C HL_EXPORT int hl_module_resolve_crash_location( void *addr, char *buffer, int size );
#endif

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
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_abstract( hl_runtime_module *runtime, int stable_id, const uchar *name, void **result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_bytes1( hl_runtime_module *runtime, int stable_id, vbyte *argument, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_closure( hl_runtime_module *runtime, int stable_id, vclosure **result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_retained_closure_i32( hl_runtime_module *runtime, vclosure *closure, int *result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_object( hl_runtime_module *runtime, int stable_id, vdynamic **result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_call_i32_object( hl_runtime_module *runtime, int stable_id, vdynamic *argument, int *result, vdynamic **exception );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_validate_call( hl_runtime_module *runtime, int stable_id, int shape );
HL_EXTERN_C HL_EXPORT hl_runtime_status hl_runtime_module_apply_hlp( hl_runtime_module *runtime, const unsigned char *bytes, int length );
HL_EXTERN_C HL_EXPORT const char *hl_runtime_module_resolve_jit_location( hl_runtime_module *runtime, int stable_id );
HL_EXTERN_C HL_EXPORT int hl_runtime_module_debug_region_count( hl_runtime_module *runtime );
/** Test hook: how a function's original entry was redirected: 0 untouched, 1 by the 12-byte writer, 2 by the atomic jump, -1 unknown. */
HL_EXTERN_C HL_EXPORT int hl_runtime_module_entry_state( hl_runtime_module *runtime, int stable_id );
/** Test hook: 1 when the base code of caller contains a direct call to the original entry of callee, 0 when not, -1 unknown. */
HL_EXTERN_C HL_EXPORT int hl_runtime_module_calls_directly( hl_runtime_module *runtime, int caller_id, int callee_id );
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
/** Wait until a remote diagnostics profiler has configured the stream. */
void hl_profile_wait_for_start( void );
/** Give a diagnostics client that is reading the stream up to a second to take the last records. Call it while diagnostics still run. */
void hl_profile_drain( void );
void hl_profile_end();

#endif
