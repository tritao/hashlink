#include <hlmodule.h>
#include <stdlib.h>
#include <string.h>

#define HL_RUNTIME_V2_INIT_STABLE_ID 0x1FFFFFFF

void hl_debug_notify_revision( hl_module *m );

struct _hl_runtime_module {
	hl_module *module;
	hl_code *owned_code;
	hl_mutex *lock;
	unsigned char module_id[16];
	int identity_count;
	const int *stable_ids;
	const int *slots;
	bool borrowed_identity;
	struct _hl_runtime_module *retirement_next;
};

static void runtime_code_free( hl_code *code ) {
	if( code == NULL ) return;
	hl_code_free(code);
	hl_free(&code->alloc);
}

static hl_runtime_module *failed_retirements = NULL;
static hl_mutex *failed_retirements_lock = NULL;
HL_THREAD_STATIC_VAR int runtime_decode_guard_depth = 0;
HL_THREAD_STATIC_VAR int runtime_decode_guard_attempts = 0;

void hl_runtime_decode_guard_begin() {
	if( runtime_decode_guard_depth == 0 ) runtime_decode_guard_attempts = 0;
	runtime_decode_guard_depth++;
}

int hl_runtime_decode_guard_end() {
	int attempts = runtime_decode_guard_attempts;
	if( runtime_decode_guard_depth > 0 ) runtime_decode_guard_depth--;
	if( runtime_decode_guard_depth == 0 ) runtime_decode_guard_attempts = 0;
	return attempts;
}

bool hl_runtime_decode_guard_active() {
	return runtime_decode_guard_depth > 0;
}

void hl_runtime_decode_guard_note() {
	runtime_decode_guard_attempts++;
}

static void runtime_identity_free( hl_runtime_module *runtime ) {
	if( runtime == NULL || runtime->borrowed_identity ) return;
	free((void*)runtime->stable_ids);
	free((void*)runtime->slots);
	runtime->stable_ids = NULL;
	runtime->slots = NULL;
}

static void runtime_wrapper_free( hl_runtime_module *runtime ) {
	hl_remove_root(&runtime->lock);
	hl_mutex_free(runtime->lock);
	runtime_code_free(runtime->owned_code);
	runtime_identity_free(runtime);
	free(runtime);
}

static void failed_retirements_free() {
	hl_runtime_module *runtime;
	if( failed_retirements_lock == NULL ) return;
	hl_mutex_acquire(failed_retirements_lock);
	runtime = failed_retirements;
	failed_retirements = NULL;
	hl_mutex_release(failed_retirements_lock);
	while( runtime != NULL ) {
		hl_runtime_module *next = runtime->retirement_next;
		if( runtime->module != NULL ) hl_module_free_shutdown(runtime->module);
		runtime_wrapper_free(runtime);
		runtime = next;
	}
	hl_remove_root(&failed_retirements_lock);
	hl_mutex_free(failed_retirements_lock);
	failed_retirements_lock = NULL;
}

static void failed_retirement_add( hl_runtime_module *runtime ) {
	if( failed_retirements_lock == NULL ) {
		hl_global_lock(true);
		if( failed_retirements_lock == NULL ) {
			failed_retirements_lock = hl_mutex_alloc(false);
			hl_add_root(&failed_retirements_lock);
			hl_setup.free_runtime_retirements = failed_retirements_free;
		}
		hl_global_lock(false);
	}
	hl_mutex_acquire(failed_retirements_lock);
	runtime->retirement_next = failed_retirements;
	failed_retirements = runtime;
	hl_mutex_release(failed_retirements_lock);
}

int hl_runtime_failed_retirements_retry() {
	hl_runtime_module **cursor;
	int pending = 0;
	if( failed_retirements_lock == NULL ) return 0;
	hl_mutex_acquire(failed_retirements_lock);
	cursor = &failed_retirements;
	while( *cursor != NULL ) {
		hl_runtime_module *runtime = *cursor;
		hl_runtime_module *next = runtime->retirement_next;
		if( hl_runtime_module_release(runtime) == HL_RUNTIME_OK )
			*cursor = next;
		else {
			pending++;
			cursor = &runtime->retirement_next;
		}
	}
	hl_mutex_release(failed_retirements_lock);
	return pending;
}

int hl_runtime_failed_retirements_count() {
	hl_runtime_module *runtime;
	int count = 0;
	if( failed_retirements_lock == NULL ) return 0;
	hl_mutex_acquire(failed_retirements_lock);
	for(runtime=failed_retirements;runtime;runtime=runtime->retirement_next) count++;
	hl_mutex_release(failed_retirements_lock);
	return count;
}

static int resolve_stable_id( hl_runtime_module *runtime, int stable_id );
static hl_function *find_function( hl_module *module, int stable_id );

static void runtime_clear_exception_state() {
	hl_thread_info *thread = hl_get_thread();
	if( thread == NULL ) return;
	thread->exc_value = NULL;
	thread->exc_stack_count = 0;
	memset(thread->exc_stack_trace,0,sizeof(thread->exc_stack_trace));
}

static hl_runtime_status validate_call_slot_locked( hl_runtime_module *runtime, int slot, int shape ) {
	hl_function *function;
	int nargs;
	hl_type_kind result_kind;
	if( shape < 0 || shape > 6 ) return HL_RUNTIME_BAD_ARGUMENT;
	nargs = shape == 3 || shape == 6 ? 1 : 0;
	result_kind = shape == 0 || shape == 6 ? HI32 : shape == 1 || shape == 3 ? HVOID : shape == 2 ? HBYTES : shape == 4 ? HFUN : (hl_type_kind)-1;
	function = find_function(runtime->module,slot);
	return function == NULL || function->type->kind != HFUN || function->type->fun->nargs != nargs
		|| (result_kind != (hl_type_kind)-1 && function->type->fun->ret->kind != result_kind)
		? HL_RUNTIME_BAD_FUNCTION : HL_RUNTIME_OK;
}

hl_runtime_status hl_runtime_module_validate_call( hl_runtime_module *runtime, int stable_id, int shape ) {
	hl_runtime_status status;
	int slot;
	if( runtime == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	slot = resolve_stable_id(runtime,stable_id);
	status = validate_call_slot_locked(runtime,slot,shape);
	hl_mutex_release(runtime->lock);
	return status;
}

hl_runtime_status hl_runtime_module_validate_call_slot( hl_runtime_module *runtime, int slot, int shape ) {
	hl_runtime_status status;
	if( runtime == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	status = validate_call_slot_locked(runtime,slot,shape);
	hl_mutex_release(runtime->lock);
	return status;
}

static hl_function *find_function( hl_module *module, int stable_id ) {
	int i;
	for(i=0;i<module->code->nfunctions;i++)
		if( module->code->functions[i].findex == stable_id )
			return module->code->functions + i;
	return NULL;
}

static unsigned int read_u32( const unsigned char *p ) {
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned int)p[3] << 24);
}

typedef struct {
	const unsigned char *module_id;
	int revision;
	int initializer_slot;
	int identity_count;
	const unsigned char *encoded_entries;
	const int *stable_ids;
	const int *slots;
} hl_runtime_manifest;

static int manifest_stable_id( const hl_runtime_manifest *manifest, int index ) {
	return manifest->encoded_entries != NULL ? (int)read_u32(manifest->encoded_entries + index * 8) : manifest->stable_ids[index];
}

static int manifest_slot( const hl_runtime_manifest *manifest, int index ) {
	return manifest->encoded_entries != NULL ? (int)read_u32(manifest->encoded_entries + index * 8 + 4) : manifest->slots[index];
}

static hl_runtime_status hl_runtime_module_load_code_manifest_internal( hl_code *code, const unsigned char *bytes, int length,
	const hl_runtime_manifest *manifest, hl_runtime_module **out, bool initialize, bool haxe_metadata,
	hl_code *owned_code, bool *code_owned ) {
	hl_module *module;
	hl_runtime_module *runtime;
	int i, j;
	/* Haxe-owned metadata loads use the Haxe retirement backlog. The native
	   retry list is compatibility state for the legacy byte-decoder path. */
	if( !haxe_metadata ) hl_runtime_failed_retirements_retry();
	if( code_owned != NULL ) *code_owned = false;
	if( out == NULL || code == NULL || length < 0 || (length > 0 && bytes == NULL) || manifest == NULL || manifest->module_id == NULL
		|| manifest->revision < 0 || manifest->initializer_slot < -1 || manifest->identity_count < 0 || manifest->identity_count > 0x100000
		|| (manifest->identity_count > 0 && manifest->encoded_entries == NULL && (manifest->stable_ids == NULL || manifest->slots == NULL)) )
		return HL_RUNTIME_BAD_ARGUMENT;
	*out = NULL;
	module = hl_module_alloc(code);
	if( module != NULL && length > 0 ) {
		module->debug_hlb = (unsigned char*)malloc(length);
		if( module->debug_hlb != NULL ) {
			memcpy(module->debug_hlb,bytes,length);
			module->debug_hlb_size = length;
		}
	}
	if( module == NULL || (length > 0 && module->debug_hlb == NULL) || !hl_module_init(module,HL_MODULE_PATCHABLE | (haxe_metadata ? HL_MODULE_HAXE_METADATA : 0)) ) {
		if( module != NULL ) hl_module_free_shutdown(module);
		return HL_RUNTIME_JIT_FAILED;
	}
	runtime = (hl_runtime_module*)malloc(sizeof(hl_runtime_module));
	if( runtime == NULL ) {
		hl_module_unload(module);
		return HL_RUNTIME_JIT_FAILED;
	}
	runtime->module = module;
	runtime->owned_code = NULL;
	runtime->module->revision = manifest->revision;
	memcpy(runtime->module_id,manifest->module_id,16);
	runtime->identity_count = manifest->identity_count;
	runtime->borrowed_identity = manifest->encoded_entries == NULL;
	runtime->stable_ids = runtime->borrowed_identity ? manifest->stable_ids : (const int*)malloc(sizeof(int) * manifest->identity_count);
	runtime->slots = runtime->borrowed_identity ? manifest->slots : (const int*)malloc(sizeof(int) * manifest->identity_count);
	runtime->retirement_next = NULL;
	runtime->owned_code = owned_code;
	if( code_owned != NULL && owned_code != NULL ) *code_owned = true;
	if( (manifest->identity_count > 0) && (runtime->stable_ids == NULL || runtime->slots == NULL) ) {
		runtime_identity_free(runtime);
		hl_module_unload(module);
		runtime_code_free(runtime->owned_code);
		free(runtime);
		return HL_RUNTIME_JIT_FAILED;
	}
	for(i=0;i<manifest->identity_count;i++) {
		if( !runtime->borrowed_identity ) {
			((int*)runtime->stable_ids)[i] = manifest_stable_id(manifest,i);
			((int*)runtime->slots)[i] = manifest_slot(manifest,i);
		}
		if( runtime->stable_ids[i] < 0 || find_function(module,runtime->slots[i]) == NULL ) {
			runtime_identity_free(runtime);
			hl_module_unload(module);
			runtime_code_free(runtime->owned_code);
			free(runtime);
			return HL_RUNTIME_BAD_FORMAT;
		}
		for(j=0;j<i;j++) if( runtime->stable_ids[j] == runtime->stable_ids[i] || runtime->slots[j] == runtime->slots[i] ) {
			runtime_identity_free(runtime);
			hl_module_unload(module);
			runtime_code_free(runtime->owned_code);
			free(runtime);
			return HL_RUNTIME_BAD_FORMAT;
		}
	}
	runtime->lock = hl_mutex_alloc(true);
	hl_add_root(&runtime->lock);
	if( manifest->initializer_slot >= 0 ) {
		int initializer_id = -1;
		for(i=0;i<manifest->identity_count;i++)
			if( runtime->slots[i] == manifest->initializer_slot ) initializer_id = runtime->stable_ids[i];
		if( initializer_id < 0 ) {
			if( hl_runtime_module_release(runtime) != HL_RUNTIME_OK ) failed_retirement_add(runtime);
			return HL_RUNTIME_BAD_FORMAT;
		}
		if( initialize ) {
			vdynamic *exception = NULL;
			hl_runtime_status status = hl_runtime_module_call_void(runtime,initializer_id,&exception);
			if( status != HL_RUNTIME_OK ) {
				exception = NULL;
				runtime_clear_exception_state();
				/* Unpublish now, but do not reclaim JIT metadata while the failed
				   initializer's native call frames can still retain raw pointers. */
				hl_module_retire_prepare(runtime->module);
				failed_retirement_add(runtime);
				return status;
			}
		}
	}
	*out = runtime;
	hl_debug_notify_revision(module);
	return HL_RUNTIME_OK;
}

static hl_runtime_status hl_runtime_module_load_code_internal( hl_code *code, const unsigned char *bytes, int length, const unsigned char *identity,
	int identity_length, hl_runtime_module **out, bool initialize, bool haxe_metadata,
	hl_code *owned_code, bool *code_owned ) {
	hl_runtime_manifest manifest;
	int version, identity_count, entries_offset, initializer_slot;
	if( out == NULL || code == NULL || bytes == NULL || length <= 0 || identity == NULL || identity_length < 28 ) return HL_RUNTIME_BAD_ARGUMENT;
	version = identity[3];
	if( memcmp(identity,"HLI",3) != 0 || (version != 2 && version != 3) ) return HL_RUNTIME_BAD_FORMAT;
	if( version == 3 && identity_length < 32 ) return HL_RUNTIME_BAD_FORMAT;
	identity_count = (int)read_u32(identity + 24);
	entries_offset = version == 3 ? 32 : 28;
	initializer_slot = version == 3 ? (int)read_u32(identity + 28) : -1;
	if( (int)read_u32(identity + 20) < 0 || identity_count < 0 || identity_count > 0x100000 || initializer_slot < -1
		|| identity_length != entries_offset + identity_count * 8 ) return HL_RUNTIME_BAD_FORMAT;
	manifest.module_id = identity + 4;
	manifest.revision = (int)read_u32(identity + 20);
	manifest.initializer_slot = initializer_slot;
	manifest.identity_count = identity_count;
	manifest.encoded_entries = identity + entries_offset;
	manifest.stable_ids = NULL;
	manifest.slots = NULL;
	if( version == 2 )
		for(int i=0;i<identity_count;i++)
			if( (int)read_u32(manifest.encoded_entries + i * 8) == HL_RUNTIME_V2_INIT_STABLE_ID )
				manifest.initializer_slot = (int)read_u32(manifest.encoded_entries + i * 8 + 4);
	return hl_runtime_module_load_code_manifest_internal(code,bytes,length,&manifest,out,initialize,haxe_metadata,owned_code,code_owned);
}

hl_runtime_status hl_runtime_module_load( const unsigned char *bytes, int length, const unsigned char *identity, int identity_length, hl_runtime_module **out ) {
	char *error = NULL;
	hl_code *code = NULL;
	hl_runtime_status status;
	if( bytes == NULL || length <= 0 ) return HL_RUNTIME_BAD_ARGUMENT;
	code = hl_code_read(bytes,length,&error);
	if( code == NULL ) return HL_RUNTIME_BAD_FORMAT;
	bool code_owned = false;
	status = hl_runtime_module_load_code_internal(code,bytes,length,identity,identity_length,out,true,false,code,&code_owned);
	if( !code_owned )
		runtime_code_free(code);
	return status;
}

hl_runtime_status hl_runtime_module_load_code( hl_code *code, const unsigned char *bytes, int length, const unsigned char *identity, int identity_length, hl_runtime_module **out ) {
	return hl_runtime_module_load_code_internal(code,bytes,length,identity,identity_length,out,false,true,NULL,NULL);
}

hl_runtime_status hl_runtime_module_load_code_manifest( hl_code *code, const unsigned char *bytes, int length, const unsigned char *module_id,
	int module_id_length, int revision, const int *stable_ids, const int *slots, int identity_count, int initializer_slot, hl_runtime_module **out ) {
	hl_runtime_manifest manifest;
	if( module_id_length != 16 ) return HL_RUNTIME_BAD_FORMAT;
	manifest.module_id = module_id;
	manifest.revision = revision;
	manifest.initializer_slot = initializer_slot;
	manifest.identity_count = identity_count;
	manifest.encoded_entries = NULL;
	manifest.stable_ids = stable_ids;
	manifest.slots = slots;
	return hl_runtime_module_load_code_manifest_internal(code,bytes,length,&manifest,out,false,true,NULL,NULL);
}

hl_runtime_status hl_runtime_module_initialize_constant( hl_runtime_module *runtime, int index ) {
	bool initialized;
	if( runtime == NULL || runtime->module == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	initialized = hl_module_init_constant(runtime->module,index) != 0;
	hl_mutex_release(runtime->lock);
	return initialized ? HL_RUNTIME_OK : HL_RUNTIME_BAD_ARGUMENT;
}

static int resolve_stable_id( hl_runtime_module *runtime, int stable_id ) {
	int i;
	for(i=0;i<runtime->identity_count;i++) if( runtime->stable_ids[i] == stable_id ) return runtime->slots[i];
	return -1;
}

static bool patch_from_haxe_input( hl_patch *patch, hl_patch_input *input ) {
	if( patch == NULL || input == NULL || input->module_id == NULL || input->base_revision < 0 || input->revision <= input->base_revision
		|| input->base_int_count < 0 || input->int_count < 0 || (input->int_count > 0 && input->ints == NULL)
		|| input->float_count < 0 || input->base_float_count < 0 || (input->float_count > 0 && input->floats == NULL)
		|| input->string_count < 0 || input->base_string_count < 0
		|| (input->string_count > 0 && (input->strings == NULL || input->string_lens == NULL))
		|| input->type_count < 0 || input->base_type_count < 0 || input->function_count <= 0 || input->functions == NULL
		|| input->debug_file_count < 0 || (input->debug_file_count > 0 && (input->debug_files == NULL || input->debug_file_lens == NULL))
		|| input->source_snapshot_count < 0
		|| (input->source_snapshot_count > 0 && input->source_snapshots == NULL) ) return false;
	memset(patch,0,sizeof(*patch));
	memcpy(patch->module_id,input->module_id,16);
	patch->base_revision = input->base_revision;
	patch->revision = input->revision;
	patch->int_prefix_hash = input->int_prefix_hash;
	patch->float_prefix_hash = input->float_prefix_hash;
	patch->string_prefix_hash = input->string_prefix_hash;
	patch->type_prefix_hash = input->type_prefix_hash;
	patch->base_int_count = input->base_int_count;
	patch->int_count = input->int_count;
	patch->ints = input->ints;
	patch->float_count = input->float_count;
	patch->base_float_count = input->base_float_count;
	patch->floats = input->floats;
	patch->string_count = input->string_count;
	patch->base_string_count = input->base_string_count;
	patch->strings = (char**)input->strings;
	patch->string_lens = input->string_lens;
	patch->type_count = input->type_count;
	patch->base_type_count = input->base_type_count;
	patch->types = NULL;
	patch->function_count = input->function_count;
	patch->functions = input->functions;
	patch->debug_file_count = input->debug_file_count;
	patch->debug_files = (char**)input->debug_files;
	patch->debug_file_lens = input->debug_file_lens;
	patch->source_snapshot_count = input->source_snapshot_count;
	patch->source_snapshots = input->source_snapshots;
	return true;
}

const char *hl_runtime_module_resolve_jit_location_slot( hl_runtime_module *runtime, int slot ) {
	void *address;
	if( runtime == NULL || find_function(runtime->module,slot) == NULL ) return NULL;
	address = runtime->module->patch_targets ? runtime->module->patch_targets[slot] : runtime->module->functions_ptrs[slot];
	return hl_module_resolve_jit_location(address);
}

const char *hl_runtime_module_resolve_jit_location( hl_runtime_module *runtime, int stable_id ) {
	return hl_runtime_module_resolve_jit_location_slot(runtime,resolve_stable_id(runtime,stable_id));
}

int hl_runtime_module_debug_region_count( hl_runtime_module *runtime ) {
	return runtime == NULL ? 0 : hl_module_patch_debug_region_count(runtime->module);
}

static hl_runtime_status call_i32_slot_locked( hl_runtime_module *runtime, int slot, int *out, vdynamic **exception ) {
	hl_function *function;
	vclosure closure;
	vdynamic *result;
	bool raised = false;
	if( exception != NULL ) *exception = NULL;
	function = find_function(runtime->module,slot);
	if( function == NULL || function->type->kind != HFUN || function->type->fun->nargs != 0 || function->type->fun->ret->kind != HI32 ) {
		return HL_RUNTIME_BAD_FUNCTION;
	}
	closure.t = function->type;
	closure.fun = runtime->module->functions_ptrs[slot];
	closure.hasValue = 0;
	closure.value = NULL;
	result = hl_dyn_call_safe(&closure,NULL,0,&raised);
	if( raised ) {
		if( exception != NULL ) *exception = result;
		return HL_RUNTIME_EXCEPTION;
	}
	*out = result->v.i;
	return HL_RUNTIME_OK;
}

hl_runtime_status hl_runtime_module_call_i32( hl_runtime_module *runtime, int stable_id, int *out, vdynamic **exception ) {
	hl_runtime_status status;
	int slot;
	if( runtime == NULL || out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	slot = resolve_stable_id(runtime,stable_id);
	status = call_i32_slot_locked(runtime,slot,out,exception);
	hl_mutex_release(runtime->lock);
	return status;
}

hl_runtime_status hl_runtime_module_call_i32_slot( hl_runtime_module *runtime, int slot, int *out, vdynamic **exception ) {
	hl_runtime_status status;
	if( runtime == NULL || out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	status = call_i32_slot_locked(runtime,slot,out,exception);
	hl_mutex_release(runtime->lock);
	return status;
}

static hl_runtime_status call_checked_slot_locked( hl_runtime_module *runtime, int slot, int nargs, hl_type_kind result_kind,
	vdynamic **args, vdynamic **result_out, vdynamic **exception ) {
	hl_function *function;
	vclosure closure;
	vdynamic *result;
	bool raised = false;
	if( exception != NULL ) *exception = NULL;
	if( result_out != NULL ) *result_out = NULL;
	function = find_function(runtime->module,slot);
	if( function == NULL || function->type->kind != HFUN || function->type->fun->nargs != nargs || (result_kind != (hl_type_kind)-1 && function->type->fun->ret->kind != result_kind) ) {
		return HL_RUNTIME_BAD_FUNCTION;
	}
	closure.t = function->type;
	closure.fun = runtime->module->functions_ptrs[slot];
	closure.hasValue = 0;
	closure.value = NULL;
	result = hl_dyn_call_safe(&closure,args,nargs,&raised);
	if( raised ) {
		if( exception != NULL ) *exception = result;
		return HL_RUNTIME_EXCEPTION;
	}
	if( result_out != NULL ) *result_out = result;
	return HL_RUNTIME_OK;
}

static hl_runtime_status call_checked( hl_runtime_module *runtime, int stable_id, int nargs, hl_type_kind result_kind,
	vdynamic **args, vdynamic **result_out, vdynamic **exception ) {
	hl_runtime_status status;
	int slot;
	if( runtime == NULL || (nargs > 0 && args == NULL) ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	slot = resolve_stable_id(runtime,stable_id);
	status = call_checked_slot_locked(runtime,slot,nargs,result_kind,args,result_out,exception);
	hl_mutex_release(runtime->lock);
	return status;
}

static hl_runtime_status call_checked_slot( hl_runtime_module *runtime, int slot, int nargs, hl_type_kind result_kind,
	vdynamic **args, vdynamic **result_out, vdynamic **exception ) {
	hl_runtime_status status;
	if( runtime == NULL || (nargs > 0 && args == NULL) ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	status = call_checked_slot_locked(runtime,slot,nargs,result_kind,args,result_out,exception);
	hl_mutex_release(runtime->lock);
	return status;
}

hl_runtime_status hl_runtime_module_call_void( hl_runtime_module *runtime, int stable_id, vdynamic **exception ) {
	return call_checked(runtime,stable_id,0,HVOID,NULL,NULL,exception);
}

hl_runtime_status hl_runtime_module_call_void_slot( hl_runtime_module *runtime, int slot, vdynamic **exception ) {
	return call_checked_slot(runtime,slot,0,HVOID,NULL,NULL,exception);
}

hl_runtime_status hl_runtime_module_call_bytes( hl_runtime_module *runtime, int stable_id, vbyte **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked(runtime,stable_id,0,HBYTES,NULL,&result,exception);
	if( status == HL_RUNTIME_OK ) *out = result == NULL ? NULL : result->v.bytes;
	return status;
}

hl_runtime_status hl_runtime_module_call_bytes_slot( hl_runtime_module *runtime, int slot, vbyte **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked_slot(runtime,slot,0,HBYTES,NULL,&result,exception);
	if( status == HL_RUNTIME_OK ) *out = result == NULL ? NULL : result->v.bytes;
	return status;
}

hl_runtime_status hl_runtime_module_call_bytes1( hl_runtime_module *runtime, int stable_id, vbyte *argument, vdynamic **exception ) {
	vdynamic *args[1];
	if( runtime == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	args[0] = hl_alloc_dynamic(&hlt_bytes);
	args[0]->v.bytes = argument;
	return call_checked(runtime,stable_id,1,HVOID,args,NULL,exception);
}

hl_runtime_status hl_runtime_module_call_bytes1_slot( hl_runtime_module *runtime, int slot, vbyte *argument, vdynamic **exception ) {
	vdynamic *args[1];
	if( runtime == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	args[0] = hl_alloc_dynamic(&hlt_bytes);
	args[0]->v.bytes = argument;
	return call_checked_slot(runtime,slot,1,HVOID,args,NULL,exception);
}

hl_runtime_status hl_runtime_module_call_closure( hl_runtime_module *runtime, int stable_id, vclosure **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked(runtime,stable_id,0,HFUN,NULL,&result,exception);
	if( status == HL_RUNTIME_OK ) *out = (vclosure*)result;
	return status;
}

hl_runtime_status hl_runtime_module_call_closure_slot( hl_runtime_module *runtime, int slot, vclosure **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked_slot(runtime,slot,0,HFUN,NULL,&result,exception);
	if( status == HL_RUNTIME_OK ) *out = (vclosure*)result;
	return status;
}

hl_runtime_status hl_runtime_module_call_retained_closure_i32( hl_runtime_module *runtime, vclosure *closure, int *out, vdynamic **exception ) {
	vdynamic *result;
	bool raised = false;
	if( runtime == NULL || closure == NULL || out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	if( exception != NULL ) *exception = NULL;
	hl_mutex_acquire(runtime->lock);
	if( closure->t->kind != HFUN || closure->t->fun->nargs != 0 || closure->t->fun->ret->kind != HI32 ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_BAD_FUNCTION;
	}
	result = hl_dyn_call_safe(closure,NULL,0,&raised);
	hl_mutex_release(runtime->lock);
	if( raised ) {
		if( exception != NULL ) *exception = result;
		return HL_RUNTIME_EXCEPTION;
	}
	*out = result->v.i;
	return HL_RUNTIME_OK;
}

hl_runtime_status hl_runtime_module_call_object( hl_runtime_module *runtime, int stable_id, vdynamic **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked(runtime,stable_id,0,(hl_type_kind)-1,NULL,&result,exception);
	if( status == HL_RUNTIME_OK && (result == NULL || (result->t->kind != HOBJ && result->t->kind != HSTRUCT)) ) return HL_RUNTIME_BAD_FUNCTION;
	if( status == HL_RUNTIME_OK ) *out = result;
	return status;
}

hl_runtime_status hl_runtime_module_call_object_slot( hl_runtime_module *runtime, int slot, vdynamic **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked_slot(runtime,slot,0,(hl_type_kind)-1,NULL,&result,exception);
	if( status == HL_RUNTIME_OK && (result == NULL || (result->t->kind != HOBJ && result->t->kind != HSTRUCT)) ) return HL_RUNTIME_BAD_FUNCTION;
	if( status == HL_RUNTIME_OK ) *out = result;
	return status;
}

hl_runtime_status hl_runtime_module_call_i32_object( hl_runtime_module *runtime, int stable_id, vdynamic *argument, int *out, vdynamic **exception ) {
	vdynamic *args[1], *result = NULL;
	hl_runtime_status status;
	if( argument == NULL || out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	args[0] = argument;
	status = call_checked(runtime,stable_id,1,HI32,args,&result,exception);
	if( status == HL_RUNTIME_OK ) *out = result->v.i;
	return status;
}

hl_runtime_status hl_runtime_module_call_i32_object_slot( hl_runtime_module *runtime, int slot, vdynamic *argument, int *out, vdynamic **exception ) {
	vdynamic *args[1], *result = NULL;
	hl_runtime_status status;
	if( argument == NULL || out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	args[0] = argument;
	status = call_checked_slot(runtime,slot,1,HI32,args,&result,exception);
	if( status == HL_RUNTIME_OK ) *out = result->v.i;
	return status;
}

hl_runtime_status hl_runtime_module_apply_hlp( hl_runtime_module *runtime, const unsigned char *bytes, int length ) {
	return hl_runtime_module_apply_hlp_capture(runtime,bytes,length,NULL);
}

hl_runtime_status hl_runtime_module_apply_hlp_capture( hl_runtime_module *runtime, const unsigned char *bytes, int length, hl_patch_code **published_code ) {
	return hl_runtime_module_apply_hlp_capture_types(runtime,bytes,length,-1,published_code);
}

hl_runtime_status hl_runtime_module_apply_hlp_capture_types( hl_runtime_module *runtime, const unsigned char *bytes, int length, int haxe_type_count, hl_patch_code **published_code ) {
	return hl_runtime_module_apply_hlp_capture_metadata(runtime,bytes,length,haxe_type_count,NULL,-1,NULL,NULL,published_code);
}

hl_runtime_status hl_runtime_module_apply_hlp_capture_metadata( hl_runtime_module *runtime, const unsigned char *bytes, int length, int haxe_type_count,
	hl_function *haxe_functions, int haxe_function_count, hl_patch_pools *haxe_pools, hl_patch_debug *haxe_debug, hl_patch_code **published_code ) {
	const char *error = NULL;
	hl_patch *patch;
	h_bool applied;
	if( published_code != NULL ) *published_code = NULL;
	if( runtime == NULL || bytes == NULL || length <= 0 ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	patch = hl_patch_read(bytes,length,&error);
	if( patch == NULL ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_BAD_FORMAT;
	}
	if( memcmp(runtime->module_id,patch->module_id,16) != 0 ) {
		hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE;
	}
	for(int i=0;i<patch->function_count;i++) {
		int slot = resolve_stable_id(runtime,patch->functions[i].stable_id);
		if( slot < 0 ) { hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE; }
		patch->functions[i].findex = slot;
		for(int j=0;j<patch->functions[i].relocation_count;j++) {
			int instruction=patch->functions[i].relocation_instructions[j];
			int target=resolve_stable_id(runtime,patch->functions[i].relocation_stable_ids[j]);
			int opcode=instruction<0||instruction>=patch->functions[i].instruction_count?-1:patch->functions[i].instructions[instruction].opcode;
			if(target<0||(opcode!=OCall0&&opcode!=OCall1&&opcode!=OCall2&&opcode!=OCallN&&opcode!=OStaticClosure&&opcode!=OInstanceClosure)){hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE;}
			patch->functions[i].instructions[instruction].operands[1]=target;
		}
	}
	applied = hl_module_apply_patch_capture_metadata(runtime->module,patch,&error,published_code,haxe_type_count,haxe_functions,haxe_function_count,haxe_pools,haxe_debug);
	hl_patch_free(patch);
	hl_mutex_release(runtime->lock);
	if( applied ) {
		hl_profile_stream_notify_revision(runtime->module->diagnostics_id,runtime->module->revision);
		hl_debug_notify_revision(runtime->module);
		return HL_RUNTIME_OK;
	}
	if( error != NULL && strcmp(error,"Stale patch revision") == 0 ) return HL_RUNTIME_STALE_PATCH;
	return HL_RUNTIME_INCOMPATIBLE;
}

hl_runtime_status hl_runtime_module_apply_hlp_capture_metadata_input( hl_runtime_module *runtime, hl_patch_input *input, int haxe_type_count,
	hl_function *haxe_functions, int haxe_function_count, hl_patch_pools *haxe_pools, hl_patch_debug *haxe_debug,
	hl_patch_code **published_code ) {
	const char *error = NULL;
	hl_patch patch;
	h_bool applied;
	if( published_code != NULL ) *published_code = NULL;
	if( runtime == NULL || input == NULL || haxe_type_count < 0 || haxe_function_count < 0 || haxe_functions == NULL
		|| haxe_pools == NULL || haxe_debug == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	if( !patch_from_haxe_input(&patch,input) ) return HL_RUNTIME_BAD_FORMAT;
	hl_mutex_acquire(runtime->lock);
	if( memcmp(runtime->module_id,patch.module_id,16) != 0 ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_INCOMPATIBLE;
	}
	applied = hl_module_apply_patch_capture_metadata(runtime->module,&patch,&error,published_code,haxe_type_count,haxe_functions,
		haxe_function_count,haxe_pools,haxe_debug);
	hl_mutex_release(runtime->lock);
	if( applied ) {
		hl_profile_stream_notify_revision(runtime->module->diagnostics_id,runtime->module->revision);
		hl_debug_notify_revision(runtime->module);
		return HL_RUNTIME_OK;
	}
	if( error != NULL && strcmp(error,"Stale patch revision") == 0 ) return HL_RUNTIME_STALE_PATCH;
	return HL_RUNTIME_INCOMPATIBLE;
}

hl_runtime_status hl_runtime_hlp_summary( const unsigned char *bytes, int length, int *base_revision, int *revision, int *function_count ) {
	const char *error = NULL;
	hl_patch *patch;
	if( bytes == NULL || length <= 0 || base_revision == NULL || revision == NULL || function_count == NULL )
		return HL_RUNTIME_BAD_ARGUMENT;
	patch = hl_patch_read(bytes,length,&error);
	if( patch == NULL ) return HL_RUNTIME_BAD_FORMAT;
	*base_revision = patch->base_revision;
	*revision = patch->revision;
	*function_count = patch->function_count;
	hl_patch_free(patch);
	return HL_RUNTIME_OK;
}

int hl_runtime_module_revision( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return 0;
	hl_mutex_acquire(runtime->lock);
	int result = runtime->module->revision;
	hl_mutex_release(runtime->lock);
	return result;
}

int hl_runtime_module_jit_count( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return 0;
	hl_mutex_acquire(runtime->lock);
	int result = runtime->module->patch_jit_count;
	hl_mutex_release(runtime->lock);
	return result;
}

int hl_runtime_module_allocation_count( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return 0;
	hl_mutex_acquire(runtime->lock);
	int result = 1 + hl_module_patch_allocation_count(runtime->module);
	hl_mutex_release(runtime->lock);
	return result;
}

int hl_runtime_module_retired_allocation_count( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return 0;
	hl_mutex_acquire(runtime->lock);
	int result = hl_module_patch_retired_allocation_count(runtime->module);
	hl_mutex_release(runtime->lock);
	return result;
}

int hl_runtime_module_type_count( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return 0;
	hl_mutex_acquire(runtime->lock);
	int result = runtime->module->code->ntypes;
	hl_mutex_release(runtime->lock);
	return result;
}

int hl_runtime_module_type_capacity( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return 0;
	hl_mutex_acquire(runtime->lock);
	int result = runtime->module->code->types_capacity;
	hl_mutex_release(runtime->lock);
	return result;
}

int hl_runtime_module_live_allocation_count( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return 0;
	hl_mutex_acquire(runtime->lock);
	int result = hl_module_live_allocation_count(runtime->module);
	hl_mutex_release(runtime->lock);
	return result;
}

int hl_runtime_module_native_root_count( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return 0;
	hl_mutex_acquire(runtime->lock);
	int result = hl_module_native_root_count(runtime->module);
	hl_mutex_release(runtime->lock);
	return result;
}

int hl_runtime_module_debug_hlb_size( hl_runtime_module *runtime ) {
	int result;
	if( runtime == NULL || runtime->module == NULL ) return -1;
	hl_mutex_acquire(runtime->lock);
	result = runtime->module->debug_hlb_size;
	hl_mutex_release(runtime->lock);
	return result;
}

void hl_runtime_module_retirement_status_get( hl_runtime_module *runtime, hl_module_retirement_status *out ) {
	if( out == NULL ) return;
	memset(out,0,sizeof(*out));
	if( runtime == NULL ) return;
	hl_mutex_acquire(runtime->lock);
	hl_module_retirement_status_get(runtime->module,out);
	hl_mutex_release(runtime->lock);
}

void hl_runtime_module_set_patch_failure_stage( hl_runtime_module *runtime, int stage ) {
	if( runtime == NULL ) return;
	hl_mutex_acquire(runtime->lock);
	runtime->module->patch_failure_stage = stage >= 1 && stage <= 3 ? stage : 0;
	hl_mutex_release(runtime->lock);
}

hl_runtime_status hl_runtime_module_release( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	if( !hl_module_retire_try(runtime->module,NULL) ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_RETIRE_BLOCKED;
	}
	runtime->module = NULL;
	hl_mutex_release(runtime->lock);
	runtime_wrapper_free(runtime);
	return HL_RUNTIME_OK;
}
