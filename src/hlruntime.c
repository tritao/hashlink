#include <hlmodule.h>
#include <stdlib.h>
#include <string.h>

#define HL_RUNTIME_V2_INIT_STABLE_ID 0x1FFFFFFF

void hl_debug_notify_revision( hl_module *m );

struct _hl_runtime_module {
	hl_module *module;
	hl_mutex *lock;
	unsigned char module_id[16];
	int identity_count;
	int *stable_ids;
	int *slots;
	struct _hl_runtime_module *retirement_next;
};

static hl_runtime_module *failed_retirements = NULL;
static hl_mutex *failed_retirements_lock = NULL;

static void runtime_wrapper_free( hl_runtime_module *runtime ) {
	hl_remove_root(&runtime->lock);
	hl_mutex_free(runtime->lock);
	free(runtime->stable_ids);
	free(runtime->slots);
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

hl_runtime_status hl_runtime_module_validate_call( hl_runtime_module *runtime, int stable_id, int shape ) {
	hl_function *function;
	int nargs;
	hl_type_kind result_kind;
	if( runtime == NULL || shape < 0 || shape > 6 ) return HL_RUNTIME_BAD_ARGUMENT;
	nargs = shape == 3 || shape == 6 ? 1 : 0;
	result_kind = shape == 0 || shape == 6 ? HI32 : shape == 1 || shape == 3 ? HVOID : shape == 2 ? HBYTES : shape == 4 ? HFUN : (hl_type_kind)-1;
	hl_mutex_acquire(runtime->lock);
	stable_id = resolve_stable_id(runtime,stable_id);
	function = find_function(runtime->module,stable_id);
	if( function == NULL || function->type->kind != HFUN || function->type->fun->nargs != nargs || (result_kind != (hl_type_kind)-1 && function->type->fun->ret->kind != result_kind) ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_BAD_FUNCTION;
	}
	hl_mutex_release(runtime->lock);
	return HL_RUNTIME_OK;
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
	const hl_runtime_manifest *manifest, hl_runtime_module **out, bool initialize ) {
	hl_module *module;
	hl_runtime_module *runtime;
	int i, j;
	hl_runtime_failed_retirements_retry();
	if( out == NULL || code == NULL || bytes == NULL || length <= 0 || manifest == NULL || manifest->module_id == NULL
		|| manifest->revision < 0 || manifest->initializer_slot < -1 || manifest->identity_count < 0 || manifest->identity_count > 0x100000
		|| (manifest->identity_count > 0 && manifest->encoded_entries == NULL && (manifest->stable_ids == NULL || manifest->slots == NULL)) )
		return HL_RUNTIME_BAD_ARGUMENT;
	*out = NULL;
	module = hl_module_alloc(code);
	if( module != NULL ) {
		module->debug_hlb = (unsigned char*)malloc(length);
		if( module->debug_hlb != NULL ) {
			memcpy(module->debug_hlb,bytes,length);
			module->debug_hlb_size = length;
		}
	}
	if( module == NULL || module->debug_hlb == NULL || !hl_module_init(module,HL_MODULE_PATCHABLE | HL_MODULE_HAXE_METADATA) ) {
		if( module != NULL ) hl_module_free_shutdown(module);
		return HL_RUNTIME_JIT_FAILED;
	}
	runtime = (hl_runtime_module*)malloc(sizeof(hl_runtime_module));
	if( runtime == NULL ) {
		hl_module_unload(module);
		return HL_RUNTIME_JIT_FAILED;
	}
	runtime->module = module;
	runtime->module->revision = manifest->revision;
	memcpy(runtime->module_id,manifest->module_id,16);
	runtime->identity_count = manifest->identity_count;
	runtime->stable_ids = (int*)malloc(sizeof(int) * manifest->identity_count);
	runtime->slots = (int*)malloc(sizeof(int) * manifest->identity_count);
	runtime->retirement_next = NULL;
	if( (manifest->identity_count > 0) && (runtime->stable_ids == NULL || runtime->slots == NULL) ) {
		free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_JIT_FAILED;
	}
	for(i=0;i<manifest->identity_count;i++) {
		runtime->stable_ids[i] = manifest_stable_id(manifest,i);
		runtime->slots[i] = manifest_slot(manifest,i);
		if( runtime->stable_ids[i] < 0 || find_function(module,runtime->slots[i]) == NULL ) {
			free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_BAD_FORMAT;
		}
		for(j=0;j<i;j++) if( runtime->stable_ids[j] == runtime->stable_ids[i] || runtime->slots[j] == runtime->slots[i] ) {
			free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_BAD_FORMAT;
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
	int identity_length, hl_runtime_module **out, bool initialize ) {
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
	return hl_runtime_module_load_code_manifest_internal(code,bytes,length,&manifest,out,initialize);
}

hl_runtime_status hl_runtime_module_load( const unsigned char *bytes, int length, const unsigned char *identity, int identity_length, hl_runtime_module **out ) {
	char *error = NULL;
	hl_code *code = NULL;
	hl_runtime_status status;
	if( bytes == NULL || length <= 0 ) return HL_RUNTIME_BAD_ARGUMENT;
	code = hl_code_read(bytes,length,&error);
	if( code == NULL ) return HL_RUNTIME_BAD_FORMAT;
	status = hl_runtime_module_load_code_internal(code,bytes,length,identity,identity_length,out,true);
	hl_code_free(code);
	return status;
}

hl_runtime_status hl_runtime_module_load_code( hl_code *code, const unsigned char *bytes, int length, const unsigned char *identity, int identity_length, hl_runtime_module **out ) {
	return hl_runtime_module_load_code_internal(code,bytes,length,identity,identity_length,out,false);
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
	return hl_runtime_module_load_code_manifest_internal(code,bytes,length,&manifest,out,false);
}

static int resolve_stable_id( hl_runtime_module *runtime, int stable_id ) {
	int i;
	for(i=0;i<runtime->identity_count;i++) if( runtime->stable_ids[i] == stable_id ) return runtime->slots[i];
	return -1;
}

static bool apply_haxe_patch_resolution( hl_runtime_module *runtime, hl_patch *patch, hl_patch_resolution *resolution ) {
	if( resolution == NULL || resolution->function_count != patch->function_count || (patch->function_count > 0 && resolution->functions == NULL) ) return false;
	for(int i=0;i<patch->function_count;i++) {
		hl_patch_function *source = patch->functions+i;
		hl_patch_function_resolution *resolved = resolution->functions+i;
		if( source->stable_id != resolved->stable_id || resolve_stable_id(runtime,source->stable_id) != resolved->slot ) return false;
		source->findex = resolved->slot;
		if( source->relocation_count != resolved->relocation_count ) return false;
		for(int j=0;j<source->relocation_count;j++) {
			int instruction = source->relocation_instructions[j];
			int target = resolve_stable_id(runtime,source->relocation_stable_ids[j]);
			if( resolved->relocation_stable_ids == NULL || resolved->relocation_slots == NULL
				|| resolved->relocation_stable_ids[j] != source->relocation_stable_ids[j] || target != resolved->relocation_slots[j]
				|| instruction < 0 || instruction >= source->instruction_count || source->instructions[instruction].operand_count < 2 ) return false;
			source->instructions[instruction].operands[1] = resolved->relocation_slots[j];
		}
	}
	return true;
}

const char *hl_runtime_module_resolve_jit_location( hl_runtime_module *runtime, int stable_id ) {
	int slot;
	void *address;
	if( runtime == NULL ) return NULL;
	slot = resolve_stable_id(runtime,stable_id);
	if( slot < 0 ) return NULL;
	address = runtime->module->patch_targets ? runtime->module->patch_targets[slot] : runtime->module->functions_ptrs[slot];
	return hl_module_resolve_jit_location(address);
}

int hl_runtime_module_debug_region_count( hl_runtime_module *runtime ) {
	return runtime == NULL ? 0 : hl_module_patch_debug_region_count(runtime->module);
}

hl_runtime_status hl_runtime_module_call_i32( hl_runtime_module *runtime, int stable_id, int *out, vdynamic **exception ) {
	hl_function *function;
	vclosure closure;
	vdynamic *result;
	bool raised = false;
	if( runtime == NULL || out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	if( exception != NULL ) *exception = NULL;
	hl_mutex_acquire(runtime->lock);
	stable_id = resolve_stable_id(runtime,stable_id);
	function = find_function(runtime->module,stable_id);
	if( function == NULL || function->type->kind != HFUN || function->type->fun->nargs != 0 || function->type->fun->ret->kind != HI32 ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_BAD_FUNCTION;
	}
	closure.t = function->type;
	closure.fun = runtime->module->functions_ptrs[stable_id];
	closure.hasValue = 0;
	closure.value = NULL;
	result = hl_dyn_call_safe(&closure,NULL,0,&raised);
	hl_mutex_release(runtime->lock);
	if( raised ) {
		if( exception != NULL ) *exception = result;
		return HL_RUNTIME_EXCEPTION;
	}
	*out = result->v.i;
	return HL_RUNTIME_OK;
}

static hl_runtime_status call_checked( hl_runtime_module *runtime, int stable_id, int nargs, hl_type_kind result_kind,
	vdynamic **args, vdynamic **result_out, vdynamic **exception ) {
	hl_function *function;
	vclosure closure;
	vdynamic *result;
	bool raised = false;
	int slot;
	if( runtime == NULL || (nargs > 0 && args == NULL) ) return HL_RUNTIME_BAD_ARGUMENT;
	if( exception != NULL ) *exception = NULL;
	if( result_out != NULL ) *result_out = NULL;
	hl_mutex_acquire(runtime->lock);
	slot = resolve_stable_id(runtime,stable_id);
	function = find_function(runtime->module,slot);
	if( function == NULL || function->type->kind != HFUN || function->type->fun->nargs != nargs || (result_kind != (hl_type_kind)-1 && function->type->fun->ret->kind != result_kind) ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_BAD_FUNCTION;
	}
	closure.t = function->type;
	closure.fun = runtime->module->functions_ptrs[slot];
	closure.hasValue = 0;
	closure.value = NULL;
	result = hl_dyn_call_safe(&closure,args,nargs,&raised);
	hl_mutex_release(runtime->lock);
	if( raised ) {
		if( exception != NULL ) *exception = result;
		return HL_RUNTIME_EXCEPTION;
	}
	if( result_out != NULL ) *result_out = result;
	return HL_RUNTIME_OK;
}

hl_runtime_status hl_runtime_module_call_void( hl_runtime_module *runtime, int stable_id, vdynamic **exception ) {
	return call_checked(runtime,stable_id,0,HVOID,NULL,NULL,exception);
}

hl_runtime_status hl_runtime_module_call_bytes( hl_runtime_module *runtime, int stable_id, vbyte **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked(runtime,stable_id,0,HBYTES,NULL,&result,exception);
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

hl_runtime_status hl_runtime_module_call_closure( hl_runtime_module *runtime, int stable_id, vclosure **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked(runtime,stable_id,0,HFUN,NULL,&result,exception);
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

hl_runtime_status hl_runtime_module_call_i32_object( hl_runtime_module *runtime, int stable_id, vdynamic *argument, int *out, vdynamic **exception ) {
	vdynamic *args[1], *result = NULL;
	hl_runtime_status status;
	if( argument == NULL || out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	args[0] = argument;
	status = call_checked(runtime,stable_id,1,HI32,args,&result,exception);
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
	return hl_runtime_module_apply_hlp_capture_metadata_resolution(runtime,bytes,length,haxe_type_count,haxe_functions,haxe_function_count,haxe_pools,haxe_debug,NULL,published_code);
}

hl_runtime_status hl_runtime_module_apply_hlp_capture_metadata_resolution( hl_runtime_module *runtime, const unsigned char *bytes, int length, int haxe_type_count,
	hl_function *haxe_functions, int haxe_function_count, hl_patch_pools *haxe_pools, hl_patch_debug *haxe_debug, hl_patch_resolution *haxe_resolution,
	hl_patch_code **published_code ) {
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
	if( haxe_resolution != NULL ) {
		if( !apply_haxe_patch_resolution(runtime,patch,haxe_resolution) ) {hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE;}
	} else {
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
	}
	applied = hl_module_apply_patch_capture_metadata_resolution(runtime->module,patch,&error,published_code,haxe_type_count,haxe_functions,haxe_function_count,haxe_pools,haxe_debug,haxe_resolution);
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
