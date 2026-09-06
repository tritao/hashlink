#include <hlmodule.h>
#include <stdlib.h>
#include <string.h>

#define HL_RUNTIME_INIT_STABLE_ID 0x7FFF0000

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

hl_runtime_status hl_runtime_module_load( const unsigned char *bytes, int length, const unsigned char *identity, int identity_length, hl_runtime_module **out ) {
	char *error = NULL;
	hl_code *code;
	hl_module *module;
	hl_runtime_module *runtime;
	int identity_count, revision, i, j;
	hl_runtime_failed_retirements_retry();
	if( out == NULL || bytes == NULL || length <= 0 || identity == NULL || identity_length < 28 ) return HL_RUNTIME_BAD_ARGUMENT;
	*out = NULL;
	if( memcmp(identity,"HLI",3) != 0 || identity[3] != 2 ) return HL_RUNTIME_BAD_FORMAT;
	revision = (int)read_u32(identity + 20);
	identity_count = (int)read_u32(identity + 24);
	if( revision < 0 || identity_count < 0 || identity_count > 0x100000 || identity_length != 28 + identity_count * 8 ) return HL_RUNTIME_BAD_FORMAT;
	code = hl_code_read(bytes,length,&error);
	if( code == NULL ) return HL_RUNTIME_BAD_FORMAT;
	module = hl_module_alloc(code);
	if( module != NULL ) {
		module->debug_hlb = (unsigned char*)malloc(length);
		if( module->debug_hlb != NULL ) {
			memcpy(module->debug_hlb,bytes,length);
			module->debug_hlb_size = length;
		}
	}
	if( module == NULL || module->debug_hlb == NULL || !hl_module_init(module,HL_MODULE_PATCHABLE) ) {
		if( module != NULL ) hl_module_free_shutdown(module);
		hl_code_free(code);
		return HL_RUNTIME_JIT_FAILED;
	}
	hl_code_free(code);
	runtime = (hl_runtime_module*)malloc(sizeof(hl_runtime_module));
	if( runtime == NULL ) {
		hl_module_unload(module);
		return HL_RUNTIME_JIT_FAILED;
	}
	runtime->module = module;
	runtime->module->revision = revision;
	memcpy(runtime->module_id,identity + 4,16);
	runtime->identity_count = identity_count;
	runtime->stable_ids = (int*)malloc(sizeof(int) * identity_count);
	runtime->slots = (int*)malloc(sizeof(int) * identity_count);
	runtime->retirement_next = NULL;
	if( (identity_count > 0) && (runtime->stable_ids == NULL || runtime->slots == NULL) ) {
		free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_JIT_FAILED;
	}
	for(i=0;i<identity_count;i++) {
		runtime->stable_ids[i] = (int)read_u32(identity + 28 + i * 8);
		runtime->slots[i] = (int)read_u32(identity + 32 + i * 8);
		if( runtime->stable_ids[i] < 0 || find_function(module,runtime->slots[i]) == NULL ) {
			free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_BAD_FORMAT;
		}
		for(j=0;j<i;j++) if( runtime->stable_ids[j] == runtime->stable_ids[i] || runtime->slots[j] == runtime->slots[i] ) {
			free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_BAD_FORMAT;
		}
	}
	runtime->lock = hl_mutex_alloc(true);
	hl_add_root(&runtime->lock);
	if( resolve_stable_id(runtime,HL_RUNTIME_INIT_STABLE_ID) >= 0 ) {
		vdynamic *exception = NULL;
		hl_runtime_status status = hl_runtime_module_call_void(runtime,HL_RUNTIME_INIT_STABLE_ID,&exception);
		if( status != HL_RUNTIME_OK ) {
			exception = NULL;
			runtime_clear_exception_state();
			if( hl_runtime_module_release(runtime) != HL_RUNTIME_OK )
				failed_retirement_add(runtime);
			return status;
		}
	}
	*out = runtime;
	hl_debug_notify_revision(module);
	return HL_RUNTIME_OK;
}

static int resolve_stable_id( hl_runtime_module *runtime, int stable_id ) {
	int i;
	for(i=0;i<runtime->identity_count;i++) if( runtime->stable_ids[i] == stable_id ) return runtime->slots[i];
	return -1;
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
	const char *error = NULL;
	hl_patch *patch;
	h_bool applied;
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
	applied = hl_module_apply_patch(runtime->module,patch,&error);
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
