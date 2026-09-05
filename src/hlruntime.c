#include <hlmodule.h>
#include <stdlib.h>
#include <string.h>

#define HL_RUNTIME_INIT_STABLE_ID 0x7FFF0000

struct _hl_runtime_module {
	hl_module *module;
	hl_mutex *lock;
	unsigned char module_id[16];
	int identity_count;
	int *stable_ids;
	int *slots;
};

static int resolve_stable_id( hl_runtime_module *runtime, int stable_id );

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
	int identity_count, i, j;
	if( out == NULL || bytes == NULL || length <= 0 || identity == NULL || identity_length < 24 ) return HL_RUNTIME_BAD_ARGUMENT;
	*out = NULL;
	if( memcmp(identity,"HLI",3) != 0 || identity[3] != 1 ) return HL_RUNTIME_BAD_FORMAT;
	identity_count = (int)read_u32(identity + 20);
	if( identity_count < 0 || identity_count > 0x100000 || identity_length != 24 + identity_count * 8 ) return HL_RUNTIME_BAD_FORMAT;
	code = hl_code_read(bytes,length,&error);
	if( code == NULL ) return HL_RUNTIME_BAD_FORMAT;
	module = hl_module_alloc(code);
	if( module == NULL || !hl_module_init(module,HL_MODULE_PATCHABLE) ) {
		if( module != NULL ) hl_module_free(module);
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
	memcpy(runtime->module_id,identity + 4,16);
	runtime->identity_count = identity_count;
	runtime->stable_ids = (int*)malloc(sizeof(int) * identity_count);
	runtime->slots = (int*)malloc(sizeof(int) * identity_count);
	if( (identity_count > 0) && (runtime->stable_ids == NULL || runtime->slots == NULL) ) {
		free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_JIT_FAILED;
	}
	for(i=0;i<identity_count;i++) {
		runtime->stable_ids[i] = (int)read_u32(identity + 24 + i * 8);
		runtime->slots[i] = (int)read_u32(identity + 28 + i * 8);
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
			hl_runtime_module_release(runtime);
			return status;
		}
	}
	*out = runtime;
	return HL_RUNTIME_OK;
}

static int resolve_stable_id( hl_runtime_module *runtime, int stable_id ) {
	int i;
	for(i=0;i<runtime->identity_count;i++) if( runtime->stable_ids[i] == stable_id ) return runtime->slots[i];
	return -1;
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
	if( function == NULL || function->type->kind != HFUN || function->type->fun->nargs != nargs || function->type->fun->ret->kind != result_kind ) {
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
	if( applied ) return HL_RUNTIME_OK;
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
	return runtime == NULL ? 0 : runtime->module->revision;
}

int hl_runtime_module_jit_count( hl_runtime_module *runtime ) {
	return runtime == NULL ? 0 : runtime->module->patch_jit_count;
}

int hl_runtime_module_allocation_count( hl_runtime_module *runtime ) {
	return runtime == NULL ? 0 : 1 + hl_module_patch_allocation_count(runtime->module);
}

void hl_runtime_module_release( hl_runtime_module *runtime ) {
	if( runtime == NULL ) return;
	hl_mutex_acquire(runtime->lock);
	hl_module_unload(runtime->module);
	hl_mutex_release(runtime->lock);
	hl_remove_root(&runtime->lock);
	hl_mutex_free(runtime->lock);
	free(runtime->stable_ids);
	free(runtime->slots);
	free(runtime);
}
