#include <hlmodule.h>
#include <stdlib.h>
#include <string.h>

/* Must match the maximum 29-bit stable ID reserved by HlFunctionCache. */
#define HL_RUNTIME_V2_INIT_STABLE_ID 0x1FFFFFFF

void hl_debug_notify_revision( hl_module *m );

struct _hl_runtime_module {
	hl_module *module;
	hl_mutex *lock;
	unsigned char module_id[16];
	int identity_count;
	int *stable_ids;
	int *slots;
	/* Why the last patch's migrations failed (HL_RUNTIME_MIGRATION_FAILED), or NULL. */
	uchar *patch_message;
	struct _hl_runtime_module *retirement_next;
};

static hl_runtime_module *failed_retirements = NULL;
static hl_mutex *failed_retirements_lock = NULL;

static void runtime_wrapper_free( hl_runtime_module *runtime ) {
	hl_remove_root(&runtime->lock);
	hl_mutex_free(runtime->lock);
	free(runtime->stable_ids);
	free(runtime->slots);
	free(runtime->patch_message);
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

/* String results are String objects; HBYTES is kept for modules predating them. */
static bool result_kind_matches( hl_type *result, hl_type_kind kind ) {
	if( kind == (hl_type_kind)-1 || result->kind == kind ) return true;
	return kind == HBYTES && hl_is_string_type(result);
}

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
	if( runtime == NULL || shape < 0 || shape > 7 ) return HL_RUNTIME_BAD_ARGUMENT;
	nargs = shape == 3 || shape == 6 ? 1 : 0;
	result_kind = shape == 0 || shape == 6 ? HI32 : shape == 1 || shape == 3 ? HVOID : shape == 2 ? HBYTES : shape == 4 ? HFUN : shape == 7 ? HABSTRACT : (hl_type_kind)-1;
	hl_mutex_acquire(runtime->lock);
	stable_id = resolve_stable_id(runtime,stable_id);
	function = find_function(runtime->module,stable_id);
	if( function == NULL || function->type->kind != HFUN || function->type->fun->nargs != nargs || !result_kind_matches(function->type->fun->ret,result_kind) ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_BAD_FUNCTION;
	}
	hl_mutex_release(runtime->lock);
	return HL_RUNTIME_OK;
}

static hl_function *find_function( hl_module *module, int stable_id ) {
	int i;
	for(i=0;i<module->code->nfunctions+module->code->npatchfunctions;i++)
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
	int identity_count, initializer_slot, entries_offset, revision, version, i, j;
	hl_runtime_failed_retirements_retry();
	if( out == NULL || bytes == NULL || length <= 0 || identity == NULL || identity_length < 28 ) return HL_RUNTIME_BAD_ARGUMENT;
	*out = NULL;
	version = identity[3];
	if( memcmp(identity,"HLI",3) != 0 || (version != 2 && version != 3) ) return HL_RUNTIME_BAD_FORMAT;
	revision = (int)read_u32(identity + 20);
	identity_count = (int)read_u32(identity + 24);
	entries_offset = version == 3 ? 32 : 28;
	initializer_slot = version == 3 ? (int)read_u32(identity + 28) : -1;
	if( revision < 0 || identity_count < 0 || identity_count > 0x100000 || initializer_slot < -1
		|| identity_length != entries_offset + identity_count * 8 ) return HL_RUNTIME_BAD_FORMAT;
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
		hl_code_destroy(code);
		return HL_RUNTIME_JIT_FAILED;
	}
	hl_code_free_function_data(code);
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
	runtime->patch_message = NULL;
	runtime->retirement_next = NULL;
	if( (identity_count > 0) && (runtime->stable_ids == NULL || runtime->slots == NULL) ) {
		free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_JIT_FAILED;
	}
	for(i=0;i<identity_count;i++) {
		runtime->stable_ids[i] = (int)read_u32(identity + entries_offset + i * 8);
		runtime->slots[i] = (int)read_u32(identity + entries_offset + 4 + i * 8);
		if( runtime->stable_ids[i] < 0 || find_function(module,runtime->slots[i]) == NULL ) {
			free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_BAD_FORMAT;
		}
		for(j=0;j<i;j++) if( runtime->stable_ids[j] == runtime->stable_ids[i] || runtime->slots[j] == runtime->slots[i] ) {
			free(runtime->stable_ids);free(runtime->slots);free(runtime);hl_module_unload(module);return HL_RUNTIME_BAD_FORMAT;
		}
	}
	runtime->lock = hl_mutex_alloc(true);
	hl_add_root(&runtime->lock);
	if( version == 2 ) {
		for(i=0;i<identity_count;i++)
			if( runtime->stable_ids[i] == HL_RUNTIME_V2_INIT_STABLE_ID ) initializer_slot = runtime->slots[i];
	}
	if( initializer_slot >= 0 ) {
		int initializer_id = -1;
		for(i=0;i<identity_count;i++)
			if( runtime->slots[i] == initializer_slot ) initializer_id = runtime->stable_ids[i];
		if( initializer_id < 0 ) {
			if( hl_runtime_module_release(runtime) != HL_RUNTIME_OK ) failed_retirement_add(runtime);
			return HL_RUNTIME_BAD_FORMAT;
		}
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
	*out = runtime;
	hl_debug_notify_revision(module);
	return HL_RUNTIME_OK;
}

static int resolve_stable_id( hl_runtime_module *runtime, int stable_id ) {
	int i;
	for(i=0;i<runtime->identity_count;i++) if( runtime->stable_ids[i] == stable_id ) return runtime->slots[i];
	return -1;
}

/* A stable ID as a patch sees it: the module's functions, then the ones the patch adds. */
static int resolve_patch_stable_id( hl_runtime_module *runtime, hl_patch *patch, int stable_id ) {
	int slot = resolve_stable_id(runtime,stable_id);
	for(int i=0;slot<0&&i<patch->added_function_count;i++) if( patch->added_functions[i].stable_id == stable_id ) slot = patch->added_functions[i].findex;
	return slot;
}

const char *hl_runtime_module_resolve_jit_location( hl_runtime_module *runtime, int stable_id ) {
	int slot;
	void *address = NULL;
	if( runtime == NULL ) return NULL;
	// A patch that adds functions reallocates the identity tables under the lock.
	hl_mutex_acquire(runtime->lock);
	slot = resolve_stable_id(runtime,stable_id);
	if( slot >= 0 ) address = runtime->module->patch_targets ? runtime->module->patch_targets[slot] : runtime->module->functions_ptrs[slot];
	hl_mutex_release(runtime->lock);
	return address == NULL ? NULL : hl_module_resolve_jit_location(address);
}

int hl_runtime_module_entry_state( hl_runtime_module *runtime, int stable_id ) {
	int slot, state = -1;
	if( runtime == NULL ) return -1;
	hl_mutex_acquire(runtime->lock);
	slot = resolve_stable_id(runtime,stable_id);
	if( slot >= 0 && runtime->module->patch_origin && runtime->module->patch_origin[slot] ) {
		const unsigned char *entry = (const unsigned char*)runtime->module->patch_origin[slot];
		state = entry[0] == 0xE9 ? 2 : entry[0] == 0x48 && entry[1] == 0xB8 ? 1 : 0;
	}
	hl_mutex_release(runtime->lock);
	return state;
}

int hl_runtime_module_calls_directly( hl_runtime_module *runtime, int caller_id, int callee_id ) {
	int caller, callee, result = -1;
	if( runtime == NULL ) return -1;
	hl_mutex_acquire(runtime->lock);
	caller = resolve_stable_id(runtime,caller_id);
	callee = resolve_stable_id(runtime,callee_id);
	if( caller >= 0 && callee >= 0 && runtime->module->patch_origin && runtime->module->patch_origin[caller] && runtime->module->patch_origin[callee] ) {
		const unsigned char *code = (const unsigned char*)runtime->module->patch_origin[caller];
		const unsigned char *end = (const unsigned char*)runtime->module->jit_code + runtime->module->codesize;
		const unsigned char *target = (const unsigned char*)runtime->module->patch_origin[callee];
		// The caller's code is scanned for a call rel32 to the callee's entry; a few hundred bytes cover a test function.
		result = 0;
		for(int i=0;i<1024&&code+i+5<=end;i++) {
			int delta;
			if( code[i] != 0xE8 ) continue;
			memcpy(&delta,code + i + 1,sizeof(delta));
			if( code + i + 5 + delta == target ) { result = 1; break; }
		}
	}
	hl_mutex_release(runtime->lock);
	return result;
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
	if( function == NULL || function->type->kind != HFUN || function->type->fun->nargs != nargs || !result_kind_matches(function->type->fun->ret,result_kind) ) {
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
	if( status == HL_RUNTIME_OK )
		*out = result == NULL ? NULL : hl_is_string_type(result->t) ? (vbyte*)((vstring*)result)->bytes : result->v.bytes;
	return status;
}

hl_runtime_status hl_runtime_module_call_abstract( hl_runtime_module *runtime, int stable_id, const uchar *name, void **out, vdynamic **exception ) {
	vdynamic *result = NULL;
	hl_runtime_status status;
	if( name == NULL || out == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	status = call_checked(runtime,stable_id,0,HABSTRACT,NULL,&result,exception);
	if( status == HL_RUNTIME_OK ) {
		if( result == NULL || result->t->kind != HABSTRACT || ucmp(result->t->abs_name,name) != 0 )
			return HL_RUNTIME_BAD_FUNCTION;
		*out = result->v.ptr;
	}
	return status;
}

hl_runtime_status hl_runtime_module_call_bytes1( hl_runtime_module *runtime, int stable_id, vbyte *argument, vdynamic **exception ) {
	vdynamic *args[1];
	if( runtime == NULL ) return HL_RUNTIME_BAD_ARGUMENT;
	if( argument == NULL )
		args[0] = NULL;
	else if( hl_string_type != NULL )
		args[0] = (vdynamic*)hl_alloc_string((uchar*)argument,(int)ustrlen((uchar*)argument));
	else {
		args[0] = hl_alloc_dynamic(&hlt_bytes);
		args[0]->v.bytes = argument;
	}
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

/*
 * The message for migrations that failed: which class's initializers threw, how often, and the first exception. The
 * patch stays applied, so the fields those calls did not set hold zero values until the module is reloaded.
 */
static uchar *migration_failure_message( hl_patch_migration_report *report ) {
	const uchar *exception = report->first_exception == NULL ? NULL : hl_to_string(report->first_exception);
	const uchar *owner = report->first_type == NULL ? USTR("?") : report->first_type->obj->name;
	int size = 256 + ustrlen(owner) + (exception == NULL ? 0 : ustrlen(exception));
	uchar *message = (uchar*)malloc(sizeof(uchar) * size);
	if( message == NULL ) return NULL;
	if( report->error != NULL ) {
		int i = 0;
		for(;report->error[i] && i < size - 1;i++) message[i] = (uchar)report->error[i];
		message[i] = 0;
	} else
		usprintf(message,size,USTR("the initializers of the fields the patch added threw on %d of %d instances, first in %s: %s"),
			report->failures,report->failures + report->migrated,owner,exception == NULL ? USTR("(no message)") : exception);
	return message;
}

hl_runtime_status hl_runtime_module_apply_hlp( hl_runtime_module *runtime, const unsigned char *bytes, int length ) {
	const char *error = NULL;
	hl_patch *patch;
	h_bool applied;
	hl_patch_migration_report migration;
	bool migration_failed;
	if( runtime == NULL || bytes == NULL || length <= 0 ) return HL_RUNTIME_BAD_ARGUMENT;
	hl_mutex_acquire(runtime->lock);
	free(runtime->patch_message);
	runtime->patch_message = NULL;
	patch = hl_patch_read(bytes,length,&error);
	if( patch == NULL ) {
		hl_mutex_release(runtime->lock);
		return HL_RUNTIME_BAD_FORMAT;
	}
	if( memcmp(runtime->module_id,patch->module_id,16) != 0 ) {
		hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE;
	}
	// Added functions bring new stable IDs, in the slots the module applies them to. Make room for their identities now,
	// so nothing can fail once the module has taken the patch.
	for(int i=0;i<patch->added_function_count;i++)
		if( resolve_stable_id(runtime,patch->added_functions[i].stable_id) >= 0 ) { hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE; }
	if( patch->added_function_count > 0 ) {
		int capacity = runtime->identity_count + patch->added_function_count;
		int *stable_ids = (int*)realloc(runtime->stable_ids,sizeof(int) * capacity);
		if( stable_ids != NULL ) runtime->stable_ids = stable_ids;
		int *slots = stable_ids == NULL ? NULL : (int*)realloc(runtime->slots,sizeof(int) * capacity);
		if( slots != NULL ) runtime->slots = slots;
		if( stable_ids == NULL || slots == NULL ) { hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_JIT_FAILED; }
	}
	for(int i=0;i<patch->function_count;i++) {
		int slot = resolve_patch_stable_id(runtime,patch,patch->functions[i].stable_id);
		if( slot < 0 ) { hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE; }
		patch->functions[i].findex = slot;
		for(int j=0;j<patch->functions[i].relocation_count;j++) {
			int instruction=patch->functions[i].relocation_instructions[j];
			int target=resolve_patch_stable_id(runtime,patch,patch->functions[i].relocation_stable_ids[j]);
			int opcode=instruction<0||instruction>=patch->functions[i].instruction_count?-1:patch->functions[i].instructions[instruction].opcode;
			if(target<0||(opcode!=OCall0&&opcode!=OCall1&&opcode!=OCall2&&opcode!=OCallN&&opcode!=OStaticClosure&&opcode!=OInstanceClosure)){hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE;}
			patch->functions[i].instructions[instruction].operands[1]=target;
		}
	}
	for(int i=0;i<patch->migration_count;i++) {
		patch->migrations[i].findex = resolve_patch_stable_id(runtime,patch,patch->migrations[i].stable_id);
		if( patch->migrations[i].findex < 0 ) { hl_patch_free(patch);hl_mutex_release(runtime->lock);return HL_RUNTIME_INCOMPATIBLE; }
	}
	applied = hl_module_apply_patch(runtime->module,patch,&migration,&error);
	if( applied )
		for(int i=0;i<patch->added_function_count;i++) {
			runtime->stable_ids[runtime->identity_count] = patch->added_functions[i].stable_id;
			runtime->slots[runtime->identity_count++] = patch->added_functions[i].findex;
		}
	// Instances made before the patch ran the initializers of the fields it added before any other code did. One that threw
	// leaves zero values behind while the patch stays applied: the module runs the new revision, and the caller decides
	// whether it can keep running it.
	migration_failed = applied && (migration.failures > 0 || migration.error != NULL);
	if( migration_failed ) runtime->patch_message = migration_failure_message(&migration);
	// A patch the module refused says why, for the caller to report.
	if( !applied && error != NULL ) runtime->patch_message = ascii_message(error);
	hl_patch_free(patch);
	hl_mutex_release(runtime->lock);
	if( applied ) {
		hl_profile_stream_notify_revision(runtime->module->diagnostics_id,runtime->module->revision);
		hl_debug_notify_revision(runtime->module);
		return migration_failed ? HL_RUNTIME_MIGRATION_FAILED : HL_RUNTIME_OK;
	}
	if( error != NULL && strcmp(error,"Stale patch revision") == 0 ) return HL_RUNTIME_STALE_PATCH;
	return HL_RUNTIME_INCOMPATIBLE;
}

static uchar *ascii_message( const char *text ) {
	int size = (int)strlen(text) + 1;
	uchar *message = (uchar*)malloc(sizeof(uchar) * size);
	if( message == NULL ) return NULL;
	for(int i=0;i<size;i++) message[i] = (uchar)(unsigned char)text[i];
	return message;
}

const uchar *hl_runtime_module_patch_message( hl_runtime_module *runtime ) {
	const uchar *result;
	if( runtime == NULL ) return NULL;
	hl_mutex_acquire(runtime->lock);
	result = runtime->patch_message;
	hl_mutex_release(runtime->lock);
	return result;
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
