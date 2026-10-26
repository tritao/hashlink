/*
 * The function hooks for native modules built with instrumentation (Linux). A compiler flag (clang's
 * -finstrument-functions-after-inlining, gcc's -finstrument-functions) makes each probed function call
 * __cyg_profile_func_enter at its start and __cyg_profile_func_exit before it returns; they test the recording flag and
 * call into libhl only while a session records. The Windows equivalent is prof_penter.c.
 *
 * This object is linked into every module of an instrumented native build, including tools the build runs that never
 * load libhl, so it finds the recorder at run time instead of importing it: until libhl is loaded the hooks do nothing.
 * Its symbols are hidden, so each module calls its own copy and the copies never interpose each other, and it is built
 * without instrumentation, as is everything the hooks call.
 */
#ifndef _GNU_SOURCE
#	define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <time.h>

#define PROF_LOCAL __attribute__((no_instrument_function))
#define PROF_HOOK __attribute__((no_instrument_function, visibility("hidden")))

typedef void (*prof_enter_fn)( unsigned long long key );
typedef void (*prof_exit_fn)( void );

static volatile int unresolved = 1;
static prof_enter_fn prof_enter;
static prof_exit_fn prof_exit;
static long long next_attempt_ms;

/* The recording flag the hooks test: libhl's hl_prof_on once found. Until a hook resolves it, it points at a nonzero
   flag so hooks take the slow path and resolve it. */
static volatile int *hooks_on = &unresolved;

/* A libhl the host loaded without making its symbols global is found by its path in the list of loaded objects. */
PROF_LOCAL static int find_libhl( struct dl_phdr_info *info, size_t size, void *data ) {
	const char *name = info->dlpi_name, *slash;
	(void)size;
	if( name == NULL || *name == 0 ) return 0;
	slash = strrchr(name,'/');
	if( strncmp(slash ? slash + 1 : name,"libhl.so",8) != 0 ) return 0;
	*(const char**)data = name;
	return 1;
}

PROF_LOCAL static void *libhl_symbol( const char *name ) {
	const char *path = NULL;
	void *handle, *symbol = dlsym(RTLD_DEFAULT,name);
	if( symbol != NULL ) return symbol;
	if( !dl_iterate_phdr(find_libhl,&path) ) return NULL;
	/* RTLD_NOLOAD only looks the object up: nothing is loaded and nothing stays referenced beyond the handle. */
	handle = dlopen(path,RTLD_NOLOAD | RTLD_LAZY);
	if( handle == NULL ) return NULL;
	symbol = dlsym(handle,name);
	dlclose(handle);
	return symbol;
}

PROF_LOCAL static void resolve( void ) {
	struct timespec now;
	volatile int *on;
	prof_enter_fn enter;
	prof_exit_fn exit_hook;
	long long now_ms;
	/* Not loaded (a tool, or a module initializing before the VM): look again at most once a millisecond. */
	clock_gettime(CLOCK_MONOTONIC_COARSE,&now);
	now_ms = (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
	if( now_ms < next_attempt_ms ) return;
	next_attempt_ms = now_ms + 1;
	on = (volatile int*)libhl_symbol("hl_prof_on");
	enter = (prof_enter_fn)libhl_symbol("hl_prof_enter_native");
	exit_hook = (prof_exit_fn)libhl_symbol("hl_prof_exit");
	if( on == NULL || enter == NULL || exit_hook == NULL ) return;
	prof_enter = enter;
	prof_exit = exit_hook;
	/* The functions are stored before the flag that tells the hooks to call them. */
	__atomic_store_n(&hooks_on,on,__ATOMIC_RELEASE);
}

/* fn is the start of the instrumented function: the key the runtime names it by, from its module's symbols. */
PROF_HOOK void __cyg_profile_func_enter( void *fn, void *call_site ) {
	volatile int *on = __atomic_load_n(&hooks_on,__ATOMIC_ACQUIRE);
	(void)call_site;
	if( on == &unresolved ) {
		resolve();
		on = __atomic_load_n(&hooks_on,__ATOMIC_ACQUIRE);
	}
	if( on != &unresolved && *on ) prof_enter((unsigned long long)(__UINTPTR_TYPE__)fn);
}

PROF_HOOK void __cyg_profile_func_exit( void *fn, void *call_site ) {
	volatile int *on = __atomic_load_n(&hooks_on,__ATOMIC_ACQUIRE);
	(void)fn;
	(void)call_site;
	if( on == &unresolved ) {
		resolve();
		on = __atomic_load_n(&hooks_on,__ATOMIC_ACQUIRE);
	}
	if( on != &unresolved && *on ) prof_exit();
}
