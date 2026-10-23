/*
 * The /Gh /GH hooks for native modules built with instrumentation (Windows x64). prof_penter_x64.asm defines _penter
 * and _pexit; they test the recording flag and call in here only while a session records.
 *
 * This library is linked into every module of an instrumented native build, including tools the build runs that never
 * load libhl, so it finds the recorder at run time instead of importing it: until libhl is loaded the hooks do nothing.
 * It uses no C runtime, so it links into modules built with either CRT.
 */
#include <windows.h>

typedef void (*prof_enter_fn)( unsigned long long key );
typedef void (*prof_exit_fn)( void );

static volatile int unresolved = 1;
static prof_enter_fn prof_enter;
static prof_exit_fn prof_exit;
static volatile ULONGLONG next_attempt;

/* The recording flag the hooks test: libhl's hl_prof_on once found. Until a hook resolves it, it points at a nonzero
   flag so hooks take the slow path and resolve it. */
volatile int *hlprof_penter_on = &unresolved;

static void resolve( void ) {
	HMODULE libhl;
	volatile int *on;
	ULONGLONG now = GetTickCount64();
	/* Not loaded (a tool, or a module initializing before the VM): look again at most once a millisecond. */
	if( now < next_attempt ) return;
	next_attempt = now + 1;
	libhl = GetModuleHandleW(L"libhl.dll");
	if( libhl == NULL ) return;
	on = (volatile int*)GetProcAddress(libhl,"hl_prof_on");
	prof_enter = (prof_enter_fn)GetProcAddress(libhl,"hl_prof_enter_native");
	prof_exit = (prof_exit_fn)GetProcAddress(libhl,"hl_prof_exit");
	if( on == NULL || prof_enter == NULL || prof_exit == NULL ) return;
	MemoryBarrier();
	hlprof_penter_on = on;
}

/* pc is the hook's return address, inside the instrumented function; the runtime names it from the module's PDB. */
void hlprof_penter_record_enter( unsigned long long pc ) {
	if( hlprof_penter_on == &unresolved ) resolve();
	if( hlprof_penter_on != &unresolved && *hlprof_penter_on ) prof_enter(pc);
}

void hlprof_penter_record_exit( void ) {
	if( hlprof_penter_on == &unresolved ) resolve();
	if( hlprof_penter_on != &unresolved && *hlprof_penter_on ) prof_exit();
}
