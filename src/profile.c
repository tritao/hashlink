/*
 * Copyright (C)2015-2019 Haxe Foundation
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
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <hl.h>
#include <hlmodule.h>
#include "hlsystem.h"
#include "hlprof.h"

#ifdef HL_WIN
#include <dbghelp.h>
#ifdef _MSC_VER
#pragma comment(lib, "Dbghelp.lib")
#endif
#endif

#ifndef HL_WIN
#include <time.h>
#endif

#ifdef HL_LINUX
#include <dlfcn.h>
#include <link.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#if defined(HL_MAC)
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <dispatch/dispatch.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#if defined(__GLIBC__)
#if __GLIBC_PREREQ(2, 30)
// tgkill is present
#else
// int tgkill(pid_t tgid, pid_t tid, int sig)
#define tgkill(tgid, tid, sig) syscall(SYS_tgkill, tgid, tid, sig)
#endif
#endif

#define MAX_STACK_SIZE (8 << 20)
/* The pc a sample holds where the unwinder skipped frames; the exporter names it from its symbol record. */
#define UNWIND_GAP_PC ((void*)1)
#define MAX_STACK_COUNT 2048

HL_API double hl_sys_time( void );
int hl_module_capture_stack_range( void *stack_top, void **stack_ptr, void **out, int size );
int hl_module_capture_stack_from_frame( void *stack_top, void **stack_ptr, void **frame_ptr, void **out, unsigned char *kinds, int size );
uchar *hl_module_resolve_symbol_full( void *addr, uchar *out, int *outSize, int **r_debug_addr );
bool hl_module_is_jit_code( void *addr );

typedef struct _thread_handle thread_handle;
typedef struct _profile_data profile_data;

struct _thread_handle {
	int tid;
#	ifdef HL_WIN
	HANDLE h;
#	endif
	hl_thread_info *inf;
	char name[128];
	thread_handle *next;
};

/* The thread that set the profiler up, named "main" in captures unless the program names it. */
static int profile_main_tid = 0;
int hl_profile_main_thread( void ) { return profile_main_tid; }
/*
 * The in-memory record behind hlprofile.dump is kept for "hl --profile" only. A diagnostics client reads the sample stream
 * instead, and recording it again would grow without bound and leave a dump in the program's working directory.
 */
static bool profile_legacy_record = false;
static bool profile_configuring_stream = false;

struct _profile_data {
	int currentPos;
	int dataSize;
	unsigned char *data;
	profile_data *next;
};

typedef struct {
	profile_data *r;
	int pos;
} profile_reader;

static struct {
	int sample_count;
	volatile int profiling_pause;
	volatile bool stopLoop;
	volatile bool waitLoop;
	thread_handle *handles;
	thread_handle *olds;
	void **tmpMemory;
	void *stackOut[MAX_STACK_COUNT];
	profile_data *record;
	profile_data *first_record;
	hl_condition *waitCond;
} data = {0};

/* Session state: whether a program held by --diagnostics-wait may run, and whether symbol metadata changed. */
static volatile bool session_waiting;
static volatile bool metadata_changed;

#include "profile_events.h"

static volatile int profile_allocation_interval = 0;

static unsigned long long native_seen[4096];
/* The sampler and allocating threads both name native frames; DbgHelp is not thread-safe and native_seen is shared. */
static hl_mutex *native_lock;
static void stream_write_u32( unsigned char *p, unsigned int value );
static void stream_write_u64( unsigned char *p, unsigned long long value );
static void stream_native_symbol( void *address, double time, int tid );

static void profile_allocation( hl_type *type, int requested, int allocated, void *return_address ) {
	static HL_THREAD_VAR unsigned int counter;
	void *frames[1];
	unsigned char payload[32 + sizeof(frames)];
	int interval = profile_allocation_interval, count = 1;
	hl_thread_info *thread;
	if( interval <= 0 || ++counter < (unsigned int)interval ) return;
	counter = 0;
	thread = hl_get_thread();
	if( thread == NULL || !hl_prof_on ) return;
	frames[0] = return_address;
	stream_write_u64(payload,(unsigned long long)requested);
	stream_write_u64(payload + 8,(unsigned long long)allocated);
	stream_write_u32(payload + 16,(unsigned int)interval);
	stream_write_u32(payload + 20,type == NULL ? 0xFFFFFFFFU : (unsigned int)type->kind);
	stream_write_u32(payload + 24,(unsigned int)count);
	stream_write_u32(payload + 28,0);
	for(int i=0;i<count;i++) {
		stream_native_symbol(frames[i],hl_sys_time(),thread->thread_id);
		stream_write_u64(payload + 32 + i * 8,(unsigned long long)(uintptr_t)frames[i]);
	}
	hl_prof_event(PROFILE_EVENT_ALLOCATION_SAMPLE,payload,32 + count * 8);
}

static void stream_native_symbol_record( unsigned long long pc, unsigned long long base, const char *module, const char *symbol, double time, int tid ) {
	unsigned int module_len = (unsigned int)strlen(module), symbol_len = (unsigned int)strlen(symbol);
	unsigned int size = 24 + module_len + symbol_len;
	unsigned char *payload = malloc(size);
	if( payload == NULL ) return;
	stream_write_u64(payload,pc); stream_write_u64(payload + 8,base);
	stream_write_u32(payload + 16,module_len); stream_write_u32(payload + 20,symbol_len);
	memcpy(payload + 24,module,module_len); memcpy(payload + 24 + module_len,symbol,symbol_len);
	(void)time; (void)tid;
	hl_prof_event(PROFILE_EVENT_NATIVE_SYMBOL,payload,size);
	free(payload);
}

static void stream_native_location_record( unsigned long long pc, unsigned long long module_base, unsigned long long module_size, unsigned int line, const char *file, double time, int tid ) {
	unsigned int file_len = file ? (unsigned int)strlen(file) : 0;
	unsigned int size = 32 + file_len;
	unsigned char *payload = malloc(size);
	if( payload == NULL ) return;
	stream_write_u64(payload,pc); stream_write_u64(payload + 8,module_base); stream_write_u64(payload + 16,module_size);
	stream_write_u32(payload + 24,line); stream_write_u32(payload + 28,file_len);
	if( file_len ) memcpy(payload + 32,file,file_len);
	(void)time; (void)tid;
	hl_prof_event(PROFILE_EVENT_NATIVE_LOCATION,payload,size);
	free(payload);
}

#ifdef HL_WIN
/* The start of the function holding pc, from its unwind data; 0 when pc has none (a leaf function, or 32-bit). */
static unsigned long long function_start( unsigned long long pc ) {
#	ifdef HL_64
	DWORD64 image_base;
	PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry((DWORD64)pc,&image_base,NULL);
	return fn ? (unsigned long long)(image_base + fn->BeginAddress) : 0;
#	else
	(void)pc;
	return 0;
#	endif
}
#endif

static void stream_native_symbol_locked( void *address, double time, int tid );

/* Callers must not have another thread suspended: a suspended thread may hold native_lock. */
static void stream_native_symbol( void *address, double time, int tid ) {
	if( native_lock == NULL ) return;
	hl_mutex_acquire(native_lock);
	/* The consumer takes native_lock to name native keys: records written holding it must not wait for the consumer. */
	hl_prof_no_wait(true);
	stream_native_symbol_locked(address,time,tid);
	hl_prof_no_wait(false);
	hl_mutex_release(native_lock);
}

static void stream_native_symbol_locked( void *address, double time, int tid ) {
	{
		void *start, *base;
		int size;
		const char *stub = hl_jit_support_symbol(address,&start,&base,&size);
		if( stub ) {
			unsigned long long pc = (unsigned long long)(uintptr_t)address;
			unsigned int slot = (unsigned int)((pc >> 4) & 4095);
			if( native_seen[slot] == pc ) return;
			native_seen[slot] = pc;
			stream_native_symbol_record(pc,(unsigned long long)(uintptr_t)start,"[hashlink-jit-support]",stub,time,tid);
			stream_native_location_record(pc,(unsigned long long)(uintptr_t)base,(unsigned long long)size,0,NULL,time,tid);
			return;
		}
	}
#if defined(HL_LINUX) || defined(HL_MAC)
	unsigned long long pc = (unsigned long long)(uintptr_t)address;
	unsigned int slot = (unsigned int)((pc >> 4) & 4095);
	Dl_info info;
	if( native_seen[slot] == pc ) return;
	if( address == UNWIND_GAP_PC ) {
		native_seen[slot] = pc;
		stream_native_symbol_record(pc,pc,"[profiler]","[unwind gap]",time,tid);
		return;
	}
	if( !dladdr(address,&info) || info.dli_fname == NULL ) return;
	native_seen[slot] = pc;
	if( info.dli_sname != NULL )
		stream_native_symbol_record(pc,(unsigned long long)(uintptr_t)info.dli_saddr,info.dli_fname,info.dli_sname,time,tid);
	else {
		// Not exported, so dladdr has no name: name it by its image, from whose base the exporter writes the offset, which a
		// symbolizer can resolve offline.
		const char *file = strrchr(info.dli_fname,'/');
		stream_native_symbol_record(pc,(unsigned long long)(uintptr_t)info.dli_fbase,info.dli_fname,file ? file + 1 : info.dli_fname,time,tid);
	}
	stream_native_location_record(pc,(unsigned long long)(uintptr_t)info.dli_fbase,0,0,NULL,time,tid);
#elif defined(HL_WIN)
	static HANDLE process;
	static bool initialized;
	static double modules_refreshed;
	unsigned long long pc = (unsigned long long)(uintptr_t)address;
	unsigned int slot = (unsigned int)((pc >> 4) & 4095);
	DWORD64 displacement = 0;
	IMAGEHLP_MODULE64 module_info;
	struct { SYMBOL_INFO info; char name[MAX_SYM_NAME]; } symbol_info;
	if( native_seen[slot] == pc ) return;
	if( !initialized ) {
		process = GetCurrentProcess();
		SymSetOptions(SymGetOptions() | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
		if( !SymInitialize(process,NULL,TRUE) ) return;
		initialized = true;
	}
	memset(&module_info,0,sizeof(module_info)); module_info.SizeOfStruct = sizeof(module_info);
	if( !SymGetModuleInfo64(process,(DWORD64)pc,&module_info) ) {
		// JIT code is described by the module metadata instead.
		if( hl_module_is_jit_code(address) ) { native_seen[slot] = pc; return; }
		// A library loaded after the last refresh is unknown to DbgHelp until the module list is refreshed; until then the
		// pc is looked up again on later samples rather than cached as unresolvable.
		bool refreshed = time - modules_refreshed >= 0.1;
		if( refreshed ) modules_refreshed = time;
		if( !refreshed || !SymRefreshModuleList(process) || !SymGetModuleInfo64(process,(DWORD64)pc,&module_info) ) {
			// DbgHelp does not list every image the loader maps (some driver libraries); name those by module and offset.
			HMODULE image;
			char path[MAX_PATH], name[MAX_PATH + 32];
			const char *file;
			if( !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCSTR)address,&image)
				|| !GetModuleFileNameA(image,path,sizeof(path)) ) {
				// Not an image at all: code generated at run time by another library. It cannot become known later.
				native_seen[slot] = pc;
				return;
			}
			const IMAGE_NT_HEADERS *headers = (const IMAGE_NT_HEADERS*)((const unsigned char*)image + ((const IMAGE_DOS_HEADER*)image)->e_lfanew);
			unsigned long long start = function_start(pc);
			if( start == 0 ) start = pc;
			file = strrchr(path,'\\');
			file = file ? file + 1 : path;
			snprintf(name,sizeof(name),"%s+0x%llx",file,start - (unsigned long long)(uintptr_t)image);
			stream_native_symbol_record(pc,start,path,name,time,tid);
			stream_native_location_record(pc,(unsigned long long)(uintptr_t)image,(unsigned long long)headers->OptionalHeader.SizeOfImage,0,NULL,time,tid);
			native_seen[slot] = pc;
			return;
		}
	}
	memset(&symbol_info,0,sizeof(symbol_info)); symbol_info.info.SizeOfStruct = sizeof(SYMBOL_INFO); symbol_info.info.MaxNameLen = MAX_SYM_NAME;
	{
		const char *module = module_info.ImageName && *module_info.ImageName ? module_info.ImageName : module_info.ModuleName;
		bool named = SymFromAddr(process,(DWORD64)pc,&displacement,&symbol_info.info) != FALSE;
		bool exact = named && !(symbol_info.info.Flags & SYMFLAG_EXPORT);
		// Without debug information DbgHelp names the nearest export. That is this function only when the export starts
		// the unwind range holding pc; otherwise the frame is named by that range's start, as an offset from the export, so
		// every sample in one function shares a name.
		unsigned long long start = function_start(pc);
		if( named && !exact )
			exact = start != 0 && start == (unsigned long long)symbol_info.info.Address;
		if( exact )
			stream_native_symbol_record(pc,(unsigned long long)symbol_info.info.Address,module,symbol_info.info.Name,time,tid);
		else {
			char name[MAX_SYM_NAME + MAX_PATH + 32];
			if( start == 0 ) start = pc;
			if( named && start >= (unsigned long long)symbol_info.info.Address )
				snprintf(name,sizeof(name),"%s!%s+0x%llx",module_info.ModuleName,symbol_info.info.Name,start - (unsigned long long)symbol_info.info.Address);
			else
				snprintf(name,sizeof(name),"%s+0x%llx",module_info.ModuleName,start - (unsigned long long)module_info.BaseOfImage);
			stream_native_symbol_record(pc,start,module,name,time,tid);
		}
	}
	{
		IMAGEHLP_LINE64 line;
		DWORD line_displacement = 0;
		memset(&line,0,sizeof(line)); line.SizeOfStruct = sizeof(line);
		bool has_line = SymGetLineFromAddr64(process,(DWORD64)pc,&line_displacement,&line) && line.FileName;
		stream_native_location_record(pc,(unsigned long long)module_info.BaseOfImage,(unsigned long long)module_info.ImageSize,has_line ? (unsigned int)line.LineNumber : 0,has_line ? line.FileName : NULL,time,tid);
	}
	native_seen[slot] = pc;
#else
	(void)address; (void)time; (void)tid;
#endif
}

static void stream_write_u32( unsigned char *p, unsigned int value ) {
	p[0] = (unsigned char)value; p[1] = (unsigned char)(value >> 8);
	p[2] = (unsigned char)(value >> 16); p[3] = (unsigned char)(value >> 24);
}

static void stream_write_u64( unsigned char *p, unsigned long long value ) {
	stream_write_u32(p,(unsigned int)value); stream_write_u32(p + 4,(unsigned int)(value >> 32));
}

#ifdef HL_LINUX
static struct
{
	sem_t msg2;
	sem_t msg3;
	sem_t msg4;
	ucontext_t context;
} shared_context;

static void sigprof_handler(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *ctx = ucontext;
	shared_context.context = *ctx;
	sem_post(&shared_context.msg2);
	sem_wait(&shared_context.msg3);
	sem_post(&shared_context.msg4);
}
#elif defined(HL_MAC)
static struct
{
	dispatch_semaphore_t msg2;
	dispatch_semaphore_t  msg3;
	dispatch_semaphore_t  msg4;
	ucontext_t context;
} shared_context;

static void sigprof_handler(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *ctx = ucontext;
	shared_context.context = *ctx;
	dispatch_semaphore_signal(shared_context.msg2);
	dispatch_semaphore_wait(shared_context.msg3, DISPATCH_TIME_FOREVER);
	dispatch_semaphore_signal(shared_context.msg4);
}
#endif

/** The frame pointer the thread stopped with, or NULL when this target cannot provide it. */
static void *get_thread_frameptr( void ) {
#if defined(HL_LINUX) && defined(__x86_64__)
	return (void*)shared_context.context.uc_mcontext.gregs[REG_RBP];
#elif defined(HL_LINUX) && defined(__aarch64__)
	return (void*)shared_context.context.uc_mcontext.regs[29];
#elif defined(HL_MAC) && defined(__x86_64__)
	struct __darwin_mcontext64 *mcontext = shared_context.context.uc_mcontext;
	return mcontext ? (void*)mcontext->__ss.__rbp : NULL;
#else
	return NULL;
#endif
}

#if defined(HL_WIN_DESKTOP) && defined(HL_64) && defined(HL_VCC)
#define WIN64_SAMPLE_UNWIND
/* The registers of the thread being sampled; only the sampler thread touches it. */
static CONTEXT sample_context;

/* A superseded JIT entry rewritten by hl_jit_patch_method: mov rax, imm64; jmp [rax]. It has no frame of its own. */
static bool is_patch_entry_stub( DWORD64 pc, DWORD64 image_base, PRUNTIME_FUNCTION fn ) {
	const unsigned char *entry = (const unsigned char*)(image_base + fn->BeginAddress);
	return pc < (DWORD64)entry + 12 && entry[0] == 0x48 && entry[1] == 0xB8 && entry[10] == 0xFF && entry[11] == 0x20;
}

/*
 * Walks a stack copied while the thread was suspended, so every frame is reported: JIT functions, the native code they
 * call and the JIT callbacks that code makes. Windows unwind data drives each step (JIT code registers its own tables);
 * a pc without unwind data is a leaf that has pushed nothing but its return address. Registers that point into the
 * original stack are moved into the copy before each step, since unwinding reads saved values through them.
 */
static int unwind_stack_copy( const CONTEXT *stopped, const unsigned char *copy, DWORD64 lo, DWORD64 hi, void **out, int max ) {
	CONTEXT c = *stopped;
	DWORD64 delta = (DWORD64)copy - lo, copy_lo = (DWORD64)copy, copy_hi = hi + delta, last_sp = 0;
	int count = 0;
#	define RELOCATE(r) if( c.r >= lo && c.r < hi ) c.r += delta
#	define RELOCATE_ALL() RELOCATE(Rsp); RELOCATE(Rbp); RELOCATE(Rbx); RELOCATE(Rsi); RELOCATE(Rdi); RELOCATE(R12); RELOCATE(R13); RELOCATE(R14); RELOCATE(R15)
	RELOCATE_ALL();
	__try {
		while( count < max && c.Rip && c.Rsp >= copy_lo && c.Rsp + 8 <= copy_hi && c.Rsp > last_sp ) {
			DWORD64 image_base;
			PRUNTIME_FUNCTION fn;
			out[count++] = (void*)c.Rip;
			last_sp = c.Rsp;
			fn = RtlLookupFunctionEntry(c.Rip,&image_base,NULL);
			if( fn && !is_patch_entry_stub(c.Rip,image_base,fn) ) {
				void *handler_data;
				DWORD64 establisher_frame;
				RtlVirtualUnwind(UNW_FLAG_NHANDLER,image_base,c.Rip,fn,&c,&handler_data,&establisher_frame,NULL);
			} else if( count == 1 ) {
				c.Rip = *(DWORD64*)c.Rsp;
				c.Rsp += 8;
			} else {
				// Only the interrupted function can be a leaf: a caller made a call, so it has unwind data. A return address
				// without any means the walk has left real frames.
				break;
			}
			RELOCATE_ALL();
		}
	} __except( EXCEPTION_EXECUTE_HANDLER ) {
	}
#	undef RELOCATE_ALL
#	undef RELOCATE
	return count;
}
#endif

static void *get_thread_stackptr( thread_handle *t, void **eip ) {
#ifdef WIN64_SAMPLE_UNWIND
	sample_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	if( !GetThreadContext(t->h,&sample_context) ) return NULL;
	*eip = (void*)sample_context.Rip;
	return (void*)sample_context.Rsp;
#elif defined(HL_WIN_DESKTOP)
	CONTEXT c;
	c.ContextFlags = CONTEXT_CONTROL;
	if( !GetThreadContext(t->h,&c) ) return NULL;
#	ifdef HL_64
	*eip = (void*)c.Rip;
	return (void*)c.Rsp;
#	else
	*eip = (void*)c.Eip;
	return (void*)c.Esp;
#	endif
#elif defined(HL_LINUX) && (defined(__x86_64__) || defined(__i386__))
#	ifdef HL_64
	*eip = (void*)shared_context.context.uc_mcontext.gregs[REG_RIP];
	return (void*)shared_context.context.uc_mcontext.gregs[REG_RSP];
#	else
	*eip = (void*)shared_context.context.uc_mcontext.gregs[REG_EIP];
	return (void*)shared_context.context.uc_mcontext.gregs[REG_ESP];
#	endif
#elif defined(HL_LINUX) && defined(__aarch64__)
	// Linux/Android ARM64: uc_mcontext has direct regs[] / sp / pc fields.
	*eip = (void*)shared_context.context.uc_mcontext.pc;
	return (void*)shared_context.context.uc_mcontext.sp;
#elif defined(HL_MAC) && defined(__x86_64__)
	struct __darwin_mcontext64 *mcontext = shared_context.context.uc_mcontext;
	if (mcontext != NULL) {
		*eip = (void*)mcontext->__ss.__rip;
		return (void*)mcontext->__ss.__rsp;
	}
	return NULL;
#else
	return NULL;
#endif
}

static void thread_data_init( thread_handle *t ) {
#ifdef HL_WIN
	t->h = OpenThread(THREAD_ALL_ACCESS,FALSE, t->tid);
#endif
}

static void thread_data_free( thread_handle *t ) {
#ifdef HL_WIN
	CloseHandle(t->h);
#endif
}

static bool pause_thread( thread_handle *t, bool b ) {
#ifdef HL_WIN
	if( b )
		return (int)SuspendThread(t->h) >= 0;
	else {
		ResumeThread(t->h);
		return true;
	}
#elif defined(HL_LINUX)
	if( b ) {
		tgkill(getpid(), t->tid, SIGPROF);
		return sem_wait(&shared_context.msg2) == 0;
	} else {
		sem_post(&shared_context.msg3);
		return sem_wait(&shared_context.msg4) == 0;
	}
#elif defined(HL_MAC)
	if( b ) {
		pthread_kill( t->inf->pthread_id, SIGPROF);
		return dispatch_semaphore_wait(shared_context.msg2, DISPATCH_TIME_FOREVER) == 0;
	} else {
		dispatch_semaphore_signal(shared_context.msg3);
		return dispatch_semaphore_wait(shared_context.msg4, DISPATCH_TIME_FOREVER) == 0;
	}
	return false;
#else
	return false;
#endif
}

static void record_data( void *ptr, int size ) {
	profile_data *r = data.record;
	if( !profile_legacy_record ) return;
	if( !r || r->currentPos + size > r->dataSize ) {
		r = malloc(sizeof(profile_data));
		r->currentPos = 0;
		r->dataSize = 1 << 20;
		r->data = malloc(r->dataSize);
		r->next = NULL;
		if( data.record )
			data.record->next = r;
		else
			data.first_record = r;
		data.record = r;
		fflush(stdout);
	}
	memcpy(r->data + r->currentPos, ptr, size);
	r->currentPos += size;
}

/* What sampling costs the program: set HL_PROFILE_STATS=1 to have it printed to stderr when the profiler stops. */
static struct {
	unsigned long long samples;
	double capture;   /* seconds of it spent reading the stack */
	double stopped;   /* seconds a sampled thread was held stopped, handshake included */
	double total;     /* seconds spent per sample, symbol lookup and recording included */
	double first, last;
} sampling_cost;

#if defined(HL_LINUX) || defined(HL_MAC)
/* The kinds of the frames being captured; only the sampler thread uses it. */
static unsigned char capture_kinds[MAX_STACK_COUNT];

#ifdef HL_LINUX
/* The executable segments of the loaded images, read with dl_iterate_phdr; only the sampler thread uses them. */
typedef struct { uintptr_t start, end; } code_range;
#define MAX_CODE_RANGES 1024
static code_range code_ranges[MAX_CODE_RANGES];
static int code_range_count;
static double code_ranges_read;

static int read_code_ranges( struct dl_phdr_info *info, size_t size, void *unused ) {
	(void)size; (void)unused;
	for(int i=0;i<info->dlpi_phnum && code_range_count<MAX_CODE_RANGES;i++) {
		const ElfW(Phdr) *segment = &info->dlpi_phdr[i];
		if( segment->p_type != PT_LOAD || !(segment->p_flags & PF_X) ) continue;
		code_ranges[code_range_count].start = (uintptr_t)(info->dlpi_addr + segment->p_vaddr);
		code_ranges[code_range_count].end = (uintptr_t)(info->dlpi_addr + segment->p_vaddr + segment->p_memsz);
		code_range_count++;
	}
	return 0;
}

static bool in_code_range( uintptr_t pc ) {
	for(int i=0;i<code_range_count;i++)
		if( pc >= code_ranges[i].start && pc < code_ranges[i].end ) return true;
	return false;
}
#endif

/* Whether a return address found on a frame-pointer chain is in native code, rather than a stale or unrelated value.
   Takes the loader lock: call it only while no thread is held stopped. */
static bool native_code_address( void *address, double time ) {
#ifdef HL_LINUX
	uintptr_t pc = (uintptr_t)address;
	if( in_code_range(pc) ) return true;
	// A library loaded since the segments were read: read them again, at most every 100 ms.
	if( time - code_ranges_read < 0.1 ) return false;
	code_ranges_read = time;
	code_range_count = 0;
	dl_iterate_phdr(read_code_ranges,NULL);
	return in_code_range(pc);
#else
	Dl_info info;
	(void)time;
	return dladdr(address,&info) && info.dli_sname != NULL;
#endif
}

/* Keeps the JIT frames and the native frames that are code, and folds runs of gaps (and the native values dropped
   around them) into one gap frame. Returns the new count. */
static int keep_sampled_frames( void **frames, unsigned char *kinds, int count, double time ) {
	int kept = 0;
	bool gap = false;
	for(int i=0;i<count;i++) {
		if( kinds[i] == HL_CAPTURE_GAP ) { gap = true; continue; }
		if( kinds[i] == HL_CAPTURE_NATIVE && !native_code_address(frames[i],time) ) continue;
		if( gap && kept > 0 ) frames[kept++] = UNWIND_GAP_PC;
		gap = false;
		frames[kept++] = frames[i];
	}
	return kept;
}
#endif

static void read_thread_data( thread_handle *t ) {
	double sample_started = hl_sys_time();
	double stopped_at;
	if( !pause_thread(t,true) )
		return;
	stopped_at = hl_sys_time();
	unsigned long long stopped_ticks = hl_prof_ticks();
	void *eip;
	void *stack = get_thread_stackptr(t,&eip);
	if( !stack ) {
		pause_thread(t,false);
		return;
	}

#if defined(HL_LINUX) || defined(HL_MAC)
    double capture_started = hl_sys_time();
    void *frame = get_thread_frameptr();
    int count = frame ?
        hl_module_capture_stack_from_frame(t->inf->stack_top, stack, frame, data.stackOut, capture_kinds, MAX_STACK_COUNT) :
        hl_module_capture_stack_range(t->inf->stack_top, stack, data.stackOut, MAX_STACK_COUNT);
    sampling_cost.capture += hl_sys_time() - capture_started;
    pause_thread(t, false);
    sampling_cost.stopped += hl_sys_time() - stopped_at;
    if( frame ) count = keep_sampled_frames(data.stackOut, capture_kinds, count, hl_sys_time());
#else
	int size = (int)((unsigned char*)t->inf->stack_top - (unsigned char*)stack);
	if( size > MAX_STACK_SIZE-32 ) size = MAX_STACK_SIZE-32;
#if defined(HL_WIN_DESKTOP) && defined(HL_VCC)
	// it seems we rarely can't make a first read on the thread stack, let's ignore errors and wait.
	__try {
#endif
		memcpy(data.tmpMemory + 2,stack,size);
#if defined(HL_WIN_DESKTOP) && defined(HL_VCC)
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	}
#endif
	pause_thread(t, false);
#ifdef WIN64_SAMPLE_UNWIND
	sampling_cost.stopped += hl_sys_time() - stopped_at;
	double capture_started = hl_sys_time();
	int count = unwind_stack_copy(&sample_context,(unsigned char*)(data.tmpMemory + 2),(DWORD64)stack,(DWORD64)stack + size,data.stackOut,MAX_STACK_COUNT);
	sampling_cost.capture += hl_sys_time() - capture_started;
#else
	data.tmpMemory[0] = eip;
	data.tmpMemory[1] = stack;
	size += sizeof(void*) * 2;

	int count = hl_module_capture_stack_range((char*)data.tmpMemory+size, (void**)data.tmpMemory, data.stackOut, MAX_STACK_COUNT);
#endif
#endif
	/* Stack scanning finds managed return addresses; preserve a native instruction
	   pointer as the leaf when the thread was interrupted inside a shared library. */
#if defined(HL_LINUX) || defined(HL_MAC)
	{
		Dl_info native_leaf;
		bool jit_leaf = eip && hl_module_is_jit_code(eip);
		bool native_leaf_code = eip && !jit_leaf && (frame ? native_code_address(eip,hl_sys_time()) : dladdr(eip,&native_leaf) && native_leaf.dli_sname);
		if( count < MAX_STACK_COUNT && (jit_leaf || native_leaf_code) ) {
			memmove(data.stackOut + 1,data.stackOut,sizeof(void*) * count);
			data.stackOut[0] = eip;
			count++;
		}
	}
#elif defined(HL_WIN) && !defined(WIN64_SAMPLE_UNWIND)
	if( eip && count < MAX_STACK_COUNT ) {
		memmove(data.stackOut + 1,data.stackOut,sizeof(void*) * count);
		data.stackOut[0] = eip;
		count++;
	}
#endif
	int eventId = count | 0x80000000;
	double time = hl_sys_time();
	hl_threads_info *gc = hl_gc_threads_info();
	if( gc->stopping_world ) eventId |= 0x40000000;
	for(int i=0;i<count;i++) stream_native_symbol(data.stackOut[i],time,t->tid);
	hl_prof_sample((unsigned int)t->tid,gc->stopping_world ? 1 : 0,data.stackOut,count,stopped_ticks);
	record_data(&time,sizeof(double));
	record_data(&t->tid,sizeof(int));
	record_data(&eventId,sizeof(int));
	record_data(data.stackOut,sizeof(void*)*count);
	if( !*t->name && (*t->inf->thread_name || t->tid == profile_main_tid) ) {
		if( *t->inf->thread_name ) memcpy(t->name, t->inf->thread_name, sizeof(t->name)); else strcpy(t->name, "main");
	}
	sampling_cost.samples++;
	sampling_cost.total += hl_sys_time() - sample_started;
	if( sampling_cost.first == 0 ) sampling_cost.first = sample_started;
	sampling_cost.last = sample_started;
}

/* True while a session records, so callers can skip building event payloads otherwise. */
static bool hl_profile_recording( void ) {
	return hl_prof_on != 0;
}

static void profile_pause() {
	hl_condition_acquire(data.waitCond);
	data.profiling_pause++;
	hl_condition_broadcast(data.waitCond);
	hl_condition_release(data.waitCond);
}

static void profile_resume() {
	hl_condition_acquire(data.waitCond);
	data.profiling_pause--;
	hl_condition_broadcast(data.waitCond);
	hl_condition_release(data.waitCond);
}

/* The sampler is paused while no session asks for samples. */
static bool sampler_paused;

static void profile_resume_remote() {
	if( data.waitCond == NULL ) return;
	hl_condition_acquire(data.waitCond);
	if( sampler_paused ) {
		sampler_paused = false;
		data.profiling_pause--;
		hl_condition_broadcast(data.waitCond);
	}
	hl_condition_release(data.waitCond);
}

static void profile_pause_remote() {
	if( data.waitCond == NULL ) return;
	hl_condition_acquire(data.waitCond);
	if( !sampler_paused ) {
		sampler_paused = true;
		data.profiling_pause++;
		hl_condition_broadcast(data.waitCond);
	}
	hl_condition_release(data.waitCond);
}

/*
 * Waits until the next sample is due instead of spinning a core. Windows needs a high-resolution waitable timer for
 * sub-millisecond waits; where that is unavailable the loop polls as before rather than sampling at the scheduler tick.
 */
static void profile_sleep( double seconds ) {
	// Only the sampler thread calls this: an auto-reset timer releases one waiter per expiry.
	if( seconds <= 0 ) return;
	if( seconds > 0.01 ) seconds = 0.01;
#ifdef HL_WIN
#	ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#		define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#	endif
	static HANDLE timer = NULL;
	static bool timer_ready = false;
	LARGE_INTEGER due;
	if( !timer_ready ) {
		timer_ready = true;
		timer = CreateWaitableTimerExW(NULL,NULL,CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,TIMER_ALL_ACCESS);
	}
	if( timer == NULL ) return;
	due.QuadPart = -(LONGLONG)(seconds * 1e7);
	if( SetWaitableTimer(timer,&due,0,NULL,NULL,FALSE) ) WaitForSingleObject(timer,INFINITE);
#else
	struct timespec wait;
	wait.tv_sec = 0;
	wait.tv_nsec = (long)(seconds * 1e9);
	nanosleep(&wait,NULL);
#endif
}

static void hl_profile_loop( void *_ ) {
	hl_prof_boundary_ignore_thread();
	hl_thread_set_name(hl_thread_current(),"hl.sampler");
	double next = hl_sys_time();
	data.tmpMemory = malloc(MAX_STACK_SIZE);
	data.waitLoop = false;
	while( !data.stopLoop ) {
		double t = hl_sys_time();
		hl_condition_acquire(data.waitCond);
		if( t < next || data.profiling_pause ) {
			if( !(t < next) ) next = t;
			if( data.profiling_pause ) {
				data.waitLoop = true;
				hl_condition_wait(data.waitCond);
				data.waitLoop = false;
				hl_condition_release(data.waitCond);
			} else {
				hl_condition_release(data.waitCond);
				profile_sleep(next - t);
			}
			continue;
		}
		hl_condition_release(data.waitCond);
		hl_threads_info *threads = hl_gc_threads_info();
		int i;
		thread_handle *prev = NULL;
		thread_handle *cur = data.handles;
		for(i=0;i<threads->count;i++) {
			hl_thread_info *t = threads->threads[i];
			if( t->flags & HL_THREAD_INVISIBLE ) continue;

			if( !cur || cur->tid != t->thread_id ) {
				// have we lost a thread ?
				thread_handle *h = cur;
				thread_handle *hprev = prev;
				while( h ) {
					if( h->tid == t->thread_id ) {
						// remove from previous queue
						if( hprev ) {
							hprev->next = h->next;
						} else {
							data.handles = h->next;
						}
						// insert at current position
						if( prev ) {
							h->next = prev->next;
							prev->next = h;
						} else {
							h->next = data.handles;
							data.handles = h;
						}
						break;
					}
					hprev = h;
					h = h->next;
				}
				if( !h ) {
					h = malloc(sizeof(thread_handle));
					memset(h,0,sizeof(thread_handle));
					h->tid = t->thread_id;
					h->inf = t;
					thread_data_init(h);
					h->next = cur;
					cur = h;
					if( prev == NULL ) data.handles = h; else prev->next = h;
				}
			}
			if( (t->flags & HL_THREAD_PROFILER_PAUSED) == 0 )
				read_thread_data(cur);
			prev = cur;
			cur = cur->next;
		}
		if( prev ) prev->next = NULL; else data.handles = NULL;
		while( cur != NULL ) {
			thread_handle *n;
			thread_data_free(cur);
			n = cur->next;
			if( *cur->name ) {
				cur->next = data.olds;
				data.olds = cur;
			} else
				free(cur);
			cur = n;
		}
		next += 1. / data.sample_count;
	}
	free(data.tmpMemory);
	data.tmpMemory = NULL;
	data.sample_count = 0;
	hl_module_patch_readers(-1);
	data.stopLoop = false;
}

static void profile_event( int code, vbyte *data, int dataLen );

/* Sys.exit skips the end of main, so it ends a streaming session here too. */
static void profile_before_exit( void ) {
	hl_profile_drain();
	hl_profile_end();
}

void hl_profile_setup( int sample_count ) {
	#	if defined(HL_THREADS) && (defined(HL_WIN_DESKTOP) || defined(HL_LINUX) || defined (HL_MAC))
	if( native_lock == NULL ) {
		native_lock = hl_mutex_alloc(false);
		hl_add_root(&native_lock);
	}
	if( data.waitCond == NULL ) {
		data.waitCond = hl_condition_alloc();
		hl_add_root(&data.waitCond);
	}
	hl_setup.profile_event = profile_event;
	hl_setup.profile_recording = hl_profile_recording;
	if( !profile_main_tid && hl_get_thread() ) profile_main_tid = hl_get_thread()->thread_id;
	hl_setup.before_exit = profile_before_exit;
	hl_setup.stop_profiler = hl_profile_end;
	if( data.sample_count ) return;
	if( sample_count < 0 ) {
		// was not started with --profile: the sampler waits for a session, and --diagnostics-wait for its start
		session_waiting = true;
		profile_pause_remote();
		return;
	}
	data.sample_count = sample_count;
	if( !profile_configuring_stream ) profile_legacy_record = true;
#	ifdef HL_LINUX
	sem_init(&shared_context.msg2, 0, 0);
	sem_init(&shared_context.msg3, 0, 0);
	sem_init(&shared_context.msg4, 0, 0);
	struct sigaction action = {0};
	action.sa_sigaction = sigprof_handler;
	action.sa_flags = SA_SIGINFO | SA_RESTART;
	sigaction(SIGPROF, &action, NULL);
#	elif defined(HL_MAC)
	shared_context.context.uc_mcontext = NULL;
	shared_context.msg2 = dispatch_semaphore_create(0);
	shared_context.msg3 = dispatch_semaphore_create(0);
	shared_context.msg4 = dispatch_semaphore_create(0);
	struct sigaction action = {0};
	action.sa_sigaction = sigprof_handler;
	action.sa_flags = SA_SIGINFO | SA_RESTART;
	sigaction(SIGPROF, &action, NULL);
#	endif
	// The sampler resolves the code it samples while the program may be patching it.
	hl_module_patch_readers(1);
	hl_thread_start(hl_profile_loop,NULL,false);
#	endif
}

void hl_profile_wait_for_start( void ) {
	#	if defined(HL_THREADS) && (defined(HL_WIN_DESKTOP) || defined(HL_LINUX) || defined (HL_MAC))
	if( data.waitCond == NULL ) return;
	hl_condition_acquire(data.waitCond);
	while( session_waiting )
		hl_condition_wait(data.waitCond);
	hl_condition_release(data.waitCond);
	#	endif
}

static bool configure_allocations( int interval ) {
	extern void hl_gc_set_profile_allocation_callback( void (*callback)(hl_type*,int,int,void*) );
	if( interval < 0 || interval > 100000000 ) return false;
	profile_allocation_interval = interval;
	hl_gc_set_profile_allocation_callback(interval == 0 ? NULL : profile_allocation);
	return true;
}

static void native_keys_reset( void );

bool hl_profile_session_start( int sources, int sample_rate, int allocation_interval ) {
	bool sampling = (sources & HL_PROF_SOURCE_SAMPLING) != 0;
	native_keys_reset();
	if( sampling && (sample_rate <= 0 || sample_rate > 100000) ) return false;
	if( !configure_allocations((sources & HL_PROF_SOURCE_ALLOC) ? allocation_interval : 0) ) return false;
	if( sampling ) {
		if( !data.sample_count ) {
			profile_configuring_stream = true;
			hl_profile_setup(sample_rate);
			profile_configuring_stream = false;
		}
		data.sample_count = sample_rate;
		profile_resume_remote();
	}
	if( data.waitCond ) {
		hl_condition_acquire(data.waitCond);
		session_waiting = false;
		hl_condition_broadcast(data.waitCond);
		hl_condition_release(data.waitCond);
	} else
		session_waiting = false;
	return true;
}

void hl_profile_session_stop( void ) {
	configure_allocations(0);
	if( data.sample_count ) profile_pause_remote();
}

/* Names the native call keys natively instrumented code recorded first since the last call (see hl_prof_enter_native).
   Consumer only: naming takes DbgHelp, which the hooked call must not, as it may hold the locks DbgHelp needs. */
void hl_profile_name_native_keys( void ) {
	unsigned long long keys[256];
	int count, tid = hl_profile_main_thread();
	while( (count = hl_prof_native_keys_take(keys,256)) > 0 )
		for(int i=0;i<count;i++) {
			const char *boundary = hl_prof_boundary_name(keys[i]);
			if( boundary ) stream_native_symbol_record(keys[i],keys[i],"[boundary]",boundary,hl_sys_time(),tid);
			else stream_native_symbol((void*)(uintptr_t)keys[i],hl_sys_time(),tid);
		}
}

/* A new session names every native pc again: its capture holds only what it streams. */
static void native_keys_reset( void ) {
	hl_prof_native_keys_reset();
	if( native_lock ) hl_mutex_acquire(native_lock);
	memset(native_seen,0,sizeof(native_seen));
	if( native_lock ) hl_mutex_release(native_lock);
}

bool hl_profile_metadata_changed( void ) {
	bool changed = metadata_changed;
	metadata_changed = false;
	return changed;
}

void hl_profile_stream_notify_module( unsigned long long module_id ) {
	unsigned char payload[8];
	metadata_changed = true;
	stream_write_u64(payload,module_id);
	hl_prof_event(PROFILE_EVENT_MODULE_LOADED,payload,sizeof(payload));
}

void hl_profile_stream_notify_revision( unsigned long long module_id, int revision ) {
	unsigned char payload[12];
	if( revision <= 0 ) return;
	metadata_changed = true;
	stream_write_u64(payload,module_id);
	stream_write_u32(payload + 8,(unsigned int)revision);
	hl_prof_event(PROFILE_EVENT_MODULE_REVISION,payload,sizeof(payload));
}

static bool read_profile_data( profile_reader *r, void *ptr, int size ) {
	while( size ) {
		if( r->r == NULL ) return false;
		int bytes = r->r->currentPos - r->pos;
		if( bytes > size ) bytes = size;
		if( ptr ) memcpy(ptr, r->r->data + r->pos, bytes);
		size -= bytes;
		r->pos += bytes;
		if( r->pos == r->r->currentPos ) {
			r->r = r->r->next;
			r->pos = 0;
		}
	}
	return true;
}

static int write_names( thread_handle *h, FILE *f ) {
	int count = 0;
	while( h ) {
		if( *h->name ) {
			if( f ) {
				int len = (int)strlen(h->name);
				fwrite(&h->tid,1,4,f);
				fwrite(&len,1,4,f);
				fwrite(h->name,1,len,f);
			} else
				count++;
		}
		h = h->next;
	}
	return count;
}

static void profile_dump( vbyte* ptr ) {
	if( !data.first_record ) return;

	profile_pause();
	printf("Writing profiling data...\n");
	fflush(stdout);

	char* filename = ptr == NULL ? "hlprofile.dump" : hl_to_utf8((uchar*)ptr);
	FILE *f = fopen(filename,"wb");
	if( f == NULL ) {
		profile_resume();
		printf("Failed to open file %s, 0 profile samples saved\n", filename);
		hl_error("Failed to open file");
		return;
	}
	int version = HL_VERSION;
	fwrite("PROF",1,4,f);
	fwrite(&version,1,4,f);
	fwrite(&data.sample_count,1,4,f);
	profile_reader r;
	r.r = data.first_record;
	r.pos = 0;
	int samples = 0;
	while( true ) {
		double time;
		int i, tid, eventId;
		if( !read_profile_data(&r,&time, sizeof(double)) ) break;
		read_profile_data(&r,&tid,sizeof(int));
		read_profile_data(&r,&eventId,sizeof(int));
		fwrite(&time,1,8,f);
		fwrite(&tid,1,4,f);
		fwrite(&eventId,1,4,f);
		if( eventId < 0 ) {
			int count = eventId & 0x3FFFFFFF;
			read_profile_data(&r,data.stackOut,sizeof(void*)*count);
			for(i=0;i<count;i++) {
				uchar outStr[256];
				int outSize = 256;
				int *debug_addr = NULL;
				hl_module_resolve_symbol_full(data.stackOut[i],outStr,&outSize,&debug_addr);
				if( debug_addr == NULL ) {
					int bad = -1;
					fwrite(&bad,1,4,f);
				} else {
					fwrite(debug_addr,1,8,f);
					if( (debug_addr[0] & 0x80000000) == 0 ) {
						debug_addr[0] |= 0x80000000;
						fwrite(&outSize,1,4,f);
						fwrite(outStr,1,outSize*sizeof(uchar),f);
					}
				}
			}
			samples++;
		} else {
			int size;
			read_profile_data(&r,&size, sizeof(int));
			fwrite(&size,1,4,f);
			while( size ) {
				int k = size > MAX_STACK_SIZE ? MAX_STACK_SIZE : size;
				read_profile_data(&r,data.tmpMemory,k);
				fwrite(data.tmpMemory,1,k,f);
				size -= k;
			}
		}
	}
	double tend = -1;
	fwrite(&tend,1,8,f);

	// reset debug_addr flags (allow further dumps)
	r.r = data.first_record;
	r.pos = 0;
	while( true ) {
		int i, eventId;
		if( !read_profile_data(&r,NULL, sizeof(double) + sizeof(int)) ) break;
		read_profile_data(&r,&eventId,sizeof(int));
		if( eventId < 0 ) {
			int count = eventId & 0x3FFFFFFF;
			read_profile_data(&r,data.stackOut,sizeof(void*)*count);
			for(i=0;i<count;i++) {
				int *debug_addr = NULL;
				hl_module_resolve_symbol_full(data.stackOut[i],NULL,NULL,&debug_addr);
				if( debug_addr )
					debug_addr[0] &= 0x7FFFFFFF;
			}
		} else {
			int size;
			read_profile_data(&r,&size,sizeof(int));
			read_profile_data(&r,NULL,size);
		}
	}
	// dump threads names
	int names_count = write_names(data.handles,NULL) + write_names(data.olds,NULL);
	fwrite(&names_count,1,4,f);
	write_names(data.handles,f);
	write_names(data.olds,f);
	// done
	fclose(f);
	printf("%d profile samples saved to %s\n", samples, filename);
	profile_resume();
}

static void profile_print_cost( void ) {
	double window = sampling_cost.last - sampling_cost.first;
	if( !getenv("HL_PROFILE_STATS") || !sampling_cost.samples ) return;
	fprintf(stderr,"profiler: %llu thread samples over %.2fs (%.0f/s); a thread was stopped %.1f us per sample (%.1f%% of the time, summed over threads; %.1f us of it reading the stack), %.1f us per sample in all\n",
		sampling_cost.samples, window, window > 0 ? sampling_cost.samples / window : 0.0,
		sampling_cost.stopped * 1e6 / sampling_cost.samples, window > 0 ? 100.0 * sampling_cost.stopped / window : 0.0,
		sampling_cost.capture * 1e6 / sampling_cost.samples, sampling_cost.total * 1e6 / sampling_cost.samples);
}

/* Ends a streaming session before the program exits, so a connected client receives every record. Call it while
   diagnostics still run. */
void hl_profile_drain( void ) {
	extern void hl_diagnostics_finish( void );
	hl_diagnostics_finish();
}

void hl_profile_end() {
	profile_print_cost();
	profile_dump(NULL);
	if( !data.sample_count ) {
		hl_setup.stop_profiler = NULL;
		return;
	}
	data.stopLoop = true;
	hl_condition_acquire(data.waitCond);
	data.profiling_pause = 0;
	hl_condition_broadcast(data.waitCond);
	hl_condition_release(data.waitCond);
	while( data.stopLoop ) {};
	hl_setup.stop_profiler = NULL;
}

static void profile_event( int code, vbyte *ptr, int dataLen ) {
	switch( code ) {
	case -1:
		hl_get_thread()->flags |= HL_THREAD_PROFILER_PAUSED;
		break;
	case -2:
		hl_get_thread()->flags &= ~HL_THREAD_PROFILER_PAUSED;
		break;
	case -3:
		profile_pause();
		while( !data.waitLoop ) {}
		profile_data *d = data.first_record;
		while( d ) {
			profile_data *n = d->next;
			free(d->data);
			free(d);
			d = n;
		}
		data.first_record = NULL;
		data.record = NULL;
		profile_resume();
		break;
	case -4:
		profile_pause();
		break;
	case -5:
		profile_resume();
		break;
	case -6:
		profile_dump(ptr);
		break;
	case -7:
		{
			uchar *end = NULL;
			hl_profile_setup( ptr ? utoi((uchar*)ptr,&end) : 1000);
		}
		break;
	case -8:
		hl_get_thread()->flags |= HL_THREAD_INVISIBLE;
		break;
	/* hl.Profile.eventBytes payloads: UTF-8 span names, and counters as an f64 followed by the UTF-8 name. */
	case PROFILE_EVENT_SPAN_BEGIN:
		hl_prof_span_begin(ptr,dataLen,HL_PROF_UTF8);
		break;
	case PROFILE_EVENT_SPAN_END:
		hl_prof_span_end();
		break;
	case PROFILE_EVENT_COUNTER:
		if( dataLen >= 8 ) {
			double value;
			memcpy(&value,ptr,8);
			hl_prof_counter(ptr + 8,dataLen - 8,HL_PROF_UTF8,value);
		}
		break;
	default:
		if( code < 0 ) return;
		if( data.profiling_pause || (code != 0 && (hl_get_thread()->flags & HL_THREAD_PROFILER_PAUSED)) ) return;
		profile_pause();
		while( !data.waitLoop ) {}
		double time = hl_sys_time();
		hl_prof_event((unsigned int)code,ptr,(unsigned int)dataLen);
		record_data(&time,sizeof(double));
		record_data(&hl_get_thread()->thread_id,sizeof(int));
		record_data(&code,sizeof(int));
		record_data(&dataLen,sizeof(int));
		record_data(ptr,dataLen);
		profile_resume();
		break;
	}
}
