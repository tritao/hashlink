/*
 * Boundary hooks for instrumented builds (Linux x86-64): calls from the process's own objects into code nobody compiled
 * with instrumentation become slices named after the function called (`libc!nanosleep`). They cover a curated set of
 * blocking and system calls, and any extra `module!function` the configuration names. prof_boundary.c is the Windows
 * version, and PROFILER-POSIX.md the design.
 *
 * Each hooked function gets a stub (prof_boundary_x64_sysv.S) that loads its descriptor and jumps to
 * hl_prof_boundary_thunk, which records an enter and an exit around the real call. A hook's key is its stub's address, and
 * the consumer names it from the descriptor.
 *
 * The hooks are installed by rewriting the GOT slots of our own objects: the program, and every loaded object not under
 * /usr, /lib or /snap. Each slot is found from the object's relocations, by the name of the symbol it binds, so it
 * does not matter whether the slot is already bound (a GLOB_DAT slot or a BIND_NOW one) or still points at its PLT stub
 * (lazy binding). After every dlopen the objects are scanned again, as one may have been loaded.
 *
 * The configuration comes from HL_PROF_BOUNDARY, which Haxeon sets when it runs an instrumented build:
 * `imports=blocking|none;extra=libfoo.so!f,libbar.so!g`. Without it nothing is hooked. The module of an extra entry names
 * the slice only: the function is matched by name.
 */
#define _GNU_SOURCE
#include <hl.h>
#include <hlmodule.h>
#include "hlprof.h"

#if defined(__linux__) && defined(__x86_64__)

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct {
	void *real;			/* read by the thunk: keep first */
	const char *name;
} boundary_desc;

#define MAX_HOOKS 1024
#define STUB_SIZE 16
#define HIDDEN __attribute__((visibility("hidden")))

HIDDEN boundary_desc hl_prof_boundary_descs[MAX_HOOKS];
extern unsigned char hl_prof_boundary_stubs[] HIDDEN;
extern void hl_prof_boundary_thunk( void ) HIDDEN;

static int desc_count;
static pthread_mutex_t hook_lock = PTHREAD_MUTEX_INITIALIZER;
static bool installed;
static bool hook_imports;
static char *extra_imports;
static __thread int boundary_busy;

/* ---- recording ------------------------------------------------------------------------------------------------- */

/* Called by the thunk before the real call. Returns whether it recorded an enter, which the thunk closes after. */
int hl_prof_boundary_enter( boundary_desc *d ) {
	/* A thread that must not wait records no call: one lost to a full pool would unpair its ENTER and EXIT. */
	if( !hl_prof_on || boundary_busy || !hl_prof_may_wait() ) return 0;
	/* The recorder may wait for the consumer through a hooked call: that wait is not recorded. */
	boundary_busy = 1;
	hl_prof_enter_blocking((unsigned long long)(uintptr_t)(hl_prof_boundary_stubs + (d - hl_prof_boundary_descs) * STUB_SIZE));
	boundary_busy = 0;
	return 1;
}

void hl_prof_boundary_exit( void ) {
	boundary_busy = 1;
	hl_prof_exit();
	boundary_busy = 0;
}

void hl_prof_boundary_ignore_thread( void ) {
	boundary_busy = 1;
}

const char *hl_prof_boundary_name( unsigned long long key ) {
	unsigned char *p = (unsigned char*)(uintptr_t)key;
	if( p < hl_prof_boundary_stubs || p >= hl_prof_boundary_stubs + MAX_HOOKS * STUB_SIZE || (p - hl_prof_boundary_stubs) % STUB_SIZE ) return NULL;
	return (int)((p - hl_prof_boundary_stubs) / STUB_SIZE) < desc_count ? hl_prof_boundary_descs[(p - hl_prof_boundary_stubs) / STUB_SIZE].name : NULL;
}

static bool is_stub( void *p ) {
	return (unsigned char*)p >= hl_prof_boundary_stubs && (unsigned char*)p < hl_prof_boundary_stubs + MAX_HOOKS * STUB_SIZE;
}

/* ---- hooks ----------------------------------------------------------------------------------------------------- */

/* A function to hook, by the name its callers bind. Its real address is found when it is first needed, as the library
   defining it may load later. replacement is a wrapper for the hooks that do their own work; the others get a stub. */
typedef struct {
	const char *name;
	const char *module;		/* the slice's prefix; NULL names the library the function is found in */
	void *real;
	void *replacement;
} hook;

#define MAX_NAMES 256
static hook hooks[MAX_NAMES];
static int hook_count;

static void refresh( void );

static void *(*real_dlopen)( const char*, int );
static void *(*real_dlmopen)( Lmid_t, const char*, int );
static void *hook_dlopen( const char *file, int flags ) { void *h = real_dlopen(file,flags); if( h ) refresh(); return h; }
static void *hook_dlmopen( Lmid_t ns, const char *file, int flags ) { void *h = real_dlmopen(ns,file,flags); if( h ) refresh(); return h; }

static void add_hook( const char *name, const char *module ) {
	if( hook_count == MAX_NAMES ) return;
	for(int i=0;i<hook_count;i++) if( strcmp(hooks[i].name,name) == 0 ) return;
	hooks[hook_count].name = name;
	hooks[hook_count].module = module;
	hook_count++;
}

/* Calls that wait: on time, threads, I/O, the network or other processes. The 64 names are what 32-bit file offsets bind. */
static const char *const blocking_names[] = {
	"pthread_join", "pthread_cond_wait", "pthread_cond_timedwait", "pthread_cond_clockwait",
	"sem_wait", "sem_timedwait", "sem_clockwait",
	"nanosleep", "clock_nanosleep", "usleep", "sleep",
	"poll", "ppoll", "select", "pselect", "epoll_wait", "epoll_pwait", "epoll_pwait2",
	"read", "write", "pread", "pwrite", "pread64", "pwrite64", "readv", "writev", "fsync", "fdatasync",
	"open", "open64", "openat", "openat64",
	"recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg", "accept", "accept4", "connect", "getaddrinfo",
	"waitpid", "waitid", "wait4", "posix_spawn", "posix_spawnp", "system", "popen", "pclose",
	"fopen", "fopen64", "fread", "fwrite", "fflush", "fclose",
};

/* The display name of a library: its file name without the version, as in `libc`. */
static char *library_name( const char *path ) {
	const char *slash = strrchr(path,'/'), *file = slash ? slash + 1 : path, *so = strstr(file,".so");
	size_t n = so ? (size_t)(so - file) : strlen(file);
	char *name = (char*)malloc(n + 1);
	if( name ) { memcpy(name,file,n); name[n] = 0; }
	return name;
}

static char *join_name( const char *prefix, const char *name ) {
	size_t a = strlen(prefix), b = strlen(name);
	char *s = (char*)malloc(a + b + 2);
	if( s ) { memcpy(s,prefix,a); s[a] = '!'; memcpy(s + a + 1,name,b + 1); }
	return s;
}

/* The stub calling real through the thunk, made on first use and named after the library defining it. */
static void *stub_for( hook *h, void *real ) {
	Dl_info info;
	char *library = NULL, *name;
	void *stub = NULL;
	if( real == NULL || is_stub(real) ) return real;
	for(int i=0;i<desc_count;i++)
		if( hl_prof_boundary_descs[i].real == real ) return hl_prof_boundary_stubs + i * STUB_SIZE;
	if( desc_count == MAX_HOOKS ) return real;
	if( h->module ) library = library_name(h->module);
	else if( dladdr(real,&info) && info.dli_fname ) library = library_name(info.dli_fname);
	name = join_name(library ? library : "?",h->name);
	free(library);
	if( name == NULL ) return real;
	hl_prof_boundary_descs[desc_count].real = real;
	hl_prof_boundary_descs[desc_count].name = name;
	stub = hl_prof_boundary_stubs + desc_count * STUB_SIZE;
	__atomic_store_n(&desc_count,desc_count + 1,__ATOMIC_RELEASE);
	return stub;
}

/* ---- the GOT --------------------------------------------------------------------------------------------------- */

typedef struct {
	const ElfW(Phdr) *phdr;
	int phnum;
	uintptr_t base;
} object_info;

/* The program, and any object not installed with the system. */
static bool is_own_object( struct dl_phdr_info *info ) {
	static const char *const system_prefixes[] = { "/usr/", "/lib/", "/lib64/", "/lib32/", "/snap/", "linux-vdso", "linux-gate" };
	const char *name = info->dlpi_name;
	if( name == NULL || *name == 0 ) return true;
	for(int i=0;i<(int)(sizeof(system_prefixes) / sizeof(system_prefixes[0]));i++)
		if( strncmp(name,system_prefixes[i],strlen(system_prefixes[i])) == 0 ) return false;
	return true;
}

static bool in_object( const object_info *o, void *p ) {
	for(int i=0;i<o->phnum;i++)
		if( o->phdr[i].p_type == PT_LOAD ) {
			uintptr_t start = o->base + o->phdr[i].p_vaddr;
			if( (uintptr_t)p >= start && (uintptr_t)p < start + o->phdr[i].p_memsz ) return true;
		}
	return false;
}

/* Stores value in a GOT slot. The slots of an object linked with -z relro are read-only once it is relocated: the page
   is made writable around the store, and made read-only again, as the whole RELRO segment is. */
static void write_slot( const object_info *o, void **slot, void *value ) {
	uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE), page = (uintptr_t)slot & ~(page_size - 1);
	bool relro = false;
	for(int i=0;i<o->phnum;i++)
		if( o->phdr[i].p_type == PT_GNU_RELRO ) {
			uintptr_t start = o->base + o->phdr[i].p_vaddr;
			if( (uintptr_t)slot >= start && (uintptr_t)slot < start + o->phdr[i].p_memsz ) relro = true;
		}
	if( relro && mprotect((void*)page,page_size,PROT_READ | PROT_WRITE) != 0 ) return;
	__atomic_store_n(slot,value,__ATOMIC_RELEASE);
	if( relro ) mprotect((void*)page,page_size,PROT_READ);
}

/* Resolves a dynamic entry that the loader may or may not have relocated already. */
static uintptr_t dynamic_address( const object_info *o, uintptr_t value ) {
	return value < o->base ? value + o->base : value;
}

static void patch_relocations( const object_info *o, const ElfW(Rela) *relocs, size_t count, const ElfW(Sym) *symbols, const char *strings, bool jump_slots ) {
	for(size_t i=0;i<count;i++) {
		unsigned type = (unsigned)ELF64_R_TYPE(relocs[i].r_info);
		const char *name;
		void **slot, *real, *replacement;
		hook *h = NULL;
		if( type != (jump_slots ? R_X86_64_JUMP_SLOT : R_X86_64_GLOB_DAT) ) continue;
		name = strings + symbols[ELF64_R_SYM(relocs[i].r_info)].st_name;
		for(int j=0;j<hook_count;j++)
			if( strcmp(hooks[j].name,name) == 0 ) { h = hooks + j; break; }
		if( h == NULL ) continue;
		slot = (void**)(o->base + relocs[i].r_offset);
		real = *slot;
		if( is_stub(real) || real == h->replacement ) continue;
		/* A lazy slot still holds its PLT stub, in this object: the function is whichever one the name finds. */
		if( in_object(o,real) ) real = h->real;
		else if( h->real == NULL ) h->real = real;
		if( real == NULL ) continue;
		replacement = h->replacement ? h->replacement : stub_for(h,real);
		if( replacement != real ) write_slot(o,slot,replacement);
	}
}

static int patch_object( struct dl_phdr_info *info, size_t size, void *data ) {
	object_info o = { info->dlpi_phdr, info->dlpi_phnum, info->dlpi_addr };
	const ElfW(Dyn) *dynamic = NULL;
	const ElfW(Sym) *symbols = NULL;
	const char *strings = NULL;
	const ElfW(Rela) *jump_slots = NULL, *relocations = NULL;
	size_t jump_size = 0, relocation_size = 0;
	(void)size;
	(void)data;
	if( !is_own_object(info) ) return 0;
	for(int i=0;i<o.phnum;i++)
		if( o.phdr[i].p_type == PT_DYNAMIC ) dynamic = (const ElfW(Dyn)*)(o.base + o.phdr[i].p_vaddr);
	if( dynamic == NULL ) return 0;
	for(const ElfW(Dyn) *d = dynamic; d->d_tag != DT_NULL; d++)
		switch( d->d_tag ) {
		case DT_SYMTAB: symbols = (const ElfW(Sym)*)dynamic_address(&o,d->d_un.d_ptr); break;
		case DT_STRTAB: strings = (const char*)dynamic_address(&o,d->d_un.d_ptr); break;
		case DT_JMPREL: jump_slots = (const ElfW(Rela)*)dynamic_address(&o,d->d_un.d_ptr); break;
		case DT_PLTRELSZ: jump_size = d->d_un.d_val; break;
		case DT_RELA: relocations = (const ElfW(Rela)*)dynamic_address(&o,d->d_un.d_ptr); break;
		case DT_RELASZ: relocation_size = d->d_un.d_val; break;
		}
	if( symbols == NULL || strings == NULL ) return 0;
	if( jump_slots ) patch_relocations(&o,jump_slots,jump_size / sizeof(ElfW(Rela)),symbols,strings,true);
	/* -fno-plt code, and objects linked with -z now, bind through GLOB_DAT slots. */
	if( relocations ) patch_relocations(&o,relocations,relocation_size / sizeof(ElfW(Rela)),symbols,strings,false);
	return 0;
}

/* Finds the functions of libraries loaded since the last refresh, and patches the objects that call them. */
static void refresh( void ) {
	static __thread int refreshing;
	if( refreshing ) return;
	refreshing = 1;
	pthread_mutex_lock(&hook_lock);
	for(int i=0;i<hook_count;i++)
		if( hooks[i].real == NULL ) hooks[i].real = dlsym(RTLD_DEFAULT,hooks[i].name);
	dl_iterate_phdr(patch_object,NULL);
	pthread_mutex_unlock(&hook_lock);
	refreshing = 0;
}

void hl_prof_boundary_install( void ) {
	const char *config = getenv("HL_PROF_BOUNDARY");
	if( installed || config == NULL || *config == 0 ) return;
	hook_imports = strstr(config,"imports=none") == NULL;
	if( hook_imports )
		for(int i=0;i<(int)(sizeof(blocking_names) / sizeof(blocking_names[0]));i++)
			add_hook(blocking_names[i],NULL);
	{
		const char *extra = strstr(config,"extra=");
		if( extra ) {
			size_t len;
			extra += 6;
			len = strcspn(extra,";");
			extra_imports = (char*)malloc(len + 1);
			if( extra_imports ) {
				char *context = NULL;
				memcpy(extra_imports,extra,len);
				extra_imports[len] = 0;
				/* module!function, comma separated; the strings stay for the life of the process */
				for(char *item = strtok_r(extra_imports,",",&context); item; item = strtok_r(NULL,",",&context)) {
					char *bang = strchr(item,'!');
					if( bang == NULL ) continue;
					*bang = 0;
					add_hook(bang + 1,item);
				}
			}
		}
	}
	/* Every dlopen is followed by a refresh, so an object loaded later is patched too. */
	real_dlopen = (void *(*)( const char*, int ))dlsym(RTLD_DEFAULT,"dlopen");
	real_dlmopen = (void *(*)( Lmid_t, const char*, int ))dlsym(RTLD_DEFAULT,"dlmopen");
	if( hook_count < MAX_NAMES - 2 ) {
		if( real_dlopen ) { hooks[hook_count].name = "dlopen"; hooks[hook_count].real = (void*)real_dlopen; hooks[hook_count++].replacement = (void*)hook_dlopen; }
		if( real_dlmopen ) { hooks[hook_count].name = "dlmopen"; hooks[hook_count].real = (void*)real_dlmopen; hooks[hook_count++].replacement = (void*)hook_dlmopen; }
	}
	installed = true;
	refresh();
}

#endif
