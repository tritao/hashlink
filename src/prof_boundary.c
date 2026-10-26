/*
 * Boundary hooks for instrumented builds (Windows x64; Linux x86-64 is in prof_boundary_linux.c): calls from the process's own modules into code nobody compiled
 * with instrumentation become slices. Import-table hooks cover a curated set of blocking and system calls (and any
 * extra `module!function` the configuration names); vtable hooks cover the DXGI swap chain and the D3D11 immediate
 * context; and Vulkan's proc-address lookups hand out hooked submit, present and wait functions.
 *
 * Each hooked function gets a stub that loads its descriptor and jumps to hl_prof_boundary_thunk
 * (prof_boundary_x64.asm), which records an enter and an exit around the real call. A hook's key is its stub's address,
 * and the consumer names it from the descriptor (`kernel32!Sleep`, `IDXGISwapChain::Present`).
 *
 * The configuration comes from HL_PROF_BOUNDARY, which Haxeon sets when it runs an instrumented build:
 * `imports=blocking|none;extra=a.dll!F,b.dll!G;dxgi=1;d3d11=1;vulkan=1`. Without it nothing is hooked.
 */
#define COBJMACROS
#define CINTERFACE
#include <hl.h>
#include <hlmodule.h>
#include "hlprof.h"

#if defined(HL_WIN) && defined(HL_64) && defined(_MSC_VER)

#include <windows.h>
#include <psapi.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <stddef.h>

typedef struct {
	void *real;			/* read by the thunk: keep first */
	const char *name;
} boundary_desc;

#define MAX_HOOKS 1024
#define STUB_SIZE 32

static boundary_desc descs[MAX_HOOKS];
static int desc_count;
static unsigned char *stubs;
static SRWLOCK hook_lock = SRWLOCK_INIT;
/* Guards the stub table alone, and is never held across a call into the loader: a Vulkan lookup, which may run under the
   loader lock, takes only this one, while refresh holds hook_lock across module enumeration. */
static SRWLOCK stub_lock = SRWLOCK_INIT;
static bool installed;
static bool hook_imports, hook_dxgi, hook_d3d11, hook_vulkan;
static char *extra_imports;
static __declspec(thread) int boundary_busy;

extern void hl_prof_boundary_thunk( void );

/* ---- recording ------------------------------------------------------------------------------------------------- */

/* Called by the thunk before the real call. Returns whether it recorded an enter, which the thunk closes after. */
int hl_prof_boundary_enter( boundary_desc *d ) {
	/* A thread that must not wait records no call: one lost to a full pool would unpair its ENTER and EXIT. */
	if( !hl_prof_on || boundary_busy || !hl_prof_may_wait() ) return 0;
	/* The recorder may wait for the consumer through a hooked call: that wait is not recorded. */
	boundary_busy = 1;
	hl_prof_enter_blocking((unsigned long long)(uintptr_t)(stubs + (d - descs) * STUB_SIZE));
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
	if( stubs == NULL || p < stubs || p >= stubs + MAX_HOOKS * STUB_SIZE || (p - stubs) % STUB_SIZE ) return NULL;
	return (int)((p - stubs) / STUB_SIZE) < desc_count ? descs[(p - stubs) / STUB_SIZE].name : NULL;
}

static bool is_stub( void *p ) {
	return stubs && (unsigned char*)p >= stubs && (unsigned char*)p < stubs + MAX_HOOKS * STUB_SIZE;
}

static char *copy_name( const char *a, const char *b );

/* The stub calling real through the thunk, made on first use and named prefix + name (name alone, not copied, when prefix
   is NULL). */
static void *stub_for( void *real, const char *prefix, const char *name ) {
	unsigned char *s;
	if( real == NULL || is_stub(real) ) return real;
	AcquireSRWLockExclusive(&stub_lock);
	for(int i=0;i<desc_count;i++)
		if( descs[i].real == real ) { ReleaseSRWLockExclusive(&stub_lock); return stubs + i * STUB_SIZE; }
	if( desc_count == MAX_HOOKS ) { ReleaseSRWLockExclusive(&stub_lock); return real; }
	descs[desc_count].real = real;
	descs[desc_count].name = prefix ? copy_name(prefix,name) : name;
	s = stubs + desc_count * STUB_SIZE;
	/* mov r10, desc; jmp [rip]; dq hl_prof_boundary_thunk */
	s[0] = 0x49; s[1] = 0xBA; *(boundary_desc**)(s + 2) = descs + desc_count;
	s[10] = 0xFF; s[11] = 0x25; *(int*)(s + 12) = 0; *(void**)(s + 16) = (void*)hl_prof_boundary_thunk;
	FlushInstructionCache(GetCurrentProcess(),s,STUB_SIZE);
	desc_count++;
	ReleaseSRWLockExclusive(&stub_lock);
	return s;
}

static char *copy_name( const char *a, const char *b ) {
	size_t n = strlen(a) + strlen(b) + 1;
	char *s = (char*)malloc(n + 1);
	if( s ) { strcpy_s(s,n + 1,a); strcat_s(s,n + 1,b); }
	return s;
}

static void write_pointer( void **slot, void *value ) {
	DWORD old;
	if( *slot == value || !VirtualProtect(slot,sizeof(void*),PAGE_READWRITE,&old) ) return;
	*slot = value;
	VirtualProtect(slot,sizeof(void*),old,&old);
}

/* ---- imports --------------------------------------------------------------------------------------------------- */

typedef struct { const char *module; const char *name; } import_name;

/* Calls that wait: on time, objects, I/O, messages, the network or other processes. */
static const import_name blocking_imports[] = {
	{"kernel32.dll","Sleep"}, {"kernel32.dll","SleepEx"},
	{"kernel32.dll","WaitForSingleObject"}, {"kernel32.dll","WaitForSingleObjectEx"},
	{"kernel32.dll","WaitForMultipleObjects"}, {"kernel32.dll","WaitForMultipleObjectsEx"},
	{"kernel32.dll","SignalObjectAndWait"}, {"kernel32.dll","SleepConditionVariableCS"},
	{"kernel32.dll","SleepConditionVariableSRW"}, {"kernelbase.dll","WaitOnAddress"},
	{"kernel32.dll","GetQueuedCompletionStatus"}, {"kernel32.dll","GetQueuedCompletionStatusEx"},
	{"kernel32.dll","ReadFile"}, {"kernel32.dll","WriteFile"}, {"kernel32.dll","FlushFileBuffers"},
	{"kernel32.dll","DeviceIoControl"}, {"kernel32.dll","CreateFileW"}, {"kernel32.dll","CreateFileA"},
	{"kernel32.dll","ConnectNamedPipe"}, {"kernel32.dll","WaitNamedPipeW"},
	{"kernel32.dll","CreateProcessW"}, {"kernel32.dll","CreateProcessA"},
	{"user32.dll","GetMessageW"}, {"user32.dll","GetMessageA"}, {"user32.dll","WaitMessage"},
	{"user32.dll","MsgWaitForMultipleObjects"}, {"user32.dll","MsgWaitForMultipleObjectsEx"},
	{"ws2_32.dll","recv"}, {"ws2_32.dll","recvfrom"}, {"ws2_32.dll","send"}, {"ws2_32.dll","sendto"},
	{"ws2_32.dll","select"}, {"ws2_32.dll","WSAPoll"}, {"ws2_32.dll","accept"}, {"ws2_32.dll","connect"},
	{"ws2_32.dll","WSARecv"}, {"ws2_32.dll","WSASend"}, {"ws2_32.dll","WSAWaitForMultipleEvents"},
	{"ws2_32.dll","getaddrinfo"}, {"ws2_32.dll","GetAddrInfoW"},
	/* C++ waits: std::condition_variable, std::thread::join and std::this_thread::sleep_for wait inside the STL's DLL,
	   whose own imports are not patched. */
	{"msvcp140.dll","_Cnd_wait"}, {"msvcp140.dll","_Cnd_timedwait"}, {"msvcp140.dll","_Thrd_join"},
	{"msvcp140.dll","_Thrd_sleep"}, {"msvcp140.dll","_Thrd_sleep_for"},
	/* HashLink's file natives go through the C runtime's streams. */
	{"ucrtbase.dll","fopen"}, {"ucrtbase.dll","_wfopen"}, {"ucrtbase.dll","fread"}, {"ucrtbase.dll","fwrite"},
	{"ucrtbase.dll","fflush"}, {"ucrtbase.dll","fclose"}, {"ucrtbase.dll","system"}, {"ucrtbase.dll","_wsystem"},
};

static const char *vulkan_functions[] = {
	"vkQueueSubmit", "vkQueueSubmit2", "vkQueueSubmit2KHR", "vkQueuePresentKHR", "vkAcquireNextImageKHR",
	"vkWaitForFences", "vkWaitSemaphores", "vkWaitSemaphoresKHR", "vkQueueWaitIdle", "vkDeviceWaitIdle",
};

/* Import entries are matched by the address they hold, which catches every way of naming a function: by name or
   ordinal, through an API set, or forwarded from another module. */
typedef struct { void *real; void *replacement; } import_hook;
static import_hook import_hooks[MAX_HOOKS];
static int import_hook_count;

static void add_import_hook( void *real, void *replacement ) {
	if( real == NULL || replacement == NULL || real == replacement || import_hook_count == MAX_HOOKS ) return;
	for(int i=0;i<import_hook_count;i++) if( import_hooks[i].real == real ) return;
	import_hooks[import_hook_count].real = real;
	import_hooks[import_hook_count].replacement = replacement;
	import_hook_count++;
}

static void hook_export( const char *module, const char *display, const char *name ) {
	HMODULE m = GetModuleHandleA(module);
	void *real = m ? (void*)GetProcAddress(m,name) : NULL;
	char prefix[64];
	const char *dot;
	size_t n;
	if( real == NULL ) return;
	for(int i=0;i<import_hook_count;i++) if( import_hooks[i].real == real ) return;
	dot = strrchr(display,'.');
	n = dot ? (size_t)(dot - display) : strlen(display);
	if( n > sizeof(prefix) - 2 ) n = sizeof(prefix) - 2;
	memcpy(prefix,display,n); prefix[n] = '!'; prefix[n + 1] = 0;
	add_import_hook(real,stub_for(real,prefix,name));
}

/* A kernel32 function is also looked up in kernelbase, which modules importing it through an API set bind to. */
static void add_named_import( const char *module, const char *name ) {
	hook_export(module,module,name);
	if( _stricmp(module,"kernel32.dll") == 0 ) hook_export("kernelbase.dll",module,name);
}

/* ---- special hooks: module loads, D3D11 and DXGI creation, Vulkan lookups ------------------------------------- */

static void refresh( void );
static void patch_d3d11_context( ID3D11DeviceContext *context );
static void patch_swapchain( IUnknown *swapchain );
static void patch_factory_of( ID3D11Device *device );

static HMODULE (WINAPI *real_LoadLibraryA)( LPCSTR );
static HMODULE (WINAPI *real_LoadLibraryW)( LPCWSTR );
static HMODULE (WINAPI *real_LoadLibraryExA)( LPCSTR, HANDLE, DWORD );
static HMODULE (WINAPI *real_LoadLibraryExW)( LPCWSTR, HANDLE, DWORD );
static HMODULE WINAPI hook_LoadLibraryA( LPCSTR a ) { HMODULE m = real_LoadLibraryA(a); if( m ) refresh(); return m; }
static HMODULE WINAPI hook_LoadLibraryW( LPCWSTR a ) { HMODULE m = real_LoadLibraryW(a); if( m ) refresh(); return m; }
static HMODULE WINAPI hook_LoadLibraryExA( LPCSTR a, HANDLE b, DWORD c ) { HMODULE m = real_LoadLibraryExA(a,b,c); if( m ) refresh(); return m; }
static HMODULE WINAPI hook_LoadLibraryExW( LPCWSTR a, HANDLE b, DWORD c ) { HMODULE m = real_LoadLibraryExW(a,b,c); if( m ) refresh(); return m; }

typedef HRESULT (WINAPI *create_device_fn)( IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT, UINT,
	ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext** );
typedef HRESULT (WINAPI *create_device_swapchain_fn)( IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT, UINT,
	const DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext** );
static create_device_fn real_D3D11CreateDevice;
static create_device_swapchain_fn real_D3D11CreateDeviceAndSwapChain;

static void patch_device( ID3D11Device **device, ID3D11DeviceContext **context ) {
	if( context && *context && hook_d3d11 ) patch_d3d11_context(*context);
	if( device && *device && hook_dxgi ) patch_factory_of(*device);
}

static HRESULT WINAPI hook_D3D11CreateDevice( IDXGIAdapter *a, D3D_DRIVER_TYPE t, HMODULE s, UINT f, const D3D_FEATURE_LEVEL *l, UINT n, UINT v,
	ID3D11Device **device, D3D_FEATURE_LEVEL *level, ID3D11DeviceContext **context ) {
	HRESULT r = real_D3D11CreateDevice(a,t,s,f,l,n,v,device,level,context);
	if( SUCCEEDED(r) ) patch_device(device,context);
	return r;
}

static HRESULT WINAPI hook_D3D11CreateDeviceAndSwapChain( IDXGIAdapter *a, D3D_DRIVER_TYPE t, HMODULE s, UINT f, const D3D_FEATURE_LEVEL *l, UINT n,
	UINT v, const DXGI_SWAP_CHAIN_DESC *desc, IDXGISwapChain **swapchain, ID3D11Device **device, D3D_FEATURE_LEVEL *level,
	ID3D11DeviceContext **context ) {
	HRESULT r = real_D3D11CreateDeviceAndSwapChain(a,t,s,f,l,n,v,desc,swapchain,device,level,context);
	if( SUCCEEDED(r) ) {
		patch_device(device,context);
		if( swapchain && *swapchain && hook_dxgi ) patch_swapchain((IUnknown*)*swapchain);
	}
	return r;
}

typedef void (*vk_function)( void );
typedef vk_function (__stdcall *vk_lookup_fn)( void *owner, const char *name );
static vk_lookup_fn real_vkGetInstanceProcAddr, real_vkGetDeviceProcAddr;

static vk_function vk_hooked( vk_function f, const char *name ) {
	int count = (int)(sizeof(vulkan_functions) / sizeof(vulkan_functions[0]));
	void *stub;
	if( f == NULL || name == NULL ) return f;
	for(int i=0;i<count;i++)
		if( strcmp(name,vulkan_functions[i]) == 0 ) {
			stub = stub_for((void*)f,"vulkan!",vulkan_functions[i]);
			return (vk_function)stub;
		}
	return f;
}
static vk_function __stdcall hook_vkGetInstanceProcAddr( void *instance, const char *name ) { return vk_hooked(real_vkGetInstanceProcAddr(instance,name),name); }
static vk_function __stdcall hook_vkGetDeviceProcAddr( void *device, const char *name ) { return vk_hooked(real_vkGetDeviceProcAddr(device,name),name); }

/* Resolves a special hook's target, remembering the real function, and hooks its import entries. */
#define SPECIAL(module,name,variable,hook) do { \
		HMODULE m_ = GetModuleHandleA(module); void *real_ = m_ ? (void*)GetProcAddress(m_,name) : NULL; \
		if( real_ ) { if( variable == NULL ) *(void**)&variable = real_; add_import_hook(real_,(void*)hook); } \
	} while(0)

/* ---- vtables --------------------------------------------------------------------------------------------------- */

#define VTABLE_INDEX(type,method) ((int)(offsetof(type,method) / sizeof(void*)))

static void patch_vtable( void **vtable, int index, const char *name ) {
	void *stub;
	if( is_stub(vtable[index]) ) return;
	stub = stub_for(vtable[index],NULL,name);
	if( stub != vtable[index] ) write_pointer(vtable + index,stub);
}

static void patch_d3d11_context( ID3D11DeviceContext *context ) {
	void **vtable = (void**)context->lpVtbl;
	AcquireSRWLockExclusive(&hook_lock);
#	define CONTEXT_METHOD(m) patch_vtable(vtable,VTABLE_INDEX(ID3D11DeviceContextVtbl,m),"ID3D11DeviceContext::" #m)
	CONTEXT_METHOD(Draw); CONTEXT_METHOD(DrawIndexed); CONTEXT_METHOD(DrawInstanced); CONTEXT_METHOD(DrawIndexedInstanced);
	CONTEXT_METHOD(Dispatch); CONTEXT_METHOD(Map); CONTEXT_METHOD(Unmap); CONTEXT_METHOD(UpdateSubresource);
	CONTEXT_METHOD(CopyResource); CONTEXT_METHOD(CopySubresourceRegion); CONTEXT_METHOD(ClearRenderTargetView);
	CONTEXT_METHOD(ClearDepthStencilView); CONTEXT_METHOD(ExecuteCommandList); CONTEXT_METHOD(Flush);
#	undef CONTEXT_METHOD
	ReleaseSRWLockExclusive(&hook_lock);
}

static void patch_swapchain( IUnknown *swapchain ) {
	IDXGISwapChain1 *one = NULL;
	void **vtable = *(void***)swapchain;
	AcquireSRWLockExclusive(&hook_lock);
	patch_vtable(vtable,VTABLE_INDEX(IDXGISwapChainVtbl,Present),"IDXGISwapChain::Present");
	ReleaseSRWLockExclusive(&hook_lock);
	/* Present1 is in the same vtable when the object's IDXGISwapChain1 is the same interface pointer. */
	if( SUCCEEDED(IUnknown_QueryInterface(swapchain,&IID_IDXGISwapChain1,(void**)&one)) ) {
		if( (IUnknown*)one == swapchain ) {
			AcquireSRWLockExclusive(&hook_lock);
			patch_vtable(vtable,VTABLE_INDEX(IDXGISwapChain1Vtbl,Present1),"IDXGISwapChain1::Present1");
			ReleaseSRWLockExclusive(&hook_lock);
		}
		IDXGISwapChain1_Release(one);
	}
}

/* Swap chains come from a factory: its creation methods are wrapped so each new swap chain's vtable is patched. A
   factory class has one vtable; the originals are kept per vtable. */
typedef struct {
	void **vtable;
	HRESULT (STDMETHODCALLTYPE *create)( IDXGIFactory2*, IUnknown*, DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain** );
	HRESULT (STDMETHODCALLTYPE *for_hwnd)( IDXGIFactory2*, IUnknown*, HWND, const DXGI_SWAP_CHAIN_DESC1*,
		const DXGI_SWAP_CHAIN_FULLSCREEN_DESC*, IDXGIOutput*, IDXGISwapChain1** );
	HRESULT (STDMETHODCALLTYPE *for_core_window)( IDXGIFactory2*, IUnknown*, IUnknown*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*,
		IDXGISwapChain1** );
	HRESULT (STDMETHODCALLTYPE *for_composition)( IDXGIFactory2*, IUnknown*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1** );
} factory_methods;
static factory_methods factories[8];
static int factory_count;

static factory_methods *factory_of( IDXGIFactory2 *factory ) {
	for(int i=0;i<factory_count;i++) if( factories[i].vtable == (void**)factory->lpVtbl ) return factories + i;
	return NULL;
}

static HRESULT STDMETHODCALLTYPE hook_CreateSwapChain( IDXGIFactory2 *f, IUnknown *d, DXGI_SWAP_CHAIN_DESC *desc, IDXGISwapChain **out ) {
	HRESULT r = factory_of(f)->create(f,d,desc,out);
	if( SUCCEEDED(r) && out && *out ) patch_swapchain((IUnknown*)*out);
	return r;
}
static HRESULT STDMETHODCALLTYPE hook_CreateSwapChainForHwnd( IDXGIFactory2 *f, IUnknown *d, HWND w, const DXGI_SWAP_CHAIN_DESC1 *desc,
	const DXGI_SWAP_CHAIN_FULLSCREEN_DESC *full, IDXGIOutput *o, IDXGISwapChain1 **out ) {
	HRESULT r = factory_of(f)->for_hwnd(f,d,w,desc,full,o,out);
	if( SUCCEEDED(r) && out && *out ) patch_swapchain((IUnknown*)*out);
	return r;
}
static HRESULT STDMETHODCALLTYPE hook_CreateSwapChainForCoreWindow( IDXGIFactory2 *f, IUnknown *d, IUnknown *w, const DXGI_SWAP_CHAIN_DESC1 *desc,
	IDXGIOutput *o, IDXGISwapChain1 **out ) {
	HRESULT r = factory_of(f)->for_core_window(f,d,w,desc,o,out);
	if( SUCCEEDED(r) && out && *out ) patch_swapchain((IUnknown*)*out);
	return r;
}
static HRESULT STDMETHODCALLTYPE hook_CreateSwapChainForComposition( IDXGIFactory2 *f, IUnknown *d, const DXGI_SWAP_CHAIN_DESC1 *desc, IDXGIOutput *o,
	IDXGISwapChain1 **out ) {
	HRESULT r = factory_of(f)->for_composition(f,d,desc,o,out);
	if( SUCCEEDED(r) && out && *out ) patch_swapchain((IUnknown*)*out);
	return r;
}

static void patch_factory( IDXGIFactory2 *factory ) {
	void **vtable = (void**)factory->lpVtbl;
	factory_methods *m;
	AcquireSRWLockExclusive(&hook_lock);
	if( factory_of(factory) || factory_count == 8 ) { ReleaseSRWLockExclusive(&hook_lock); return; }
	m = factories + factory_count;
	m->vtable = vtable;
	*(void**)&m->create = vtable[VTABLE_INDEX(IDXGIFactory2Vtbl,CreateSwapChain)];
	*(void**)&m->for_hwnd = vtable[VTABLE_INDEX(IDXGIFactory2Vtbl,CreateSwapChainForHwnd)];
	*(void**)&m->for_core_window = vtable[VTABLE_INDEX(IDXGIFactory2Vtbl,CreateSwapChainForCoreWindow)];
	*(void**)&m->for_composition = vtable[VTABLE_INDEX(IDXGIFactory2Vtbl,CreateSwapChainForComposition)];
	/* Published before the vtable points at the wrappers, which look it up. */
	MemoryBarrier();
	factory_count++;
	write_pointer(vtable + VTABLE_INDEX(IDXGIFactory2Vtbl,CreateSwapChain),(void*)hook_CreateSwapChain);
	write_pointer(vtable + VTABLE_INDEX(IDXGIFactory2Vtbl,CreateSwapChainForHwnd),(void*)hook_CreateSwapChainForHwnd);
	write_pointer(vtable + VTABLE_INDEX(IDXGIFactory2Vtbl,CreateSwapChainForCoreWindow),(void*)hook_CreateSwapChainForCoreWindow);
	write_pointer(vtable + VTABLE_INDEX(IDXGIFactory2Vtbl,CreateSwapChainForComposition),(void*)hook_CreateSwapChainForComposition);
	ReleaseSRWLockExclusive(&hook_lock);
}

static void patch_factory_of( ID3D11Device *device ) {
	IDXGIDevice *dxgi = NULL;
	IDXGIAdapter *adapter = NULL;
	IDXGIFactory2 *factory = NULL;
	if( SUCCEEDED(ID3D11Device_QueryInterface(device,&IID_IDXGIDevice,(void**)&dxgi)) ) {
		if( SUCCEEDED(IDXGIDevice_GetAdapter(dxgi,&adapter)) ) {
			if( SUCCEEDED(IDXGIAdapter_GetParent(adapter,&IID_IDXGIFactory2,(void**)&factory)) ) {
				patch_factory(factory);
				IDXGIFactory2_Release(factory);
			}
			IDXGIAdapter_Release(adapter);
		}
		IDXGIDevice_Release(dxgi);
	}
}

/* ---- module scan ----------------------------------------------------------------------------------------------- */

static wchar_t windows_dir[MAX_PATH];

/* The process's own modules: everything not installed with Windows. */
static bool is_own_module( HMODULE m ) {
	wchar_t path[MAX_PATH];
	size_t n = wcslen(windows_dir);
	if( !GetModuleFileNameW(m,path,MAX_PATH) ) return false;
	return _wcsnicmp(path,windows_dir,n) != 0 || (path[n] != L'\\' && path[n] != 0);
}

static void patch_imports( HMODULE m ) {
	unsigned char *base = (unsigned char*)m;
	IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
	IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR *d;
	if( dir->VirtualAddress == 0 ) return;
	for(d = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir->VirtualAddress); d->Name; d++) {
		void **slot = (void**)(base + d->FirstThunk);
		for(; *slot; slot++)
			for(int i=0;i<import_hook_count;i++)
				if( *slot == import_hooks[i].real ) { write_pointer(slot,import_hooks[i].replacement); break; }
	}
}

/* Resolves the hooks of modules loaded since the last refresh and patches every own module's imports. */
static void refresh( void ) {
	HMODULE modules[1024];
	DWORD needed = 0;
	int count;
	AcquireSRWLockExclusive(&hook_lock);
	SPECIAL("kernel32.dll","LoadLibraryA",real_LoadLibraryA,hook_LoadLibraryA);
	SPECIAL("kernel32.dll","LoadLibraryW",real_LoadLibraryW,hook_LoadLibraryW);
	SPECIAL("kernel32.dll","LoadLibraryExA",real_LoadLibraryExA,hook_LoadLibraryExA);
	SPECIAL("kernel32.dll","LoadLibraryExW",real_LoadLibraryExW,hook_LoadLibraryExW);
	if( hook_d3d11 || hook_dxgi ) {
		SPECIAL("d3d11.dll","D3D11CreateDevice",real_D3D11CreateDevice,hook_D3D11CreateDevice);
		SPECIAL("d3d11.dll","D3D11CreateDeviceAndSwapChain",real_D3D11CreateDeviceAndSwapChain,hook_D3D11CreateDeviceAndSwapChain);
	}
	if( hook_vulkan ) {
		SPECIAL("vulkan-1.dll","vkGetInstanceProcAddr",real_vkGetInstanceProcAddr,hook_vkGetInstanceProcAddr);
		SPECIAL("vulkan-1.dll","vkGetDeviceProcAddr",real_vkGetDeviceProcAddr,hook_vkGetDeviceProcAddr);
		for(int i=0;i<(int)(sizeof(vulkan_functions) / sizeof(vulkan_functions[0]));i++) add_named_import("vulkan-1.dll",vulkan_functions[i]);
	}
	if( hook_imports )
		for(int i=0;i<(int)(sizeof(blocking_imports) / sizeof(blocking_imports[0]));i++)
			add_named_import(blocking_imports[i].module,blocking_imports[i].name);
	if( extra_imports ) {
		/* module!function, comma separated */
		char *list = _strdup(extra_imports), *context = NULL;
		for(char *item = list ? strtok_s(list,",",&context) : NULL; item; item = strtok_s(NULL,",",&context)) {
			char *bang = strchr(item,'!');
			if( bang == NULL ) continue;
			*bang = 0;
			add_named_import(item,bang + 1);
		}
		free(list);
	}
	if( EnumProcessModules(GetCurrentProcess(),modules,sizeof(modules),&needed) ) {
		count = (int)(needed / sizeof(HMODULE));
		if( count > 1024 ) count = 1024;
		for(int i=0;i<count;i++)
			if( is_own_module(modules[i]) ) patch_imports(modules[i]);
	}
	ReleaseSRWLockExclusive(&hook_lock);
}

static bool flag( const char *config, const char *key, bool fallback ) {
	const char *p = strstr(config,key);
	if( p == NULL ) return fallback;
	p += strlen(key);
	return *p != '0';
}

void hl_prof_boundary_install( void ) {
	char config[4096];
	DWORD n = GetEnvironmentVariableA("HL_PROF_BOUNDARY",config,sizeof(config));
	if( installed || n == 0 || n >= sizeof(config) ) return;
	stubs = (unsigned char*)VirtualAlloc(NULL,MAX_HOOKS * STUB_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	if( stubs == NULL ) return;
	GetWindowsDirectoryW(windows_dir,MAX_PATH);
	hook_imports = strstr(config,"imports=none") == NULL;
	hook_dxgi = flag(config,"dxgi=",true);
	hook_d3d11 = flag(config,"d3d11=",true);
	hook_vulkan = flag(config,"vulkan=",true);
	{
		const char *extra = strstr(config,"extra=");
		if( extra ) {
			size_t len;
			extra += 6;
			len = strcspn(extra,";");
			extra_imports = (char*)malloc(len + 1);
			if( extra_imports ) { memcpy(extra_imports,extra,len); extra_imports[len] = 0; }
		}
	}
	installed = true;
	refresh();
}

#elif !(defined(__linux__) && defined(__x86_64__))
/* Linux x86-64 has its own: prof_boundary_linux.c. */

void hl_prof_boundary_install( void ) {}
void hl_prof_boundary_ignore_thread( void ) {}
const char *hl_prof_boundary_name( unsigned long long key ) { (void)key; return NULL; }

#endif
