/*
 * HLDI v2: a small, explicitly encoded diagnostics envelope.
 * The debugger remains on HLD2/HLD3; this endpoint starts with profiling and
 * leaves room for independent debugger, trace, and runtime-metrics services.
 */
#include "diagnostics.h"
#include <hlmodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef HL_WIN
#	include <time.h>
#endif
#include "hlprof.h"
#include "profile_events.h"
#include "../include/lz4/lz4.h"

HL_API void hl_sys_sleep( double t );
HL_API int hl_sys_getpid();

typedef struct {
	unsigned char service;
	unsigned char type;
	unsigned short flags;
	unsigned int request_id;
	unsigned int length;
	unsigned int reserved;
} diag_header;

enum { DIAG_SERVICE_CONTROL = 0, DIAG_SERVICE_PROFILER = 2 };
enum { DIAG_CONTROL_CAPABILITIES = 1, DIAG_CONTROL_AUTHENTICATE = 2 };
enum { DIAG_PROFILE_STATUS = 1, DIAG_PROFILE_METADATA = 4, DIAG_PROFILE_START = 16, DIAG_PROFILE_STOP = 17, DIAG_PROFILE_PAUSE = 18,
	DIAG_PROFILE_RESUME = 19 };
/* Flags of a start request's optional fifth word. An optional sixth word is the minimum call duration in nanoseconds
   (see hl_prof_set_min_call_ns); without it every call is kept. */
#define DIAG_START_PAUSED 1
/* Frames the runtime pushes during a session. Metadata is pushed with the type of its request. */
enum { DIAG_PUSH_SESSION = 16, DIAG_PUSH_DATA = 17, DIAG_PUSH_CLOCK = 18, DIAG_PUSH_THREADS = 19, DIAG_PUSH_END = 20, DIAG_PUSH_STATS = 21,
	DIAG_PUSH_RECORDING = 22 };
enum { DIAG_RESPONSE = 1, DIAG_ERROR = 2, DIAG_PUSH = 4, DIAG_CAP_PROFILER = 1, DIAG_CAP_SYMBOLS = 2, DIAG_CAP_AUTH_REQUIRED = 4 };

static hl_diag_transport *diag_transport;
static hl_socket *diag_client;
static volatile bool diag_stopped;
static const char *diag_token;

typedef struct {
	unsigned char *data;
	unsigned int length;
	unsigned int capacity;
	bool failed;
} diag_buffer;

static bool send_frame( hl_socket *socket, int service, int type, int flags, unsigned int request_id, const void *payload, unsigned int length );

static unsigned int read_u32( const unsigned char *p ) {
	return (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned long long read_u64( const unsigned char *p ) {
	return (unsigned long long)read_u32(p) | ((unsigned long long)read_u32(p + 4) << 32);
}

static void write_u16( unsigned char *p, unsigned int value ) {
	p[0] = (unsigned char)value; p[1] = (unsigned char)(value >> 8);
}

static void write_u32( unsigned char *p, unsigned int value ) {
	p[0] = (unsigned char)value; p[1] = (unsigned char)(value >> 8);
	p[2] = (unsigned char)(value >> 16); p[3] = (unsigned char)(value >> 24);
}

static void write_u64( unsigned char *p, unsigned long long value ) {
	write_u32(p,(unsigned int)value); write_u32(p + 4,(unsigned int)(value >> 32));
}

static unsigned char *buffer_reserve( diag_buffer *buffer, unsigned int size ) {
	unsigned int required = buffer->length + size;
	unsigned int capacity = buffer->capacity ? buffer->capacity : 4096;
	unsigned char *data;
	if( buffer->failed || required < buffer->length || required > (64 << 20) ) { buffer->failed = true; return NULL; }
	while( capacity < required ) capacity <<= 1;
	if( capacity != buffer->capacity ) {
		data = realloc(buffer->data,capacity);
		if( data == NULL ) { buffer->failed = true; return NULL; }
		buffer->data = data;
		buffer->capacity = capacity;
	}
	data = buffer->data + buffer->length;
	buffer->length = required;
	return data;
}

static void buffer_u32( diag_buffer *buffer, unsigned int value ) {
	unsigned char *p = buffer_reserve(buffer,4);
	if( p ) write_u32(p,value);
}

static void buffer_u64( diag_buffer *buffer, unsigned long long value ) {
	unsigned char *p = buffer_reserve(buffer,8);
	if( p ) write_u64(p,value);
}

static void buffer_bytes( diag_buffer *buffer, const void *data, unsigned int size ) {
	unsigned char *p = buffer_reserve(buffer,size);
	if( p && size ) memcpy(p,data,size);
}

static unsigned int function_end( hl_debug_infos *debug, int count, int index, unsigned int region_size ) {
	int start = debug[index].start;
	int end = (int)region_size;
	for(int i=0;i<count;i++)
		if( debug[i].offsets && debug[i].start > start && debug[i].start < end ) end = debug[i].start;
	return end < start ? (unsigned int)start : (unsigned int)end;
}

static void function_name( hl_code *code, hl_function *function, char *output, int capacity ) {
	const char *qualified = hl_code_function_name(code,function);
	if( qualified )
		snprintf(output,capacity,"%s",qualified);
	else if( function->obj ) {
		char object_name[256], field_name[256];
		snprintf(object_name,sizeof(object_name),"%s",hl_to_utf8(function->obj->name));
		snprintf(field_name,sizeof(field_name),"%s",hl_to_utf8(function->field.name));
		snprintf(output,capacity,"%s.%s",object_name,field_name);
	} else if( function->field.ref && function->field.ref->obj ) {
		char object_name[256], field_name[256];
		snprintf(object_name,sizeof(object_name),"%s",hl_to_utf8(function->field.ref->obj->name));
		snprintf(field_name,sizeof(field_name),"%s",hl_to_utf8(function->field.ref->field.name));
		snprintf(output,capacity,"%s.~%s.%d",object_name,field_name,function->ref);
	} else
		snprintf(output,capacity,"fun$%d",function->findex);
}

static unsigned int function_jit_offset( hl_debug_infos *debug, int opcode ) {
	return debug->large ? (unsigned int)((int*)debug->offsets)[opcode] : (unsigned int)((unsigned short*)debug->offsets)[opcode];
}

static int function_location_count( hl_code *code, hl_function *function, hl_debug_infos *debug, unsigned int size ) {
	int count = 0;
	if( !code->hasdebug || function->debug == NULL ) return 0;
	for(int i=0;i<function->nops;i++) {
		int file = function->debug[i * 2] & 0x7FFFFFFF;
		int line = function->debug[i * 2 + 1];
		unsigned int start = function_jit_offset(debug,i), end = function_jit_offset(debug,i + 1);
		if( file >= 0 && file < code->ndebugfiles && line > 0 && start < end && start < size ) count++;
	}
	return count;
}

static void append_function( diag_buffer *buffer, hl_code *code, hl_function *function, hl_debug_infos *debug, unsigned int start, unsigned int size ) {
	char name[768];
	unsigned int length, line_count;
	function_name(code,function,name,sizeof(name));
	length = (unsigned int)strlen(name);
	buffer_u32(buffer,(unsigned int)function->findex);
	buffer_u32(buffer,start);
	buffer_u32(buffer,size);
	buffer_u32(buffer,length);
	buffer_bytes(buffer,name,length);
	line_count = (unsigned int)function_location_count(code,function,debug,size);
	buffer_u32(buffer,line_count);
	if( line_count ) {
		for(int i=0;i<function->nops;i++) {
			int file = function->debug[i * 2] & 0x7FFFFFFF;
			int line = function->debug[i * 2 + 1];
			unsigned int start = function_jit_offset(debug,i), end = function_jit_offset(debug,i + 1);
			if( file < 0 || file >= code->ndebugfiles || line <= 0 || start >= end || start >= size ) continue;
			if( end > size ) end = size;
			buffer_u32(buffer,start);
			buffer_u32(buffer,end);
			buffer_u32(buffer,(unsigned int)i);
			buffer_u32(buffer,(unsigned int)debug->opcodes[i]);
			buffer_u32(buffer,(unsigned int)file);
			buffer_u32(buffer,(unsigned int)line);
		}
	}
}

static void append_region( diag_buffer *buffer, hl_code *code, unsigned long long base, unsigned int size, unsigned int flags, unsigned int revision, hl_function *functions, hl_debug_infos *debug, int debug_count, int function_count ) {
	int valid = 0;
	for(int i=0;i<function_count;i++) if( debug && debug[i].offsets && debug[i].start >= 0 && (unsigned int)debug[i].start < size ) valid++;
	buffer_u64(buffer,base);
	buffer_u64(buffer,size);
	buffer_u32(buffer,flags);
	buffer_u32(buffer,revision);
	buffer_u32(buffer,(unsigned int)valid);
	for(int i=0;i<function_count;i++)
		if( debug && debug[i].offsets && debug[i].start >= 0 && (unsigned int)debug[i].start < size )
			append_function(buffer,code,functions + i,debug + i,(unsigned int)debug[i].start,function_end(debug,debug_count,i,size) - (unsigned int)debug[i].start);
}

/* Each function of a patchable module is called through a small entry stub that jumps to its current code, so a sample can
   stop in one. The stubs are listed as a region of their own (flag 4), each named after the function it enters. The region
   has revision 0, since the stubs belong to no revision, so readers that key functions by revision keep them apart. */
static void append_entry_region( diag_buffer *buffer, hl_module *module ) {
	hl_code *code = module->code;
	unsigned int stride = HL_JIT_PATCH_ENTRY_STRIDE, size = (unsigned int)module->patch_entry_code_size, count_at;
	int valid = 0, nfunctions = code->nfunctions + code->npatchfunctions;
	buffer_u64(buffer,(unsigned long long)(uintptr_t)module->patch_entry_code);
	buffer_u64(buffer,size);
	buffer_u32(buffer,4);
	buffer_u32(buffer,0);
	count_at = buffer->length;
	buffer_u32(buffer,0);
	for(int i=0;i<nfunctions;i++) {
		hl_function *function = code->functions + i;
		char name[768];
		unsigned int length;
		if( function->findex < 0 || (unsigned int)function->findex >= size / stride ) continue;
		function_name(code,function,name,sizeof(name) - 8);
		strcat(name," [entry]");
		length = (unsigned int)strlen(name);
		buffer_u32(buffer,(unsigned int)function->findex);
		buffer_u32(buffer,(unsigned int)function->findex * stride);
		buffer_u32(buffer,stride);
		buffer_u32(buffer,length);
		buffer_bytes(buffer,name,length);
		buffer_u32(buffer,0);
		valid++;
	}
	if( !buffer->failed ) write_u32(buffer->data + count_at,(unsigned int)valid);
}

static bool send_metadata( hl_socket *socket, unsigned int request_id, int flags ) {
	diag_buffer buffer = {0};
	int count;
	hl_module **modules;
	// Patch regions are read while the program may be patching them.
	hl_module_patch_readers(1);
	modules = hl_module_registry_snapshot(&count);
	/* Schema 4 adds each JIT region's introduction revision. */
	buffer_u32(&buffer,4);
	buffer_u32(&buffer,(unsigned int)count);
	for(int i=0;i<count;i++) {
		hl_module *module = modules[i];
		int patch_count = hl_module_patch_debug_region_count(module);
		bool entries = module->patch_entry_code != NULL;
		buffer_u64(&buffer,module->diagnostics_id);
		buffer_u32(&buffer,(unsigned int)module->revision);
		/* Patched below: a patch region can vanish between counting and reading it. */
		unsigned int regions = 1 + (entries ? 1 : 0), regions_at = buffer.length;
		buffer_u32(&buffer,0);
		buffer_u32(&buffer,(unsigned int)module->code->ndebugfiles);
		for(int file_index=0;file_index<module->code->ndebugfiles;file_index++) {
			buffer_u32(&buffer,(unsigned int)module->code->debugfiles_lens[file_index]);
			buffer_bytes(&buffer,module->code->debugfiles[file_index],(unsigned int)module->code->debugfiles_lens[file_index]);
		}
		append_region(&buffer,module->code,(unsigned long long)(uintptr_t)module->jit_code,(unsigned int)module->codesize,0,1,module->code->functions,module->jit_debug,module->code->nfunctions,module->code->nfunctions);
		for(int region_index=0;region_index<patch_count;region_index++) {
			hl_patch_debug_region region;
			int valid = 0;
			unsigned int count_at;
			if( !hl_module_patch_debug_region_get(module,region_index,&region) ) continue;
			regions++;
			buffer_u64(&buffer,(unsigned long long)(uintptr_t)region.code);
			buffer_u64(&buffer,(unsigned int)region.code_size);
			buffer_u32(&buffer,1 | (region.retired ? 2 : 0));
			buffer_u32(&buffer,(unsigned int)region.revision);
			count_at = buffer.length;
			buffer_u32(&buffer,0);
			for(int j=0;j<region.function_count;j++) {
				int function_index;
				hl_function *function;
				hl_debug_infos *debug;
				unsigned int end = (unsigned int)region.code_size;
				if( !hl_module_patch_debug_function_get(module,region_index,j,&function_index,&function,&debug) ) continue;
				if( debug->start < 0 || (unsigned int)debug->start >= (unsigned int)region.code_size ) continue;
				for(int k=0;k<region.function_count;k++) {
					int other_index;
					hl_function *other_function;
					hl_debug_infos *other_debug;
					if( hl_module_patch_debug_function_get(module,region_index,k,&other_index,&other_function,&other_debug) && other_debug->start > debug->start && (unsigned int)other_debug->start < end ) end = (unsigned int)other_debug->start;
				}
				append_function(&buffer,module->code,function,debug,(unsigned int)debug->start,end - (unsigned int)debug->start);
				valid++;
			}
			if( !buffer.failed ) write_u32(buffer.data + count_at,(unsigned int)valid);
		}
		if( entries ) append_entry_region(&buffer,module);
		if( !buffer.failed ) write_u32(buffer.data + regions_at,regions);
	}
	hl_module_registry_snapshot_free(modules,count);
	hl_module_patch_readers(-1);
	if( buffer.failed ) { free(buffer.data); return false; }
	{
		bool sent = send_frame(socket,DIAG_SERVICE_PROFILER,DIAG_PROFILE_METADATA,flags,request_id,buffer.data,buffer.length);
		free(buffer.data);
		return sent;
	}
}

static bool recv_header( hl_socket *socket, diag_header *header ) {
	unsigned char bytes[16];
	if( !hl_diag_transport_recv(socket,bytes,sizeof(bytes)) ) return false;
	header->service = bytes[0]; header->type = bytes[1];
	header->flags = (unsigned short)(bytes[2] | (bytes[3] << 8));
	header->request_id = read_u32(bytes + 4);
	header->length = read_u32(bytes + 8);
	header->reserved = read_u32(bytes + 12);
	return header->length <= (1 << 20);
}

static bool send_frame( hl_socket *socket, int service, int type, int flags, unsigned int request_id, const void *payload, unsigned int length ) {
	unsigned char bytes[16];
	bytes[0] = (unsigned char)service; bytes[1] = (unsigned char)type;
	write_u16(bytes + 2,(unsigned int)flags); write_u32(bytes + 4,request_id);
	write_u32(bytes + 8,length); write_u32(bytes + 12,0);
	return hl_diag_transport_send(socket,bytes,sizeof(bytes)) && (length == 0 || hl_diag_transport_send(socket,payload,(int)length));
}

static bool send_status( hl_socket *socket, int type, unsigned int request_id );

/* ---- streaming sessions ------------------------------------------------------------------------------------------
 * After a start request the diagnostics thread is the profiler's consumer: it drains every thread's records, compresses
 * each thread's segment and pushes it, interleaved with the requests it still answers. docs/PROFILER.md in Haxeon
 * describes the frames.
 */

static struct {
	volatile bool active;
	volatile bool finish_requested;
	volatile bool finished;
	bool failed;
	int sources;
	unsigned long long data_frames;
	unsigned long long raw_bytes;
	unsigned long long sent_bytes;
	unsigned int threads_signature;
	int recording_changes;
	double next_clock;
	double next_threads;
	double next_stats;
	double next_gc;
	unsigned char *frame;
	int frame_capacity;
} session;

HL_API double hl_sys_time( void );
int hl_profile_main_thread( void );

static unsigned long long unix_ns( void ) {
#ifdef HL_WIN
	FILETIME now;
	unsigned long long value;
	GetSystemTimePreciseAsFileTime(&now);
	value = ((unsigned long long)now.dwHighDateTime << 32) | now.dwLowDateTime;
	return (value - 116444736000000000ULL) * 100ULL;
#else
	struct timespec now;
	clock_gettime(CLOCK_REALTIME,&now);
	return (unsigned long long)now.tv_sec * 1000000000ULL + (unsigned long long)now.tv_nsec;
#endif
}

static bool push( hl_socket *socket, int type, const void *payload, unsigned int length ) {
	if( session.failed ) return false;
	if( !send_frame(socket,DIAG_SERVICE_PROFILER,type,DIAG_PUSH,0,payload,length) ) {
		session.failed = true;
		return false;
	}
	session.sent_bytes += 16 + length;
	return true;
}

static void push_data( void *context, unsigned int tid, const unsigned char *data, unsigned int length ) {
	hl_socket *socket = (hl_socket*)context;
	int bound = LZ4_compressBound((int)length), compressed;
	unsigned char *frame;
	if( session.failed ) return;
	if( session.frame_capacity < 32 + bound ) {
		unsigned char *grown = (unsigned char*)realloc(session.frame,32 + bound);
		if( grown == NULL ) { session.failed = true; return; }
		session.frame = grown;
		session.frame_capacity = 32 + bound;
	}
	frame = session.frame;
	compressed = LZ4_compress_default((const char*)data,(char*)frame + 32,(int)length,bound);
	/* frame: the 16-byte diagnostics header, then tid, flags, raw length and a reserved word */
	frame[0] = DIAG_SERVICE_PROFILER; frame[1] = DIAG_PUSH_DATA; write_u16(frame + 2,DIAG_PUSH); write_u32(frame + 4,0);
	write_u32(frame + 12,0);
	write_u32(frame + 16,tid);
	write_u32(frame + 24,length);
	write_u32(frame + 28,0);
	if( compressed > 0 && (unsigned int)compressed < length ) {
		write_u32(frame + 8,16 + (unsigned int)compressed);
		write_u32(frame + 20,1);
	} else {
		compressed = (int)length;
		memcpy(frame + 32,data,length);
		write_u32(frame + 8,16 + length);
		write_u32(frame + 20,0);
	}
	if( !hl_diag_transport_send(socket,frame,32 + compressed) ) {
		session.failed = true;
		return;
	}
	session.data_frames++;
	session.raw_bytes += length;
	session.sent_bytes += 32 + (unsigned int)compressed;
}

static void push_clock( hl_socket *socket ) {
	unsigned char payload[24];
	unsigned long long ns = hl_prof_monotonic_ns();
	unsigned long long ticks = hl_prof_ticks() - hl_prof_base_ticks();
	write_u64(payload,ticks); write_u64(payload + 8,ns); write_u64(payload + 16,unix_ns());
	push(socket,DIAG_PUSH_CLOCK,payload,sizeof(payload));
}

/* A thread's name as the system knows it (SetThreadDescription, pthread_setname_np), into out; false if it has none. */
static bool system_thread_name( unsigned int tid, char *out, int capacity ) {
#if defined(HL_WIN_DESKTOP)
	HANDLE h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,tid);
	PWSTR wide = NULL;
	int n = 0;
	if( h == NULL ) return false;
	if( SUCCEEDED(GetThreadDescription(h,&wide)) && wide != NULL ) {
		if( *wide ) n = WideCharToMultiByte(CP_UTF8,0,wide,-1,out,capacity,NULL,NULL);
		LocalFree(wide);
	}
	CloseHandle(h);
	return n > 1;
#elif defined(HL_LINUX)
	char path[64];
	FILE *f;
	size_t n;
	snprintf(path,sizeof(path),"/proc/self/task/%u/comm",tid);
	f = fopen(path,"r");
	if( f == NULL ) return false;
	n = fread(out,1,(size_t)capacity - 1,f);
	fclose(f);
	while( n > 0 && (out[n - 1] == '\n' || out[n - 1] == 0) ) n--;
	out[n] = 0;
	return n > 0;
#else
	return false;
#endif
}

typedef struct {
	diag_buffer *buffer;
	unsigned int *signature;
	unsigned int *count;
	unsigned int *named;
	int named_count;
} thread_names;

static void add_thread_name( thread_names *names, unsigned int tid, const char *name ) {
	unsigned int length = (unsigned int)strlen(name);
	buffer_u32(names->buffer,tid);
	buffer_u32(names->buffer,length);
	buffer_bytes(names->buffer,name,length);
	*names->signature = (*names->signature ^ tid) * 16777619U;
	for(unsigned int c=0;c<length;c++) *names->signature = (*names->signature ^ (unsigned char)name[c]) * 16777619U;
	(*names->count)++;
}

/* Recorded threads the runtime has no name for (native threads, or ones named by other means) take their system names,
   looked up outside the recorder's lock. */
#define RECORDED_THREADS 1024
static void add_system_thread_names( thread_names *names ) {
	unsigned int *tids = (unsigned int*)malloc(sizeof(unsigned int) * RECORDED_THREADS);
	char name[128];
	int count;
	if( tids == NULL ) return;
	count = hl_prof_thread_ids(tids,RECORDED_THREADS);
	for(int i=0;i<count;i++) {
		bool named = false;
		for(int j=0;j<names->named_count && !named;j++) named = names->named[j] == tids[i];
		if( !named && system_thread_name(tids[i],name,sizeof(name)) ) add_thread_name(names,tids[i],name);
	}
	free(tids);
}

/* Thread names, pushed whenever the set of named threads changes. */
static void push_threads( hl_socket *socket, bool force ) {
	hl_threads_info *threads = hl_gc_threads_info();
	diag_buffer buffer = {0};
	unsigned int signature = 2166136261U, count = 0;
	int main_tid = hl_profile_main_thread();
	thread_names names = { &buffer, &signature, &count, NULL, 0 };
	names.named = (unsigned int*)malloc(sizeof(unsigned int) * (threads->count + 1));
	buffer_u32(&buffer,0);
	for(int i=0;i<threads->count;i++) {
		hl_thread_info *t = threads->threads[i];
		const char *name = *t->thread_name ? t->thread_name : t->thread_id == main_tid ? "main" : NULL;
		if( name == NULL || (t->flags & HL_THREAD_INVISIBLE) ) continue;
		add_thread_name(&names,(unsigned int)t->thread_id,name);
		if( names.named ) names.named[names.named_count++] = (unsigned int)t->thread_id;
	}
	if( names.named ) add_system_thread_names(&names);
	free(names.named);
	if( !buffer.failed && (force || signature != session.threads_signature) ) {
		write_u32(buffer.data,count);
		session.threads_signature = signature;
		push(socket,DIAG_PUSH_THREADS,buffer.data,buffer.length);
	}
	free(buffer.data);
}

static void push_stats( hl_socket *socket ) {
	unsigned char payload[40];
	hl_prof_stats stats;
	hl_prof_get_stats(&stats);
	write_u32(payload,(unsigned int)stats.chunks_in_use); write_u32(payload + 4,(unsigned int)stats.chunk_count);
	write_u64(payload + 8,stats.stalls); write_u64(payload + 16,stats.stall_ticks);
	write_u64(payload + 24,session.raw_bytes); write_u64(payload + 32,session.sent_bytes);
	push(socket,DIAG_PUSH_STATS,payload,sizeof(payload));
}

static void record_gc_stats( void ) {
	unsigned long long values[5];
	unsigned char payload[40];
	hl_gc_profile_stats(values,values + 1,values + 2,values + 3,values + 4);
	for(int i=0;i<5;i++) write_u64(payload + i * 8,values[i]);
	hl_prof_event(PROFILE_EVENT_GC_STATS,payload,sizeof(payload));
}

/* Stops recording and pushes everything recorded, then the end frame. */
static void session_end( hl_socket *socket ) {
	unsigned char payload[16];
	if( !session.active ) return;
	hl_profile_session_stop();
	record_gc_stats();
	hl_profile_name_native_keys();
	hl_prof_stop();
	hl_blocking(true);
	hl_prof_drain(push_data,socket);
	hl_blocking(false);
	if( hl_profile_metadata_changed() ) send_metadata(socket,0,DIAG_PUSH);
	push_threads(socket,false);
	push_stats(socket);
	push_clock(socket);
	write_u64(payload,session.data_frames); write_u64(payload + 8,session.raw_bytes);
	push(socket,DIAG_PUSH_END,payload,sizeof(payload));
	session.active = false;
	session.finished = true;
}

/* Whether the session records, pushed whenever the program or the client pauses or resumes it. */
static void push_recording( hl_socket *socket, bool force ) {
	unsigned char payload[4];
	int changes = hl_prof_recording_changes();
	if( !force && changes == session.recording_changes ) return;
	session.recording_changes = changes;
	write_u32(payload,hl_prof_on ? 1 : 0);
	push(socket,DIAG_PUSH_RECORDING,payload,sizeof(payload));
}

/* One consumer step: drain, then the periodic frames. Returns the bytes drained. */
static unsigned long long session_pump( hl_socket *socket ) {
	unsigned long long drained;
	double now;
	if( session.finish_requested ) {
		session_end(socket);
		return 0;
	}
	/* Blocking for the GC: this thread touches no GC memory while it drains and pushes, and a collection must not wait
	   for it. Metadata is built outside, as it converts names through the GC. */
	hl_profile_name_native_keys();
	hl_blocking(true);
	drained = hl_prof_drain(push_data,socket);
	now = hl_sys_time();
	if( now >= session.next_gc ) { record_gc_stats(); session.next_gc = now + 1.0; }
	if( now >= session.next_clock ) { push_clock(socket); session.next_clock = now + 0.1; }
	if( now >= session.next_threads ) { push_threads(socket,false); session.next_threads = now + 0.5; }
	if( now >= session.next_stats ) { push_stats(socket); session.next_stats = now + 1.0; }
	push_recording(socket,false);
	hl_blocking(false);
	if( hl_profile_metadata_changed() && !send_metadata(socket,0,DIAG_PUSH) ) session.failed = true;
	return drained;
}

static bool session_start( hl_socket *socket, const unsigned char *payload, unsigned int length, unsigned int request_id ) {
	unsigned char frame[32];
	int sources = (int)read_u32(payload), rate = (int)read_u32(payload + 4), interval = (int)read_u32(payload + 8);
	unsigned int pool_mib = read_u32(payload + 12), flags = length >= 20 ? read_u32(payload + 16) : 0;
	unsigned int min_call_ns = length >= 24 ? read_u32(payload + 20) : 0;
	double now;
	if( session.active ) return false;
	hl_prof_set_min_call_ns(min_call_ns);
	if( !hl_prof_start(pool_mib) ) return false;
	/* A paused session records nothing until the client or the program resumes it. */
	if( flags & DIAG_START_PAUSED ) hl_prof_set_recording(false);
	session.active = true;
	session.failed = false;
	session.finish_requested = false;
	session.finished = false;
	session.sources = sources;
	session.data_frames = session.raw_bytes = session.sent_bytes = 0;
	session.threads_signature = 0;
	if( !send_status(socket,DIAG_PROFILE_START,request_id) ) { session.failed = true; return true; }
	write_u32(frame,1); write_u32(frame + 4,(unsigned int)sources);
	write_u32(frame + 8,(unsigned int)hl_prof_tick_kind()); write_u32(frame + 12,0);
	write_u64(frame + 16,hl_prof_base_ticks()); write_u64(frame + 24,hl_prof_nominal_hz());
	push(socket,DIAG_PUSH_SESSION,frame,sizeof(frame));
	hl_profile_metadata_changed();
	if( !session.failed && !send_metadata(socket,0,DIAG_PUSH) ) session.failed = true;
	push_clock(socket);
	push_threads(socket,true);
	push_recording(socket,true);
	now = hl_sys_time();
	session.next_clock = now + 0.1;
	session.next_threads = now + 0.5;
	session.next_stats = now + 1.0;
	session.next_gc = now;
	/* Released last: a program held by --diagnostics-wait starts once its session is fully set up. */
	if( !hl_profile_session_start(sources,rate,interval) ) {
		session_end(socket);
		return true;
	}
	return true;
}

void hl_diagnostics_finish( void ) {
	double deadline;
	if( !session.active ) return;
	session.finish_requested = true;
	deadline = hl_sys_time() + 5.0;
	/* Blocking for the GC: finishing builds metadata on the diagnostics thread, and a collection it starts must not
	   wait for this thread. */
	hl_blocking(true);
	while( session.active && !session.finished && hl_sys_time() < deadline ) hl_sys_sleep(0.001);
	hl_blocking(false);
}

/* status: active, sources, chunk count, chunks in use, data frames pushed, raw bytes pushed */
static bool send_status( hl_socket *socket, int type, unsigned int request_id ) {
	unsigned char payload[32];
	hl_prof_stats stats;
	hl_prof_get_stats(&stats);
	write_u32(payload,session.active ? 1 : 0); write_u32(payload + 4,(unsigned int)session.sources);
	write_u32(payload + 8,(unsigned int)stats.chunk_count); write_u32(payload + 12,(unsigned int)stats.chunks_in_use);
	write_u64(payload + 16,session.data_frames); write_u64(payload + 24,session.raw_bytes);
	return send_frame(socket,DIAG_SERVICE_PROFILER,type,DIAG_RESPONSE,request_id,payload,sizeof(payload));
}

static void discard_segment( void *context, unsigned int tid, const unsigned char *data, unsigned int length ) {
	(void)context; (void)tid; (void)data; (void)length;
}

static void handle_client( hl_socket *socket ) {
	unsigned char hello[16];
	bool authenticated = diag_token == NULL || *diag_token == 0;
	int capabilities = DIAG_CAP_PROFILER | DIAG_CAP_SYMBOLS | (authenticated ? 0 : DIAG_CAP_AUTH_REQUIRED);
	memcpy(hello,"HLDI",4); write_u16(hello + 4,2); write_u16(hello + 6,capabilities);
	write_u32(hello + 8,HL_VERSION); write_u32(hello + 12,(unsigned int)hl_sys_getpid());
	if( !hl_diag_transport_send(socket,hello,sizeof(hello)) ) return;
	while( true ) {
		diag_header header;
		unsigned char *payload = NULL;
		bool ok = false;
		if( session.active ) {
			/* Streaming: answer requests as they come and drain the buffers in between. */
			int ready;
			if( session.failed ) break;
			hl_blocking(true);
			ready = hl_diag_transport_readable(socket,0);
			hl_blocking(false);
			if( ready < 0 ) break;
			if( ready == 0 ) {
				/* Drains are paced: polling every thread's write position continuously would pull it across cores on
				   each record the thread writes. Records wait about a millisecond, in buffers that hold far longer. */
				session_pump(socket);
				if( session.active ) {
					hl_blocking(true);
					ready = hl_diag_transport_readable(socket,1);
					hl_blocking(false);
					if( ready < 0 ) break;
				}
				continue;
			}
		}
		if( !recv_header(socket,&header) ) break;
		if( header.length ) {
			payload = malloc(header.length);
			if( payload == NULL || !hl_diag_transport_recv(socket,payload,(int)header.length) ) { free(payload); break; }
		}
		if( header.service == DIAG_SERVICE_CONTROL && header.type == DIAG_CONTROL_AUTHENTICATE && header.length <= 1024 ) {
			unsigned int expected = diag_token ? (unsigned int)strlen(diag_token) : 0, difference = expected ^ header.length;
			for(unsigned int i=0;i<header.length;i++) difference |= payload[i] ^ (i < expected ? (unsigned char)diag_token[i] : 0);
			authenticated = difference == 0;
			ok = authenticated && send_frame(socket,header.service,header.type,DIAG_RESPONSE,header.request_id,NULL,0);
		} else if( !authenticated ) {
			ok = false;
		} else if( header.service == DIAG_SERVICE_CONTROL && header.type == DIAG_CONTROL_CAPABILITIES && header.length == 0 ) {
			unsigned char caps[4]; write_u32(caps,capabilities);
			ok = send_frame(socket,header.service,header.type,DIAG_RESPONSE,header.request_id,caps,sizeof(caps));
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_STATUS && header.length == 0 ) {
			ok = send_status(socket,header.type,header.request_id);
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_START && (header.length == 16 || header.length == 20 || header.length == 24) ) {
			ok = session_start(socket,payload,header.length,header.request_id);
		} else if( header.service == DIAG_SERVICE_PROFILER && (header.type == DIAG_PROFILE_PAUSE || header.type == DIAG_PROFILE_RESUME) && header.length == 0 ) {
			ok = session.active && hl_prof_set_recording(header.type == DIAG_PROFILE_RESUME) && send_status(socket,header.type,header.request_id);
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_STOP && header.length == 0 ) {
			session_end(socket);
			ok = send_status(socket,header.type,header.request_id);
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_METADATA && header.length == 0 ) {
			ok = send_metadata(socket,header.request_id,DIAG_RESPONSE);
		}
		free(payload);
		if( !ok && !send_frame(socket,header.service,header.type,DIAG_RESPONSE | DIAG_ERROR,header.request_id,NULL,0) ) break;
	}
	if( session.active ) {
		/* The client went away mid-session: stop recording and drop what it can no longer receive. */
		hl_profile_session_stop();
		hl_prof_stop();
		hl_prof_drain(discard_segment,NULL);
		session.active = false;
		session.finished = true;
	}
}

static void diagnostics_loop( void *_ ) {
	hl_get_thread()->flags |= HL_THREAD_INVISIBLE;
	hl_prof_boundary_ignore_thread();
	hl_thread_set_name(hl_thread_current(),"hl.diagnostics");
	while( diag_transport ) {
		hl_socket *socket = hl_diag_transport_accept(diag_transport);
		if( socket == NULL ) break;
		if( diag_transport == NULL ) {
			hl_diag_transport_close_client(socket);
			break;
		}
		diag_client = socket;
		handle_client(socket);
		diag_client = NULL;
		hl_diag_transport_close_client(socket);
	}
	diag_stopped = true;
}

bool hl_diagnostics_start( int port, bool public_bind ) {
	if( diag_transport || port <= 0 ) return false;
	diag_token = getenv("HL_DIAGNOSTICS_TOKEN");
	if( public_bind && (diag_token == NULL || *diag_token == 0) ) {
		fprintf(stderr,"Public diagnostics requires HL_DIAGNOSTICS_TOKEN\n");
		return false;
	}
	diag_transport = hl_diag_transport_listen(port,public_bind);
	if( diag_transport == NULL ) return false;
	diag_stopped = false;
#ifdef HL_THREADS
	hl_add_root(&diag_client);
	if( !hl_thread_start(diagnostics_loop,NULL,true) ) {
		hl_remove_root(&diag_client);
		hl_diag_transport_close(diag_transport); diag_transport = NULL; return false;
	}
#else
	hl_diag_transport_close(diag_transport);
	diag_transport = NULL;
	return false;
#endif
	return true;
}

void hl_diagnostics_stop( void ) {
	hl_diag_transport *transport = diag_transport;
	if( transport == NULL ) return;
	diag_transport = NULL;
#ifdef HL_THREADS
	if( diag_client ) hl_diag_transport_interrupt(diag_client);
	hl_diag_transport_wake(transport);
	while( !diag_stopped ) hl_sys_sleep(0.01);
	hl_remove_root(&diag_client);
#endif
	hl_diag_transport_close(transport);
}
