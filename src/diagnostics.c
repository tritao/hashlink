/*
 * HLDI v1: a small, explicitly encoded diagnostics envelope.
 * The debugger remains on HLD2/HLD3; this endpoint starts with profiling and
 * leaves room for independent debugger, trace, and runtime-metrics services.
 */
#include "diagnostics.h"
#include <hlmodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
enum { DIAG_PROFILE_STATUS = 1, DIAG_PROFILE_CONFIGURE = 2, DIAG_PROFILE_READ = 3, DIAG_PROFILE_METADATA = 4 };
enum { DIAG_RESPONSE = 1, DIAG_ERROR = 2, DIAG_CAP_PROFILER = 1, DIAG_CAP_SYMBOLS = 2, DIAG_CAP_AUTH_REQUIRED = 4 };

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

static void function_name( hl_function *function, char *output, int capacity ) {
	if( function->obj ) {
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
	function_name(function,name,sizeof(name));
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

static bool send_metadata( hl_socket *socket, unsigned int request_id ) {
	diag_buffer buffer = {0};
	int count;
	hl_module **modules = hl_module_registry_snapshot(&count);
	/* Schema 4 adds each JIT region's introduction revision. */
	buffer_u32(&buffer,4);
	buffer_u32(&buffer,(unsigned int)count);
	for(int i=0;i<count;i++) {
		hl_module *module = modules[i];
		int patch_count = hl_module_patch_debug_region_count(module);
		buffer_u64(&buffer,module->diagnostics_id);
		buffer_u32(&buffer,(unsigned int)module->revision);
		buffer_u32(&buffer,(unsigned int)(1 + patch_count));
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
	}
	hl_module_registry_snapshot_free(modules,count);
	if( buffer.failed ) { free(buffer.data); return false; }
	{
		bool sent = send_frame(socket,DIAG_SERVICE_PROFILER,DIAG_PROFILE_METADATA,DIAG_RESPONSE,request_id,buffer.data,buffer.length);
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

static bool send_status( hl_socket *socket, int type, unsigned int request_id ) {
	unsigned char payload[56];
	unsigned long long first, next, dropped, consumer;
	int rate, paused, requested_rate;
	hl_profile_stream_status(&first,&next,&dropped,&rate,&paused,&consumer,&requested_rate);
	write_u64(payload,first); write_u64(payload + 8,next);
	write_u64(payload + 16,dropped);
	write_u32(payload + 24,(unsigned int)rate); write_u32(payload + 28,(unsigned int)paused);
	write_u64(payload + 32,HL_PROFILE_STREAM_SIZE);
	write_u64(payload + 40,consumer);
	write_u32(payload + 48,(unsigned int)requested_rate); write_u32(payload + 52,0);
	return send_frame(socket,DIAG_SERVICE_PROFILER,type,DIAG_RESPONSE,request_id,payload,sizeof(payload));
}

static void handle_client( hl_socket *socket ) {
	unsigned char hello[16];
	bool authenticated = diag_token == NULL || *diag_token == 0;
	int capabilities = DIAG_CAP_PROFILER | DIAG_CAP_SYMBOLS | (authenticated ? 0 : DIAG_CAP_AUTH_REQUIRED);
	memcpy(hello,"HLDI",4); write_u16(hello + 4,1); write_u16(hello + 6,capabilities);
	write_u32(hello + 8,HL_VERSION); write_u32(hello + 12,(unsigned int)hl_sys_getpid());
	if( !hl_diag_transport_send(socket,hello,sizeof(hello)) ) return;
	while( true ) {
		diag_header header;
		unsigned char *payload = NULL;
		bool ok = false;
		if( !recv_header(socket,&header) ) break;
		if( header.length ) {
			payload = malloc(header.length);
			if( payload == NULL || !hl_diag_transport_recv(socket,payload,(int)header.length) ) { free(payload); break; }
		}
		if( header.service == DIAG_SERVICE_CONTROL && header.type == DIAG_CONTROL_AUTHENTICATE && header.length <= 1024 ) {
			unsigned int expected = authenticated ? 0 : (unsigned int)strlen(diag_token), difference = expected ^ header.length;
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
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_CONFIGURE && header.length == 8 ) {
			ok = hl_profile_stream_configure((int)read_u32(payload),read_u32(payload + 4) != 0);
			if( ok ) ok = send_status(socket,header.type,header.request_id);
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_READ && header.length == 12 ) {
			unsigned long long cursor = read_u64(payload);
			unsigned int limit = read_u32(payload + 8), count;
			unsigned long long next, dropped;
			unsigned char *out;
			if( limit > 256 * 1024 ) limit = 256 * 1024;
			out = malloc(16 + limit);
			if( out ) {
				count = hl_profile_stream_read(cursor,out + 16,limit,&next,&dropped);
				write_u64(out,next); write_u64(out + 8,dropped);
				ok = send_frame(socket,header.service,header.type,DIAG_RESPONSE,header.request_id,out,16 + count);
				free(out);
			}
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_METADATA && header.length == 0 ) {
			ok = send_metadata(socket,header.request_id);
		}
		free(payload);
		if( !ok && !send_frame(socket,header.service,header.type,DIAG_RESPONSE | DIAG_ERROR,header.request_id,NULL,0) ) break;
	}
}

static void diagnostics_loop( void *_ ) {
	hl_get_thread()->flags |= HL_THREAD_INVISIBLE;
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
