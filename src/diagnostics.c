/*
 * HLDI v1: a small, explicitly encoded diagnostics envelope.
 * The debugger remains on HLD2/HLD3; this endpoint starts with profiling and
 * leaves room for independent debugger, trace, and runtime-metrics services.
 */
#include "diagnostics.h"
#include <hlmodule.h>
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
enum { DIAG_CONTROL_CAPABILITIES = 1 };
enum { DIAG_PROFILE_STATUS = 1, DIAG_PROFILE_CONFIGURE = 2, DIAG_PROFILE_READ = 3 };
enum { DIAG_RESPONSE = 1, DIAG_ERROR = 2, DIAG_CAP_PROFILER = 1 };

static hl_diag_transport *diag_transport;
static hl_socket *diag_client;
static volatile bool diag_stopped;

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

static bool send_status( hl_socket *socket, unsigned int request_id ) {
	unsigned char payload[32];
	unsigned long long first, next, dropped;
	int rate, paused;
	hl_profile_stream_status(&first,&next,&dropped,&rate,&paused);
	write_u64(payload,first); write_u64(payload + 8,next);
	write_u64(payload + 16,dropped);
	write_u32(payload + 24,(unsigned int)rate); write_u32(payload + 28,(unsigned int)paused);
	return send_frame(socket,DIAG_SERVICE_PROFILER,DIAG_PROFILE_STATUS,DIAG_RESPONSE,request_id,payload,sizeof(payload));
}

static void handle_client( hl_socket *socket ) {
	unsigned char hello[16];
	memcpy(hello,"HLDI",4); write_u16(hello + 4,1); write_u16(hello + 6,DIAG_CAP_PROFILER);
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
		if( header.service == DIAG_SERVICE_CONTROL && header.type == DIAG_CONTROL_CAPABILITIES && header.length == 0 ) {
			unsigned char caps[4]; write_u32(caps,DIAG_CAP_PROFILER);
			ok = send_frame(socket,header.service,header.type,DIAG_RESPONSE,header.request_id,caps,sizeof(caps));
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_STATUS && header.length == 0 ) {
			ok = send_status(socket,header.request_id);
		} else if( header.service == DIAG_SERVICE_PROFILER && header.type == DIAG_PROFILE_CONFIGURE && header.length == 8 ) {
			ok = hl_profile_stream_configure((int)read_u32(payload),read_u32(payload + 4) != 0);
			if( ok ) ok = send_status(socket,header.request_id);
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

bool hl_diagnostics_start( int port ) {
	if( diag_transport || port <= 0 ) return false;
	diag_transport = hl_diag_transport_listen(port);
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
