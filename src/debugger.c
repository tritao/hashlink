/*
 * Copyright (C)2015-2016 Haxe Foundation
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
#include <hl.h>
#include <hlmodule.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HL_WIN
#include <windows.h>
#else
#include <time.h>
#endif

struct _hl_socket;
typedef struct _hl_socket hl_socket;
HL_API void hl_socket_init();
HL_API hl_socket *hl_socket_new( bool udp );
HL_API bool hl_socket_bind( hl_socket *s, int host, int port );
HL_API bool hl_socket_listen( hl_socket *s, int n );
HL_API void hl_socket_close( hl_socket *s );
HL_API hl_socket *hl_socket_accept( hl_socket *s );
HL_API int hl_socket_send( hl_socket *s, vbyte *buf, int pos, int len );
HL_API int hl_socket_recv( hl_socket *s, vbyte *buf, int pos, int len );
HL_API void hl_sys_sleep( double t );
HL_API int hl_sys_getpid();

static hl_socket *debug_socket = NULL;
static hl_socket *client_socket = NULL;
static bool debugger_connected = false;
static bool debugger_stopped = false;
static bool debug_protocol3 = false;
static volatile int debug_pending_sequence = 0;
static volatile int debug_ack_sequence = 0;
static hl_mutex *debug_notify_lock = NULL;

static void debug_trace( const char *event, hl_module *m, int revision, void *address, int value ) {
	const char *path = getenv("HL_DEBUG_TRACE");
	FILE *out;
	if( path == NULL || *path == 0 ) return;
	out = fopen(path,"a");
	if( out == NULL ) return;
	fprintf(out,"{\"component\":\"runtime\",\"event\":\"%s\",\"pid\":%d,\"module\":\"%p\",\"revision\":%d,\"address\":\"%p\",\"value\":%d}\n",event,hl_sys_getpid(),(void*)m,revision,address,value);
	fclose(out);
}

#define send hl_send_data
static void send( void *ptr, int size ) {
	hl_socket_send(client_socket, ptr, 0, size);
}

static bool recv_all( hl_socket *s, void *ptr, int size ) {
	int pos = 0;
	while( pos < size ) {
		int count = hl_socket_recv(s,(vbyte*)ptr,pos,size-pos);
		if( count <= 0 ) return false;
		pos += count;
	}
	return true;
}

static void debug_wait_tick() {
#ifdef HL_WIN
	Sleep(1);
#else
	struct timespec delay = {0,1000000};
	nanosleep(&delay,NULL);
#endif
}

static void send_debug_function( hl_function *f, hl_debug_infos *d, int function_index, bool indexed, bool include_stable_id, int stable_id ) {
	struct {
		int nops;
		int start;
		int vars_size;
		unsigned char large;
	} fdata;
	if( indexed ) send(&function_index,4);
	if( include_stable_id ) send(&stable_id,4);
	fdata.nops = f->nops;
	fdata.start = d->start;
	fdata.vars_size = d->vars_size;
	fdata.large = (unsigned char)d->large;
	send(&fdata,13);
	send(d->offsets,(d->large ? sizeof(int) : sizeof(unsigned short)) * (f->nops + 1));
	send(d->vars,d->vars_size);
}

static void send_patch_regions( hl_module *m ) {
	int count = hl_module_patch_debug_region_count(m);
	send(&m,sizeof(void*));
	send(&m->debug_hlb_size,4);
	if( m->debug_hlb_size > 0 ) send(m->debug_hlb,m->debug_hlb_size);
	send(&m->revision,4);
	send(&m->globals_data,sizeof(void*));
	send(&m->code->types,sizeof(void*));
	send(&m->jit_code,sizeof(void*));
	send(&m->codesize,4);
	send(&m->code->nfunctions,4);
	for(int i=0;i<m->code->nfunctions;i++) {
		send_debug_function(m->code->functions+i,m->jit_debug+i,i,false,true,m->code->function_stable_ids[i]);
		int span_count = 0; send(&span_count,4);
	}
	send(&count,4);
	for(int i=0;i<count;i++) {
		hl_patch_debug_region region;
		unsigned char retired;
		hl_module_patch_debug_region_get(m,i,&region);
		retired = region.retired ? 1 : 0;
		send(&region.code,sizeof(void*));
		send(&region.code_size,4);
		send(&retired,1);
		send(&region.function_count,4);
		for(int j=0;j<region.function_count;j++) {
			int function_index;
			hl_function *function;
			hl_debug_infos *debug;
			if( !hl_module_patch_debug_function_get(m,i,j,&function_index,&function,&debug) ) return;
			send_debug_function(function,debug,function_index,true,true,m->code->function_stable_ids[function_index]);
			hl_source_span first_span;
			int span_count = function->nops > 0 && hl_module_patch_debug_source_span_get(m,i,j,0,&first_span) ? function->nops : 0;
			send(&span_count,4);
			for(int opcode=0;opcode<span_count;opcode++) {
				hl_source_span span;
				if( opcode == 0 ) span=first_span;
				else if( !hl_module_patch_debug_source_span_get(m,i,j,opcode,&span) ) return;
				send(&span,sizeof(span));
			}
		}
		int snapshot_count = hl_module_patch_debug_source_snapshot_count(m,i);
		send(&snapshot_count,4);
		for(int j=0;j<snapshot_count;j++) {
			hl_source_snapshot snapshot;
			if( !hl_module_patch_debug_source_snapshot_get(m,i,j,&snapshot) ) return;
			send(&snapshot.source_hash,4);
			send(&snapshot.length,4);
			if( snapshot.length > 0 ) send(snapshot.content,snapshot.length);
		}
	}
}

static void send_patch_refresh() {
	int count;
	hl_module **modules = hl_module_registry_snapshot(&count);
	debug_trace("map3_sent",NULL,0,NULL,count);
	send("MAP3",4);
	send(&count,4);
	for(int i=0;i<count;i++)
		send_patch_regions(modules[i]);
	hl_module_registry_snapshot_free(modules,count);
}

/* Patch publication calls this before returning to user code. The short REV3
   record is sent only while the protocol thread is blocked waiting for a
   command, so it cannot interleave with MAP3. The publisher stays parked until
   breakpoint mappings have been rebound and the adapter has acknowledged. */
void hl_debug_notify_revision( hl_module *m ) {
	int sequence;
	if( !debug_protocol3 || debug_notify_lock == NULL || m == NULL ) return;
	hl_mutex_acquire(debug_notify_lock);
	if( client_socket == NULL ) { hl_mutex_release(debug_notify_lock); return; }
	sequence = ++debug_pending_sequence;
	debug_trace("rev3_sent",m,m->revision,NULL,0);
	send("REV3",4);
	send(&m,sizeof(void*));
	send(&m->revision,4);
	hl_mutex_release(debug_notify_lock);
	while( client_socket != NULL && debug_ack_sequence < sequence ) debug_wait_tick();
	debug_trace("revision_released",m,m->revision,NULL,0);
}

/* Retirement has unpublished the module and established that no registry
   reader remains. Keep its metadata alive until the debugger has discarded
   cached mappings and acknowledged the stable identity. */
static void hl_debug_notify_remove( void *module ) {
	hl_module *m = (hl_module*)module;
	int sequence;
	if( !debug_protocol3 || debug_notify_lock == NULL || m == NULL ) return;
	hl_mutex_acquire(debug_notify_lock);
	if( client_socket == NULL ) { hl_mutex_release(debug_notify_lock); return; }
	sequence = ++debug_pending_sequence;
	debug_trace("rem3_sent",m,m->revision,NULL,0);
	send("REM3",4);
	send(&m,sizeof(void*));
	hl_mutex_release(debug_notify_lock);
	while( client_socket != NULL && debug_ack_sequence < sequence ) debug_wait_tick();
	debug_trace("removal_released",m,m->revision,NULL,0);
}

static void hl_debug_loop() {
	void *inf_addr = hl_gc_threads_info();
	int flags = 0;
	int hl_ver = HL_VERSION;
	bool loop = false;
	int pid = hl_sys_getpid();
	const char *protocol = getenv("HL_DEBUG_PROTOCOL");
	if( protocol && protocol[0] == '3' && protocol[1] == 0 ) debug_protocol3 = true;
#	ifdef HL_64
	flags |= 1;
#	endif
	if( sizeof(bool) == 4 ) flags |= 2;
#	ifdef HL_THREADS
	flags |= 4;
	loop = true;
#	endif
#	ifdef HL_WIN_CALL
	flags |= 8;
#	endif
	hl_get_thread()->flags |= HL_THREAD_INVISIBLE;
	do {
		vbyte cmd;
		hl_socket *s = hl_socket_accept(debug_socket);
		if( s == NULL ) break;
		debug_ack_sequence = debug_pending_sequence;
		hl_mutex_acquire(debug_notify_lock);
		client_socket = s;
		hl_mutex_release(debug_notify_lock);
		send(debug_protocol3 ? "HLD3" : "HLD2",4);
		send(&flags,4);
		send(&hl_ver, 4);
		send(&pid,4);
		send(&inf_addr, sizeof(void*));

		for(int i=1;i<=HBYTES;i++) {
			hl_type t = {(hl_type_kind)i};
			int k = 1 + hl_pad_struct(1,&t);
			send(&k,4);
		}

		int nmodules;
		hl_module **mods = hl_module_registry_snapshot(&nmodules);

		send(&hl_jit_trampoline,4);

		send(&nmodules,4);
		for(int i=0;i<nmodules;i++) {
			hl_module *m = mods[i];
			send(&m->globals_data,sizeof(void*));
			send(&m->jit_code,sizeof(void*));
			send(&m->codesize,4);
			send(&m->code->types,sizeof(void*));
			send(&m->code->nfunctions,4);
			for(int j=0;j<m->code->nfunctions;j++)
				send_debug_function(m->code->functions+j,m->jit_debug+j,j,false,false,-1);
			if( debug_protocol3 ) send_patch_regions(m);
		}
		hl_module_registry_snapshot_free(mods,nmodules);

		hl_setup.closure_stack_capture = 8;
		hl_setup.is_debugger_attached = true;

		// wait answer
		// for some reason, this is not working on windows (recv returns 0 ?)
		hl_socket_recv(s,&cmd,0,1);
		if( debug_protocol3 ) debugger_connected = true;
		while( debug_protocol3 && (cmd == 'R' || cmd == 'A' || cmd == 'B') ) {
			if( cmd == 'R' )
				send_patch_refresh();
			else if( cmd == 'A' ) {
				if( debug_pending_sequence == 0 ) send("ACK3",4);
				debug_ack_sequence = debug_pending_sequence;
				debug_trace("ack3_received",NULL,debug_ack_sequence,NULL,0);
			}
			else {
				int count;
				if( !recv_all(s,&count,4) || count < 0 || count > 65536 ) break;
				send("BRK3",4);
				send(&count,4);
				for(int i=0;i<count;i++) {
					void *address;
					unsigned char byte, old;
					if( !recv_all(s,&address,sizeof(void*)) || !recv_all(s,&byte,1) ) { count = -1; break; }
					old = *(unsigned char*)address;
					*(unsigned char*)address = byte;
					debug_trace("breakpoint_write",NULL,debug_pending_sequence,address,byte);
					send(&old,1);
				}
				if( count < 0 ) break;
			}
			if( hl_socket_recv(s,&cmd,0,1) <= 0 ) break;
		}
		debug_ack_sequence = debug_pending_sequence;
		hl_mutex_acquire(debug_notify_lock);
		client_socket = NULL;
		hl_mutex_release(debug_notify_lock);
		hl_socket_close(s);
		debugger_connected = true;
	} while( loop );
	debugger_stopped = true;
}

h_bool hl_module_debug( hl_module *m, int port, h_bool wait ) {
	hl_socket *s;
	hl_socket_init();
	s = hl_socket_new(false);
	if( s == NULL ) return false;
	if( !hl_socket_bind(s,0x0100007F/*127.0.0.1*/,port) || !hl_socket_listen(s, 10) ) {
		hl_socket_close(s);
		return false;
	}
	debug_socket = s;
	if( debug_notify_lock == NULL ) {
		debug_notify_lock = hl_mutex_alloc(false);
		hl_add_root(&debug_notify_lock);
	}
#	ifdef HL_THREADS
	hl_add_root(&debug_socket);
	hl_add_root(&client_socket);
	if( !hl_thread_start(hl_debug_loop, m, true) ) {
		hl_socket_close(s);
		return false;
	}
	if( wait ) {
		while( !debugger_connected )
			hl_sys_sleep(0.01);
	}
#	else
	// imply --debug-wait
	hl_debug_loop(m);
	hl_socket_close(debug_socket);
	debug_socket = NULL;
#	endif
	hl_setup.is_debugger_enabled = true;
	hl_setup.debug_module_removed = hl_debug_notify_remove;
	return true;
}

void hl_module_debug_stop() {
	if( !debug_socket ) return;
#	ifdef HL_THREADS
	hl_socket_close(debug_socket);
	while( !debugger_stopped )
		hl_sys_sleep(0.01);
	hl_remove_root(&debug_socket);
	hl_remove_root(&client_socket);
#	endif
}
