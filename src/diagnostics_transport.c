/* Shared transport primitives for versioned runtime diagnostics services. */
#include "diagnostics.h"
#include <stdlib.h>

HL_API void hl_socket_init();
HL_API hl_socket *hl_socket_new( bool udp );
HL_API bool hl_socket_bind( hl_socket *s, int host, int port );
HL_API bool hl_socket_listen( hl_socket *s, int n );
HL_API bool hl_socket_connect( hl_socket *s, int host, int port );
HL_API void hl_socket_close( hl_socket *s );
HL_API hl_socket *hl_socket_accept( hl_socket *s );
HL_API int hl_socket_send( hl_socket *s, vbyte *buf, int pos, int len );
HL_API int hl_socket_recv( hl_socket *s, vbyte *buf, int pos, int len );
HL_API bool hl_socket_shutdown( hl_socket *s, bool read, bool write );

struct _hl_diag_transport {
	hl_socket *listener;
	int port;
};

hl_diag_transport *hl_diag_transport_listen( int port ) {
	hl_diag_transport *transport;
	hl_socket *listener;
	hl_socket_init();
	listener = hl_socket_new(false);
	if( listener == NULL ) return NULL;
	/* Remote exposure should be done deliberately through a tunnel or host proxy. */
	if( !hl_socket_bind(listener,0x0100007F/*127.0.0.1*/,port) || !hl_socket_listen(listener,10) ) {
		hl_socket_close(listener);
		return NULL;
	}
	transport = malloc(sizeof(hl_diag_transport));
	transport->listener = listener;
	transport->port = port;
	hl_add_root(&transport->listener);
	return transport;
}

void hl_diag_transport_wake( hl_diag_transport *transport ) {
	hl_socket *socket;
	if( transport == NULL ) return;
	socket = hl_socket_new(false);
	if( socket == NULL ) return;
	hl_socket_connect(socket,0x0100007F/*127.0.0.1*/,transport->port);
	hl_socket_close(socket);
}

hl_socket *hl_diag_transport_accept( hl_diag_transport *transport ) {
	return transport == NULL ? NULL : hl_socket_accept(transport->listener);
}

bool hl_diag_transport_send( hl_socket *socket, const void *data, int size ) {
	int pos = 0;
	while( pos < size ) {
		int count = hl_socket_send(socket,(vbyte*)data,pos,size-pos);
		if( count <= 0 ) return false;
		pos += count;
	}
	return true;
}

bool hl_diag_transport_recv( hl_socket *socket, void *data, int size ) {
	int pos = 0;
	while( pos < size ) {
		int count = hl_socket_recv(socket,(vbyte*)data,pos,size-pos);
		if( count <= 0 ) return false;
		pos += count;
	}
	return true;
}

void hl_diag_transport_interrupt( hl_socket *socket ) {
	if( socket ) hl_socket_shutdown(socket,true,true);
}

void hl_diag_transport_close_client( hl_socket *socket ) {
	if( socket ) hl_socket_close(socket);
}

void hl_diag_transport_close( hl_diag_transport *transport ) {
	if( transport == NULL ) return;
	if( transport->listener ) hl_socket_close(transport->listener);
	hl_remove_root(&transport->listener);
	free(transport);
}
