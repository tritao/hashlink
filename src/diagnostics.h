#ifndef HL_DIAGNOSTICS_H
#define HL_DIAGNOSTICS_H

#include <hl.h>

typedef struct _hl_diag_transport hl_diag_transport;
typedef struct _hl_socket hl_socket;

hl_diag_transport *hl_diag_transport_listen( int port );
hl_socket *hl_diag_transport_accept( hl_diag_transport *transport );
void hl_diag_transport_wake( hl_diag_transport *transport );
bool hl_diag_transport_send( hl_socket *socket, const void *data, int size );
bool hl_diag_transport_recv( hl_socket *socket, void *data, int size );
void hl_diag_transport_interrupt( hl_socket *socket );
void hl_diag_transport_close_client( hl_socket *socket );
void hl_diag_transport_close( hl_diag_transport *transport );

bool hl_diagnostics_start( int port );
void hl_diagnostics_stop( void );

#endif
