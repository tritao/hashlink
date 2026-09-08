#ifndef HL_JIT_GDB_H
#define HL_JIT_GDB_H

#include <hlmodule.h>

void hl_gdb_jit_register( hl_module *m );
void hl_gdb_jit_register_patch( hl_module *m );
void hl_gdb_jit_unregister( hl_module *m );

#endif
