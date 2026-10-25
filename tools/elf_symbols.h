#ifndef ELF_SYMBOLS_H
#define ELF_SYMBOLS_H

#include <stdint.h>

/* The function holding `offset` (an address minus the image base dladdr reported) in the ELF image at `path`, from its
   symbol tables, with the address's offset into it; NULL when the image cannot be read or has no such function. Images
   are read once and kept until elf_symbols_free. */
const char *elf_function_name( const char *path, uint64_t offset, uint64_t *function_offset );
void elf_symbols_free( void );

/* A C++ name demangled with the C++ runtime's __cxa_demangle when it is loadable, as a new string the caller frees;
   NULL when `name` is not mangled or no demangler is available. */
char *demangle_cpp( const char *name );

#endif
