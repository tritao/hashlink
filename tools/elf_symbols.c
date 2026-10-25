/*
 * Function names from an ELF image's symbol tables, for native frames the runtime could not name.
 *
 * The runtime names a sampled native frame with dladdr, which sees only exported functions; any other frame is recorded
 * by its image and offset. The images we build keep their full symbol table (.symtab) unless stripped, so the exporter
 * names those frames from it. Only 64-bit little-endian images are read, which covers Linux x86-64 and arm64.
 */
#include "elf_symbols.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <dlfcn.h>
#endif

typedef struct { uint64_t start, size; char *name; } elf_function;
typedef struct { char *path; uint64_t first_vaddr; elf_function *functions; size_t count; } elf_image;

static elf_image *images;
static size_t image_count;

static uint16_t rd16( const unsigned char *p ) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32( const unsigned char *p ) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t rd64( const unsigned char *p ) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }

static int by_start( const void *a, const void *b ) {
	const elf_function *x = a, *y = b;
	return x->start < y->start ? -1 : x->start > y->start;
}

static unsigned char *read_file( const char *path, size_t *size ) {
	FILE *f = fopen(path, "rb");
	unsigned char *data = NULL;
	long length;
	if( !f ) return NULL;
	if( fseek(f, 0, SEEK_END) == 0 && (length = ftell(f)) > 0 && fseek(f, 0, SEEK_SET) == 0 && (data = malloc((size_t)length)) != NULL
		&& fread(data, 1, (size_t)length, f) != (size_t)length ) {
		free(data);
		data = NULL;
	}
	fclose(f);
	*size = data ? (size_t)length : 0;
	return data;
}

/* The path of the detached debug file for an image's GNU build ID (/usr/lib/debug/.build-id/ab/cdef....debug), as
   distributions install them for their stripped libraries, or 0 when the image has no build ID. */
static int debug_file_for( const unsigned char *data, size_t size, char *out, size_t capacity ) {
	uint64_t phoff = rd64(data + 32);
	uint16_t phentsize = rd16(data + 54), phnum = rd16(data + 56);
	for( uint16_t i = 0; i < phnum; i++ ) {
		if( phoff + (size_t)(i + 1) * phentsize > size ) break;
		const unsigned char *ph = data + phoff + (size_t)i * phentsize;
		if( rd32(ph) != 4 ) continue; // PT_NOTE
		uint64_t offset = rd64(ph + 8), length = rd64(ph + 32);
		if( offset + length > size ) continue;
		for( uint64_t at = 0; at + 12 <= length; ) {
			const unsigned char *note = data + offset + at;
			uint32_t name_size = rd32(note), descriptor_size = rd32(note + 4), type = rd32(note + 8);
			uint64_t name_padded = (name_size + 3) & ~3u, descriptor_padded = (descriptor_size + 3) & ~3u;
			if( at + 12 + name_padded + descriptor_padded > length ) break;
			if( type == 3 && name_size == 4 && memcmp(note + 12, "GNU", 4) == 0 && descriptor_size >= 2 ) { // NT_GNU_BUILD_ID
				const unsigned char *id = note + 12 + name_padded;
				size_t written = (size_t)snprintf(out, capacity, "/usr/lib/debug/.build-id/%02x/", id[0]);
				for( uint32_t b = 1; b < descriptor_size && written + 3 < capacity; b++ )
					written += (size_t)snprintf(out + written, capacity - written, "%02x", id[b]);
				snprintf(out + written, capacity - written, ".debug");
				return 1;
			}
			at += 12 + name_padded + descriptor_padded;
		}
	}
	return 0;
}

static int has_symtab( const unsigned char *data, size_t size ) {
	uint64_t shoff = rd64(data + 40);
	uint16_t shentsize = rd16(data + 58), shnum = rd16(data + 60);
	if( shoff == 0 || shoff + (size_t)shnum * shentsize > size ) return 0;
	for( uint16_t i = 0; i < shnum; i++ )
		if( rd32(data + shoff + (size_t)i * shentsize + 4) == 2 ) return 1; // SHT_SYMTAB
	return 0;
}

/* Reads the function symbols of .symtab and .dynsym; a stripped image's come from its detached debug file when one is
   installed. An image that cannot be read is kept with no functions. */
static void load_image( elf_image *image ) {
	size_t size, capacity = 0;
	unsigned char *data = read_file(image->path, &size);
	if( !data ) return;
	if( size < 64 || memcmp(data, "\177ELF", 4) != 0 || data[4] != 2 || data[5] != 1 ) { free(data); return; }
	uint64_t phoff = rd64(data + 32);
	uint16_t phentsize = rd16(data + 54), phnum = rd16(data + 56), shentsize = rd16(data + 58), shnum = rd16(data + 60);
	// dladdr reports where the image's first loaded page sits, so an offset from it is a virtual address once the first
	// segment's page-aligned address is added back (0 for shared libraries, the link address for other executables).
	int found_load = 0;
	for( uint16_t i = 0; i < phnum; i++ ) {
		const unsigned char *ph = data + phoff + (size_t)i * phentsize;
		if( phoff + (size_t)(i + 1) * phentsize > size ) break;
		if( rd32(ph) != 1 ) continue; // PT_LOAD
		uint64_t vaddr = rd64(ph + 16) & ~(uint64_t)0xFFF;
		if( !found_load || vaddr < image->first_vaddr ) image->first_vaddr = vaddr;
		found_load = 1;
	}
	// Addresses come from the loaded image; symbols from its debug file when it carries none of its own.
	char debug_path[512];
	if( !has_symtab(data, size) && debug_file_for(data, size, debug_path, sizeof(debug_path)) ) {
		size_t debug_size;
		unsigned char *debug = read_file(debug_path, &debug_size);
		if( debug && debug_size >= 64 && memcmp(debug, "\177ELF", 4) == 0 && debug[4] == 2 && debug[5] == 1 ) {
			free(data);
			data = debug;
			size = debug_size;
		} else
			free(debug);
	}
	uint64_t shoff = rd64(data + 40);
	shentsize = rd16(data + 58);
	shnum = rd16(data + 60);
	if( shoff == 0 || shoff + (size_t)shnum * shentsize > size ) { free(data); return; }
	for( uint16_t i = 0; i < shnum; i++ ) {
		const unsigned char *sh = data + shoff + (size_t)i * shentsize;
		uint32_t type = rd32(sh + 4);
		if( type != 2 && type != 11 ) continue; // SHT_SYMTAB, SHT_DYNSYM
		uint64_t offset = rd64(sh + 24), section_size = rd64(sh + 32), entsize = rd64(sh + 56);
		uint32_t link = rd32(sh + 40);
		if( entsize < 24 || link >= shnum || offset + section_size > size ) continue;
		const unsigned char *strtab_header = data + shoff + (size_t)link * shentsize;
		uint64_t strtab = rd64(strtab_header + 24), strtab_size = rd64(strtab_header + 32);
		if( strtab + strtab_size > size ) continue;
		for( uint64_t at = 0; at + entsize <= section_size; at += entsize ) {
			const unsigned char *sym = data + offset + at;
			uint32_t name = rd32(sym);
			unsigned char kind = sym[4] & 0xF;
			uint16_t section = rd16(sym + 6);
			uint64_t value = rd64(sym + 8), symbol_size = rd64(sym + 16);
			if( (kind != 2 && kind != 10) || section == 0 || value == 0 || symbol_size == 0 || name >= strtab_size ) continue; // STT_FUNC, STT_GNU_IFUNC
			const char *text = (const char*)data + strtab + name;
			size_t length = strnlen(text, (size_t)(strtab_size - name));
			if( length == 0 || length == strtab_size - name ) continue;
			if( image->count == capacity ) {
				size_t next = capacity ? capacity * 2 : 256;
				elf_function *grown = realloc(image->functions, next * sizeof(elf_function));
				if( !grown ) break;
				image->functions = grown;
				capacity = next;
			}
			elf_function *f = image->functions + image->count;
			if( (f->name = malloc(length + 1)) == NULL ) break;
			memcpy(f->name, text, length);
			f->name[length] = 0;
			f->start = value;
			f->size = symbol_size;
			image->count++;
		}
	}
	free(data);
	qsort(image->functions, image->count, sizeof(elf_function), by_start);
}

static elf_image *image_for( const char *path ) {
	for( size_t i = 0; i < image_count; i++ )
		if( strcmp(images[i].path, path) == 0 ) return images + i;
	elf_image *grown = realloc(images, (image_count + 1) * sizeof(elf_image));
	if( !grown ) return NULL;
	images = grown;
	elf_image *image = images + image_count;
	memset(image, 0, sizeof(*image));
	if( (image->path = malloc(strlen(path) + 1)) == NULL ) return NULL;
	strcpy(image->path, path);
	image_count++;
	load_image(image);
	return image;
}

const char *elf_function_name( const char *path, uint64_t offset, uint64_t *function_offset ) {
	elf_image *image = image_for(path);
	if( !image || image->count == 0 ) return NULL;
	uint64_t vaddr = offset + image->first_vaddr;
	size_t lo = 0, hi = image->count;
	while( lo < hi ) {
		size_t mid = (lo + hi) / 2;
		if( image->functions[mid].start <= vaddr ) lo = mid + 1; else hi = mid;
	}
	// Symbols may overlap (aliases); the closest start below the address that still contains it wins.
	for( size_t i = lo; i > 0; i-- ) {
		const elf_function *f = image->functions + i - 1;
		if( vaddr - f->start < f->size ) {
			*function_offset = vaddr - f->start;
			return f->name;
		}
		if( lo - i >= 8 ) break;
	}
	return NULL;
}

void elf_symbols_free( void ) {
	for( size_t i = 0; i < image_count; i++ ) {
		for( size_t j = 0; j < images[i].count; j++ ) free(images[i].functions[j].name);
		free(images[i].functions);
		free(images[i].path);
	}
	free(images);
	images = NULL;
	image_count = 0;
}

char *demangle_cpp( const char *name ) {
#ifdef _WIN32
	(void)name;
	return NULL; // DbgHelp names Windows frames already demangled.
#else
	typedef char *(*demangler)(const char *, char *, size_t *, int *);
	static demangler demangle;
	static int looked;
	if( !name || strncmp(name, "_Z", 2) != 0 ) return NULL;
	if( !looked ) {
		looked = 1;
		// Loaded on demand, so the exporter has no link-time dependency on a C++ runtime.
		const char *libraries[] = { "libstdc++.so.6", "libc++abi.so.1", "libc++abi.dylib", "libc++.1.dylib" };
		for( size_t i = 0; i < sizeof(libraries) / sizeof(libraries[0]) && !demangle; i++ ) {
			void *library = dlopen(libraries[i], RTLD_LAZY | RTLD_LOCAL);
			if( library ) demangle = (demangler)dlsym(library, "__cxa_demangle");
		}
		if( !demangle ) demangle = (demangler)dlsym(RTLD_DEFAULT, "__cxa_demangle");
	}
	if( !demangle ) return NULL;
	int status = 0;
	char *result = demangle(name, NULL, NULL, &status);
	if( status != 0 ) { free(result); return NULL; }
	return result;
#endif
}
