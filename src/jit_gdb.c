#include "jit_gdb.h"

#if defined(HL_LINUX) && defined(HL_64) && (defined(__x86_64__) || defined(__aarch64__))
#include <elf.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct jit_code_entry {
	struct jit_code_entry *next_entry, *prev_entry;
	const char *symfile_addr;
	uint64_t symfile_size;
} jit_code_entry;

typedef struct {
	uint32_t version, action_flag;
	jit_code_entry *relevant_entry, *first_entry;
} jit_descriptor;

HL_EXPORT jit_descriptor __jit_debug_descriptor = { 1, 0, NULL, NULL };
HL_EXPORT __attribute__((noinline)) void __jit_debug_register_code() { __asm__ volatile ("" ::: "memory"); }

typedef struct {
	jit_code_entry entry;
	unsigned char data[];
} hl_gdb_entry;

typedef struct {
	unsigned char *data;
	size_t size, capacity;
} byte_buffer;

static pthread_mutex_t jit_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t align8( size_t value ) { return (value + 7) & ~(size_t)7; }

static bool buffer_reserve( byte_buffer *buffer, size_t size ) {
	size_t capacity;
	unsigned char *data;
	if( buffer->size + size <= buffer->capacity ) return true;
	capacity = buffer->capacity ? buffer->capacity : 256;
	while( capacity < buffer->size + size ) capacity *= 2;
	data = (unsigned char*)realloc(buffer->data,capacity);
	if( !data ) return false;
	buffer->data = data;
	buffer->capacity = capacity;
	return true;
}

static bool buffer_bytes( byte_buffer *buffer, const void *data, size_t size ) {
	if( !buffer_reserve(buffer,size) ) return false;
	memcpy(buffer->data+buffer->size,data,size);
	buffer->size += size;
	return true;
}

static bool buffer_u8( byte_buffer *buffer, unsigned char value ) { return buffer_bytes(buffer,&value,1); }
static bool buffer_u16( byte_buffer *buffer, uint16_t value ) { return buffer_bytes(buffer,&value,sizeof(value)); }
static bool buffer_u32( byte_buffer *buffer, uint32_t value ) { return buffer_bytes(buffer,&value,sizeof(value)); }
static bool buffer_u64( byte_buffer *buffer, uint64_t value ) { return buffer_bytes(buffer,&value,sizeof(value)); }

static bool buffer_uleb( byte_buffer *buffer, uint64_t value ) {
	do {
		unsigned char byte = value & 0x7F;
		value >>= 7;
		if( value ) byte |= 0x80;
		if( !buffer_u8(buffer,byte) ) return false;
	} while( value );
	return true;
}

static bool buffer_sleb( byte_buffer *buffer, int64_t value ) {
	bool more;
	do {
		unsigned char byte = value & 0x7F;
		bool sign = (byte & 0x40) != 0;
		value >>= 7;
		more = !((value == 0 && !sign) || (value == -1 && sign));
		if( more ) byte |= 0x80;
		if( !buffer_u8(buffer,byte) ) return false;
	} while( more );
	return true;
}

static unsigned int function_offset( hl_debug_infos *debug, int opcode ) {
	return debug->large ? (unsigned int)((int*)debug->offsets)[opcode] : (unsigned int)((unsigned short*)debug->offsets)[opcode];
}

static bool build_debug_line( hl_module *m, byte_buffer *buffer ) {
	static const unsigned char opcode_lengths[] = { 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1 };
	size_t unit_length_at, header_length_at, header_start;
	uint32_t length;
	int i, j;
	if( m->code->ndebugfiles <= 0 ) return true;
	unit_length_at = buffer->size;
	if( !buffer_u32(buffer,0) || !buffer_u16(buffer,4) ) return false;
	header_length_at = buffer->size;
	if( !buffer_u32(buffer,0) ) return false;
	header_start = buffer->size;
	if( !buffer_u8(buffer,1) || !buffer_u8(buffer,1) || !buffer_u8(buffer,1) ||
		!buffer_u8(buffer,(unsigned char)-5) || !buffer_u8(buffer,14) || !buffer_u8(buffer,13) ||
		!buffer_bytes(buffer,opcode_lengths,sizeof(opcode_lengths)) || !buffer_u8(buffer,0) ) return false;
	for(i=0;i<m->code->ndebugfiles;i++) {
		if( !buffer_bytes(buffer,m->code->debugfiles[i],m->code->debugfiles_lens[i]) || !buffer_u8(buffer,0) ||
			!buffer_uleb(buffer,0) || !buffer_uleb(buffer,0) || !buffer_uleb(buffer,0) ) return false;
	}
	if( !buffer_u8(buffer,0) ) return false;
	length = (uint32_t)(buffer->size - header_start);
	memcpy(buffer->data+header_length_at,&length,sizeof(length));
	for(i=0;i<m->code->nfunctions;i++) {
		hl_function *function = m->code->functions+i;
		hl_debug_infos *debug = m->jit_debug+i;
		uint64_t previous_address = 0;
		int current_file = 0, current_line = 1;
		bool emitted = false;
		if( !debug->offsets || !function->debug ) continue;
		for(j=0;j<function->nops;j++) {
			int file = function->debug[j*2] & 0x7FFFFFFF;
			int line = function->debug[j*2+1];
			unsigned int start = function_offset(debug,j), end = function_offset(debug,j+1);
			uint64_t address;
			if( file < 0 || file >= m->code->ndebugfiles || line <= 0 || start >= end ) continue;
			address = (uint64_t)(uintptr_t)m->jit_code + debug->start + start;
			if( !emitted ) {
				if( !buffer_u8(buffer,0) || !buffer_uleb(buffer,9) || !buffer_u8(buffer,2) || !buffer_u64(buffer,address) ) return false;
				emitted = true;
			} else if( !buffer_u8(buffer,2) || !buffer_uleb(buffer,address-previous_address) ) return false;
			if( current_file != file + 1 ) {
				if( !buffer_u8(buffer,4) || !buffer_uleb(buffer,file+1) ) return false;
				current_file = file + 1;
			}
			if( current_line != line ) {
				if( !buffer_u8(buffer,3) || !buffer_sleb(buffer,line-current_line) ) return false;
				current_line = line;
			}
			if( !buffer_u8(buffer,1) ) return false;
			previous_address = address;
		}
		if( emitted ) {
			uint64_t end_address = (uint64_t)(uintptr_t)m->jit_code + debug->start + function_offset(debug,function->nops);
			if( end_address > previous_address && (!buffer_u8(buffer,2) || !buffer_uleb(buffer,end_address-previous_address)) ) return false;
			if( !buffer_u8(buffer,0) || !buffer_uleb(buffer,1) || !buffer_u8(buffer,1) ) return false;
		}
	}
	length = (uint32_t)(buffer->size - unit_length_at - 4);
	memcpy(buffer->data+unit_length_at,&length,sizeof(length));
	return true;
}

static bool build_debug_frame( hl_module *m, byte_buffer *buffer ) {
#if defined(__x86_64__)
	size_t start;
	uint32_t length;
	int i, j;
	start = buffer->size;
	if( !buffer_u32(buffer,0) || !buffer_u32(buffer,UINT32_MAX) ||
		!buffer_u8(buffer,4) || !buffer_u8(buffer,0) || !buffer_u8(buffer,8) || !buffer_u8(buffer,0) ||
		!buffer_uleb(buffer,1) || !buffer_sleb(buffer,-8) || !buffer_uleb(buffer,16) ||
		!buffer_u8(buffer,0x0C) || !buffer_uleb(buffer,7) || !buffer_uleb(buffer,8) ||
		!buffer_u8(buffer,0x90) || !buffer_uleb(buffer,1) ) return false;
	while( buffer->size & 7 ) if( !buffer_u8(buffer,0) ) return false;
	length = (uint32_t)(buffer->size-start-4);
	memcpy(buffer->data+start,&length,sizeof(length));
	for(i=0;i<m->code->nfunctions;i++) {
		hl_debug_infos *debug = m->jit_debug+i;
		int end = m->codesize;
		unsigned char *code;
		if( !debug->offsets ) continue;
		code = (unsigned char*)m->jit_code + debug->start;
		if( debug->start < 0 || debug->start + 4 > m->codesize ||
			code[0] != 0x55 || code[1] != 0x48 || code[2] != 0x89 || code[3] != 0xE5 ) continue;
		for(j=0;j<m->code->nfunctions;j++)
			if( m->jit_debug[j].offsets && m->jit_debug[j].start > debug->start && m->jit_debug[j].start < end ) end = m->jit_debug[j].start;
		start = buffer->size;
		if( !buffer_u32(buffer,0) || !buffer_u32(buffer,0) ||
			!buffer_u64(buffer,(uint64_t)(uintptr_t)code) || !buffer_u64(buffer,(uint64_t)(end-debug->start)) ||
			!buffer_u8(buffer,0x41) || !buffer_u8(buffer,0x0E) || !buffer_uleb(buffer,16) ||
			!buffer_u8(buffer,0x86) || !buffer_uleb(buffer,2) ||
			!buffer_u8(buffer,0x43) || !buffer_u8(buffer,0x0D) || !buffer_uleb(buffer,6) ) return false;
		while( buffer->size & 7 ) if( !buffer_u8(buffer,0) ) return false;
		length = (uint32_t)(buffer->size-start-4);
		memcpy(buffer->data+start,&length,sizeof(length));
	}
#else
	(void)m;
#endif
	return true;
}

static int function_name( hl_code *code, hl_function *f, char *out, int size ) {
	const char *qualified = hl_code_function_name(code,f);
	hl_type_obj *obj = fun_obj(f);
	const uchar *field = fun_field_name(f);
	if( qualified ) return snprintf(out,size,"%s",qualified);
	if( obj && field ) return snprintf(out,size,"%s.%s",hl_to_utf8(obj->name),hl_to_utf8(field));
	return snprintf(out,size,"fun$%d",f->findex);
}

void hl_gdb_jit_register( hl_module *m ) {
	static const char shnames[] = "\0.text\0.symtab\0.strtab\0.shstrtab\0.debug_line\0.debug_info\0.debug_abbrev\0.debug_frame\0";
	static const unsigned char debug_abbrev[] = {
		1, 0x11, 0,       /* DW_TAG_compile_unit, no children */
		0x11, 0x01,       /* DW_AT_low_pc, DW_FORM_addr */
		0x12, 0x01,       /* DW_AT_high_pc, DW_FORM_addr */
		0x10, 0x17,       /* DW_AT_stmt_list, DW_FORM_sec_offset */
		0x03, 0x08,       /* DW_AT_name, DW_FORM_string */
		0x13, 0x05,       /* DW_AT_language, DW_FORM_data2 */
		0, 0, 0
	};
	unsigned char debug_info[] = {
		43, 0, 0, 0,     /* unit length */
		4, 0,             /* DWARF version */
		0, 0, 0, 0,      /* abbreviation offset */
		8,                /* address size */
		1,                /* abbreviation code */
		0, 0, 0, 0, 0, 0, 0, 0, /* low PC */
		0, 0, 0, 0, 0, 0, 0, 0, /* high PC */
		0, 0, 0, 0,      /* line table offset */
		'H','a','s','h','L','i','n','k',' ','J','I','T',0,
		2, 0              /* DW_LANG_C */
	};
	size_t sym_off, str_off, shstr_off, line_off, info_off, abbrev_off, frame_off, shdr_off, total, string_size = 1;
	int frame_section;
	int i, j, count = 0;
	char name[512];
	byte_buffer lines = {0}, frames = {0};
	hl_gdb_entry *entry;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *sections;
	Elf64_Sym *symbols;
	char *strings;
	if( !m || !m->jit_code || !m->jit_debug || m->gdb_jit_entry ) return;
	for(i=0;i<m->code->nfunctions;i++) if( m->jit_debug[i].offsets ) {
		int length = function_name(m->code,m->code->functions+i,name,sizeof(name));
		if( length < 0 ) return;
		if( length >= (int)sizeof(name) ) length = sizeof(name) - 1;
		string_size += length + 1;
		count++;
	}
	if( !build_debug_line(m,&lines) || !build_debug_frame(m,&frames) ) {
		free(lines.data);
		free(frames.data);
		return;
	}
	{
		uint64_t low_pc = (uint64_t)(uintptr_t)m->jit_code;
		uint64_t high_pc = low_pc + m->codesize;
		memcpy(debug_info+12,&low_pc,sizeof(low_pc));
		memcpy(debug_info+20,&high_pc,sizeof(high_pc));
	}
	sym_off = align8(sizeof(Elf64_Ehdr));
	str_off = align8(sym_off + sizeof(Elf64_Sym) * (count + 1));
	shstr_off = str_off + string_size;
	line_off = shstr_off + sizeof(shnames);
	if( lines.size ) {
		info_off = line_off + lines.size;
		abbrev_off = info_off + sizeof(debug_info);
		frame_off = abbrev_off + sizeof(debug_abbrev);
		frame_section = 8;
	} else {
		info_off = abbrev_off = line_off;
		frame_off = line_off;
		frame_section = 5;
	}
	shdr_off = align8(frame_off + frames.size);
	total = shdr_off + sizeof(Elf64_Shdr) * (frame_section + (frames.size ? 1 : 0));
	entry = (hl_gdb_entry*)calloc(1,sizeof(*entry) + total);
	if( !entry ) {
		free(lines.data);
		free(frames.data);
		return;
	}
	ehdr = (Elf64_Ehdr*)entry->data;
	symbols = (Elf64_Sym*)(entry->data + sym_off);
	strings = (char*)(entry->data + str_off);
	sections = (Elf64_Shdr*)(entry->data + shdr_off);
	memcpy(ehdr->e_ident,ELFMAG,SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_type = ET_EXEC;
#if defined(__aarch64__)
	ehdr->e_machine = EM_AARCH64;
#else
	ehdr->e_machine = EM_X86_64;
#endif
	ehdr->e_version = EV_CURRENT;
	ehdr->e_ehsize = sizeof(*ehdr);
	ehdr->e_shoff = shdr_off;
	ehdr->e_shentsize = sizeof(*sections);
	ehdr->e_shnum = frame_section + (frames.size ? 1 : 0);
	ehdr->e_shstrndx = 4;
	sections[1] = (Elf64_Shdr){ .sh_name=1, .sh_type=SHT_NOBITS, .sh_flags=SHF_ALLOC|SHF_EXECINSTR,
		.sh_addr=(Elf64_Addr)(uintptr_t)m->jit_code, .sh_size=m->codesize, .sh_addralign=16 };
	sections[2] = (Elf64_Shdr){ .sh_name=7, .sh_type=SHT_SYMTAB, .sh_offset=sym_off,
		.sh_size=sizeof(Elf64_Sym)*(count+1), .sh_link=3, .sh_info=1, .sh_addralign=8, .sh_entsize=sizeof(Elf64_Sym) };
	sections[3] = (Elf64_Shdr){ .sh_name=15, .sh_type=SHT_STRTAB, .sh_offset=str_off, .sh_size=string_size, .sh_addralign=1 };
	sections[4] = (Elf64_Shdr){ .sh_name=23, .sh_type=SHT_STRTAB, .sh_offset=shstr_off, .sh_size=sizeof(shnames), .sh_addralign=1 };
	memcpy(entry->data+shstr_off,shnames,sizeof(shnames));
	if( lines.size ) {
		sections[5] = (Elf64_Shdr){ .sh_name=33, .sh_type=SHT_PROGBITS, .sh_offset=line_off, .sh_size=lines.size, .sh_addralign=1 };
		sections[6] = (Elf64_Shdr){ .sh_name=45, .sh_type=SHT_PROGBITS, .sh_offset=info_off, .sh_size=sizeof(debug_info), .sh_addralign=1 };
		sections[7] = (Elf64_Shdr){ .sh_name=57, .sh_type=SHT_PROGBITS, .sh_offset=abbrev_off, .sh_size=sizeof(debug_abbrev), .sh_addralign=1 };
		memcpy(entry->data+line_off,lines.data,lines.size);
		memcpy(entry->data+info_off,debug_info,sizeof(debug_info));
		memcpy(entry->data+abbrev_off,debug_abbrev,sizeof(debug_abbrev));
	}
	if( frames.size ) {
		sections[frame_section] = (Elf64_Shdr){ .sh_name=71, .sh_type=SHT_PROGBITS, .sh_offset=frame_off, .sh_size=frames.size, .sh_addralign=8 };
		memcpy(entry->data+frame_off,frames.data,frames.size);
	}
	free(lines.data);
	free(frames.data);
	string_size = 1;
	count = 1;
	for(i=0;i<m->code->nfunctions;i++) if( m->jit_debug[i].offsets ) {
		int length = function_name(m->code,m->code->functions+i,name,sizeof(name));
		int end = m->codesize;
		if( length >= (int)sizeof(name) ) length = sizeof(name) - 1;
		for(j=0;j<m->code->nfunctions;j++)
			if( m->jit_debug[j].offsets && m->jit_debug[j].start > m->jit_debug[i].start && m->jit_debug[j].start < end ) end=m->jit_debug[j].start;
		memcpy(strings+string_size,name,length+1);
		symbols[count].st_name = string_size;
		symbols[count].st_info = ELF64_ST_INFO(STB_GLOBAL,STT_FUNC);
		symbols[count].st_shndx = 1;
		symbols[count].st_value = (Elf64_Addr)(uintptr_t)m->jit_code + m->jit_debug[i].start;
		symbols[count].st_size = end - m->jit_debug[i].start;
		string_size += length + 1;
		count++;
	}
	entry->entry.symfile_addr = (const char*)entry->data;
	entry->entry.symfile_size = total;
	pthread_mutex_lock(&jit_lock);
	entry->entry.next_entry = __jit_debug_descriptor.first_entry;
	if( entry->entry.next_entry ) entry->entry.next_entry->prev_entry = &entry->entry;
	__jit_debug_descriptor.first_entry = &entry->entry;
	__jit_debug_descriptor.relevant_entry = &entry->entry;
	__jit_debug_descriptor.action_flag = 1;
	m->gdb_jit_entry = entry;
	__jit_debug_register_code();
	pthread_mutex_unlock(&jit_lock);
}

__attribute__((noinline)) void hl_gdb_jit_register_patch( hl_module *m ) {
	hl_gdb_jit_register(m);
	__asm__ volatile ("" ::: "memory");
}

void hl_gdb_jit_unregister( hl_module *m ) {
	hl_gdb_entry *entry;
	if( !m || !m->gdb_jit_entry ) return;
	entry = (hl_gdb_entry*)m->gdb_jit_entry;
	pthread_mutex_lock(&jit_lock);
	if( entry->entry.prev_entry ) entry->entry.prev_entry->next_entry = entry->entry.next_entry;
	else __jit_debug_descriptor.first_entry = entry->entry.next_entry;
	if( entry->entry.next_entry ) entry->entry.next_entry->prev_entry = entry->entry.prev_entry;
	__jit_debug_descriptor.relevant_entry = &entry->entry;
	__jit_debug_descriptor.action_flag = 2;
	__jit_debug_register_code();
	m->gdb_jit_entry = NULL;
	pthread_mutex_unlock(&jit_lock);
	free(entry);
}
#else
void hl_gdb_jit_register( hl_module *m ) { (void)m; }
void hl_gdb_jit_register_patch( hl_module *m ) { (void)m; }
void hl_gdb_jit_unregister( hl_module *m ) { (void)m; }
#endif
