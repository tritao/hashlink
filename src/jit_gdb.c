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

static pthread_mutex_t jit_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t align8( size_t value ) { return (value + 7) & ~(size_t)7; }

static int function_name( hl_function *f, char *out, int size ) {
	hl_type_obj *obj = fun_obj(f);
	const uchar *field = fun_field_name(f);
	if( obj && field ) return snprintf(out,size,"%s.%s",hl_to_utf8(obj->name),hl_to_utf8(field));
	return snprintf(out,size,"fun$%d",f->findex);
}

void hl_gdb_jit_register( hl_module *m ) {
	static const char shnames[] = "\0.text\0.symtab\0.strtab\0.shstrtab\0";
	size_t text_off, sym_off, str_off, shstr_off, shdr_off, total, string_size = 1;
	int i, j, count = 0;
	char name[512];
	hl_gdb_entry *entry;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *sections;
	Elf64_Sym *symbols;
	char *strings;
	if( !m || !m->jit_code || !m->jit_debug || m->gdb_jit_entry ) return;
	for(i=0;i<m->code->nfunctions;i++) if( m->jit_debug[i].offsets ) {
		int length = function_name(m->code->functions+i,name,sizeof(name));
		if( length < 0 ) return;
		if( length >= (int)sizeof(name) ) length = sizeof(name) - 1;
		string_size += length + 1;
		count++;
	}
	text_off = sizeof(Elf64_Ehdr);
	sym_off = align8(text_off + m->codesize);
	str_off = align8(sym_off + sizeof(Elf64_Sym) * (count + 1));
	shstr_off = str_off + string_size;
	shdr_off = align8(shstr_off + sizeof(shnames));
	total = shdr_off + sizeof(Elf64_Shdr) * 5;
	entry = (hl_gdb_entry*)calloc(1,sizeof(*entry) + total);
	if( !entry ) return;
	ehdr = (Elf64_Ehdr*)entry->data;
	symbols = (Elf64_Sym*)(entry->data + sym_off);
	strings = (char*)(entry->data + str_off);
	sections = (Elf64_Shdr*)(entry->data + shdr_off);
	memcpy(entry->data+text_off,m->jit_code,m->codesize);
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
	ehdr->e_shnum = 5;
	ehdr->e_shstrndx = 4;
	sections[1] = (Elf64_Shdr){ .sh_name=1, .sh_type=SHT_PROGBITS, .sh_flags=SHF_ALLOC|SHF_EXECINSTR,
		.sh_addr=(Elf64_Addr)(uintptr_t)m->jit_code, .sh_offset=text_off, .sh_size=m->codesize, .sh_addralign=16 };
	sections[2] = (Elf64_Shdr){ .sh_name=7, .sh_type=SHT_SYMTAB, .sh_offset=sym_off,
		.sh_size=sizeof(Elf64_Sym)*(count+1), .sh_link=3, .sh_info=1, .sh_addralign=8, .sh_entsize=sizeof(Elf64_Sym) };
	sections[3] = (Elf64_Shdr){ .sh_name=15, .sh_type=SHT_STRTAB, .sh_offset=str_off, .sh_size=string_size, .sh_addralign=1 };
	sections[4] = (Elf64_Shdr){ .sh_name=23, .sh_type=SHT_STRTAB, .sh_offset=shstr_off, .sh_size=sizeof(shnames), .sh_addralign=1 };
	memcpy(entry->data+shstr_off,shnames,sizeof(shnames));
	string_size = 1;
	count = 1;
	for(i=0;i<m->code->nfunctions;i++) if( m->jit_debug[i].offsets ) {
		int length = function_name(m->code->functions+i,name,sizeof(name));
		int end = m->codesize;
		if( length >= (int)sizeof(name) ) length = sizeof(name) - 1;
		for(j=i+1;j<m->code->nfunctions;j++) if( m->jit_debug[j].start > m->jit_debug[i].start ) { end=m->jit_debug[j].start; break; }
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
void hl_gdb_jit_unregister( hl_module *m ) { (void)m; }
#endif
