#include <hlmodule.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const unsigned char *p, *end; const char *error; } patch_reader;

static bool take( patch_reader *r, int count, const unsigned char **out ) {
	if( count < 0 || r->end - r->p < count ) { r->error = "Truncated HLP data"; return false; }
	*out = r->p; r->p += count; return true;
}

static bool read_byte( patch_reader *r, int *out ) {
	const unsigned char *p; if( !take(r,1,&p) ) return false; *out = *p; return true;
}

static bool read_index( patch_reader *r, int *out ) {
	int first, value; const unsigned char *p;
	if( !read_byte(r,&first) ) return false;
	if( !(first & 0x80) ) { *out = first; return true; }
	if( !(first & 0x40) ) {
		if( !take(r,1,&p) ) return false;
		value = p[0] | ((first & 31) << 8);
	} else {
		if( !take(r,3,&p) ) return false;
		value = ((first & 31) << 24) | (p[0] << 16) | (p[1] << 8) | p[2];
	}
	*out = (first & 0x20) ? -value : value; return true;
}

static bool read_count( patch_reader *r, int *out ) {
	if( !read_index(r,out) ) return false;
	if( *out < 0 || *out > 0x1000000 ) { r->error = "Invalid HLP count"; return false; }
	return true;
}

static int opcode_operands( int opcode ) {
	switch( opcode ) {
	case OInt: case OBool: case OCall0: case OJTrue: return 2;
	case OAdd: case OSub: case OCall1: case OJSLt: case OJSLte: case OJEq: return 3;
	case OCall2: return 4;
	case OJAlways: case ORet: return 1;
	default: return -1;
	}
}

void hl_patch_free( hl_patch *patch ) {
	int i, j;
	if( patch == NULL ) return;
	for(i=0;i<patch->string_count;i++) free(patch->strings[i]);
	for(i=0;i<patch->function_count;i++) {
		hl_patch_function *f = patch->functions + i;
		for(j=0;j<f->instruction_count;j++) free(f->instructions[j].operands);
		free(f->instructions); free(f->registers);
	}
	free(patch->functions); free(patch->strings); free(patch->floats); free(patch->ints); free(patch);
}

hl_patch *hl_patch_read( const unsigned char *data, int size, const char **error_msg ) {
	patch_reader r = { data, data + (size < 0 ? 0 : size), NULL };
	hl_patch *patch = (hl_patch*)calloc(1,sizeof(hl_patch));
	const unsigned char *p; int version, i, j, count, tag;
#define FAIL(msg) do { r.error = msg; goto fail; } while(0)
	if( patch == NULL ) FAIL("Out of memory reading HLP");
	if( !take(&r,3,&p) ) goto fail;
	if( memcmp(p,"HLP",3) != 0 ) FAIL("Invalid HLP magic");
	if( !read_byte(&r,&version) ) goto fail;
	if( version != 1 ) FAIL("Unsupported HLP version");
	if( !read_count(&r,&patch->base_revision) || !read_count(&r,&patch->revision) ) goto fail;
	if( patch->revision <= patch->base_revision ) FAIL("Invalid patch revision range");
	if( !read_count(&r,&patch->int_count) ) goto fail;
	patch->ints = (int*)calloc(patch->int_count,sizeof(int));
	for(i=0;i<patch->int_count;i++) { if( !take(&r,4,&p) ) goto fail; patch->ints[i]=(int)(p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned int)p[3]<<24)); }
	if( !read_count(&r,&patch->float_count) ) goto fail;
	patch->floats = (double*)calloc(patch->float_count,sizeof(double));
	for(i=0;i<patch->float_count;i++) { if( !take(&r,8,&p) ) goto fail; memcpy(patch->floats+i,p,8); }
	if( !read_count(&r,&patch->string_count) ) goto fail;
	patch->strings = (char**)calloc(patch->string_count,sizeof(char*));
	for(i=0;i<patch->string_count;i++) { if( !read_count(&r,&count) || !take(&r,count,&p) ) goto fail; patch->strings[i]=(char*)malloc(count+1); if(!patch->strings[i])FAIL("Out of memory reading HLP");memcpy(patch->strings[i],p,count);patch->strings[i][count]=0; }
	if( !read_count(&r,&patch->type_count) ) goto fail;
	for(i=0;i<patch->type_count;i++) { if(!read_byte(&r,&tag))goto fail;if(tag==HFUN){if(!read_byte(&r,&count))goto fail;for(j=0;j<count+1;j++)if(!read_index(&r,&version))goto fail;}else if(tag<0||tag>HGUID)FAIL("Unsupported HLP type"); }
	if( !read_count(&r,&patch->function_count) ) goto fail;
	patch->functions=(hl_patch_function*)calloc(patch->function_count,sizeof(hl_patch_function));
	for(i=0;i<patch->function_count;i++) { hl_patch_function *f=patch->functions+i; int length; const unsigned char *end;
		if( !read_count(&r,&length) || r.end-r.p<length ) goto fail;
		end=r.p+length;
		if(!read_index(&r,&f->type)||!read_count(&r,&f->findex)||!read_count(&r,&f->register_count)||!read_count(&r,&f->instruction_count))goto fail;
		f->registers=(int*)calloc(f->register_count,sizeof(int));for(j=0;j<f->register_count;j++)if(!read_index(&r,f->registers+j))goto fail;
		f->instructions=(hl_patch_instruction*)calloc(f->instruction_count,sizeof(hl_patch_instruction));for(j=0;j<f->instruction_count;j++){hl_patch_instruction *op=f->instructions+j;if(!read_byte(&r,&op->opcode))goto fail;op->operand_count=opcode_operands(op->opcode);if(op->operand_count<0)FAIL("Unsupported patch opcode");op->operands=(int*)calloc(op->operand_count,sizeof(int));for(int k=0;k<op->operand_count;k++)if(!read_index(&r,op->operands+k))goto fail;}
		if(r.p!=end)FAIL("Invalid patch function length");
	}
	if(r.p!=r.end)FAIL("Trailing HLP data");
	if( error_msg ) *error_msg=NULL;
	return patch;
fail:
	if( error_msg ) *error_msg=r.error?r.error:"Truncated HLP data";
	hl_patch_free(patch);
	return NULL;
#undef FAIL
}
