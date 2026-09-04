#include <hlmodule.h>
#include <jit.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const unsigned char *p, *end; const char *error; } patch_reader;

struct _hl_patch_code {
	void *code;
	int code_size;
	int references;
	int function_count;
	hl_function *functions;
};

static hl_function *find_live_function( hl_module *m, int findex ) {
	for(int i=0;i<m->code->nfunctions;i++) if(m->code->functions[i].findex==findex)return m->code->functions+i;
	return NULL;
}

static void patch_code_free( hl_patch_code *code ) {
	if(!code)return;
	for(int i=0;i<code->function_count;i++) {
		free(code->functions[i].regs);
		free(code->functions[i].ops);
	}
	if(code->code) hl_free_executable_memory(code->code,code->code_size);
	free(code->functions);
	free(code);
}

void hl_module_patch_release_all( hl_module *m ) {
	if(!m||!m->patch_owners)return;
	for(int i=0;i<m->code->nfunctions+m->code->nnatives;i++){hl_patch_code *owner=m->patch_owners[i];if(owner){m->patch_owners[i]=NULL;if(--owner->references==0)patch_code_free(owner);}}
}

int hl_module_patch_allocation_count( hl_module *m ) {
	int count=0;
	if(!m||!m->patch_owners)return 0;
	for(int i=0;i<m->code->nfunctions+m->code->nnatives;i++){hl_patch_code *owner=m->patch_owners[i];if(!owner)continue;bool seen=false;for(int j=0;j<i;j++)if(m->patch_owners[j]==owner){seen=true;break;}if(!seen)count++;}
	return count;
}

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
	if( version != 2 ) FAIL("Unsupported HLP version");
	if( !read_count(&r,&patch->base_revision) || !read_count(&r,&patch->revision) ) goto fail;
	if( patch->revision <= patch->base_revision ) FAIL("Invalid patch revision range");
	if( !read_count(&r,&patch->base_int_count) || !read_count(&r,&patch->int_count) ) goto fail;
	patch->ints = (int*)calloc(patch->int_count,sizeof(int));
	for(i=0;i<patch->int_count;i++) { if( !take(&r,4,&p) ) goto fail; patch->ints[i]=(int)(p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned int)p[3]<<24)); }
	if( !read_count(&r,&patch->base_float_count) || !read_count(&r,&patch->float_count) ) goto fail;
	patch->floats = (double*)calloc(patch->float_count,sizeof(double));
	for(i=0;i<patch->float_count;i++) { if( !take(&r,8,&p) ) goto fail; memcpy(patch->floats+i,p,8); }
	if( !read_count(&r,&patch->base_string_count) || !read_count(&r,&patch->string_count) ) goto fail;
	patch->strings = (char**)calloc(patch->string_count,sizeof(char*));
	for(i=0;i<patch->string_count;i++) { if( !read_count(&r,&count) || !take(&r,count,&p) ) goto fail; patch->strings[i]=(char*)malloc(count+1); if(!patch->strings[i])FAIL("Out of memory reading HLP");memcpy(patch->strings[i],p,count);patch->strings[i][count]=0; }
	if( !read_count(&r,&patch->base_type_count) || !read_count(&r,&patch->type_count) ) goto fail;
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

static bool valid_reg( hl_patch_function *f, int reg ) { return reg >= 0 && reg < f->register_count; }

static bool validate_function( hl_module *m, hl_patch *patch, hl_patch_function *f, const char **error ) {
	hl_function *live=find_live_function(m,f->findex);
	if(!live){*error="Unknown stable function slot";return false;}
	if(f->type<0||f->type>=m->code->ntypes||live->type!=m->code->types+f->type){*error="Patch function signature changed";return false;}
	for(int i=0;i<f->register_count;i++)if(f->registers[i]<0||f->registers[i]>=m->code->ntypes){*error="Invalid patch register type";return false;}
	for(int i=0;i<f->instruction_count;i++){
		hl_patch_instruction *op=f->instructions+i;int *p=op->operands;
		switch(op->opcode){
		case OInt:if(!valid_reg(f,p[0])||p[1]<0||p[1]>=patch->base_int_count+patch->int_count){*error="Invalid Int operands";return false;}break;
		case OBool:if(!valid_reg(f,p[0])||(p[1]!=0&&p[1]!=1)){*error="Invalid Bool operands";return false;}break;
		case OAdd:case OSub:if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||!valid_reg(f,p[2])){*error="Invalid arithmetic operands";return false;}break;
		case OCall0:case OCall1:case OCall2:
			if(!valid_reg(f,p[0])||p[1]<0||p[1]>=m->code->nfunctions+m->code->nnatives||m->functions_ptrs[p[1]]==NULL){*error="Invalid call target";return false;}
			for(int k=2;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OJTrue:if(!valid_reg(f,p[0])||i+1+p[1]<0||i+1+p[1]>=f->instruction_count){*error="Invalid conditional branch";return false;}break;
		case OJSLt:case OJSLte:case OJEq:if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||i+1+p[2]<0||i+1+p[2]>=f->instruction_count){*error="Invalid comparison branch";return false;}break;
		case OJAlways:if(i+1+p[0]<0||i+1+p[0]>=f->instruction_count){*error="Invalid branch";return false;}break;
		case ORet:if(!valid_reg(f,p[0])){*error="Invalid return register";return false;}break;
		default:*error="Unsupported patch opcode";return false;
		}
	}
	return true;
}

h_bool hl_module_apply_patch( hl_module *m, hl_patch *patch, const char **error_msg ) {
	const char *error=NULL;hl_patch_code *allocation=NULL;jit_ctx *jit=NULL;int *offsets=NULL,*combined_ints=NULL;hl_code code;hl_module temp;
	if(!m||!patch||!m->patchable){error="Module is not patchable";goto fail;}
	if(patch->function_count<=0){error="Patch contains no functions";goto fail;}
	if(m->revision!=patch->base_revision||patch->revision<=patch->base_revision){error="Stale patch revision";goto fail;}
	if(patch->base_int_count!=m->code->nints||patch->base_float_count!=m->code->nfloats||patch->base_string_count!=m->code->nstrings||patch->base_type_count!=m->code->ntypes){error="Patch symbol base does not match module";goto fail;}
	if(patch->float_count||patch->string_count||patch->type_count){error="This patch introduces unsupported symbols";goto fail;}
	for(int i=0;i<patch->function_count;i++){for(int j=0;j<i;j++)if(patch->functions[j].findex==patch->functions[i].findex){error="Duplicate stable function slot";goto fail;}if(!validate_function(m,patch,patch->functions+i,&error))goto fail;}
	allocation=(hl_patch_code*)calloc(1,sizeof(hl_patch_code));if(!allocation){error="Out of memory applying patch";goto fail;}
	allocation->function_count=patch->function_count;allocation->functions=(hl_function*)calloc(patch->function_count,sizeof(hl_function));
	offsets=(int*)calloc(patch->function_count,sizeof(int));if(!allocation->functions||!offsets){error="Out of memory applying patch";goto fail;}
	for(int i=0;i<patch->function_count;i++){hl_patch_function *src=patch->functions+i;hl_function *dst=allocation->functions+i;dst->type=m->code->types+src->type;dst->findex=src->findex;dst->nregs=src->register_count;dst->nops=src->instruction_count;dst->regs=(hl_type**)calloc(dst->nregs,sizeof(hl_type*));dst->ops=(hl_opcode*)calloc(dst->nops,sizeof(hl_opcode));if(!dst->regs||!dst->ops){error="Out of memory applying patch";goto fail;}for(int j=0;j<dst->nregs;j++)dst->regs[j]=m->code->types+src->registers[j];for(int j=0;j<dst->nops;j++){hl_patch_instruction *s=src->instructions+j;hl_opcode *d=dst->ops+j;d->op=(hl_op)s->opcode;if(s->operand_count>0)d->p1=s->operands[0];if(s->operand_count>1)d->p2=s->operands[1];if(s->operand_count>2)d->p3=s->operands[2];if(s->operand_count==4)d->extra=(int*)(int_val)s->operands[3];}}
	combined_ints=(int*)malloc(sizeof(int)*(patch->base_int_count+patch->int_count));if(!combined_ints){error="Out of memory applying patch";goto fail;}memcpy(combined_ints,m->code->ints,sizeof(int)*patch->base_int_count);memcpy(combined_ints+patch->base_int_count,patch->ints,sizeof(int)*patch->int_count);
	memset(&code,0,sizeof(code));code.nints=patch->base_int_count+patch->int_count;code.ints=combined_ints;code.nfloats=m->code->nfloats;code.floats=m->code->floats;code.nstrings=m->code->nstrings;code.strings=m->code->strings;code.ntypes=m->code->ntypes;code.types=m->code->types;code.nfunctions=m->code->nfunctions;code.nnatives=m->code->nnatives;code.functions=allocation->functions;
	temp=*m;temp.code=&code;temp.jit_code=NULL;temp.jit_debug=NULL;temp.jit_ctx=NULL;
	jit=hl_jit_alloc();if(!jit){error="Could not allocate patch JIT";goto fail;}hl_jit_init(jit,&temp);
	for(int i=0;i<patch->function_count;i++){offsets[i]=hl_jit_function(jit,&temp,allocation->functions+i);if(offsets[i]<0){error="Could not JIT patch function";goto fail;}}
	allocation->code=hl_jit_code(jit,&temp,&allocation->code_size,&temp.jit_debug,NULL);if(!allocation->code){error="Could not finalize patch JIT";goto fail;}hl_jit_free(jit,false);jit=NULL;
	for(int i=0;i<patch->function_count;i++){int slot=allocation->functions[i].findex;hl_patch_code *old=m->patch_owners[slot];m->functions_ptrs[slot]=(unsigned char*)allocation->code+offsets[i];m->patch_owners[slot]=allocation;allocation->references++;if(old&&--old->references==0)patch_code_free(old);}
	free(m->patch_ints);m->patch_ints=combined_ints;m->code->ints=combined_ints;m->code->nints=code.nints;combined_ints=NULL;m->revision=patch->revision;m->patch_jit_count+=patch->function_count;free(offsets);if(error_msg)*error_msg=NULL;return true;
fail:
	if(jit) hl_jit_free(jit,false);
	free(offsets);
	free(combined_ints);
	patch_code_free(allocation);
	if(error_msg) *error_msg=error?error:"Invalid patch";
	return false;
}
