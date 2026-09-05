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
		for(int j=0;j<code->functions[i].nops;j++) {
			hl_opcode *op=code->functions[i].ops+j;
			if(op->extra && (op->op==OCall3||op->op==OCall4||op->op==OCallN||op->op==OCallMethod||op->op==OCallThis||op->op==OCallClosure||op->op==OMakeEnum)) free(op->extra);
		}
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

static bool read_hash( patch_reader *r, unsigned int *out ) {
	const unsigned char *p;
	if( !take(r,4,&p) ) return false;
	*out = p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned int)p[3] << 24);
	return true;
}

static unsigned int hash_bytes( unsigned int hash, const unsigned char *p, int length ) {
	for(int i=0;i<length;i++) hash = (hash ^ p[i]) * 16777619U;
	return hash;
}

static unsigned int hash_i32( unsigned int hash, int value ) {
	unsigned char bytes[4] = { value & 255, (value >> 8) & 255, (value >> 16) & 255, ((unsigned int)value >> 24) & 255 };
	return hash_bytes(hash,bytes,4);
}

static unsigned int hash_int_prefix( hl_code *code, int count ) {
	unsigned int hash=2166136261U;for(int i=0;i<count;i++)hash=hash_i32(hash,code->ints[i]);return hash;
}

static unsigned int hash_float_prefix( hl_code *code, int count ) {
	unsigned int hash=2166136261U;for(int i=0;i<count;i++)hash=hash_bytes(hash,(unsigned char*)(code->floats+i),8);return hash;
}

static unsigned int hash_string_prefix( hl_code *code, int count ) {
	unsigned int hash=2166136261U;for(int i=0;i<count;i++){int length=code->strings_lens[i];hash=hash_i32(hash,length);hash=hash_bytes(hash,(unsigned char*)code->strings[i],length);}return hash;
}

static int hash_type_string_index( hl_code *code, const uchar *name ) {
	int length = ustrlen(name);
	for(int i=0;i<code->nstrings;i++) {
		const uchar *candidate = hl_get_ustring(code,i);
		if( ustrlen(candidate) == length && memcmp(candidate,name,length * sizeof(uchar)) == 0 )
			return i;
	}
	return -1;
}

static int hash_type_index( hl_code *code, hl_type *type ) {
	return type == NULL ? -1 : (int)(type - code->types);
}

static int hash_type_global_index( hl_module *module, void **value ) {
	int i;
	if( value == NULL ) return 0;
	for( i = 0; i < module->code->nglobals; i++ )
		if( module->globals_data + module->globals_indexes[i] == (unsigned char*)value ) return i + 1;
	return -1;
}

static unsigned int hash_type_prefix( hl_module *module, int count ) {
	hl_code *code = module->code;
	unsigned int hash=2166136261U;
	for(int i=0;i<count;i++){
		hl_type *type=code->types+i;
		hash=hash_i32(hash,type->kind);
		switch(type->kind) {
		case HFUN:
			hash=hash_i32(hash,type->fun->nargs);
			for(int j=0;j<type->fun->nargs;j++) hash=hash_i32(hash,hash_type_index(code,type->fun->args[j]));
			hash=hash_i32(hash,hash_type_index(code,type->fun->ret));
			break;
		case HABSTRACT:
			hash=hash_i32(hash,hash_type_string_index(code,type->abs_name));
			break;
		case HOBJ: case HSTRUCT: {
			hl_type_obj *obj=type->obj;
			hash=hash_i32(hash,hash_type_string_index(code,obj->name));
			hash=hash_i32(hash,obj->super == NULL ? -1 : hash_type_index(code,obj->super));
			hash=hash_i32(hash,hash_type_global_index(module,obj->global_value));
			hash=hash_i32(hash,obj->nfields);
			for(int j=0;j<obj->nfields;j++) { hash=hash_i32(hash,hash_type_string_index(code,obj->fields[j].name)); hash=hash_i32(hash,hash_type_index(code,obj->fields[j].t)); }
			hash=hash_i32(hash,obj->nproto);
			for(int j=0;j<obj->nproto;j++) { hash=hash_i32(hash,hash_type_string_index(code,obj->proto[j].name)); hash=hash_i32(hash,obj->proto[j].findex); hash=hash_i32(hash,obj->proto[j].pindex); }
			hash=hash_i32(hash,obj->nbindings);
			for(int j=0;j<obj->nbindings*2;j++) hash=hash_i32(hash,obj->bindings[j]);
			break;
		}
		case HVIRTUAL:
			hash=hash_i32(hash,type->virt->nfields);
			for(int j=0;j<type->virt->nfields;j++) { hash=hash_i32(hash,hash_type_string_index(code,type->virt->fields[j].name)); hash=hash_i32(hash,hash_type_index(code,type->virt->fields[j].t)); }
			break;
		case HENUM:
			hash=hash_i32(hash,hash_type_string_index(code,type->tenum->name));
			hash=hash_i32(hash,hash_type_global_index(module,type->tenum->global_value));
			hash=hash_i32(hash,type->tenum->nconstructs);
			for(int j=0;j<type->tenum->nconstructs;j++) { hl_enum_construct *c=type->tenum->constructs+j; hash=hash_i32(hash,hash_type_string_index(code,c->name)); hash=hash_i32(hash,c->nparams); for(int k=0;k<c->nparams;k++) hash=hash_i32(hash,hash_type_index(code,c->params[k])); }
			break;
		default:
			break;
		}
	}
	return hash;
}

static int opcode_operands( int opcode ) {
	switch( opcode ) {
	case OLabel: return 0;
	case OMov: case OInt: case OFloat: case OBool: case OBytes: case OString: case OCall0: case OStaticClosure:
	case OGetGlobal: case OSetGlobal: case OGetThis: case OSetThis: case ONull: case OArraySize: case ONew:
	case OToDyn: case OToSFloat: case OToUFloat: case OToInt: case OSafeCast: case OUnsafeCast: case OToVirtual:
	case OEnumAlloc: case OEnumIndex: case OJTrue: case OJFalse: case OJNull: case OJNotNull: case ORet:
	case OThrow: case ORethrow: case OTrap: case OEndTrap:
		return opcode == ONull || opcode == ONew || opcode == ORet || opcode == OThrow || opcode == ORethrow || opcode == OEndTrap ? 1 : 2;
	case OAdd: case OSub: case OMul: case OSDiv: case OUDiv: case OSMod: case OUMod: case OShl: case OSShr: case OUShr:
	case OAnd: case OOr: case OXor: case OCall1: case OInstanceClosure: case OField: case OSetField: case OGetArray:
	case OSetArray: case OJSLt: case OJSGte: case OJSGt: case OJSLte: case OJULt: case OJUGte: case OJNotLt:
	case OJNotGte: case OJEq: case OJNotEq: case OEnumField:
		return 3;
	case OCall2: return 4;
	case OCall3: return 5;
	case OCall4: return 6;
	case OCallN: case OCallMethod: case OCallThis: case OCallClosure: case OMakeEnum: case OSwitch: return -1;
	case OVirtualClosure: return 3;
	case ONeg: case ONot: case OIncr: case ODecr: case ONullCheck: return 2;
	case OJAlways: return 1;
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
		free(f->instructions); free(f->registers); free(f->relocation_instructions); free(f->relocation_stable_ids);
	}
	for(i=0;i<patch->type_count;i++) free(patch->types[i].arguments);
	free(patch->types);
	free(patch->functions); free(patch->strings); free(patch->string_lens); free(patch->floats); free(patch->ints); free(patch);
}

hl_patch *hl_patch_read( const unsigned char *data, int size, const char **error_msg ) {
	patch_reader r = { data, data + (size < 0 ? 0 : size), NULL };
	hl_patch *patch = (hl_patch*)calloc(1,sizeof(hl_patch));
	const unsigned char *p; int version, i, j, count, tag, section_count, section_length;
	bool have_symbols = false, have_functions = false;
#define FAIL(msg) do { r.error = msg; goto fail; } while(0)
	if( patch == NULL ) FAIL("Out of memory reading HLP");
	if( !take(&r,3,&p) ) goto fail;
	if( memcmp(p,"HLP",3) != 0 ) FAIL("Invalid HLP magic");
	if( !read_byte(&r,&version) ) goto fail;
	if( version != 4 ) FAIL("Unsupported HLP version");
	if( !take(&r,16,&p) ) goto fail;
	memcpy(patch->module_id,p,16);
	if( !read_count(&r,&patch->base_revision) || !read_count(&r,&patch->revision) ) goto fail;
	if( patch->revision <= patch->base_revision ) FAIL("Invalid patch revision range");
	if( !read_count(&r,&section_count) ) goto fail;
	for(int section=0;section<section_count;section++) {
		patch_reader s;
		if( !read_byte(&r,&tag) || !read_count(&r,&section_length) || r.end-r.p<section_length ) goto fail;
		s.p=r.p;s.end=r.p+section_length;s.error=NULL;r.p=s.end;
		if( tag == 1 ) {
			if( have_symbols ) FAIL("Duplicate HLP symbols section");
			have_symbols=true;
			if( !read_hash(&s,&patch->int_prefix_hash) || !read_count(&s,&patch->base_int_count) || !read_count(&s,&patch->int_count) ) goto section_fail;
			patch->ints=(int*)calloc(patch->int_count,sizeof(int));
			for(i=0;i<patch->int_count;i++){if(!take(&s,4,&p))goto section_fail;patch->ints[i]=(int)(p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned int)p[3]<<24));}
			if(!read_hash(&s,&patch->float_prefix_hash)||!read_count(&s,&patch->base_float_count)||!read_count(&s,&patch->float_count))goto section_fail;
			patch->floats=(double*)calloc(patch->float_count,sizeof(double));for(i=0;i<patch->float_count;i++){if(!take(&s,8,&p))goto section_fail;memcpy(patch->floats+i,p,8);}
			if(!read_hash(&s,&patch->string_prefix_hash)||!read_count(&s,&patch->base_string_count)||!read_count(&s,&patch->string_count))goto section_fail;
			patch->strings=(char**)calloc(patch->string_count,sizeof(char*));patch->string_lens=(int*)calloc(patch->string_count,sizeof(int));for(i=0;i<patch->string_count;i++){if(!read_count(&s,&count)||!take(&s,count,&p))goto section_fail;patch->string_lens[i]=count;patch->strings[i]=(char*)malloc(count+1);if(!patch->strings[i])FAIL("Out of memory reading HLP");memcpy(patch->strings[i],p,count);patch->strings[i][count]=0;}
			if(!read_hash(&s,&patch->type_prefix_hash)||!read_count(&s,&patch->base_type_count)||!read_count(&s,&patch->type_count))goto section_fail;
			patch->types=(hl_patch_type*)calloc(patch->type_count,sizeof(hl_patch_type));if(patch->type_count&&!patch->types)FAIL("Out of memory reading patch types");
			for(i=0;i<patch->type_count;i++){
				hl_patch_type *type=patch->types+i;if(!read_byte(&s,&type->tag))goto section_fail;
				if(type->tag==HFUN){if(!read_byte(&s,&type->count))goto section_fail;type->arguments=(int*)calloc(type->count,sizeof(int));if(type->count&&!type->arguments)FAIL("Out of memory reading function type");for(j=0;j<type->count;j++)if(!read_index(&s,type->arguments+j))goto section_fail;if(!read_index(&s,&type->result))goto section_fail;}
				else if(type->tag==HABSTRACT){if(!read_index(&s,&type->name))goto section_fail;}
				else if(type->tag<HVOID||type->tag>HGUID||type->tag==HOBJ||type->tag==HVIRTUAL||type->tag==HENUM||type->tag==HREF||type->tag==HNULL||type->tag==HPACKED)FAIL("Unsupported HLP type");
			}
		} else if( tag == 2 ) {
			if( have_functions ) FAIL("Duplicate HLP functions section");
			have_functions=true;if(!read_count(&s,&patch->function_count))goto section_fail;
			patch->functions=(hl_patch_function*)calloc(patch->function_count,sizeof(hl_patch_function));
				for(i=0;i<patch->function_count;i++){hl_patch_function *f=patch->functions+i;int length;const unsigned char *end;if(!read_count(&s,&length)||s.end-s.p<length)goto section_fail;end=s.p+length;if(!read_count(&s,&f->stable_id)||!read_index(&s,&f->type)||!read_count(&s,&f->findex)||!read_count(&s,&f->register_count)||!read_count(&s,&f->instruction_count))goto section_fail;f->registers=(int*)calloc(f->register_count,sizeof(int));for(j=0;j<f->register_count;j++)if(!read_index(&s,f->registers+j))goto section_fail;f->instructions=(hl_patch_instruction*)calloc(f->instruction_count,sizeof(hl_patch_instruction));for(j=0;j<f->instruction_count;j++){hl_patch_instruction *op=f->instructions+j;if(!read_byte(&s,&op->opcode))goto section_fail;op->operand_count=opcode_operands(op->opcode);if(op->operand_count<0){if(op->opcode!=OCallN&&op->opcode!=OCallMethod&&op->opcode!=OCallThis&&op->opcode!=OCallClosure&&op->opcode!=OMakeEnum)FAIL("Unsupported patch opcode");op->operand_count=3;}op->operands=(int*)calloc(op->operand_count,sizeof(int));for(int k=0;k<op->operand_count;k++)if(!read_index(&s,op->operands+k))goto section_fail;if(opcode_operands(op->opcode)<0){int count=op->operands[2];if(count<0||count>0x1000000)FAIL("Invalid variable operand count");op->operand_count=3+count;op->operands=(int*)realloc(op->operands,sizeof(int)*op->operand_count);if(!op->operands)FAIL("Out of memory reading patch operands");for(int k=3;k<op->operand_count;k++)if(!read_index(&s,op->operands+k))goto section_fail;}}if(!read_count(&s,&f->relocation_count))goto section_fail;f->relocation_instructions=(int*)calloc(f->relocation_count,sizeof(int));f->relocation_stable_ids=(int*)calloc(f->relocation_count,sizeof(int));for(j=0;j<f->relocation_count;j++)if(!read_count(&s,f->relocation_instructions+j)||!read_count(&s,f->relocation_stable_ids+j))goto section_fail;if(s.p!=end)FAIL("Invalid patch function length");}
		} else {
			s.p = s.end;
		}
		if( s.p != s.end ) FAIL("Invalid HLP section length");
		continue;
section_fail:
		r.error=s.error?s.error:"Truncated HLP data";goto fail;
	}
	if( !have_symbols || !have_functions ) FAIL("Missing required HLP section");
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

static bool valid_function_target( hl_module *m, int index ) {
	return index >= 0 && index < m->code->nfunctions + m->code->nnatives && m->functions_ptrs[index] != NULL
		&& m->functions_indexes[index] >= 0 && m->functions_indexes[index] < m->code->nfunctions;
}

static bool validate_function( hl_module *m, hl_patch *patch, hl_patch_function *f, const char **error ) {
	hl_function *live=find_live_function(m,f->findex);
	int trap_depth=0, trap_targets[256];
	int type_count=patch->base_type_count+patch->type_count;
	if(!live){*error="Unknown stable function slot";return false;}
	if(f->type<0||f->type>=type_count||live->type!=m->code->types+f->type){*error="Patch function signature changed";return false;}
	for(int i=0;i<f->register_count;i++)if(f->registers[i]<0||f->registers[i]>=type_count){*error="Invalid patch register type";return false;}
	for(int i=0;i<f->instruction_count;i++){
		hl_patch_instruction *op=f->instructions+i;int *p=op->operands;
		while(trap_depth>0&&trap_targets[trap_depth-1]==i)trap_depth--;
		switch(op->opcode){
		case OLabel:break;
		case OMov:if(!valid_reg(f,p[0])||!valid_reg(f,p[1])){*error="Invalid move operands";return false;}break;
		case OInt:if(!valid_reg(f,p[0])||p[1]<0||p[1]>=patch->base_int_count+patch->int_count){*error="Invalid Int operands";return false;}break;
		case OFloat:if(!valid_reg(f,p[0])||p[1]<0||p[1]>=patch->base_float_count+patch->float_count){*error="Invalid Float operands";return false;}break;
		case OString:if(!valid_reg(f,p[0])||p[1]<0||p[1]>=patch->base_string_count+patch->string_count){*error="Invalid String operands";return false;}break;
		case OBool:if(!valid_reg(f,p[0])||(p[1]!=0&&p[1]!=1)){*error="Invalid Bool operands";return false;}break;
		case OAdd:case OSub:case OMul:case OSDiv:if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||!valid_reg(f,p[2])){*error="Invalid arithmetic operands";return false;}break;
		case OCall0:case OCall1:case OCall2:case OCall3:case OCall4:
			if(!valid_reg(f,p[0])||p[1]<0||p[1]>=m->code->nfunctions+m->code->nnatives||m->functions_ptrs[p[1]]==NULL){*error="Invalid call target";return false;}
			for(int k=2;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OCallN:
			if(!valid_reg(f,p[0])||p[1]<0||p[1]>=m->code->nfunctions+m->code->nnatives||m->functions_ptrs[p[1]]==NULL||p[2]<0||p[2]!=op->operand_count-3){*error="Invalid variadic call";return false;}
			for(int k=3;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OCallMethod:case OCallThis:
			if(!valid_reg(f,p[0])||p[1]<0||p[2]<0||p[2]!=op->operand_count-3){*error="Invalid method call";return false;}
			for(int k=3;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OCallClosure:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||p[2]<0||p[2]!=op->operand_count-3){*error="Invalid closure call";return false;}
			for(int k=3;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid call argument";return false;}
			break;
		case OStaticClosure:
			if(!valid_reg(f,p[0])||!valid_function_target(m,p[1])){*error="Invalid static closure";return false;}
			break;
		case OInstanceClosure:
			if(!valid_reg(f,p[0])||!valid_function_target(m,p[1])||!valid_reg(f,p[2])){*error="Invalid instance closure";return false;}
			break;
		case OField:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||p[2]<0){*error="Invalid field read";return false;}
			break;
		case OSetField:
			if(!valid_reg(f,p[0])||p[1]<0||!valid_reg(f,p[2])){*error="Invalid field write";return false;}
			break;
		case OGetArray:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||!valid_reg(f,p[2])){*error="Invalid array read";return false;}
			break;
		case OSetArray:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||!valid_reg(f,p[2])){*error="Invalid array write";return false;}
			break;
		case OArraySize:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])){*error="Invalid array size";return false;}
			break;
		case ONew:
			if(!valid_reg(f,p[0])){*error="Invalid object allocation";return false;}
			break;
		case OMakeEnum:
			if(!valid_reg(f,p[0])||p[1]<0||p[2]<0||p[2]!=op->operand_count-3){*error="Invalid enum construction";return false;}
			for(int k=3;k<op->operand_count;k++) if(!valid_reg(f,p[k])){*error="Invalid enum argument";return false;}
			break;
		case OEnumAlloc:case OEnumIndex:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])){*error="Invalid enum operation";return false;}
			break;
		case OEnumField:
			if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||p[2]<0||p[3]<0){*error="Invalid enum field";return false;}
			break;
		case ONull:case OGetGlobal:case OSetGlobal:case OGetThis:case OSetThis:case OToDyn:case OToSFloat:case OToUFloat:case OToInt:case OSafeCast:case OUnsafeCast:case OToVirtual:
			if(!valid_reg(f,p[0])||(op->operand_count>1&&!valid_reg(f,p[1]))){*error="Invalid unary operation";return false;}
			break;
		case OJTrue:if(!valid_reg(f,p[0])||i+1+p[1]<0||i+1+p[1]>=f->instruction_count){*error="Invalid conditional branch";return false;}break;
		case OJSLt:case OJSLte:case OJEq:if(!valid_reg(f,p[0])||!valid_reg(f,p[1])||i+1+p[2]<0||i+1+p[2]>=f->instruction_count){*error="Invalid comparison branch";return false;}break;
		case OJAlways:if(i+1+p[0]<0||i+1+p[0]>=f->instruction_count){*error="Invalid branch";return false;}break;
		case ORet:if(!valid_reg(f,p[0])){*error="Invalid return register";return false;}break;
		case OThrow:case ORethrow:if(!valid_reg(f,p[0])){*error="Invalid throw register";return false;}break;
		case OTrap:
			if(!valid_reg(f,p[0])||p[1]<0||i+1+p[1]>=f->instruction_count||trap_depth==256){*error="Invalid trap operands";return false;}
			trap_targets[trap_depth++]=i+1+p[1];
			break;
		case OEndTrap:
			if(!valid_reg(f,p[0])||trap_depth==0){*error="Invalid end-trap operands";return false;}
			trap_depth--;
			break;
		default:*error="Unsupported patch opcode";return false;
		}
	}
	if(trap_depth!=0){*error="Unbalanced patch traps";return false;}
	return true;
}

static bool stage_patch_types( hl_module *m, hl_patch *patch, uchar **strings, int string_count, void ***allocations, int *allocation_count, const char **error ) {
	int total=patch->base_type_count+patch->type_count;
	if(total>m->code->types_capacity){*error="Type arena capacity exceeded";return false;}
	*allocations=(void**)calloc(patch->type_count,sizeof(void*));
	if(patch->type_count&&!*allocations){*error="Out of memory staging patch types";return false;}
	for(int i=0;i<patch->type_count;i++){
		hl_patch_type *src=patch->types+i;hl_type *dst=m->code->types+patch->base_type_count+i;
		memset(dst,0,sizeof(*dst));dst->kind=(hl_type_kind)src->tag;
		if(src->tag==HFUN){
			for(int j=0;j<src->count;j++)if(src->arguments[j]<0||src->arguments[j]>=total){*error="Invalid appended function argument type";return false;}
			if(src->result<0||src->result>=total){*error="Invalid appended function result type";return false;}
			size_t size=sizeof(hl_type_fun)+sizeof(hl_type*)*src->count;hl_type_fun *fun=(hl_type_fun*)calloc(1,size);
			if(!fun){*error="Out of memory staging function type";return false;}
			(*allocations)[(*allocation_count)++]=fun;fun->nargs=src->count;fun->args=(hl_type**)(fun+1);fun->ret=m->code->types+src->result;
			for(int j=0;j<src->count;j++)fun->args[j]=m->code->types+src->arguments[j];
			dst->fun=fun;
		}else if(src->tag==HABSTRACT){
			if(src->name<0||src->name>=string_count){*error="Invalid appended abstract name";return false;}dst->abs_name=strings[src->name];
		}
	}
	return true;
}

h_bool hl_module_apply_patch( hl_module *m, hl_patch *patch, const char **error_msg ) {
	const char *error=NULL;hl_patch_code *allocation=NULL;jit_ctx *jit=NULL;int *offsets=NULL,*combined_ints=NULL,*combined_string_lens=NULL;double *combined_floats=NULL;char **combined_strings=NULL,*combined_string_data=NULL;uchar **combined_ustrings=NULL;hl_function *combined_functions=NULL;void **type_allocations=NULL;int type_allocation_count=0;hl_code code;hl_module temp;
	if(!m||!patch||!m->patchable){error="Module is not patchable";goto fail;}
	if(patch->function_count<=0){error="Patch contains no functions";goto fail;}
	if(m->revision!=patch->base_revision||patch->revision<=patch->base_revision){error="Stale patch revision";goto fail;}
	if(patch->base_int_count!=m->code->nints||patch->base_float_count!=m->code->nfloats||patch->base_string_count!=m->code->nstrings||patch->base_type_count!=m->code->ntypes){error="Patch symbol base does not match module";goto fail;}
	if(patch->int_prefix_hash!=hash_int_prefix(m->code,patch->base_int_count)||patch->float_prefix_hash!=hash_float_prefix(m->code,patch->base_float_count)||patch->string_prefix_hash!=hash_string_prefix(m->code,patch->base_string_count)||patch->type_prefix_hash!=hash_type_prefix(m,patch->base_type_count)){error="Patch symbol prefix hash does not match module";goto fail;}
	for(int i=0;i<patch->function_count;i++){for(int j=0;j<i;j++)if(patch->functions[j].findex==patch->functions[i].findex){error="Duplicate stable function slot";goto fail;}if(!validate_function(m,patch,patch->functions+i,&error))goto fail;}
	combined_ints=(int*)malloc(sizeof(int)*(patch->base_int_count+patch->int_count));if(!combined_ints){error="Out of memory applying patch";goto fail;}memcpy(combined_ints,m->code->ints,sizeof(int)*patch->base_int_count);memcpy(combined_ints+patch->base_int_count,patch->ints,sizeof(int)*patch->int_count);
	combined_floats=(double*)malloc(sizeof(double)*(patch->base_float_count+patch->float_count));if(!combined_floats){error="Out of memory applying patch";goto fail;}memcpy(combined_floats,m->code->floats,sizeof(double)*patch->base_float_count);memcpy(combined_floats+patch->base_float_count,patch->floats,sizeof(double)*patch->float_count);
	{int total=patch->base_string_count+patch->string_count,bytes=0,pos=0;for(int i=0;i<patch->base_string_count;i++)bytes+=m->code->strings_lens[i]+1;for(int i=0;i<patch->string_count;i++)bytes+=patch->string_lens[i]+1;combined_strings=(char**)malloc(sizeof(char*)*total);combined_string_lens=(int*)malloc(sizeof(int)*total);combined_ustrings=(uchar**)calloc(total,sizeof(uchar*));combined_string_data=(char*)malloc(bytes);if((total>0)&&(!combined_strings||!combined_string_lens||!combined_ustrings||!combined_string_data)){error="Out of memory applying patch";goto fail;}for(int i=0;i<total;i++){const char *src;int length;if(i<patch->base_string_count){src=m->code->strings[i];length=m->code->strings_lens[i];combined_ustrings[i]=(uchar*)hl_get_ustring(m->code,i);}else{src=patch->strings[i-patch->base_string_count];length=patch->string_lens[i-patch->base_string_count];int usize=hl_utf8_length((vbyte*)src,0);combined_ustrings[i]=(uchar*)malloc((usize+1)*sizeof(uchar));if(!combined_ustrings[i]){error="Out of memory applying patch";goto fail;}hl_from_utf8(combined_ustrings[i],usize,src);}combined_strings[i]=combined_string_data+pos;combined_string_lens[i]=length;memcpy(combined_string_data+pos,src,length);combined_string_data[pos+length]=0;pos+=length+1;}}
	if(!stage_patch_types(m,patch,combined_ustrings,patch->base_string_count+patch->string_count,&type_allocations,&type_allocation_count,&error))goto fail;
	allocation=(hl_patch_code*)calloc(1,sizeof(hl_patch_code));if(!allocation){error="Out of memory applying patch";goto fail;}
	allocation->function_count=patch->function_count;allocation->functions=(hl_function*)calloc(patch->function_count,sizeof(hl_function));
	offsets=(int*)calloc(patch->function_count,sizeof(int));if(!allocation->functions||!offsets){error="Out of memory applying patch";goto fail;}
	for(int i=0;i<patch->function_count;i++){hl_patch_function *src=patch->functions+i;hl_function *dst=allocation->functions+i;dst->type=m->code->types+src->type;dst->findex=src->findex;dst->nregs=src->register_count;dst->nops=src->instruction_count;dst->regs=(hl_type**)calloc(dst->nregs,sizeof(hl_type*));dst->ops=(hl_opcode*)calloc(dst->nops,sizeof(hl_opcode));if(!dst->regs||!dst->ops){error="Out of memory applying patch";goto fail;}for(int j=0;j<dst->nregs;j++)dst->regs[j]=m->code->types+src->registers[j];for(int j=0;j<dst->nops;j++){hl_patch_instruction *s=src->instructions+j;hl_opcode *d=dst->ops+j;d->op=(hl_op)s->opcode;if(s->operand_count>0)d->p1=s->operands[0];if(s->operand_count>1)d->p2=s->operands[1];if(s->operand_count>2)d->p3=s->operands[2];if(s->operand_count==4&&d->op!=OCallN&&d->op!=OCallMethod&&d->op!=OCallThis&&d->op!=OCallClosure&&d->op!=OMakeEnum)d->extra=(int*)(int_val)s->operands[3];if(s->operand_count>3&&(d->op==OCall3||d->op==OCall4||d->op==OCallN||d->op==OCallMethod||d->op==OCallThis||d->op==OCallClosure||d->op==OMakeEnum)){int count=d->op==OCall3?2:d->op==OCall4?3:s->operand_count-3;d->extra=(int*)malloc(sizeof(int)*count);if(!d->extra){error="Out of memory applying patch";goto fail;}memcpy(d->extra,s->operands+3,sizeof(int)*count);}}}
	combined_functions=(hl_function*)calloc(m->code->nfunctions,sizeof(hl_function));
	if(!combined_functions){error="Out of memory applying patch";goto fail;}
	memcpy(combined_functions,m->code->functions,sizeof(hl_function)*m->code->nfunctions);
	for(int i=0;i<patch->function_count;i++) {
		int function_index=m->functions_indexes[allocation->functions[i].findex];
		if(function_index<0||function_index>=m->code->nfunctions){error="Invalid patch function slot";goto fail;}
		combined_functions[function_index]=allocation->functions[i];
	}
	memset(&code,0,sizeof(code));code.nints=patch->base_int_count+patch->int_count;code.ints=combined_ints;code.nfloats=patch->base_float_count+patch->float_count;code.floats=combined_floats;code.nstrings=patch->base_string_count+patch->string_count;code.strings=combined_strings;code.strings_lens=combined_string_lens;code.ustrings=combined_ustrings;code.ntypes=patch->base_type_count+patch->type_count;code.types_capacity=m->code->types_capacity;code.types=m->code->types;code.nfunctions=m->code->nfunctions;code.nnatives=m->code->nnatives;code.functions=combined_functions;code.alloc=m->code->alloc;
	temp=*m;temp.code=&code;temp.jit_code=NULL;temp.jit_debug=NULL;temp.jit_ctx=NULL;
	jit=hl_jit_alloc();if(!jit){error="Could not allocate patch JIT";goto fail;}hl_jit_init(jit,&temp);
	for(int i=0;i<patch->function_count;i++){offsets[i]=hl_jit_function(jit,&temp,allocation->functions+i);if(offsets[i]<0){error="Could not JIT patch function";goto fail;}}
	allocation->code=hl_jit_code(jit,&temp,&allocation->code_size,&temp.jit_debug,NULL);if(!allocation->code){error="Could not finalize patch JIT";goto fail;}hl_jit_free(jit,false);jit=NULL;free(combined_functions);combined_functions=NULL;
	if(type_allocation_count){int needed=m->patch_type_allocation_count+type_allocation_count;if(needed>m->patch_type_allocation_capacity){int capacity=needed<16?16:needed*2;void **owners=(void**)realloc(m->patch_type_allocations,sizeof(void*)*capacity);if(!owners){error="Out of memory publishing patch types";goto fail;}m->patch_type_allocations=owners;m->patch_type_allocation_capacity=capacity;}}
	for(int i=0;i<type_allocation_count;i++)m->patch_type_allocations[m->patch_type_allocation_count++]=type_allocations[i];
	free(type_allocations);type_allocations=NULL;type_allocation_count=0;m->code->ntypes=code.ntypes;
	for(int i=0;i<patch->function_count;i++){int slot=allocation->functions[i].findex;hl_patch_code *old=m->patch_owners[slot];m->functions_ptrs[slot]=(unsigned char*)allocation->code+offsets[i];m->patch_owners[slot]=allocation;allocation->references++;if(old&&--old->references==0)patch_code_free(old);}
	if(m->patch_ustrings==NULL)m->patch_initial_string_count=patch->base_string_count;
	free(m->patch_ints);free(m->patch_floats);free(m->patch_strings);free(m->patch_string_lens);free(m->patch_ustrings);free(m->patch_string_data);
	m->patch_ints=combined_ints;m->patch_floats=combined_floats;m->patch_strings=combined_strings;m->patch_string_lens=combined_string_lens;m->patch_ustrings=combined_ustrings;m->patch_string_data=combined_string_data;
	m->code->ints=combined_ints;m->code->nints=code.nints;m->code->floats=combined_floats;m->code->nfloats=code.nfloats;m->code->strings=combined_strings;m->code->strings_lens=combined_string_lens;m->code->ustrings=combined_ustrings;m->code->nstrings=code.nstrings;
	combined_ints=NULL;combined_floats=NULL;combined_strings=NULL;combined_string_lens=NULL;combined_ustrings=NULL;combined_string_data=NULL;
	m->revision=patch->revision;m->patch_jit_count+=patch->function_count;free(offsets);if(error_msg)*error_msg=NULL;return true;
fail:
	if(jit) hl_jit_free(jit,false);
	free(combined_functions);
	free(offsets);
	free(combined_ints);
	free(combined_floats);free(combined_strings);free(combined_string_lens);if(combined_ustrings)for(int i=patch->base_string_count;i<patch->base_string_count+patch->string_count;i++)free(combined_ustrings[i]);free(combined_ustrings);free(combined_string_data);
	for(int i=0;i<type_allocation_count;i++)free(type_allocations[i]);
	free(type_allocations);if(m&&patch&&m->code&&patch->base_type_count<=m->code->types_capacity&&patch->type_count<=m->code->types_capacity-patch->base_type_count)memset(m->code->types+patch->base_type_count,0,sizeof(hl_type)*patch->type_count);
	patch_code_free(allocation);
	if(error_msg) *error_msg=error?error:"Invalid patch";
	return false;
}
