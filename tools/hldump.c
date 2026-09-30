/*
 * hldump: prints a HashLink bytecode (.hl) file as text.
 *
 * It reads the file with the VM's own reader (code.c), so every opcode decodes exactly as it does at run time, and
 * prints it in a form made to be diffed: two builds of the same source should give identical text, and when they do
 * not, the first differing line names the function, the section and the instruction.
 *
 *   hldump [--raw] [--debug] [--function TEXT] [--hashes] [--sections] [--identities] [--spans] file.hl
 *
 * By default functions, globals and types are shown by name, because their indexes change whenever anything is added
 * before them. --raw shows the indexes as well. --function limits the functions to those whose name contains TEXT.
 * --hashes prints one line per function with a hash of its text (compare two builds quickly, then dump the differing
 * ones). --sections prints only the counts and the extra debug sections. --debug adds the source file and line of every
 * instruction and the local variable table. --identities and --spans decode the function identity and opcode source span
 * sections (by function name), which is where two builds of one source can differ without any function differing.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <hl.h>
#include <hlmodule.h>

#define OP(n,a,b,c) #n,
#define OP_BEGIN static const char *op_names[] = {
#define OP_END };
#include "opcodes.h"

#define OP(_,_a,_b,_c) (_b == AR ? _c : (_c == X ? (_b == X ? (_a == X ? 0 : 1) : 2) : 3)),
#define OP_BEGIN static int op_nargs[] = {
#define OP_END };
#include "opcodes.h"

#define OP(_,_a,_b,_c) { _a, _b, _c },
#define OP_BEGIN static int op_kinds[][3] = {
#define OP_END };
#include "opcodes.h"

/* The opcodes the dump needs to know by name. */
enum { K_X = 0, K_R = 1, K_R_NW = 2, K_C = 3, K_G = 4, K_AR = 5, K_J = 6 };

static hl_code *code;
static int raw_mode = 0, debug_mode = 0, hash_mode = 0, identities_mode = 0, spans_mode = 0;
static const char *function_filter = NULL;
static char **function_label;   /* by function index (findex) */
static int label_count;

typedef struct {
	char *data;
	size_t size, capacity;
} text;

static void text_add(text *t, const char *format, ...) {
	va_list args;
	for(;;) {
		size_t room = t->capacity - t->size;
		int written;
		va_start(args, format);
		written = vsnprintf(t->data + t->size, room, format, args);
		va_end(args);
		if( written >= 0 && (size_t)written < room ) {
			t->size += written;
			return;
		}
		t->capacity = t->capacity ? t->capacity * 2 : 4096;
		t->data = (char*)realloc(t->data, t->capacity);
	}
}

static const char *utf8(const uchar *s) {
	return s ? hl_to_utf8(s) : "(null)";
}

static void escape(text *t, const char *s, int length) {
	text_add(t, "\"");
	for(int i=0;i<length;i++) {
		unsigned char c = (unsigned char)s[i];
		if( c == '"' || c == '\\' ) text_add(t, "\\%c", c);
		else if( c == '\n' ) text_add(t, "\\n");
		else if( c == '\r' ) text_add(t, "\\r");
		else if( c == '\t' ) text_add(t, "\\t");
		else if( c < 32 ) text_add(t, "\\x%02x", c);
		else text_add(t, "%c", c);
	}
	text_add(t, "\"");
}

static uint64_t fnv(const char *data, size_t size) {
	uint64_t h = 1469598103934665603ULL;
	for(size_t i=0;i<size;i++) {
		h ^= (unsigned char)data[i];
		h *= 1099511628211ULL;
	}
	return h;
}

static int type_index(hl_type *t) {
	if( !t ) return -1;
	if( t >= code->types && t < code->types + code->ntypes ) return (int)(t - code->types);
	return -1;
}

static void print_type(text *t, hl_type *type) {
	int index = type_index(type);
	if( !type ) { text_add(t, "null"); return; }
	if( raw_mode && index >= 0 ) text_add(t, "T%d:", index);
	switch( type->kind ) {
	case HFUN: {
		text_add(t, "fun(");
		for(int i=0;i<type->fun->nargs;i++) {
			if( i ) text_add(t, ",");
			print_type(t, type->fun->args[i]);
		}
		text_add(t, ")->");
		print_type(t, type->fun->ret);
		break;
	}
	case HOBJ: case HSTRUCT:
		text_add(t, "%s %s", type->kind == HOBJ ? "obj" : "struct", utf8(type->obj->name));
		break;
	case HENUM:
		text_add(t, "enum %s", type->tenum->name ? utf8(type->tenum->name) : "?");
		break;
	case HVIRTUAL: {
		text_add(t, "virtual{");
		for(int i=0;i<type->virt->nfields;i++) {
			if( i ) text_add(t, ",");
			text_add(t, "%s:", utf8(type->virt->fields[i].name));
			print_type(t, type->virt->fields[i].t);
		}
		text_add(t, "}");
		break;
	}
	case HABSTRACT:
		text_add(t, "abstract %s", utf8(type->abs_name));
		break;
	case HREF: case HNULL: case HPACKED:
		text_add(t, "%s<", type->kind == HREF ? "ref" : type->kind == HNULL ? "null" : "packed");
		print_type(t, type->tparam);
		text_add(t, ">");
		break;
	default:
		text_add(t, "%s", utf8(hl_type_str(type)));
	}
}

static void print_function_name(text *t, int findex) {
	if( findex >= 0 && findex < label_count && function_label[findex] )
		text_add(t, "%s", function_label[findex]);
	else
		text_add(t, "fn#%d", findex);
	if( raw_mode ) text_add(t, "[#%d]", findex);
}

static void print_global(text *t, int index) {
	if( index >= 0 && index < code->nglobals ) {
		text_add(t, "global<");
		print_type(t, code->globals[index]);
		text_add(t, ">");
	} else
		text_add(t, "global?");
	if( raw_mode ) text_add(t, "[#%d]", index);
}

static void print_operand(text *t, hl_function *f, hl_opcode *o, int opcode_index, int kind, int value, int position) {
	switch( kind ) {
	case K_X:
		return;
	case K_R: case K_R_NW:
		text_add(t, " r%d", value);
		return;
	case K_J:
		text_add(t, " ->%+d", value + 1);
		return;
	case K_AR:
		text_add(t, " n=%d", value);
		return;
	case K_G: case K_C: default:
		break;
	}
	text_add(t, " ");
	switch( o->op ) {
	case OInt:
		if( position == 2 && value >= 0 && value < code->nints ) { text_add(t, "%d", code->ints[value]); return; }
		break;
	case OFloat:
		if( position == 2 && value >= 0 && value < code->nfloats ) { text_add(t, "%.17g", code->floats[value]); return; }
		break;
	case OString:
		if( position == 2 && value >= 0 && value < code->nstrings ) { escape(t, code->strings[value], code->strings_lens[value]); return; }
		break;
	case OBool:
		if( position == 2 ) { text_add(t, "%s", value ? "true" : "false"); return; }
		break;
	case OType:
		if( position == 2 && value >= 0 && value < code->ntypes ) { print_type(t, code->types + value); return; }
		break;
	case OCall0: case OCall1: case OCall2: case OCall3: case OCall4: case OCallN: case OStaticClosure: case OInstanceClosure:
		if( position == 2 ) { print_function_name(t, value); return; }
		break;
	case OGetGlobal: case OSetGlobal:
		if( (o->op == OGetGlobal && position == 2) || (o->op == OSetGlobal && position == 1) ) { print_global(t, value); return; }
		break;
	case ODynGet: case ODynSet:
		if( (o->op == ODynGet && position == 3) || (o->op == ODynSet && position == 2) )
			if( value >= 0 && value < code->nstrings ) { escape(t, code->strings[value], code->strings_lens[value]); return; }
		break;
	default:
		break;
	}
	text_add(t, "#%d", value);
}

static void print_function(text *t, hl_function *f, const char *label) {
	text_add(t, "function %s", label);
	if( raw_mode ) text_add(t, " [#%d]", f->findex);
	text_add(t, " : ");
	print_type(t, f->type);
	text_add(t, "\n");
	for(int i=0;i<f->nregs;i++) {
		text_add(t, "  reg r%d : ", i);
		print_type(t, f->regs[i]);
		text_add(t, "\n");
	}
	for(int i=0;i<f->nops;i++) {
		hl_opcode *o = f->ops + i;
		int nargs = op_nargs[o->op];
		const char *name = op_names[o->op];
		text_add(t, "  %4d %s", i, name);
		if( debug_mode && f->debug )
			text_add(t, "  @%d:%d", f->debug[i*2] & 0x7FFFFFFF, f->debug[i*2+1]);
		switch( nargs ) {
		case 0: break;
		case 1:
			print_operand(t, f, o, i, op_kinds[o->op][0], o->p1, 1);
			break;
		case 2:
			print_operand(t, f, o, i, op_kinds[o->op][0], o->p1, 1);
			print_operand(t, f, o, i, op_kinds[o->op][1], o->p2, 2);
			break;
		case 3:
			print_operand(t, f, o, i, op_kinds[o->op][0], o->p1, 1);
			print_operand(t, f, o, i, op_kinds[o->op][1], o->p2, 2);
			print_operand(t, f, o, i, op_kinds[o->op][2], o->p3, 3);
			break;
		case 4:
			print_operand(t, f, o, i, op_kinds[o->op][0], o->p1, 1);
			print_operand(t, f, o, i, op_kinds[o->op][1], o->p2, 2);
			print_operand(t, f, o, i, op_kinds[o->op][2], o->p3, 3);
			text_add(t, " r%d", (int)(intptr_t)o->extra);
			break;
		case -1:
			if( o->op == OSwitch ) {
				text_add(t, " r%d cases=%d [", o->p1, o->p2);
				for(int j=0;j<o->p2;j++) text_add(t, "%s%+d", j ? "," : "", o->extra[j] + 1);
				text_add(t, "] default=%+d", o->p3 + 1);
			} else {
				text_add(t, " r%d", o->p1);
				if( o->op == OCallN ) { text_add(t, " "); print_function_name(t, o->p2); }
				else text_add(t, " #%d", o->p2);
				text_add(t, " (");
				for(int j=0;j<o->p3;j++) text_add(t, "%sr%d", j ? "," : "", o->extra[j]);
				text_add(t, ")");
			}
			break;
		default: {
			int extra = nargs - 3;
			if( o->op >= OCall2 && o->op <= OCall4 ) {
				text_add(t, " r%d ", o->p1);
				print_function_name(t, o->p2);
				text_add(t, " (r%d", o->p3);
				for(int j=0;j<extra;j++) text_add(t, ",r%d", o->extra[j]);
				text_add(t, ")");
			} else {
				text_add(t, " r%d #%d #%d", o->p1, o->p2, o->p3);
				for(int j=0;j<extra;j++) text_add(t, " #%d", o->extra[j]);
			}
			break;
		}
		}
		text_add(t, "\n");
	}
	if( debug_mode && f->nassigns ) {
		for(int i=0;i<f->nassigns;i++) {
			int name = ASSIGN_NAME(f,i);
			text_add(t, "  local %s op=%d scope-end=%d\n", name >= 0 && name < code->nstrings ? code->strings[name] : "?", ASSIGN_POS(f,i), ASSIGN_SCOPE_END(f,i));
		}
	}
}


typedef struct { const unsigned char *b; int size, pos, error; } reader;

static int rd_byte(reader *r) {
	if( r->pos >= r->size ) { r->error = 1; return 0; }
	return r->b[r->pos++];
}

/* HashLink's variable width signed index. */
static int rd_index(reader *r) {
	int b = rd_byte(r);
	if( !(b & 0x80) ) return b;
	if( !(b & 0x40) ) {
		int v = rd_byte(r) | ((b & 31) << 8);
		return (b & 0x20) ? -v : v;
	}
	{
		int c = rd_byte(r), d = rd_byte(r), e = rd_byte(r);
		int v = ((b & 31) << 24) | (c << 16) | (d << 8) | e;
		return (b & 0x20) ? -v : v;
	}
}

static int rd_i32(reader *r) {
	int v = rd_byte(r);
	v |= rd_byte(r) << 8;
	v |= rd_byte(r) << 16;
	v |= rd_byte(r) << 24;
	return v;
}

static void rd_string(reader *r, text *out) {
	int length = rd_index(r);
	if( length < 0 || r->pos + length > r->size ) { r->error = 1; return; }
	escape(out, (const char*)r->b + r->pos, length);
	r->pos += length;
}

/* Stable identity of each function, so spans can be shown under the function's name. */
static char **stable_name;
static int stable_count;

static void dump_identities(text *out, hl_debug_section *s) {
	reader r = { s->data, s->size, 0, 0 };
	int count = rd_index(&r);
	for(int i=0;i<count && !r.error;i++) {
		int stable = rd_index(&r), findex = rd_index(&r);
		text qualified = {0}, display = {0}, path = {0};
		int start, end, line, flags;
		rd_string(&r, &qualified); rd_string(&r, &display); rd_string(&r, &path);
		start = rd_index(&r) - 1; end = rd_index(&r) - 1; line = rd_index(&r); flags = rd_index(&r);
		if( r.error ) break;
		if( stable >= stable_count ) {
			int grown = stable + 1024;
			stable_name = (char**)realloc(stable_name, grown * sizeof(char*));
			memset(stable_name + stable_count, 0, (grown - stable_count) * sizeof(char*));
			stable_count = grown;
		}
		stable_name[stable] = strdup(findex >= 0 && findex < label_count && function_label[findex] ? function_label[findex] : "?");
		text_add(out, "identity %s", stable_name[stable]);
		if( raw_mode ) text_add(out, " stable=%d findex=%d", stable, findex);
		text_add(out, " qualified=%s display=%s path=%s span=%d..%d line=%d flags=%d\n", qualified.data, display.data, path.data, start, end, line, flags);
		free(qualified.data); free(display.data); free(path.data);
	}
	if( r.error || r.pos != r.size ) text_add(out, "identities: malformed section (read %d of %d bytes)\n", r.pos, r.size);
}

static void dump_spans(text *out, hl_debug_section *s) {
	reader r = { s->data, s->size, 0, 0 };
	int nfiles = rd_index(&r), ngroups;
	char **files = (char**)calloc(nfiles + 1, sizeof(char*));
	for(int i=0;i<nfiles && !r.error;i++) {
		text name = {0};
		rd_string(&r, &name);
		files[i] = name.data;
	}
	ngroups = rd_index(&r);
	for(int g=0;g<ngroups && !r.error;g++) {
		int stable = rd_index(&r), n = rd_index(&r);
		text_add(out, "spans %s", stable >= 0 && stable < stable_count && stable_name[stable] ? stable_name[stable] : "?");
		if( raw_mode ) text_add(out, " stable=%d", stable);
		text_add(out, " mappings=%d\n", n);
		for(int i=0;i<n && !r.error;i++) {
			int opcode = rd_index(&r), file = rd_index(&r), start = rd_index(&r) - 1, end = rd_index(&r) - 1;
			int line = rd_index(&r), column = rd_index(&r), endLine = rd_index(&r), endColumn = rd_index(&r);
			int hash = rd_i32(&r), flags = rd_index(&r);
			text_add(out, "  op %d %s %d..%d %d:%d-%d:%d hash=%08x flags=%d\n", opcode, file >= 0 && file < nfiles ? files[file] : "?",
				start, end, line, column, endLine, endColumn, (unsigned)hash, flags);
		}
	}
	if( r.error || r.pos != r.size ) text_add(out, "spans: malformed section (read %d of %d bytes)\n", r.pos, r.size);
	for(int i=0;i<nfiles;i++) free(files[i]);
	free(files);
}

static unsigned char *read_file(const char *path, int *size) {
	FILE *file = fopen(path, "rb");
	unsigned char *data;
	long length;
	if( !file ) return NULL;
	fseek(file, 0, SEEK_END);
	length = ftell(file);
	fseek(file, 0, SEEK_SET);
	data = (unsigned char*)malloc(length + 1);
	if( !data || fread(data, 1, length, file) != (size_t)length ) { fclose(file); return NULL; }
	fclose(file);
	*size = (int)length;
	return data;
}

int main(int argc, char **argv) {
	const char *path = NULL;
	int only_sections = 0, size = 0, max_findex = 0;
	unsigned char *data;
	char *error = NULL;
	text out = {0};
	for(int i=1;i<argc;i++) {
		if( !strcmp(argv[i], "--raw") ) raw_mode = 1;
		else if( !strcmp(argv[i], "--debug") ) debug_mode = 1;
		else if( !strcmp(argv[i], "--hashes") ) hash_mode = 1;
		else if( !strcmp(argv[i], "--sections") ) only_sections = 1;
		else if( !strcmp(argv[i], "--identities") ) identities_mode = 1;
		else if( !strcmp(argv[i], "--spans") ) spans_mode = 1;
		else if( !strcmp(argv[i], "--function") && i + 1 < argc ) function_filter = argv[++i];
		else if( argv[i][0] == '-' ) { fprintf(stderr, "unknown option %s\n", argv[i]); return 2; }
		else path = argv[i];
	}
	if( !path ) {
		fprintf(stderr, "usage: hldump [--raw] [--debug] [--function TEXT] [--hashes] [--sections] file.hl\n");
		return 2;
	}
	hl_global_init();
	data = read_file(path, &size);
	if( !data ) { fprintf(stderr, "cannot read %s\n", path); return 1; }
	code = hl_code_read(data, size, &error);
	if( !code ) { fprintf(stderr, "invalid bytecode: %s\n", error ? error : "?"); return 1; }

	for(int i=0;i<code->nfunctions;i++) if( code->functions[i].findex > max_findex ) max_findex = code->functions[i].findex;
	for(int i=0;i<code->nnatives;i++) if( code->natives[i].findex > max_findex ) max_findex = code->natives[i].findex;
	label_count = max_findex + 1;
	function_label = (char**)calloc(label_count, sizeof(char*));
	for(int i=0;i<code->nnatives;i++) {
		char buffer[512];
		snprintf(buffer, sizeof(buffer), "native %s.%s", code->natives[i].lib, code->natives[i].name);
		function_label[code->natives[i].findex] = strdup(buffer);
	}
	for(int i=0;i<code->nfunctions;i++) {
		hl_function *f = code->functions + i;
		const char *name = hl_code_function_name(code, f);
		char buffer[512];
		if( name ) snprintf(buffer, sizeof(buffer), "%s", name);
		else if( fun_obj(f) && fun_field_name(f) ) snprintf(buffer, sizeof(buffer), "%s.%s", utf8(fun_obj(f)->name), utf8(fun_field_name(f)));
		else snprintf(buffer, sizeof(buffer), "fn#%d", f->findex);
		function_label[f->findex] = strdup(buffer);
	}

	text_add(&out, "hlb version=%d debug=%d entry=%s\n", code->version, code->hasdebug ? 1 : 0,
		code->entrypoint >= 0 && code->entrypoint < label_count && function_label[code->entrypoint] ? function_label[code->entrypoint] : "?");
	text_add(&out, "counts ints=%d floats=%d strings=%d bytes=%d types=%d globals=%d natives=%d functions=%d constants=%d sections=%d debugfiles=%d\n",
		code->nints, code->nfloats, code->nstrings, code->nbytes, code->ntypes, code->nglobals, code->nnatives, code->nfunctions,
		code->nconstants, code->ndebugsections, code->ndebugfiles);
	for(int i=0;i<code->ndebugsections;i++) {
		hl_debug_section *s = code->debugsections + i;
		text_add(&out, "section kind=%d version=%d flags=%d size=%d hash=%016llx\n", s->kind, s->version, s->flags, s->size,
			(unsigned long long)fnv((const char*)s->data, s->size));
	}
	if( identities_mode || spans_mode ) {
		for(int i=0;i<code->ndebugsections;i++)
			if( code->debugsections[i].kind == 1 ) dump_identities(&out, code->debugsections + i);
		if( spans_mode )
			for(int i=0;i<code->ndebugsections;i++)
				if( code->debugsections[i].kind == 2 ) dump_spans(&out, code->debugsections + i);
		fwrite(out.data, 1, out.size, stdout);
		return 0;
	}
	if( !only_sections && !function_filter && !hash_mode ) {
		for(int i=0;i<code->nints;i++) text_add(&out, "int %d %d\n", i, code->ints[i]);
		for(int i=0;i<code->nfloats;i++) text_add(&out, "float %d %.17g\n", i, code->floats[i]);
		for(int i=0;i<code->nstrings;i++) { text_add(&out, "string %d ", i); escape(&out, code->strings[i], code->strings_lens[i]); text_add(&out, "\n"); }
		for(int i=0;i<code->ndebugfiles;i++) text_add(&out, "file %d %s\n", i, code->debugfiles[i]);
		for(int i=0;i<code->ntypes;i++) {
			hl_type *t = code->types + i;
			text_add(&out, "type %d ", i);
			print_type(&out, t);
			if( t->kind == HOBJ || t->kind == HSTRUCT ) {
				hl_type_obj *obj = t->obj;
				text_add(&out, " super=");
				print_type(&out, obj->super);
				text_add(&out, "\n");
				for(int j=0;j<obj->nfields;j++) { text_add(&out, "  field %s : ", utf8(obj->fields[j].name)); print_type(&out, obj->fields[j].t); text_add(&out, "\n"); }
				for(int j=0;j<obj->nproto;j++) { text_add(&out, "  method %s -> ", utf8(obj->proto[j].name)); print_function_name(&out, obj->proto[j].findex); text_add(&out, " slot=%d\n", obj->proto[j].pindex); }
				for(int j=0;j<obj->nbindings;j++) text_add(&out, "  binding %d -> %d\n", obj->bindings[j*2], obj->bindings[j*2+1]);
				continue;
			}
			if( t->kind == HENUM ) {
				text_add(&out, "\n");
				for(int j=0;j<t->tenum->nconstructs;j++) {
					hl_enum_construct *c = t->tenum->constructs + j;
					text_add(&out, "  construct %s(", utf8(c->name));
					for(int k=0;k<c->nparams;k++) { if( k ) text_add(&out, ","); print_type(&out, c->params[k]); }
					text_add(&out, ")\n");
				}
				continue;
			}
			text_add(&out, "\n");
		}
		for(int i=0;i<code->nglobals;i++) { text_add(&out, "global %d ", i); print_type(&out, code->globals[i]); text_add(&out, "\n"); }
		for(int i=0;i<code->nnatives;i++) { text_add(&out, "native %s.%s : ", code->natives[i].lib, code->natives[i].name); print_type(&out, code->natives[i].t); text_add(&out, "\n"); }
		for(int i=0;i<code->nconstants;i++) {
			text_add(&out, "constant %d global=", i);
			print_global(&out, code->constants[i].global);
			text_add(&out, " fields=[");
			for(int j=0;j<code->constants[i].nfields;j++) text_add(&out, "%s%d", j ? "," : "", code->constants[i].fields[j]);
			text_add(&out, "]\n");
		}
	}
	if( !only_sections ) {
		for(int i=0;i<code->nfunctions;i++) {
			hl_function *f = code->functions + i;
			const char *label = function_label[f->findex];
			text body = {0};
			if( function_filter && !strstr(label, function_filter) ) continue;
			print_function(&body, f, label);
			if( hash_mode )
				text_add(&out, "%016llx %s\n", (unsigned long long)fnv(body.data, body.size), label);
			else
				text_add(&out, "%s", body.data);
			free(body.data);
		}
	}
	fwrite(out.data, 1, out.size, stdout);
	return 0;
}
