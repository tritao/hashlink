/* Standalone HLDI profiler client: records sessions to HLPC captures, and reports on and exports captures. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
#include <io.h>
typedef SOCKET socket_t;
#define CLOSE_SOCKET closesocket
#else
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define CLOSE_SOCKET close
#endif

enum { SVC_PROFILE=2, P_STATUS=1, P_CONFIGURE=2, P_READ=3, P_METADATA=4 };
enum { F_RESPONSE=1, F_ERROR=2, CAP_PROFILE=1, CAP_SYMBOLS=2 };
#include "../src/profile_events.h"
#include "elf_symbols.h"
#include "pftrace.h"
#include "../include/lz4/lz4.h"

typedef struct { uint32_t offset,end,opcode_index,opcode,line; char *file; uint64_t self,total; } source_line;
typedef struct { uint64_t start,end,self,total,region_base,region_size,module_id; uint32_t function_id,revision,region_flags; char *name; source_line *lines; uint32_t line_count; } symbol;
typedef struct { symbol *items; size_t count,capacity; } symbols;
typedef struct { const unsigned char *data; size_t length,pos; } reader;
typedef struct { FILE *file; double started; int failed; } capture;
typedef struct folded folded;
struct folded { char *stack; uint64_t count; folded *next; };
typedef struct { folded *buckets[4096]; } folded_table;
typedef struct native_symbol native_symbol;
struct native_symbol { uint64_t pc,base,module_base,module_size; uint32_t line; char *module,*name,*file; native_symbol *next; };
typedef struct { uint64_t allocated,allocations,collections,mark_micros; double time; int valid; } perfetto_gc_state;
static volatile sig_atomic_t interrupted;
static native_symbol *native_symbols;
static perfetto_gc_state perfetto_gc;
static uint32_t perfetto_threads[4096];
static uint64_t health_capacity,health_used,health_records,health_sample_nanos,health_generated;
static uint32_t health_requested_rate,health_effective_rate;

static uint16_t u16( const unsigned char *p ) { return (uint16_t)(p[0]|((uint16_t)p[1]<<8)); }
static uint32_t u32( const unsigned char *p ) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t u64( const unsigned char *p ) { return (uint64_t)u32(p)|((uint64_t)u32(p+4)<<32); }
static void put32( unsigned char *p,uint32_t v ) { p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24); }
static void put64( unsigned char *p,uint64_t v ) { put32(p,(uint32_t)v);put32(p+4,(uint32_t)(v>>32)); }
static void stop_signal( int sig ) { (void)sig; interrupted=1; }
static int parse_status( const unsigned char *data,uint32_t size ) {if(size!=32&&size!=56&&size!=80)return 0;health_effective_rate=u32(data+24);health_requested_rate=size>=56?u32(data+48):health_effective_rate;health_capacity=size>=56?u64(data+32):0;health_used=size>=56?u64(data+8)-u64(data+40):0;if(size>=80){health_records=u64(data+56);health_sample_nanos=u64(data+64);health_generated=u64(data+72);}return 1;}

static double monotime( void ) {
#ifdef _WIN32
	LARGE_INTEGER now,frequency;QueryPerformanceCounter(&now);QueryPerformanceFrequency(&frequency);return (double)now.QuadPart/(double)frequency.QuadPart;
#else
	struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1000000000.0;
#endif
}
static void sleep_ms( int ms ) {
#ifdef _WIN32
	Sleep((DWORD)ms);
#else
	struct timespec t={ms/1000,(ms%1000)*1000000L}; nanosleep(&t,NULL);
#endif
}
static int capture_record_parts( capture *c,uint32_t type,const void *prefix,uint32_t prefix_size,const void *body,uint32_t body_size ) {
	unsigned char header[16];uint64_t nanos;
	if(!c->file)return 1;
	if(c->failed)return 0;
	nanos=(uint64_t)((monotime()-c->started)*1000000000.0);put32(header,type);put32(header+4,prefix_size+body_size);put64(header+8,nanos);
	if(fwrite(header,1,16,c->file)!=16||(prefix_size&&fwrite(prefix,1,prefix_size,c->file)!=prefix_size)||(body_size&&fwrite(body,1,body_size,c->file)!=body_size))c->failed=1;
	return !c->failed;
}
static int capture_open( capture *c,const char *path,uint32_t pid,uint32_t rate ) {
	unsigned char header[24];
	if(!path)return 1;
	c->file=fopen(path,"wb");if(!c->file)return 0;c->started=monotime();
	memcpy(header,"HLPC",4);header[4]=1;header[5]=0;header[6]=24;header[7]=0;put32(header+8,0);put32(header+12,pid);put32(header+16,rate);put32(header+20,0);
	if(fwrite(header,1,24,c->file)!=24)c->failed=1;
	return !c->failed;
}
static void capture_close( capture *c,uint64_t cursor,uint64_t dropped,int completed ) {
	unsigned char end[16];if(!c->file)return;if(completed){put64(end,cursor);put64(end+8,dropped);capture_record_parts(c,3,end,16,NULL,0);}if(fclose(c->file)!=0)c->failed=1;c->file=NULL;
}
static int send_all( socket_t s,const void *data,size_t size ) {
	const char *p=(const char*)data; while(size){int n=(int)send(s,p,(int)size,0);if(n<=0)return 0;p+=n;size-=n;}return 1;
}
static int recv_all( socket_t s,void *data,size_t size ) {
	char *p=(char*)data; while(size){int n=(int)recv(s,p,(int)size,0);if(n<=0)return 0;p+=n;size-=n;}return 1;
}
static socket_t open_socket( const char *host,const char *port ) {
	struct addrinfo hints,*list=NULL,*it; socket_t result=INVALID_SOCKET;
	memset(&hints,0,sizeof(hints));hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
	if(getaddrinfo(host,port,&hints,&list)!=0)return INVALID_SOCKET;
	for(it=list;it;it=it->ai_next){result=(socket_t)socket(it->ai_family,it->ai_socktype,it->ai_protocol);if(result==INVALID_SOCKET)continue;if(connect(result,it->ai_addr,(int)it->ai_addrlen)==0)break;CLOSE_SOCKET(result);result=INVALID_SOCKET;}
	freeaddrinfo(list);return result;
}
static socket_t open_socket_until( const char *host,const char *port,int timeout_seconds ) {
	double deadline=monotime()+timeout_seconds;socket_t result;
	do{result=open_socket(host,port);if(result!=INVALID_SOCKET)return result;if(monotime()>=deadline)break;sleep_ms(100);}while(1);
	return INVALID_SOCKET;
}
static int request_service( socket_t s,unsigned char service,unsigned char type,uint32_t id,const void *body,uint32_t size,unsigned char **reply,uint32_t *reply_size ) {
	unsigned char h[16];h[0]=service;h[1]=type;h[2]=h[3]=0;put32(h+4,id);put32(h+8,size);put32(h+12,0);
	if(!send_all(s,h,16)||(size&&!send_all(s,body,size))||!recv_all(s,h,16))return 0;
	*reply_size=u32(h+8);
	if(h[0]!=service||h[1]!=type||u32(h+4)!=id||(u16(h+2)&F_RESPONSE)==0||(u16(h+2)&F_ERROR)||*reply_size>(64U<<20))return 0;
	*reply=*reply_size?(unsigned char*)malloc(*reply_size):NULL;
	if(*reply_size&&(!*reply||!recv_all(s,*reply,*reply_size))){free(*reply);*reply=NULL;return 0;}return 1;
}
static int request( socket_t s,unsigned char type,uint32_t id,const void *body,uint32_t size,unsigned char **reply,uint32_t *reply_size ) {return request_service(s,SVC_PROFILE,type,id,body,size,reply,reply_size);}
static int get32( reader *r,uint32_t *v ){if(r->length-r->pos<4)return 0;*v=u32(r->data+r->pos);r->pos+=4;return 1;}
static int get64( reader *r,uint64_t *v ){if(r->length-r->pos<8)return 0;*v=u64(r->data+r->pos);r->pos+=8;return 1;}

static void free_symbols( symbols *s ){for(size_t i=0;i<s->count;i++){free(s->items[i].name);for(uint32_t j=0;j<s->items[i].line_count;j++)free(s->items[i].lines[j].file);free(s->items[i].lines);}free(s->items);memset(s,0,sizeof(*s));}
static symbol *add_symbol( symbols *s,uint64_t start,uint64_t end,uint32_t id,uint32_t revision,const unsigned char *name,uint32_t length ) {
	if(s->count==s->capacity){size_t cap=s->capacity?s->capacity*2:1024;symbol *p=(symbol*)realloc(s->items,cap*sizeof(symbol));if(!p)return NULL;s->items=p;s->capacity=cap;}
	symbol *x=s->items+s->count++;memset(x,0,sizeof(*x));x->start=start;x->end=end;x->function_id=id;x->revision=revision;x->name=(char*)malloc((size_t)length+1);if(!x->name)return NULL;memcpy(x->name,name,length);x->name[length]=0;return x;
}
static int by_address( const void *a,const void *b ){const symbol *x=a,*y=b;return x->start<y->start?-1:x->start>y->start?1:0;}
static symbol *resolve( symbols *s,uint64_t pc ){size_t lo=0,hi=s->count;while(lo<hi){size_t m=(lo+hi)>>1;if(s->items[m].start<=pc)lo=m+1;else hi=m;}return lo&&pc<s->items[lo-1].end?s->items+lo-1:NULL;}
static source_line *resolve_line( symbol *s,uint64_t pc ){uint32_t offset=(uint32_t)(pc-s->start),lo=0,hi=s->line_count;while(lo<hi){uint32_t m=(lo+hi)>>1;if(s->lines[m].offset<=offset)lo=m+1;else hi=m;}if(!lo)return NULL;source_line *line=s->lines+lo-1;return line->end&&offset>=line->end?NULL:line;}
static native_symbol *resolve_native( uint64_t pc ){for(native_symbol *n=native_symbols;n;n=n->next)if(n->pc==pc)return n;return NULL;}
static int add_native( uint64_t pc,uint64_t base,const unsigned char *module,uint32_t module_len,const unsigned char *name,uint32_t name_len ) {
	native_symbol *n=resolve_native(pc);if(n)return 1;n=(native_symbol*)calloc(1,sizeof(*n));if(!n)return 0;
	n->module=(char*)malloc((size_t)module_len+1);n->name=(char*)malloc((size_t)name_len+1);if(!n->module||!n->name){free(n->module);free(n->name);free(n);return 0;}
	memcpy(n->module,module,module_len);n->module[module_len]=0;memcpy(n->name,name,name_len);n->name[name_len]=0;n->pc=pc;n->base=base;n->next=native_symbols;native_symbols=n;
	/* The runtime names a function that is not exported by its image, from the image's base: name it from the image's symbol
	   table when it can be read here. */
	{const char *file=n->module;for(const char *c=n->module;*c;c++)if(*c=='/'||*c=='\\')file=c+1;
	uint64_t into=0;const char *function=pc>=base&&!strcmp(n->name,file)?elf_function_name(n->module,pc-base,&into):NULL;
	if(function){char *named=(char*)malloc(strlen(function)+1);if(named){strcpy(named,function);free(n->name);n->name=named;n->base=pc-into;}}}
	return 1;
}
static void free_native( void ){while(native_symbols){native_symbol *next=native_symbols->next;free(native_symbols->module);free(native_symbols->name);free(native_symbols->file);free(native_symbols);native_symbols=next;}elf_symbols_free();}
static int add_native_location( const unsigned char *payload,uint32_t size ) {
	if(size<32||u32(payload+28)!=size-32)return 0;
	native_symbol *n=resolve_native(u64(payload));if(!n||n->file)return 1;
	n->module_base=u64(payload+8);n->module_size=u64(payload+16);n->line=u32(payload+24);
	if(size>32){n->file=(char*)malloc((size_t)size-31);if(!n->file)return 0;memcpy(n->file,payload+32,size-32);n->file[size-32]=0;}
	return 1;
}
static int parse_symbols( const unsigned char *data,uint32_t size,symbols *current ) {
	uint32_t schema,nmodules;reader r;symbols next={0};char **files=NULL;uint32_t file_count=0;
	r.data=data;r.length=size;r.pos=0;
	if(!get32(&r,&schema)||(schema<1||schema>4)||!get32(&r,&nmodules))goto fail;
	for(uint32_t m=0;m<nmodules;m++){
		uint64_t module_id;uint32_t revision,nregions;if(!get64(&r,&module_id)||!get32(&r,&revision)||!get32(&r,&nregions))goto fail;
		if(schema>=2){if(!get32(&r,&file_count))goto fail;files=(char**)calloc(file_count,sizeof(char*));if(file_count&&!files)goto fail;for(uint32_t i=0;i<file_count;i++){uint32_t length;if(!get32(&r,&length)||length>r.length-r.pos)goto fail;files[i]=(char*)malloc((size_t)length+1);if(!files[i])goto fail;memcpy(files[i],r.data+r.pos,length);files[i][length]=0;r.pos+=length;}}
		for(uint32_t g=0;g<nregions;g++){
			uint64_t base,region_size;uint32_t flags,region_revision=revision,nfunctions;if(!get64(&r,&base)||!get64(&r,&region_size)||!get32(&r,&flags)||(schema>=4&&!get32(&r,&region_revision))||!get32(&r,&nfunctions))goto fail;
			for(uint32_t f=0;f<nfunctions;f++){
				uint32_t fid,off,len,nlen;if(!get32(&r,&fid)||!get32(&r,&off)||!get32(&r,&len)||!get32(&r,&nlen)||nlen>r.length-r.pos||!len||(uint64_t)off+len>region_size)goto fail;
				symbol *added=add_symbol(&next,base+off,base+off+len,fid,region_revision,r.data+r.pos,nlen);if(!added)goto fail;added->region_base=base;added->region_size=region_size;added->module_id=module_id;added->region_flags=flags;
				r.pos+=nlen;
				if(schema>=2){uint32_t lines;if(!get32(&r,&lines))goto fail;added->lines=(source_line*)calloc(lines,sizeof(source_line));if(lines&&!added->lines)goto fail;added->line_count=lines;for(uint32_t i=0;i<lines;i++){uint32_t offset,end=0,opcode_index=0,opcode=0,file,line;if(!get32(&r,&offset)||(schema>=3&&(!get32(&r,&end)||!get32(&r,&opcode_index)||!get32(&r,&opcode)))||!get32(&r,&file)||!get32(&r,&line)||offset>=len||(schema>=3&&(end<=offset||end>len))||file>=file_count||(i&&offset<added->lines[i-1].offset))goto fail;added->lines[i].offset=offset;added->lines[i].end=end;added->lines[i].opcode_index=opcode_index;added->lines[i].opcode=opcode;added->lines[i].line=line;added->lines[i].file=(char*)malloc(strlen(files[file])+1);if(!added->lines[i].file)goto fail;strcpy(added->lines[i].file,files[file]);}}
			}
		}
		for(uint32_t i=0;i<file_count;i++)free(files[i]);
		free(files);files=NULL;file_count=0;
	}
	if(r.pos!=r.length)goto fail;
	qsort(next.items,next.count,sizeof(symbol),by_address);
	for(size_t i=0;i<next.count;i++){
		symbol *old=resolve(current,next.items[i].start);
		if(old&&old->start==next.items[i].start&&old->end==next.items[i].end&&!strcmp(old->name,next.items[i].name)){next.items[i].self=old->self;next.items[i].total=old->total;for(uint32_t j=0;j<next.items[i].line_count;j++){source_line *line=resolve_line(old,old->start+next.items[i].lines[j].offset);if(line&&!strcmp(line->file,next.items[i].lines[j].file)&&line->line==next.items[i].lines[j].line){next.items[i].lines[j].self=line->self;next.items[i].lines[j].total=line->total;}}}
	}
	free_symbols(current);*current=next;return 1;
	fail: if(files){for(uint32_t i=0;i<file_count;i++)free(files[i]);free(files);}free_symbols(&next);return 0;
}
static int fetch_symbols( socket_t sock,symbols *current,uint32_t id,capture *output ) {
	unsigned char *data=NULL;uint32_t size;
	if(!request(sock,P_METADATA,id,NULL,0,&data,&size))return 0;
	if(!parse_symbols(data,size,current)){free(data);return 0;}
	if(output&&!capture_record_parts(output,1,NULL,0,data,size)){free(data);return 0;}
	free(data);return 1;
}
static int by_hot( const void *a,const void *b ){const symbol *x=*(symbol*const*)a,*y=*(symbol*const*)b;if(x->self!=y->self)return x->self<y->self?1:-1;return x->total<y->total?1:x->total>y->total?-1:0;}
typedef struct { symbol *function; source_line *line; } hot_line;
static int by_hot_line( const void *a,const void *b ){const hot_line *x=a,*y=b;if(x->line->self!=y->line->self)return x->line->self<y->line->self?1:-1;return x->line->total<y->line->total?1:x->line->total>y->line->total?-1:0;}
static void report( symbols *s,uint64_t samples,uint64_t unresolved,uint64_t dropped,int top,int show_lines ) {
	symbol **hot=(symbol**)malloc(s->count*sizeof(symbol*));size_t count=0;if(!hot)return;
	printf("\nsamples=%llu unresolved_frames=%llu dropped_records=%llu\n",(unsigned long long)samples,(unsigned long long)unresolved,(unsigned long long)dropped);printf("%8s %8s  %s\n","self","total",show_lines?"location / function":"function");
	if(health_capacity)printf("buffer=%llu/%llu (%.1f%%) requested_rate=%u effective_rate=%u\n",(unsigned long long)health_used,(unsigned long long)health_capacity,health_used*100.0/health_capacity,health_requested_rate,health_effective_rate);
	if(health_records)printf("profiler_overhead=%.2fus/sample generated_bytes=%llu\n",health_sample_nanos/1000.0/health_records,(unsigned long long)health_generated);
	if(show_lines){size_t line_capacity=0;for(size_t i=0;i<s->count;i++)line_capacity+=s->items[i].line_count;hot_line *lines=(hot_line*)malloc(line_capacity*sizeof(hot_line));if(!lines){free(hot);return;}for(size_t i=0;i<s->count;i++)for(uint32_t j=0;j<s->items[i].line_count;j++)if(s->items[i].lines[j].total){lines[count].function=s->items+i;lines[count++].line=s->items[i].lines+j;}qsort(lines,count,sizeof(hot_line),by_hot_line);for(size_t i=0;i<count&&i<(size_t)top;i++)printf("%7.2f%% %7.2f%%  %s:%u  %s\n",samples?lines[i].line->self*100.0/samples:0.0,samples?lines[i].line->total*100.0/samples:0.0,lines[i].line->file,lines[i].line->line,lines[i].function->name);free(lines);}
	else{for(size_t i=0;i<s->count;i++)if(s->items[i].total)hot[count++]=s->items+i;qsort(hot,count,sizeof(symbol*),by_hot);for(size_t i=0;i<count&&i<(size_t)top;i++)printf("%7.2f%% %7.2f%%  %s\n",samples?hot[i]->self*100.0/samples:0.0,samples?hot[i]->total*100.0/samples:0.0,hot[i]->name);}
	fflush(stdout);for(size_t i=0;i<s->count;i++){s->items[i].self=s->items[i].total=0;for(uint32_t j=0;j<s->items[i].line_count;j++)s->items[i].lines[j].self=s->items[i].lines[j].total=0;}free(hot);
}
static uint32_t stack_hash( const char *text ){uint32_t h=2166136261U;while(*text){h^=(unsigned char)*text++;h*=16777619U;}return h;}
static int folded_add( folded_table *table,const char *stack ) {
	uint32_t slot=stack_hash(stack)&4095;folded *entry;
	for(entry=table->buckets[slot];entry;entry=entry->next)if(!strcmp(entry->stack,stack)){entry->count++;return 1;}
	entry=(folded*)malloc(sizeof(folded));if(!entry)return 0;entry->stack=(char*)malloc(strlen(stack)+1);if(!entry->stack){free(entry);return 0;}strcpy(entry->stack,stack);entry->count=1;entry->next=table->buckets[slot];table->buckets[slot]=entry;return 1;
}
static void folded_write( folded_table *table ) {for(int i=0;i<4096;i++)for(folded *e=table->buckets[i];e;e=e->next)printf("%s %llu\n",e->stack,(unsigned long long)e->count);}
static void folded_free( folded_table *table ){for(int i=0;i<4096;i++){folded *e=table->buckets[i];while(e){folded *next=e->next;free(e->stack);free(e);e=next;}}}
static void json_string( FILE *file,const char *text ){fputc('"',file);for(;*text;text++){unsigned char c=(unsigned char)*text;if(c=='"'||c=='\\'){fputc('\\',file);fputc(c,file);}else if(c=='\n')fputs("\\n",file);else if(c=='\r')fputs("\\r",file);else if(c=='\t')fputs("\\t",file);else if(c<32)fprintf(file,"\\u%04x",c);else fputc(c,file);}fputc('"',file);}
static void perfetto_begin_event( FILE *file,int *first ){if(!*first)fputc(',',file);*first=0;}
/* Span payloads are UTF-8 names; the event timestamp already uses the sample clock. */
static int perfetto_span_event( FILE *file,int *first,uint32_t pid,uint32_t tid,
        uint32_t event_id,const unsigned char *payload,uint32_t payload_size,double timestamp_us ) {
    char *name=(char*)malloc((size_t)payload_size+1);
    if(!name)return 0;
    memcpy(name,payload,payload_size);
    name[payload_size]=0;
    perfetto_begin_event(file,first);
    fprintf(file,"{\"ph\":\"%c\",\"cat\":\"hl.span\",\"name\":",
        event_id==PROFILE_EVENT_SPAN_BEGIN?'B':'E');
    json_string(file,name);
    fprintf(file,",\"pid\":%u,\"tid\":%u,\"ts\":%.3f}",pid,tid,timestamp_us);
    free(name);
    return 1;
}
/*
 * Native-protobuf Perfetto export. Samples keep their real call stacks (interned frames with source lines, attributed to the
 * JIT region or native module that holds them), spans become nested slices and GC statistics become counter tracks.
 * Event times are the runtime's clock in seconds; the trace uses them as nanoseconds.
 */
/* A thread's call stack on its "Call stacks" track, root first. While the thread's frames are marked, each frame (and
   each idle stretch between frames) is a root slice, so the track reads as one flame graph per frame: a frame boundary
   ends every slice and reopens the stack under the next root. */
typedef struct { uint32_t tid,depth,capacity,emitted; char **names; char *root; double last; int instrumented; } pf_stack;
typedef struct { pftrace *trace; uint64_t weight_ns,last_ns; uint64_t *frames; uint32_t frame_capacity; perfetto_gc_state gc; double sampled_allocation_bytes; pf_stack *stacks; uint32_t stack_count,stack_capacity; } pf_export;
static uint64_t pf_time( pf_export *pf,double seconds ){uint64_t ns=seconds>0?(uint64_t)(seconds*1e9+0.5):1;if(ns>pf->last_ns)pf->last_ns=ns;return ns;}
static char *pf_text( const unsigned char *data,uint32_t size ){char *text=(char*)malloc((size_t)size+1);if(text){memcpy(text,data,size);text[size]=0;}return text;}
static uint64_t pf_frame( pf_export *pf,symbols *s,uint64_t pc ) {
	symbol *x=resolve(s,pc);
	if(x){char mapping[64];source_line *line=resolve_line(x,pc);if(x->region_flags&4)snprintf(mapping,sizeof(mapping),"[hashlink-jit-entries m%llu]",(unsigned long long)x->module_id);else snprintf(mapping,sizeof(mapping),"[hashlink-jit m%llu r%u]",(unsigned long long)x->module_id,x->revision);
		uint64_t id=pftrace_mapping(pf->trace,mapping,x->region_base,x->region_base+x->region_size);
		return pftrace_frame(pf->trace,x->name,id,pc-x->region_base,line?line->file:NULL,line?line->line:0);}
	native_symbol *n=resolve_native(pc);
	if(n){uint64_t base=n->module_base?n->module_base:n->base;return pftrace_frame(pf->trace,n->name,pftrace_mapping(pf->trace,n->module,base,base+n->module_size),pc-base,n->file,n->line);}
	{char name[40];snprintf(name,sizeof(name),"[unknown 0x%llx]",(unsigned long long)pc);return pftrace_frame(pf->trace,name,0,0,NULL,0);}
}
static const char *pf_function( symbols *s,uint64_t pc ) {
	symbol *x=resolve(s,pc);native_symbol *n;
	if(x)return x->name;
	if((n=resolve_native(pc))!=NULL)return n->name;
	return "[unknown]";
}
static pf_stack *pf_stack_of( pf_export *pf,uint32_t tid ) {
	for(uint32_t i=0;i<pf->stack_count;i++)if(pf->stacks[i].tid==tid)return pf->stacks+i;
	if(pf->stack_count==pf->stack_capacity){uint32_t capacity=pf->stack_capacity?pf->stack_capacity*2:16;pf_stack *next=(pf_stack*)realloc(pf->stacks,sizeof(pf_stack)*capacity);if(!next)return NULL;pf->stacks=next;pf->stack_capacity=capacity;}
	memset(pf->stacks+pf->stack_count,0,sizeof(pf_stack));pf->stacks[pf->stack_count].tid=tid;
	return pf->stacks+pf->stack_count++;
}
/* Ends open slices until `keep` remain (the root counts as one). */
static void pf_stack_cut( pf_export *pf,pf_stack *st,uint32_t keep,double time ) {
	while(st->emitted>keep){st->emitted--;pftrace_stack_end(pf->trace,pf_time(pf,time),st->tid);}
}
static void pf_stack_reopen( pf_export *pf,pf_stack *st,double time ) {
	if(st->root){pftrace_stack_begin(pf->trace,pf_time(pf,time),st->tid,st->root);st->emitted=1;}
	for(uint32_t i=0;i<st->depth;i++){pftrace_stack_begin(pf->trace,pf_time(pf,time),st->tid,st->names[i]);st->emitted++;}
}
static void pf_stack_truncate( pf_stack *st,uint32_t depth ) {
	while(st->depth>depth)free(st->names[--st->depth]);
}
/* Lays a sample's stack out over time: frames shared with the previous sample extend its slices, the rest end and start
   here. Each sample stands for one sampling interval, so a thread unsampled for longer has its slices end after the last
   interval it was seen. */
static int pf_stack_sample( pf_export *pf,symbols *s,double time,uint32_t tid,const unsigned char *leaf_first,uint32_t frames ) {
	double interval=pf->weight_ns/1e9;uint32_t shared=0,base;pf_stack *st=pf_stack_of(pf,tid);
	if(!st)return 0;
	/* A thread with instrumented calls shows them exactly; its samples stay in the aggregate flame graph only. */
	if(st->instrumented)return 1;
	base=st->root?1:0;
	if(st->depth&&time-st->last>interval*3){pf_stack_cut(pf,st,base,st->last+interval);pf_stack_truncate(st,0);}
	while(shared<st->depth&&shared<frames&&!strcmp(st->names[shared],pf_function(s,u64(leaf_first+(frames-1-shared)*8))))shared++;
	pf_stack_cut(pf,st,base+shared,time);pf_stack_truncate(st,shared);
	if(frames>st->capacity){char **next=(char**)realloc(st->names,sizeof(char*)*frames);if(!next)return 0;st->names=next;st->capacity=frames;}
	for(uint32_t i=shared;i<frames;i++){const char *name=pf_function(s,u64(leaf_first+(frames-1-i)*8));size_t n=strlen(name);
		if(!(st->names[i]=(char*)malloc(n+1)))return 0;memcpy(st->names[i],name,n+1);st->depth=i+1;
		pftrace_stack_begin(pf->trace,pf_time(pf,time),tid,name);st->emitted++;}
	st->last=time;
	return 1;
}
/* An instrumented call begins or ends on the thread. The first one replaces the stack the thread's samples built. A startup
   phase (instrumented 0) is laid out the same way but leaves the thread's samples shown. */
static int pf_stack_call( pf_export *pf,double time,uint32_t tid,const unsigned char *name,uint32_t size,int begin,int instrumented ) {
	pf_stack *st=pf_stack_of(pf,tid);uint32_t base;
	if(!st)return 0;
	base=st->root?1:0;
	if(instrumented&&!st->instrumented){st->instrumented=1;pf_stack_cut(pf,st,base,time);pf_stack_truncate(st,0);}
	if(!begin){if(st->depth){pf_stack_cut(pf,st,base+st->depth-1,time);pf_stack_truncate(st,st->depth-1);}st->last=time;return 1;}
	if(st->depth==st->capacity){uint32_t capacity=st->capacity?st->capacity*2:64;char **next=(char**)realloc(st->names,sizeof(char*)*capacity);if(!next)return 0;st->names=next;st->capacity=capacity;}
	if(!(st->names[st->depth]=(char*)malloc((size_t)size+1)))return 0;
	memcpy(st->names[st->depth],name,size);st->names[st->depth][size]=0;
	pftrace_stack_begin(pf->trace,pf_time(pf,time),tid,st->names[st->depth]);
	st->depth++;st->emitted++;st->last=time;
	return 1;
}
/* A frame boundary on the thread: ends everything and reopens the stack under the new root ("Frame N" or "Idle"). */
static int pf_stack_frame( pf_export *pf,double time,uint32_t tid,const char *root ) {
	pf_stack *st=pf_stack_of(pf,tid);size_t n=strlen(root);
	if(!st)return 0;
	pf_stack_cut(pf,st,0,time);free(st->root);
	if(!(st->root=(char*)malloc(n+1)))return 0;memcpy(st->root,root,n+1);
	pf_stack_reopen(pf,st,time);
	return 1;
}
static void pf_stacks_finish( pf_export *pf ) {
	for(uint32_t i=0;i<pf->stack_count;i++){pf_stack *st=pf->stacks+i;pf_stack_cut(pf,st,0,st->last+pf->weight_ns/1e9);pf_stack_truncate(st,0);free(st->names);free(st->root);}
	free(pf->stacks);pf->stacks=NULL;pf->stack_count=pf->stack_capacity=0;
}
/* Whether a native module is HashLink's own launcher or runtime library. */
static int runtime_image( const char *module ) {
	const char *base=module;for(const char *c=module;*c;c++)if(*c=='/'||*c=='\\')base=c+1;
	return !strcmp(base,"hl")||!strcmp(base,"hl.exe")||!strncmp(base,"libhl.",6);
}
/* A sample's frame count without the root-most frames in HashLink's launcher and runtime (main, hl_dyn_call, the thread
   entry): every Haxe stack starts with them and they say nothing about the program. Native frames of the program's own,
   such as a native thread's loop, are kept. */
static uint32_t launcher_trimmed( symbols *s,const unsigned char *leaf_first,uint32_t frames ) {
	while(frames>1){uint64_t pc=u64(leaf_first+(frames-1)*8);native_symbol *n;
		if(resolve(s,pc)||(n=resolve_native(pc))==NULL||!runtime_image(n->module))break;
		frames--;}
	return frames;
}
static int pf_sample( pf_export *pf,symbols *s,double time,uint32_t tid,const unsigned char *leaf_first,uint32_t frames,int gc_stop ) {
	uint64_t ts=pf_time(pf,time);
	if(frames>pf->frame_capacity){uint64_t *next=(uint64_t*)realloc(pf->frames,sizeof(uint64_t)*frames);if(!next)return 0;pf->frames=next;pf->frame_capacity=frames;}
	for(uint32_t i=0;i<frames;i++)pf->frames[frames-1-i]=pf_frame(pf,s,u64(leaf_first+i*8));
	pftrace_sample(pf->trace,ts,tid,pf->frames,frames,pf->weight_ns);
	if(!pf_stack_sample(pf,s,time,tid,leaf_first,frames))return 0;
	if(gc_stop)pftrace_instant(pf->trace,ts,tid,"GC stop sample");
	return 1;
}
static int pf_event( pf_export *pf,double time,uint32_t tid,uint32_t event_id,const unsigned char *payload,uint32_t size ) {
	uint64_t ts=pf_time(pf,time);char *text;
	switch(event_id){
	case PROFILE_EVENT_SPAN_BEGIN:if(!(text=pf_text(payload,size)))return 0;pftrace_slice_begin(pf->trace,ts,tid,text,"hl.span");free(text);break;
	case PROFILE_EVENT_SPAN_END:pftrace_slice_end(pf->trace,ts,tid);break;
	/* Instrumented calls go on the thread's call-stack track, cut into frames like sampled stacks. */
	case 0x484C2001U:if(!pf_stack_call(pf,time,tid,payload,size,1,1))return 0;break;
	case 0x484C2002U:if(!pf_stack_call(pf,time,tid,NULL,0,0,1))return 0;break;
	case 0x484C2007U:if(!pf_stack_call(pf,time,tid,payload,size,1,0))return 0;break;
	case 0x484C2008U:if(!pf_stack_call(pf,time,tid,NULL,0,0,0))return 0;break;
	case 0x484C2004U:if(!(text=pf_text(payload,size)))return 0;{int ok=pf_stack_frame(pf,time,tid,text);free(text);if(!ok)return 0;}break;
	case 0x484C2005U:if(!pf_stack_frame(pf,time,tid,"Idle"))return 0;break;
	case 0x484C2003U:if(size==8){double end;memcpy(&end,payload,8);pftrace_slice_begin(pf->trace,ts,tid,"profiler stall","hl.profiler");pftrace_slice_end(pf->trace,pf_time(pf,end),tid);}break;
	case PROFILE_EVENT_THREAD_NAME:if(!(text=pf_text(payload,size)))return 0;pftrace_thread(pf->trace,tid,text);free(text);break;
	/* A track of the process, not of a thread (payload: its name): the frames track, above the main thread's calls. */
	case 0x484C2006U:if(!(text=pf_text(payload,size)))return 0;pftrace_process_track(pf->trace,tid,text,-2);free(text);break;
	case PROFILE_EVENT_MODULE_REVISION:pftrace_instant(pf->trace,ts,0,"module revision");break;
	case PROFILE_EVENT_MODULE_LOADED:pftrace_instant(pf->trace,ts,0,"module loaded");break;
	case PROFILE_EVENT_RECORDING:if(size>=4)pftrace_instant(pf->trace,ts,0,payload[0]?"recording resumed":"recording paused");break;
	case PROFILE_EVENT_COUNTER:if(size>8){double value;uint64_t bits=u64(payload);memcpy(&value,&bits,sizeof(value));if(!(text=pf_text(payload+8,size-8)))return 0;pftrace_counter(pf->trace,ts,text,NULL,value);free(text);}break;
	/* Each sample stands for interval allocations' worth of bytes, so the running sum estimates the bytes allocated. */
	case PROFILE_EVENT_ALLOCATION_SAMPLE:if(size>=20){pf->sampled_allocation_bytes+=(double)u64(payload+8)*u32(payload+16);pftrace_counter(pf->trace,ts,"Allocated bytes (sampled estimate)","bytes",pf->sampled_allocation_bytes);}break;
	case PROFILE_EVENT_GC_STATS:
		if(size==40){uint64_t allocated=u64(payload),heap=u64(payload+16),collections=u64(payload+24),mark=u64(payload+32);double seconds=pf->gc.valid?time-pf->gc.time:0;
			pftrace_counter(pf->trace,ts,"GC heap","bytes",(double)heap);
			pftrace_counter(pf->trace,ts,"GC allocated","bytes",(double)allocated);
			pftrace_counter(pf->trace,ts,"GC collections",NULL,(double)collections);
			pftrace_counter(pf->trace,ts,"GC mark time","ns",(double)mark*1000.0);
			if(seconds>0)pftrace_counter(pf->trace,ts,"GC allocation rate","bytes/s",(allocated-pf->gc.allocated)/seconds);
			pf->gc.allocated=allocated;pf->gc.collections=collections;pf->gc.mark_micros=mark;pf->gc.time=time;pf->gc.valid=1;}
		break;
	}
	return 1;
}
static int consume( symbols *s,unsigned char *pending,size_t *length,uint64_t *samples,uint64_t *unresolved,folded_table *folded_stacks,int show_lines,int raw_leaf,int *metadata_dirty,FILE *perfetto,int *perfetto_first,double *time_origin,uint32_t pid,pf_export *pf ) {
	size_t pos=0;while(*length-pos>=4){uint32_t body=u32(pending+pos);if(body<20||body>(8U<<20))return 0;if(*length-pos<(size_t)body+4)break;
		double event_time=0;if(perfetto||pf){uint64_t time_bits=u64(pending+pos+8);memcpy(&event_time,&time_bits,sizeof(event_time));if(time_origin&&*time_origin<0)*time_origin=event_time;}
		if(pending[pos+4]==1){uint32_t frames=u32(pending+pos+20),tid=u32(pending+pos+16);uint64_t leaf_pc=frames?u64(pending+pos+24):0;symbol *raw_symbol=frames?resolve(s,leaf_pc):NULL;native_symbol *raw_native=frames?resolve_native(leaf_pc):NULL;source_line *raw_line=raw_symbol?resolve_line(raw_symbol,leaf_pc):NULL;if(body!=20+frames*8U)return 0;symbol *leaf=NULL;native_symbol *native_leaf=NULL;source_line *leaf_line=NULL;char *stack=NULL;size_t stack_len=0,stack_cap=0;(*samples)++;for(uint32_t i=0;i<frames;i++){uint64_t pc=u64(pending+pos+24+i*8);symbol *x=resolve(s,pc);native_symbol *native=x?NULL:resolve_native(pc);if(x){source_line *line=resolve_line(x,pc);x->total++;if(line)line->total++;if(!leaf){leaf=x;leaf_line=line;}}else if(native){if(!leaf&&!native_leaf)native_leaf=native;}else(*unresolved)++;}
			if(perfetto&&perfetto_threads[tid&4095]!=tid){perfetto_threads[tid&4095]=tid;perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"M\",\"name\":\"thread_name\",\"pid\":%u,\"tid\":%u,\"args\":{\"name\":\"Thread %u\"}}",pid,tid,tid);}
			if(leaf)leaf->self++;
			if(leaf_line)leaf_line->self++;
			if(raw_leaf&&frames){if(raw_symbol){printf("leaf_pc=0x%llx offset=0x%llx function=%s",(unsigned long long)leaf_pc,(unsigned long long)(leaf_pc-raw_symbol->start),raw_symbol->name);if(raw_line)printf(" opcode=%u opcode_kind=%u location=%s:%u",raw_line->opcode_index,raw_line->opcode,raw_line->file,raw_line->line);putchar('\n');}else if(raw_native)printf("leaf_pc=0x%llx offset=0x%llx function=%s module=%s\n",(unsigned long long)leaf_pc,(unsigned long long)(leaf_pc-raw_native->base),raw_native->name,raw_native->module);else printf("leaf_pc=0x%llx offset=? function=[native/unknown]\n",(unsigned long long)leaf_pc);}
			if(folded_stacks||perfetto){for(uint32_t i=launcher_trimmed(s,pending+pos+24,frames);i>0;i--){uint64_t pc=u64(pending+pos+24+(i-1)*8);symbol *x=resolve(s,pc);native_symbol *native=x?NULL:resolve_native(pc);source_line *line=x?resolve_line(x,pc):NULL;char label[1536];const char *name;if(show_lines&&line){snprintf(label,sizeof(label),"%s (%s:%u)",x->name,line->file,line->line);name=label;}else if(native){if(pc==native->base&&native->module[0]=='[')snprintf(label,sizeof(label),"%s",native->name);else snprintf(label,sizeof(label),"%s+0x%llx (%s)",native->name,(unsigned long long)(pc-native->base),native->module);name=label;}else name=x?x->name:"[unknown]";size_t n=strlen(name),need=stack_len+n+(stack_len?1:0)+1;if(need>stack_cap){size_t cap=stack_cap?stack_cap*2:256;while(cap<need)cap*=2;char *next=(char*)realloc(stack,cap);if(!next){free(stack);return 0;}stack=next;stack_cap=cap;}if(stack_len)stack[stack_len++]=';';memcpy(stack+stack_len,name,n);stack_len+=n;stack[stack_len]=0;}}
			if(folded_stacks&&stack&&!folded_add(folded_stacks,stack)){free(stack);return 0;}
			if(perfetto){perfetto_begin_event(perfetto,perfetto_first);fputs("{\"ph\":\"i\",\"s\":\"t\",\"cat\":\"hl.sample\",\"name\":",perfetto);json_string(perfetto,leaf?leaf->name:native_leaf?native_leaf->name:"sample");fprintf(perfetto,",\"pid\":%u,\"tid\":%u,\"ts\":%.3f,\"args\":{\"stack\":",pid,tid,(event_time-*time_origin)*1000000.0);json_string(perfetto,stack?stack:"");fprintf(perfetto,",\"gc_stop\":%s",(pending[pos+5]&1)?"true":"false");if(leaf_line){fputs(",\"file\":",perfetto);json_string(perfetto,leaf_line->file);fprintf(perfetto,",\"line\":%u",leaf_line->line);}fputs("}}",perfetto);if(pending[pos+5]&1){perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"t\",\"cat\":\"hl.gc\",\"name\":\"GC stop sample\",\"pid\":%u,\"tid\":%u,\"ts\":%.3f}",pid,tid,(event_time-*time_origin)*1000000.0);}}
			free(stack);
			if(pf&&frames&&!pf_sample(pf,s,event_time,tid,pending+pos+24,launcher_trimmed(s,pending+pos+24,frames),pending[pos+5]&1))return 0;
		}else if(pending[pos+4]==2){uint32_t tid=u32(pending+pos+16),event_id=u32(pending+pos+20),payload_size=body-20;const unsigned char *payload=pending+pos+24;if(metadata_dirty&&((event_id==PROFILE_EVENT_MODULE_REVISION&&body==32)||(event_id==PROFILE_EVENT_MODULE_LOADED&&body==28)))*metadata_dirty=1;
			if(event_id==PROFILE_EVENT_NATIVE_SYMBOL&&payload_size>=24){uint32_t module_len=u32(payload+16),name_len=u32(payload+20);if(module_len>payload_size-24||name_len!=payload_size-24-module_len||!add_native(u64(payload),u64(payload+8),payload+24,module_len,payload+24+module_len,name_len))return 0;}
			if(event_id==PROFILE_EVENT_NATIVE_LOCATION&&!add_native_location(payload,payload_size))return 0;
			if(pf&&!pf_event(pf,event_time,tid,event_id,payload,payload_size))return 0;
			if(perfetto&&(event_id==0x484C2001U||event_id==0x484C2002U)){
                if(!perfetto_span_event(perfetto,perfetto_first,pid,tid,event_id==0x484C2001U?PROFILE_EVENT_SPAN_BEGIN:PROFILE_EVENT_SPAN_END,payload,payload_size,
                    (event_time-*time_origin)*1000000.0))return 0;
            }
			else if(perfetto&&event_id==0x484C2003U&&payload_size==8){double end;memcpy(&end,payload,8);perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"X\",\"cat\":\"hl.profiler\",\"name\":\"profiler stall\",\"pid\":%u,\"tid\":%u,\"ts\":%.3f,\"dur\":%.3f}",pid,tid,(event_time-*time_origin)*1000000.0,(end-event_time)*1000000.0);}
			else if(perfetto&&(event_id==PROFILE_EVENT_SPAN_BEGIN||event_id==PROFILE_EVENT_SPAN_END)){
                if(!perfetto_span_event(perfetto,perfetto_first,pid,tid,event_id,payload,payload_size,
                    (event_time-*time_origin)*1000000.0))return 0;
            }
            else if(perfetto&&(event_id==PROFILE_EVENT_THREAD_NAME||event_id==0x484C2006U)){char *name=(char*)malloc((size_t)payload_size+1);if(!name)return 0;memcpy(name,payload,payload_size);name[payload_size]=0;perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"M\",\"name\":\"thread_name\",\"pid\":%u,\"tid\":%u,\"args\":{\"name\":",pid,tid);json_string(perfetto,name);fputs("}}",perfetto);free(name);}
			else if(perfetto&&event_id==PROFILE_EVENT_GC_STATS&&payload_size==40){uint64_t allocated=u64(payload),allocations=u64(payload+8),heap=u64(payload+16),collections=u64(payload+24),mark=u64(payload+32);double seconds=perfetto_gc.valid?event_time-perfetto_gc.time:0,allocation_rate=seconds>0?(allocated-perfetto_gc.allocated)/seconds:0,collection_rate=seconds>0?(collections-perfetto_gc.collections)/seconds:0,mark_rate=seconds>0?(mark-perfetto_gc.mark_micros)/seconds:0;perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"C\",\"cat\":\"hl.gc\",\"name\":\"HashLink GC\",\"pid\":%u,\"tid\":0,\"ts\":%.3f,\"args\":{\"heap_bytes\":%llu,\"allocated_bytes\":%llu,\"allocation_bytes_per_second\":%.3f,\"allocations\":%llu,\"collections\":%llu,\"collections_per_second\":%.3f,\"mark_micros\":%llu,\"mark_micros_per_second\":%.3f}}",pid,(event_time-*time_origin)*1000000.0,(unsigned long long)heap,(unsigned long long)allocated,allocation_rate,(unsigned long long)allocations,(unsigned long long)collections,collection_rate,(unsigned long long)mark,mark_rate);perfetto_gc.allocated=allocated;perfetto_gc.allocations=allocations;perfetto_gc.collections=collections;perfetto_gc.mark_micros=mark;perfetto_gc.time=event_time;perfetto_gc.valid=1;}
			else if(perfetto&&event_id==PROFILE_EVENT_ALLOCATION_SAMPLE&&payload_size>=32&&(payload_size-32)%8==0){uint32_t interval=u32(payload+16),type_kind=u32(payload+20),frames=u32(payload+24);char allocation_stack[4096];size_t allocation_len=0;allocation_stack[0]=0;if(frames!=(payload_size-32)/8)return 0;for(uint32_t i=frames;i>0;i--){uint64_t pc=u64(payload+32+(i-1)*8);symbol *x=resolve(s,pc);native_symbol *native=x?NULL:resolve_native(pc);char label[1024];if(x)snprintf(label,sizeof(label),"%s",x->name);else if(native)snprintf(label,sizeof(label),"%s+0x%llx",native->name,(unsigned long long)(pc-native->base));else snprintf(label,sizeof(label),"0x%llx",(unsigned long long)pc);size_t n=strlen(label);if(allocation_len+n+(allocation_len?1:0)>=sizeof(allocation_stack))break;if(allocation_len)allocation_stack[allocation_len++]=';';memcpy(allocation_stack+allocation_len,label,n+1);allocation_len+=n;}perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"t\",\"cat\":\"hl.alloc\",\"name\":\"allocation sample\",\"pid\":%u,\"tid\":%u,\"ts\":%.3f,\"args\":{\"requested_bytes\":%llu,\"allocated_bytes\":%llu,\"estimated_bytes\":%llu,\"sample_interval\":%u,\"type_kind\":%u,\"stack\":",pid,tid,(event_time-*time_origin)*1000000.0,(unsigned long long)u64(payload),(unsigned long long)u64(payload+8),(unsigned long long)(u64(payload+8)*interval),interval,type_kind);json_string(perfetto,allocation_stack);fputs("}}",perfetto);}
			else if(perfetto&&event_id==PROFILE_EVENT_COUNTER&&payload_size>8){double value;uint64_t bits=u64(payload);char *name;memcpy(&value,&bits,sizeof(value));if(!(name=(char*)malloc((size_t)payload_size-7)))return 0;memcpy(name,payload+8,payload_size-8);name[payload_size-8]=0;perfetto_begin_event(perfetto,perfetto_first);fputs("{\"ph\":\"C\",\"cat\":\"hl.counter\",\"name\":",perfetto);json_string(perfetto,name);fprintf(perfetto,",\"pid\":%u,\"tid\":0,\"ts\":%.3f,\"args\":{\"value\":%.17g}}",pid,(event_time-*time_origin)*1000000.0,value);free(name);}
			else if(perfetto&&event_id==PROFILE_EVENT_RECORDING){if(payload_size>=4){perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"g\",\"cat\":\"hl.profiler\",\"name\":\"%s\",\"pid\":%u,\"tid\":%u,\"ts\":%.3f}",payload[0]?"recording resumed":"recording paused",pid,tid,(event_time-*time_origin)*1000000.0);}}
			else if(perfetto&&event_id!=PROFILE_EVENT_NATIVE_SYMBOL&&event_id!=PROFILE_EVENT_NATIVE_LOCATION&&event_id!=PROFILE_EVENT_MODULE_LOADED&&event_id!=PROFILE_EVENT_STARTUP&&event_id!=PROFILE_EVENT_DROPPED_CALLS&&(event_id<0x484C2004U||event_id>0x484C2008U)){perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"t\",\"cat\":\"hl.event\",\"name\":\"event %u\",\"pid\":%u,\"tid\":%u,\"ts\":%.3f,\"args\":{\"payload\":\"",event_id,pid,tid,(event_time-*time_origin)*1000000.0);for(uint32_t i=0;i<payload_size;i++)fprintf(perfetto,"%02x",payload[i]);fputs("\"}}",perfetto);}}
		pos+=body+4;if(metadata_dirty&&*metadata_dirty)break;}
	if(pos){memmove(pending,pending+pos,*length-pos);*length-=pos;}return 1;
}
/* ---- HLDI v2 sessions and HLPC v2 captures ------------------------------------------------------------------------
 * The runtime pushes frames during a session; the recorder writes each one as a capture record of the same type.
 * Exports decode the per-thread records and turn them into the stream records consume() already reads, with a few
 * export-only event ids for what v1 had no record for. docs/PROFILER.md in Haxeon describes both formats.
 */
enum { P_START=16, P_STOP=17, P_PAUSE=18, P_RESUME=19 };
enum { PUSH_METADATA=4, PUSH_SESSION=16, PUSH_DATA=17, PUSH_CLOCK=18, PUSH_THREADS=19, PUSH_END=20, PUSH_STATS=21, PUSH_RECORDING=22, CAPTURE_COMPLETE=3 };

/* Recording controls: start paused, stop once the capture reaches max_bytes (0: no limit). At a console, Enter pauses
   and resumes recording. */
static int start_paused;
static uint64_t max_bytes;
/* The session drops calls shorter than this as they exit (0 keeps every call). */
static uint32_t min_call_ns;

static int console_toggle_available( void ) {
#ifdef _WIN32
	return _isatty(_fileno(stdin));
#else
	return isatty(STDIN_FILENO);
#endif
}

/* Whether Enter was pressed at the console since the last call. */
static int console_toggle( void ) {
#ifdef _WIN32
	int pressed=0;
	if(!console_toggle_available())return 0;
	while(_kbhit()){int c=_getch();if(c=='\r'||c=='\n')pressed=1;}
	return pressed;
#else
	fd_set set;struct timeval none={0,0};char line[256];
	if(!console_toggle_available())return 0;
	FD_ZERO(&set);FD_SET(STDIN_FILENO,&set);
	if(select(STDIN_FILENO+1,&set,NULL,NULL,&none)<=0)return 0;
	return fgets(line,sizeof(line),stdin)!=NULL;
#endif
}
enum { F_PUSH=4 };
#define PAD8_64(n) (((uint64_t)(n)+7)&~7ULL)
/* Larger capture records are malformed: the runtime never pushes a frame over 256 MiB. */
#define MAX_RECORD (256U<<20)
enum { SOURCE_INSTRUMENT=1, SOURCE_SAMPLING=2, SOURCE_ALLOC=4 };
enum { R_ENTER=0x01, R_EXIT=0x02, R_UNWIND=0x03, R_SPAN_BEGIN=0x10, R_SPAN_END=0x11, R_FRAME_MARK=0x12, R_FRAME_IDLE=0x13, R_EVENT=0x20, R_COUNTER=0x21, R_SAMPLE=0x22, R_STALL=0x30 };
/* Export-only events synthesized from v2 records. */
#define EXPORT_CALL_BEGIN 0x484C2001U
#define EXPORT_CALL_END 0x484C2002U
#define EXPORT_STALL 0x484C2003U
/* The main frame set's boundaries on the thread that marked them: a frame starts (payload: its name) or the thread idles. */
#define EXPORT_FRAME_BEGIN 0x484C2004U
#define EXPORT_FRAME_IDLE 0x484C2005U
/* A process-level track (payload: its name) for the slices of a pseudo-thread. */
#define EXPORT_PROCESS_TRACK 0x484C2006U
/* A runtime startup phase begins (payload: its name) or ends: a call that leaves the thread's samples shown. */
#define EXPORT_PHASE_BEGIN 0x484C2007U
#define EXPORT_PHASE_END 0x484C2008U
#define FRAME_TRACK_TID 0x7FFFF000U
#define TICK_MASK 0x00FFFFFFFFFFFFFFULL

static int parse_sources( const char *list ) {
	int sources=0;const char *p=list;
	while(*p){const char *end=strchr(p,',');size_t n=end?(size_t)(end-p):strlen(p);
		if(n==10&&!strncmp(p,"instrument",n))sources|=SOURCE_INSTRUMENT;else if(n==8&&!strncmp(p,"sampling",n))sources|=SOURCE_SAMPLING;else if(n==5&&!strncmp(p,"alloc",n))sources|=SOURCE_ALLOC;else return -1;
		p+=n;if(*p==',')p++;}
	return sources;
}

/* Writes the pushed frames of one session to path until the runtime ends it, the program exits, or the recorder is
   interrupted or reaches its duration. */
static int record_session( socket_t sock,const char *output_path,uint32_t pid,int sources,int rate,int allocation_interval,int pool_mib,int duration,int interval ) {
	unsigned char start[24],header[16],*payload=NULL,record[16];uint32_t id=1,payload_cap=0,stop_id=0;int code=1,ended=0,stop_sent=0;
	uint64_t frames=0,bytes=0,raw=0,last_raw=0;double started=monotime(),next_report=started+interval/1000.0,stop_deadline=0,last_report=started;
	/* Duration counts recorded time: a paused session's clock stands still. */
	int recording=1;double recording_since=started,recorded_seconds=0;uint64_t dropped=0;
	FILE *out=NULL;unsigned char file_header[24];uint32_t chunks_in_use=0,chunk_count=0;uint64_t stalls=0,lost=0;
	if(output_path){out=fopen(output_path,"wb");if(!out){fprintf(stderr,"Could not open capture file %s\n",output_path);return 1;}setvbuf(out,NULL,_IOFBF,1<<20);
		memcpy(file_header,"HLPC",4);file_header[4]=2;file_header[5]=0;file_header[6]=24;file_header[7]=0;put32(file_header+8,0);put32(file_header+12,pid);put32(file_header+16,(uint32_t)rate);put32(file_header+20,(uint32_t)sources);
		if(fwrite(file_header,1,24,out)!=24)goto done;}
	put32(start,(uint32_t)sources);put32(start+4,(uint32_t)rate);put32(start+8,(uint32_t)allocation_interval);put32(start+12,(uint32_t)pool_mib);put32(start+16,start_paused?1:0);put32(start+20,min_call_ns);
	{unsigned char h[16];uint32_t length=min_call_ns?24:start_paused?20:16;h[0]=SVC_PROFILE;h[1]=P_START;h[2]=h[3]=0;put32(h+4,id++);put32(h+8,length);put32(h+12,0);if(!send_all(sock,h,16)||!send_all(sock,start,length)){fprintf(stderr,"Could not start the session\n");goto done;}}
	recording=!start_paused;recording_since=started;
	printf("%s HashLink process %u (sources 0x%x)\n",start_paused?"Connected to":"Recording",pid,sources);if(min_call_ns)printf("dropping calls shorter than %.3g us\n",min_call_ns/1000.0);
	if(start_paused)printf("recording paused until the program starts it (haxeon.ProfileRecording)%s\n",console_toggle_available()?" or Enter is pressed":"");
	fflush(stdout);
	signal(SIGINT,stop_signal);
#ifdef SIGTERM
	signal(SIGTERM,stop_signal);
#endif
	while(!ended){
		double now=monotime();fd_set set;struct timeval wait={0,100000};int ready;
		if(!stop_sent&&console_toggle()){unsigned char h[16];h[0]=SVC_PROFILE;h[1]=recording?P_PAUSE:P_RESUME;h[2]=h[3]=0;put32(h+4,id++);put32(h+8,0);put32(h+12,0);if(!send_all(sock,h,16))break;}
		if(!stop_sent&&max_bytes&&bytes>=max_bytes&&!interrupted){fprintf(stderr,"The capture reached its size limit (%.0f MiB); stopping\n",max_bytes/1048576.0);interrupted=1;}
		if(!stop_sent&&(interrupted||(duration&&recorded_seconds+(recording?now-recording_since:0)>=duration))){unsigned char h[16];stop_id=id++;h[0]=SVC_PROFILE;h[1]=P_STOP;h[2]=h[3]=0;put32(h+4,stop_id);put32(h+8,0);put32(h+12,0);if(!send_all(sock,h,16))break;stop_sent=1;stop_deadline=now+10;}
		if(stop_sent&&now>stop_deadline){fprintf(stderr,"The runtime did not end the session in time\n");break;}
		if(interval>0&&now>=next_report){double seconds=now-last_report;printf("recorded %.1f MiB (%.1f MiB/s), %llu frames, chunks %u/%u, stalls %llu\n",raw/1048576.0,seconds>0?(raw-last_raw)/1048576.0/seconds:0.0,(unsigned long long)frames,chunks_in_use,chunk_count,(unsigned long long)stalls);fflush(stdout);last_raw=raw;last_report=now;next_report=now+interval/1000.0;}
		FD_ZERO(&set);FD_SET(sock,&set);ready=select((int)sock+1,&set,NULL,NULL,&wait);
		if(ready<0)break;if(ready==0)continue;
		if(!recv_all(sock,header,16)){if(!stop_sent)fprintf(stderr,"Profiler target disconnected; finalizing capture\n");break;}
		{uint32_t size=u32(header+8),flags=u16(header+2),type=header[1];
			if(size>(256U<<20)){fprintf(stderr,"Oversized frame\n");goto done;}
			if(size>payload_cap){unsigned char *p=(unsigned char*)realloc(payload,size);if(!p)goto done;payload=p;payload_cap=size;}
			if(size&&!recv_all(sock,payload,size)){fprintf(stderr,"Profiler target disconnected; finalizing capture\n");break;}
			if(flags&F_ERROR){fprintf(stderr,"The runtime refused request type %u\n",type);if(type==P_START)goto done;continue;}
			if(!(flags&F_PUSH))continue;
			if(type==PUSH_DATA&&size>=16)raw+=u32(payload+8);
			if(type==PUSH_STATS&&size>=16){chunks_in_use=u32(payload);chunk_count=u32(payload+4);stalls=u64(payload+8);if(size>=48)lost=u64(payload+40);}
			if(type==PUSH_RECORDING&&size>=4&&(u32(payload)!=0)!=recording){double at=monotime();
				if(recording)recorded_seconds+=at-recording_since;else recording_since=at;
				recording=u32(payload)!=0;printf("recording %s\n",recording?"resumed":"paused");fflush(stdout);}
			/* Over the size limit, records the runtime pushes before it handles the stop are dropped; everything else is
			   kept, so the capture stays complete and ends where the limit was reached. */
			if(type==PUSH_DATA&&max_bytes&&bytes>=max_bytes){dropped+=size;continue;}
			if(out){put32(record,type);put32(record+4,size);put64(record+8,(uint64_t)((monotime()-started)*1e9));if(fwrite(record,1,16,out)!=16||(size&&fwrite(payload,1,size,out)!=size)){fprintf(stderr,"Capture write failed\n");goto done;}}
			frames++;bytes+=size;
			if(type==PUSH_END)ended=1;}
	}
	if(out&&ended){unsigned char end[16];put64(end,frames);put64(end+8,bytes);put32(record,CAPTURE_COMPLETE);put32(record+4,16);put64(record+8,(uint64_t)((monotime()-started)*1e9));if(fwrite(record,1,16,out)!=16||fwrite(end,1,16,out)!=16)goto done;}
	if(!ended)fprintf(stderr,"warning: the session ended without its final frame; the capture is partial\n");
	printf("recorded %.1f MiB of records in %llu frames\n",raw/1048576.0,(unsigned long long)frames);
	if(dropped)printf("dropped %.1f MiB pushed after the size limit\n",dropped/1048576.0);
	if(lost)fprintf(stderr,"warning: the runtime lost %llu records written while its buffers were full\n",(unsigned long long)lost);
	code=0;
done:
	free(payload);if(out&&fclose(out)!=0){fprintf(stderr,"Capture finalization failed\n");code=1;}
	return code;
}

/* ---- decoding ---- */

typedef struct { uint64_t ticks,ns; } clock_pair;
typedef struct { clock_pair *pairs; size_t count,capacity; uint64_t nominal_hz,origin_ns; } tick_clock;
static int clock_add( tick_clock *c,uint64_t ticks,uint64_t ns ) {
	if(c->count&&ticks<=c->pairs[c->count-1].ticks)return 1;
	if(c->count==c->capacity){size_t cap=c->capacity?c->capacity*2:256;clock_pair *p=(clock_pair*)realloc(c->pairs,cap*sizeof(clock_pair));if(!p)return 0;c->pairs=p;c->capacity=cap;}
	c->pairs[c->count].ticks=ticks;c->pairs[c->count].ns=ns;c->count++;return 1;
}
/* Seconds since the session's first clock pair, interpolated between pairs and extrapolated past the ends. */
static double clock_seconds( tick_clock *c,uint64_t ticks ) {
	size_t lo=0,hi;double rate;const clock_pair *a,*b;
	if(c->count==0)return c->nominal_hz?(double)ticks/(double)c->nominal_hz:(double)ticks/1e9;
	if(c->count==1){rate=c->nominal_hz?1e9/(double)c->nominal_hz:1.0;return ((double)c->pairs[0].ns-(double)c->origin_ns+((double)ticks-(double)c->pairs[0].ticks)*rate)/1e9;}
	hi=c->count;while(lo<hi){size_t m=(lo+hi)>>1;if(c->pairs[m].ticks<=ticks)lo=m+1;else hi=m;}
	if(lo==0)lo=1;if(lo>=c->count)lo=c->count-1;
	a=c->pairs+lo-1;b=c->pairs+lo;rate=(double)(b->ns-a->ns)/(double)(b->ticks-a->ticks);
	return ((double)a->ns-(double)c->origin_ns+((double)ticks-(double)a->ticks)*rate)/1e9;
}

/* A thread's open calls (kind 1), spans (2) and hidden calls (3: a thread-start wrapper, which counts as a call but has no
   slice). named: the thread has a name, from the runtime or from its entry function. */
typedef struct { uint32_t tid; int used,named; unsigned char *kinds; uint32_t count,capacity,calls,pause; } open_stack;
#define OPEN_STACKS 65536
static open_stack open_stacks[OPEN_STACKS];
static open_stack *stack_of( uint32_t tid ) {
	uint32_t slot=(tid*2654435761U)&(OPEN_STACKS-1);
	for(uint32_t i=0;i<OPEN_STACKS;i++){open_stack *s=open_stacks+((slot+i)&(OPEN_STACKS-1));if(!s->used){s->used=1;s->tid=tid;return s;}if(s->tid==tid)return s;}
	fprintf(stderr,"The capture has more than %d threads, which the export cannot hold\n",OPEN_STACKS);
	return NULL;
}
static int stack_push( open_stack *s,unsigned char kind ) {
	if(s->count==s->capacity){uint32_t cap=s->capacity?s->capacity*2:64;unsigned char *k=(unsigned char*)realloc(s->kinds,cap);if(!k)return 0;s->kinds=k;s->capacity=cap;}
	s->kinds[s->count++]=kind;if(kind!=2)s->calls++;return 1;
}
static void stacks_free( void ){for(int i=0;i<OPEN_STACKS;i++)free(open_stacks[i].kinds);memset(open_stacks,0,sizeof(open_stacks));}

/* Pauses within the session (PROFILE_EVENT_RECORDING 0), collected in pass 1. Calls that ran while recording was paused
   went unrecorded, so each thread's open calls end at a pause and its stack starts empty after it. */
typedef struct { uint64_t ticks; uint32_t tid; } recording_pause;
static recording_pause *pauses;static uint32_t pause_count,pause_capacity;
static int pause_compare( const void *a,const void *b ){uint64_t x=((const recording_pause*)a)->ticks,y=((const recording_pause*)b)->ticks;return x<y?-1:x>y?1:0;}
/* Also from pass 1: the thread that marks the main frames, and the runtime's startup phases (PROFILE_EVENT_STARTUP). */
static uint32_t frame_thread;
/* The frame thread's dropped short calls, summed per frame in pass 1, so pass 2 writes each frame's total where the frame
   starts rather than where its last count arrives, which can be later than the reorder window. The runtime writes counts
   whenever a thread's table fills and at each frame boundary, right after the boundary's record, so the counts that follow
   a boundary close the frame before it. Frame i starts at tick frame_drop_starts[i]: 0 for the one before the first
   boundary. Pass 2 finds frames by tick, since a window skips some boundaries. */
static uint64_t *frame_drops,*frame_drop_starts;static uint32_t frame_drop_count,frame_drop_capacity,frame_drop_cursor;static uint64_t frame_drop_running,frame_drop_start;static int frame_drop_follows;
/* Other threads' counts in pass 1, until one of them turns out to be the frame thread. */
typedef struct { uint32_t tid; int used; uint64_t total; } thread_drops;
static thread_drops early_drops[OPEN_STACKS];
static thread_drops *early_drops_of( uint32_t tid ) {
	uint32_t slot=(tid*2654435761U)&(OPEN_STACKS-1);
	for(uint32_t i=0;i<OPEN_STACKS;i++){thread_drops *d=early_drops+((slot+i)&(OPEN_STACKS-1));if(!d->used){d->used=1;d->tid=tid;return d;}if(d->tid==tid)return d;}
	return NULL;
}
/* Ends the frame thread's current frame; the next starts at next_start. */
static int frame_drops_close( uint64_t next_start ) {
	if(frame_drop_count==frame_drop_capacity){uint32_t cap=frame_drop_capacity?frame_drop_capacity*2:1024;uint64_t *totals=(uint64_t*)realloc(frame_drops,cap*sizeof(uint64_t)),*starts;
		if(!totals)return 0;frame_drops=totals;if(!(starts=(uint64_t*)realloc(frame_drop_starts,cap*sizeof(uint64_t))))return 0;frame_drop_starts=starts;frame_drop_capacity=cap;}
	frame_drop_starts[frame_drop_count]=frame_drop_start;frame_drops[frame_drop_count++]=frame_drop_running;frame_drop_running=0;frame_drop_start=next_start;return 1;
}
/* The dropped calls of the frame starting at ticks, or -1 if none starts there. */
static double frame_drops_at( uint64_t ticks ) {
	while(frame_drop_cursor<frame_drop_count&&frame_drop_starts[frame_drop_cursor]<ticks)frame_drop_cursor++;
	return frame_drop_cursor<frame_drop_count&&frame_drop_starts[frame_drop_cursor]==ticks?(double)frame_drops[frame_drop_cursor]:-1;
}
static unsigned char *startup;static uint32_t startup_size;
/* Whether a thread's first call is its entry function, so it can name the thread: see decode_records. */
static int entry_names;
static int add_pause( uint64_t ticks,uint32_t tid ) {
	if(pause_count==pause_capacity){uint32_t cap=pause_capacity?pause_capacity*2:16;recording_pause *p=(recording_pause*)realloc(pauses,cap*sizeof(*p));if(!p)return 0;pauses=p;pause_capacity=cap;}
	pauses[pause_count].ticks=ticks;pauses[pause_count].tid=tid;pause_count++;return 1;
}

typedef struct { unsigned char *data; size_t length,capacity; } byte_buffer;
static int out_reserve( byte_buffer *o,size_t n ) {
	if(o->length+n<=o->capacity)return 1;
	size_t cap=o->capacity?o->capacity:1<<20;while(cap<o->length+n)cap*=2;
	unsigned char *p=(unsigned char*)realloc(o->data,cap);if(!p)return 0;o->data=p;o->capacity=cap;return 1;
}
/* A record in the shape consume() reads: body length, kind (1 sample, 2 event), flags, time in seconds, tid, value. */
static int synth( byte_buffer *o,int kind,int flags,double time,uint32_t tid,uint32_t value,const void *a,uint32_t a_size,const void *b,uint32_t b_size ) {
	uint32_t body=20+a_size+b_size;unsigned char *p;uint64_t bits;
	if(!out_reserve(o,4+(size_t)body))return 0;
	p=o->data+o->length;put32(p,body);p[4]=(unsigned char)kind;p[5]=(unsigned char)flags;p[6]=p[7]=0;memcpy(&bits,&time,8);put64(p+8,bits);put32(p+16,tid);put32(p+20,value);
	if(a_size)memcpy(p+24,a,a_size);if(b_size)memcpy(p+24+a_size,b,b_size);
	o->length+=4+(size_t)body;return 1;
}
static int synth_event( byte_buffer *o,double time,uint32_t tid,uint32_t id,const void *payload,uint32_t size ){return synth(o,2,0,time,tid,id,payload,size,NULL,0);}
static int synth_counter( byte_buffer *o,double time,uint32_t tid,const char *name,double value ){unsigned char v[8];uint64_t bits;memcpy(&bits,&value,8);put64(v,bits);return synth(o,2,0,time,tid,PROFILE_EVENT_COUNTER,v,8,name,(uint32_t)strlen(name));}

/* Data frames arrive in drain order, one thread's segment at a time, so records of different threads interleave only
   roughly in time: a sample can arrive before the frame mark that precedes it. The reorder window holds synthesized
   records and releases them in time order once they are REORDER_WINDOW seconds older than the newest record seen.
   Symbol and thread-name events are released first, so the samples that use them resolve. A record arriving after
   later records were released keeps its order by taking the last released time. A release sorts and compacts every
   record held, so it waits for REORDER_STEP seconds of new records; releasing after each data frame made an export
   quadratic in the records per window. */
#define REORDER_WINDOW 2.0
#define REORDER_STEP 0.5
typedef struct { double time; uint64_t seq; size_t offset; uint32_t length; } ordered_record;
typedef struct { byte_buffer data; ordered_record *index; size_t count,capacity; uint64_t seq,late; double newest,released,released_until; } reorder_buffer;
static int ordered_compare( const void *a,const void *b ) {
	const ordered_record *x=(const ordered_record*)a,*y=(const ordered_record*)b;
	if(x->time!=y->time)return x->time<y->time?-1:1;
	return x->seq<y->seq?-1:x->seq>y->seq?1:0;
}
static int reorder_add( reorder_buffer *r,const unsigned char *records,size_t length ) {
	size_t pos=0;
	while(length-pos>=24){uint32_t body=u32(records+pos);uint64_t bits=u64(records+pos+8);double time;
		if(length-pos<(size_t)body+4)break;
		memcpy(&time,&bits,8);
		if(records[pos+4]==2){uint32_t id=u32(records+pos+20);if(id==PROFILE_EVENT_NATIVE_SYMBOL||id==PROFILE_EVENT_NATIVE_LOCATION||id==PROFILE_EVENT_THREAD_NAME)time=-1e300;}
		if(time>r->newest)r->newest=time;
		if(r->count==r->capacity){size_t cap=r->capacity?r->capacity*2:65536;ordered_record *next=(ordered_record*)realloc(r->index,cap*sizeof(ordered_record));if(!next)return 0;r->index=next;r->capacity=cap;}
		if(!out_reserve(&r->data,(size_t)body+4))return 0;
		memcpy(r->data.data+r->data.length,records+pos,(size_t)body+4);
		r->index[r->count].time=time;r->index[r->count].seq=r->seq++;r->index[r->count].offset=r->data.length;r->index[r->count].length=body+4;r->count++;
		r->data.length+=(size_t)body+4;pos+=(size_t)body+4;}
	return 1;
}
/* Moves every record at or before `until` to out, in time order. */
static int reorder_release( reorder_buffer *r,double until,byte_buffer *out ) {
	size_t kept=0,released=0;byte_buffer rest={0};
	if(!r->count)return 1;
	qsort(r->index,r->count,sizeof(ordered_record),ordered_compare);
	while(released<r->count&&r->index[released].time<=until)released++;
	for(size_t i=0;i<released;i++){ordered_record *x=r->index+i;unsigned char *p;
		if(!out_reserve(out,x->length))return 0;
		p=out->data+out->length;memcpy(p,r->data.data+x->offset,x->length);out->length+=x->length;
		if(x->time>-1e299){if(x->time<r->released){uint64_t bits;memcpy(&bits,&r->released,8);put64(p+8,bits);r->late++;}else r->released=x->time;}}
	if(released==r->count){r->count=0;r->data.length=0;return 1;}
	if(!out_reserve(&rest,r->data.length))return 0;
	for(size_t i=released;i<r->count;i++){ordered_record *x=r->index+i;memcpy(rest.data+rest.length,r->data.data+x->offset,x->length);r->index[kept]=*x;r->index[kept].offset=rest.length;rest.length+=x->length;kept++;}
	free(r->data.data);r->data=rest;r->count=kept;
	return 1;
}

/* A UTF-16 or UTF-8 name from a record, as UTF-8. */
static uint32_t record_name( const unsigned char *p,uint32_t units,uint32_t encoding,char *out,uint32_t capacity ) {
	uint32_t n=0;
	if(encoding==1){n=units<capacity?units:capacity;memcpy(out,p,n);return n;}
	for(uint32_t i=0;i<units;i++){uint32_t c=u16(p+i*2);
		if(c>=0xD800&&c<0xDC00&&i+1<units){uint32_t d=u16(p+(i+1)*2);if(d>=0xDC00&&d<0xE000){c=0x10000+((c-0xD800)<<10)+(d-0xDC00);i++;}}
		if(c<0x80){if(n+1>capacity)break;out[n++]=(char)c;}
		else if(c<0x800){if(n+2>capacity)break;out[n++]=(char)(0xC0|(c>>6));out[n++]=(char)(0x80|(c&63));}
		else if(c<0x10000){if(n+3>capacity)break;out[n++]=(char)(0xE0|(c>>12));out[n++]=(char)(0x80|((c>>6)&63));out[n++]=(char)(0x80|(c&63));}
		else{if(n+4>capacity)break;out[n++]=(char)(0xF0|(c>>18));out[n++]=(char)(0x80|((c>>12)&63));out[n++]=(char)(0x80|((c>>6)&63));out[n++]=(char)(0x80|(c&63));}}
	return n;
}

/* The name of an instrumented function: its key is the function's code address. */
static uint32_t call_name( symbols *s,uint64_t key,char *out,uint32_t capacity ) {
	symbol *x=resolve(s,key);native_symbol *n;int written;
	if(x)written=snprintf(out,capacity,"%s",x->name);
	else if((n=resolve_native(key))!=NULL)written=snprintf(out,capacity,"%s",n->name);
	else written=snprintf(out,capacity,"[0x%llx]",(unsigned long long)key);
	return written<0?0:(uint32_t)written>=capacity?capacity-1:(uint32_t)written;
}

/* Calls the recorder dropped for being short (PROFILE_EVENT_DROPPED_CALLS), counted per call key over the window. */
typedef struct { uint64_t key,count; } short_call;
static short_call *short_calls;static size_t short_call_count,short_call_capacity;static uint64_t short_call_total;
static size_t short_call_slot( uint64_t key,size_t capacity ){return (size_t)((key*0x9E3779B97F4A7C15ULL)>>32)&(capacity-1);}
static int short_calls_add( uint64_t key,uint64_t count ) {
	size_t slot;
	if(!key||!count)return 1;
	if(short_call_count*2>=short_call_capacity){size_t cap=short_call_capacity?short_call_capacity*2:1024;short_call *next=(short_call*)calloc(cap,sizeof(short_call));if(!next)return 0;
		for(size_t i=0;i<short_call_capacity;i++)if(short_calls[i].key){size_t j=short_call_slot(short_calls[i].key,cap);while(next[j].key)j=(j+1)&(cap-1);next[j]=short_calls[i];}
		free(short_calls);short_calls=next;short_call_capacity=cap;}
	slot=short_call_slot(key,short_call_capacity);
	while(short_calls[slot].key&&short_calls[slot].key!=key)slot=(slot+1)&(short_call_capacity-1);
	if(!short_calls[slot].key){short_calls[slot].key=key;short_call_count++;}
	short_calls[slot].count+=count;short_call_total+=count;
	return 1;
}
static int short_call_compare( const void *a,const void *b ){uint64_t x=((const short_call*)a)->count,y=((const short_call*)b)->count;return x<y?1:x>y?-1:0;}
/* Prints the functions whose short calls were dropped most often. Ends the table's use. */
static void short_calls_report( symbols *s,int top ) {
	char name[256];size_t n=0;
	if(!short_call_total)return;
	for(size_t i=0;i<short_call_capacity;i++)if(short_calls[i].key)short_calls[n++]=short_calls[i];
	qsort(short_calls,n,sizeof(short_call),short_call_compare);
	printf("dropped %llu short calls to %zu functions; most often:\n",(unsigned long long)short_call_total,n);
	for(size_t i=0;i<n&&(int)i<top;i++){call_name(s,short_calls[i].key,name,sizeof(name));printf("%14llu  %s\n",(unsigned long long)short_calls[i].count,name);}
	free(short_calls);short_calls=NULL;short_call_count=short_call_capacity=0;short_call_total=0;
}

typedef struct { int open; uint64_t number; uint32_t tid; } frame_set_state;
static frame_set_state frame_sets[16];
/* Frames marked before the exported window, counted in pass 1, so a window's frames keep their numbers. */
static uint64_t frames_before_window[16];

/* Closes slices on a thread's track down to `calls` open calls (or every span when spans_only). */
static int close_slices( byte_buffer *o,open_stack *st,double time,uint32_t tid,uint32_t calls,int until_span ) {
	while(st->count){unsigned char kind=st->kinds[st->count-1];
		if(!until_span&&st->calls<=calls)break;
		st->count--;if(kind!=2)st->calls--;
		if(kind!=3&&!synth_event(o,time,tid,kind==1?EXPORT_CALL_END:PROFILE_EVENT_SPAN_END,NULL,0))return 0;
		if(until_span&&kind==2)break;}
	return 1;
}

/* A wrapper the C++ runtime runs a thread's function in. */
static int thread_wrapper( const char *name ) {
	return !strncmp(name,"std::thread::_Invoke<",21)||!strncmp(name,"std::__thread_proxy<",20)||!strncmp(name,"std::__1::__thread_proxy<",25);
}
/* Names a thread after its entry function's last two name components ("WorkerPool::worker_loop"), unless the function is a
   hooked system call ("kernel32!Sleep"), which says nothing about the thread. */
static int name_thread( byte_buffer *o,uint32_t tid,const char *function ) {
	const char *start=function,*last=NULL,*previous=NULL;int angle=0;
	if(strchr(function,'!'))return 1;
	for(const char *c=function;*c;c++){
		if(*c=='<')angle++;else if(*c=='>'&&angle)angle--;
		else if(!angle&&(*c=='.'||(c[0]==':'&&c[1]==':'))){previous=last;last=c;if(*c==':')c++;}}
	if(previous)start=previous+(*previous==':'?2:1);
	while(*start=='`')start++;
	if(!strncmp(start,"anonymous namespace'::",22))start+=22;
	return synth_event(o,0,tid,PROFILE_EVENT_THREAD_NAME,start,(uint32_t)strlen(start));
}

static int decode_records( byte_buffer *o,symbols *s,tick_clock *c,uint32_t tid,const unsigned char *p,uint32_t length,uint64_t *malformed ) {
	uint32_t pos=0;char name[1536];open_stack *st=stack_of(tid);
	if(!st)return 0;
	while(pos+8<=length){
		uint64_t w0=u64(p+pos);uint32_t kind=(uint32_t)(w0>>56);double time=clock_seconds(c,w0&TICK_MASK);uint32_t size=8;
		/* Crossing a pause: this thread's calls end there, and so does a frame it marked. */
		while(st->pause<pause_count&&pauses[st->pause].ticks<=(w0&TICK_MASK)){double at=clock_seconds(c,pauses[st->pause++].ticks);
			if(!close_slices(o,st,at,tid,0,0))return 0;
			for(uint32_t i=0;i<16;i++)if(frame_sets[i].open&&frame_sets[i].tid==tid){frame_sets[i].open=0;
				if(!synth_event(o,at,FRAME_TRACK_TID+i,PROFILE_EVENT_SPAN_END,NULL,0)||(i==0&&!synth_event(o,at,tid,EXPORT_FRAME_IDLE,NULL,0)))return 0;}}
		switch(kind){
		case R_ENTER:{if(pos+16>length)goto bad;uint32_t n=call_name(s,u64(p+pos+8),name,sizeof(name));size=16;
			/* A thread's entry function names it if the runtime did not; a thread-start wrapper around it is hidden. The thread
			   must have started while recording: when the session began before the program, the export starts with the capture
			   and no pause came first. A thread recording only from a later point would be named after whatever it called first. */
			if(!st->count&&thread_wrapper(name)){if(!stack_push(st,3))return 0;break;}
			if(!st->named&&(!st->count||(st->count==1&&st->kinds[0]==3))){st->named=1;if(entry_names&&!st->pause&&!name_thread(o,tid,name))return 0;}
			if(!stack_push(st,1)||!synth_event(o,time,tid,EXPORT_CALL_BEGIN,name,n))return 0;break;}
		case R_EXIT:if(st->calls&&!close_slices(o,st,time,tid,st->calls-1,0))return 0;break;
		case R_UNWIND:if(pos+16>length)goto bad;{uint64_t skipped=u64(p+pos+8);if(!close_slices(o,st,time,tid,skipped<st->calls?st->calls-(uint32_t)skipped:0,0))return 0;}size=16;break;
		case R_SPAN_BEGIN:{if(pos+16>length)goto bad;uint32_t units=u32(p+pos+8),encoding=u32(p+pos+12);uint64_t record=16+PAD8_64((uint64_t)units*(encoding==1?1:2));if(pos+record>length)goto bad;
			uint32_t n=record_name(p+pos+16,units,encoding,name,sizeof(name));if(!stack_push(st,2)||!synth_event(o,time,tid,PROFILE_EVENT_SPAN_BEGIN,name,n))return 0;size=(uint32_t)record;break;}
		case R_SPAN_END:{int has_span=0;for(uint32_t i=0;i<st->count;i++)if(st->kinds[i]==2)has_span=1;if(has_span&&!close_slices(o,st,time,tid,0,1))return 0;break;}
		case R_FRAME_MARK:case R_FRAME_IDLE:{if(pos+16>length)goto bad;uint64_t set=u64(p+pos+8);size=16;if(set>=16)break;frame_set_state *f=frame_sets+set;uint32_t frame_tid=FRAME_TRACK_TID+(uint32_t)set;
			if(f->open&&!synth_event(o,time,frame_tid,PROFILE_EVENT_SPAN_END,NULL,0))return 0;f->open=0;
			/* The frame (or idle stretch) starting here: its dropped calls, from pass 1. */
			if(set==0&&tid==frame_thread){double dropped=frame_drops_at(w0&TICK_MASK);if(dropped>=0&&!synth_counter(o,time,tid,"Short calls dropped per frame",dropped))return 0;}
			if(kind==R_FRAME_MARK){int n=snprintf(name,sizeof(name),"Frame %llu",(unsigned long long)++f->number);if(!synth_event(o,time,frame_tid,PROFILE_EVENT_SPAN_BEGIN,name,(uint32_t)n))return 0;f->open=1;f->tid=tid;
				if(set==0&&!synth_event(o,time,tid,EXPORT_FRAME_BEGIN,name,(uint32_t)n))return 0;}
			else if(set==0&&!synth_event(o,time,tid,EXPORT_FRAME_IDLE,NULL,0))return 0;
			break;}
		case R_EVENT:{if(pos+16>length)goto bad;uint32_t id=u32(p+pos+8),n=u32(p+pos+12);if(pos+16+PAD8_64(n)>length)goto bad;
			/* A name the thread recorded itself replaces one taken from its entry function. */
			if(id==PROFILE_EVENT_THREAD_NAME)st->named=1;
			if(id==PROFILE_EVENT_DROPPED_CALLS){for(uint32_t i=0;i+16<=n;i+=16)if(!short_calls_add(u64(p+pos+16+i),u32(p+pos+24+i)))return 0;}
			else if(!synth_event(o,time,tid,id,p+pos+16,n))return 0;size=16+((n+7)&~7u);break;}
		case R_COUNTER:{if(pos+24>length)goto bad;uint32_t units=u32(p+pos+16),encoding=u32(p+pos+20);uint64_t record=24+PAD8_64((uint64_t)units*(encoding==1?1:2));if(pos+record>length)goto bad;
			uint32_t n=record_name(p+pos+24,units,encoding,name,sizeof(name));if(!synth(o,2,0,time,tid,PROFILE_EVENT_COUNTER,p+pos+8,8,name,n))return 0;size=(uint32_t)record;break;}
		case R_SAMPLE:{if(pos+16>length)goto bad;uint64_t w1=u64(p+pos+8);uint32_t sample_tid=(uint32_t)w1,frames=(uint32_t)((w1>>32)&0xFFFF),flags=(uint32_t)((w1>>48)&0xFF);if(pos+16+(uint64_t)frames*8>length)goto bad;
			if(!synth(o,1,(int)flags,time,sample_tid,frames,p+pos+16,frames*8,NULL,0))return 0;size=16+frames*8;break;}
		case R_STALL:{if(pos+16>length)goto bad;double end=clock_seconds(c,u64(p+pos+8)&TICK_MASK);if(!synth_event(o,time,tid,EXPORT_STALL,&end,8))return 0;size=16;break;}
		default:goto bad;}
		pos+=size;}
	return 1;
bad:
	(*malformed)++;return 1;
}

/* Pass 1 over one thread's records: registers the native symbols they name, collects the pauses and finds the frame
   thread and the startup phases. Natively
   instrumented calls are named by their key when they are decoded, and the runtime names a key on its consumer thread
   after the call, so every name is collected first; a pause applies to every thread, whichever recorded it. */
static int scan_pass1( const unsigned char *p,uint32_t length,uint32_t tid,int before_window ) {
	uint32_t pos=0;
	while(pos+8<=length){
		uint32_t kind=(uint32_t)(u64(p+pos)>>56);uint64_t size=8;int follows=0;
		if(tid==frame_thread&&kind!=R_STALL){follows=frame_drop_follows;frame_drop_follows=0;}
		if(kind==R_EXIT||kind==R_SPAN_END){pos+=8;continue;}
		if(pos+16>length)return 1;
		if(kind==R_FRAME_MARK&&!frame_thread&&u64(p+pos+8)==0){thread_drops *d=early_drops_of(tid);frame_thread=tid;frame_drop_running=d?d->total:0;}
		if(kind==R_FRAME_MARK&&before_window&&u64(p+pos+8)<16)frames_before_window[u64(p+pos+8)]++;
		if((kind==R_FRAME_MARK||kind==R_FRAME_IDLE)&&tid==frame_thread&&u64(p+pos+8)==0){if(!frame_drops_close(u64(p+pos)&TICK_MASK))return 0;frame_drop_follows=1;}
		switch(kind){
		case R_ENTER:case R_UNWIND:case R_FRAME_MARK:case R_FRAME_IDLE:case R_STALL:size=16;break;
		case R_SPAN_BEGIN:size=16+PAD8_64((uint64_t)u32(p+pos+8)*(u32(p+pos+12)==1?1:2));break;
		case R_COUNTER:if(pos+24>length)return 1;size=24+PAD8_64((uint64_t)u32(p+pos+16)*(u32(p+pos+20)==1?1:2));break;
		case R_SAMPLE:size=16+((u64(p+pos+8)>>32)&0xFFFF)*8;break;
		case R_EVENT:{uint32_t id=u32(p+pos+8),n=u32(p+pos+12);const unsigned char *payload=p+pos+16;size=16+PAD8_64(n);
			if(pos+size>length)return 1;
			if(id==PROFILE_EVENT_RECORDING&&n>=4&&payload[0]==0&&!add_pause(u64(p+pos)&TICK_MASK,tid))return 0;
			if(id==PROFILE_EVENT_DROPPED_CALLS){uint64_t total=0;thread_drops *d;for(uint32_t i=0;i+16<=n;i+=16)total+=u32(payload+8+i);
				if(tid!=frame_thread){if((d=early_drops_of(tid))!=NULL)d->total+=total;}else if(follows&&frame_drop_count)frame_drops[frame_drop_count-1]+=total;else frame_drop_running+=total;}
			if(id==PROFILE_EVENT_STARTUP&&!startup&&n>=8){if(!(startup=(unsigned char*)malloc(n)))return 0;memcpy(startup,payload,n);startup_size=n;}
			if(id==PROFILE_EVENT_NATIVE_SYMBOL&&n>=24){uint32_t module_len=u32(payload+16),name_len=u32(payload+20);if(module_len<=n-24&&name_len==n-24-module_len&&!add_native(u64(payload),u64(payload+8),payload+24,module_len,payload+24+module_len,name_len))return 0;}
			break;}
		default:return 1;}
		if(pos+size>length)return 1;
		pos+=(uint32_t)size;}
	return 1;
}

/* Grows *buffer to hold size bytes; on failure *buffer is kept, for the caller to free. */
static int grow( unsigned char **buffer,uint32_t *capacity,uint32_t size ) {
	unsigned char *next;
	if(size<=*capacity&&*buffer)return 1;
	if(!(next=(unsigned char*)realloc(*buffer,size?size:1)))return 0;
	*buffer=next;*capacity=size;return 1;
}

/* Reads a v2 capture (positioned after its header) into consume(): metadata, clock pairs and thread names first, then
   every thread's records. */
static int read_v2( FILE *file,symbols *table,uint64_t start_ns,uint64_t end_ns,uint64_t *samples,uint64_t *unresolved,folded_table *folded_stacks,int show_lines,int raw_leaf,FILE *perfetto,int *perfetto_first,double *time_origin,uint32_t pid,pf_export *pf,int *complete ) {
	unsigned char record_header[16],*payload=NULL,*raw=NULL;uint32_t raw_cap=0,payload_cap=0;long data_start=ftell(file);tick_clock clock={0};byte_buffer out={0},fresh={0};reorder_buffer order={0};int code=0,have_metadata=0;uint64_t malformed=0;
	unsigned char *names=NULL;uint32_t names_size=0;
	memset(frame_sets,0,sizeof(frame_sets));
	memset(frames_before_window,0,sizeof(frames_before_window));
	pause_count=0;frame_thread=0;free(startup);startup=NULL;startup_size=0;free(frame_drops);free(frame_drop_starts);frame_drops=frame_drop_starts=NULL;frame_drop_count=frame_drop_capacity=frame_drop_cursor=0;frame_drop_running=frame_drop_start=0;frame_drop_follows=0;memset(early_drops,0,sizeof(early_drops));
	/* pass 1: the last metadata snapshot (it lists retired regions too), clock pairs, session and thread names */
	while(fread(record_header,1,16,file)==16){
		uint32_t type=u32(record_header),size=u32(record_header+4);
		if(size>MAX_RECORD){fprintf(stderr,"warning: oversized capture record; the capture ends there\n");break;}
		if(!grow(&payload,&payload_cap,size))goto done;
		if(size&&fread(payload,1,size,file)!=size){fprintf(stderr,"warning: truncated capture record\n");break;}
		if(type==PUSH_METADATA){if(!parse_symbols(payload,size,table)){fprintf(stderr,"Malformed symbol metadata\n");goto done;}have_metadata=1;}
		else if(type==PUSH_SESSION&&size>=32)clock.nominal_hz=u64(payload+24);
		else if(type==PUSH_CLOCK&&size>=16){if(!clock.count)clock.origin_ns=u64(payload+8);if(!clock_add(&clock,u64(payload),u64(payload+8)))goto done;}
		/* Every thread list's entries, in order: a thread that exited is in an earlier list only, and a later name wins. */
		else if(type==PUSH_THREADS&&size>=4){unsigned char *next=(unsigned char*)realloc(names,(size_t)names_size+size-4);if(!next)goto done;names=next;memcpy(names+names_size,payload+4,size-4);names_size+=size-4;}
		else if(type==CAPTURE_COMPLETE)*complete=1;
		else if(type==PUSH_DATA&&size>=16){uint32_t flags=u32(payload+4),raw_size=u32(payload+8);const unsigned char *records=payload+16;
			if(flags&1){if(raw_size>MAX_RECORD)continue;if(!grow(&raw,&raw_cap,raw_size))goto done;
				if(LZ4_decompress_safe((const char*)payload+16,(char*)raw,(int)(size-16),(int)raw_size)!=(int)raw_size)continue;records=raw;}
			else raw_size=size-16;
			if(!scan_pass1(records,raw_size,u32(payload),u64(record_header+8)<start_ns))goto done;}
	}
	if(!have_metadata){fprintf(stderr,"The capture holds no symbol metadata\n");goto done;}
	if(frame_thread&&!frame_drops_close(0))goto done;
	for(int i=0;i<16;i++)frame_sets[i].number=frames_before_window[i];
	entry_names=startup!=NULL&&start_ns==0;
	if(pause_count)qsort(pauses,pause_count,sizeof(recording_pause),pause_compare);
	/* Time 0 is the session's base tick, which a session started during the runtime's startup puts at its first phase,
	   before the first clock pair. */
	if(clock.count&&clock.nominal_hz)clock.origin_ns=clock.pairs[0].ns-(uint64_t)((double)clock.pairs[0].ticks*1e9/(double)clock.nominal_hz);
	/* thread names, then the frame track names */
	{uint32_t pos=0;while(pos+8<=names_size){uint32_t tid=u32(names+pos),n=u32(names+pos+4);open_stack *st=stack_of(tid);if(n>names_size-pos-8)break;if(!st||!synth_event(&out,0,tid,PROFILE_EVENT_THREAD_NAME,names+pos+8,n))goto done;st->named=1;pos+=8+n;}}
	if(!synth_event(&out,0,FRAME_TRACK_TID,EXPORT_PROCESS_TRACK,"Frames",6))goto done;
	/* The runtime's startup: its phases on the thread that ran them, and a "Startup" frame from the start of the session to
	   the first frame, so the program's own startup (its entry point until the first frame) is a frame too. Only
	   the Perfetto trace shows them, the other exports reading spans and calls as the program's own, and only from the
	   capture's start: a window from later on would show one frame from 0 to its first. */
	if(startup&&pf&&start_ns==0){uint32_t tid=u32(startup),count=u32(startup+4),pos=8,frames_tid=frame_thread?frame_thread:tid;
		if(!synth_event(&out,0,FRAME_TRACK_TID,PROFILE_EVENT_SPAN_BEGIN,"Startup",7)||!synth_event(&out,0,frames_tid,EXPORT_FRAME_BEGIN,"Startup",7))goto done;
		frame_sets[0].open=1;frame_sets[0].tid=frames_tid;
		if(frame_drop_count&&frame_drop_starts[0]==0&&!synth_counter(&out,0,frames_tid,"Short calls dropped per frame",(double)frame_drops[0]))goto done;
		for(uint32_t i=0;i<count&&pos+24<=startup_size;i++){uint32_t n=u32(startup+pos+16);if(n>startup_size-pos-24)break;
			if(!synth_event(&out,clock_seconds(&clock,u64(startup+pos)),tid,EXPORT_PHASE_BEGIN,startup+pos+24,n)||!synth_event(&out,clock_seconds(&clock,u64(startup+pos+8)),tid,EXPORT_PHASE_END,NULL,0))goto done;
			pos+=24+((n+7)&~7u);}}
	/* pass 2: the threads' records */
	if(fseek(file,data_start,SEEK_SET)!=0)goto done;
	while(fread(record_header,1,16,file)==16){
		uint32_t type=u32(record_header),size=u32(record_header+4);uint64_t elapsed=u64(record_header+8);
		if(size>MAX_RECORD)break;
		if(!grow(&payload,&payload_cap,size))goto done;
		if(size&&fread(payload,1,size,file)!=size)break;
		if(type!=PUSH_DATA||size<16||elapsed<start_ns||elapsed>end_ns)continue;
		{uint32_t tid=u32(payload),flags=u32(payload+4),raw_size=u32(payload+8);const unsigned char *records=payload+16;
			if(flags&1){if(raw_size>MAX_RECORD){malformed++;continue;}if(!grow(&raw,&raw_cap,raw_size))goto done;
				if(LZ4_decompress_safe((const char*)payload+16,(char*)raw,(int)(size-16),(int)raw_size)!=(int)raw_size){malformed++;continue;}records=raw;}
			else raw_size=size-16;
			if(!decode_records(&fresh,table,&clock,tid,records,raw_size,&malformed)||!reorder_add(&order,fresh.data,fresh.length))goto done;
			fresh.length=0;}
		if(order.newest-REORDER_WINDOW>=order.released_until+REORDER_STEP){order.released_until=order.newest-REORDER_WINDOW;if(!reorder_release(&order,order.released_until,&out))goto done;}
		if(out.length>(8U<<20)&&!consume(table,out.data,&out.length,samples,unresolved,folded_stacks,show_lines,raw_leaf,NULL,perfetto,perfetto_first,time_origin,pid,pf))goto malformed_stream;
	}
	/* close what is still open when the capture ends */
	{double end=clock.count?clock_seconds(&clock,clock.pairs[clock.count-1].ticks):0;if(end<order.newest)end=order.newest;
		for(int i=0;i<OPEN_STACKS;i++)if(open_stacks[i].used&&!close_slices(&fresh,open_stacks+i,end,open_stacks[i].tid,0,0))goto done;
		for(int i=0;i<16;i++)if(frame_sets[i].open&&!synth_event(&fresh,end,FRAME_TRACK_TID+(uint32_t)i,PROFILE_EVENT_SPAN_END,NULL,0))goto done;
		if(!reorder_add(&order,fresh.data,fresh.length)||!reorder_release(&order,1e300,&out))goto done;}
	if(order.late)fprintf(stderr,"warning: %llu records arrived more than %.0f s late and were moved to keep time order\n",(unsigned long long)order.late,REORDER_WINDOW);
	if(out.length&&!consume(table,out.data,&out.length,samples,unresolved,folded_stacks,show_lines,raw_leaf,NULL,perfetto,perfetto_first,time_origin,pid,pf))goto malformed_stream;
	if(malformed)fprintf(stderr,"warning: skipped %llu malformed record segments\n",(unsigned long long)malformed);
	code=1;
	goto done;
malformed_stream:
	fprintf(stderr,"Malformed profiler stream\n");
done:
	free(payload);free(raw);free(out.data);free(fresh.data);free(order.data.data);free(order.index);free(clock.pairs);free(names);free(startup);startup=NULL;stacks_free();
	return code;
}

static void usage( const char *p ){fprintf(stderr,"Usage:\n  %s [--host HOST] [--sources LIST] [--rate HZ] [--alloc-interval N] [--pool MIB] [--interval MS] [--duration SEC] [--max-size MIB] [--paused] [--min-call-us US] [--connect-timeout SEC] [--output FILE] PORT\n  %s report [--top N] [--lines] [--start-ms N] [--end-ms N] CAPTURE\n  %s export --format folded [--lines] [--start-ms N] [--end-ms N] CAPTURE\n  %s export --format perfetto [--lines] [--start-ms N] [--end-ms N] --output FILE CAPTURE\n  %s export --format pftrace [--process-name NAME] [--start-ms N] [--end-ms N] --output FILE CAPTURE\n",p,p,p,p,p);}

static int offline( int argc,char **argv,int exporting ) {
	const char *path=NULL,*output_path=NULL;int top=15,code=1,complete=0,format=0,show_lines=0,raw_leaf=0,perfetto_first=1,metadata_dirty=0;FILE *file=NULL,*perfetto=NULL;symbols table={0};folded_table folded_stacks={0};unsigned char header[24],record_header[16],*payload=NULL,*pending=NULL;size_t pending_len=0,pending_cap=512*1024;uint64_t samples=0,unresolved=0,dropped=0,cursor=0,last_time=0,reported_dropped=0,start_ns=0,end_ns=UINT64_MAX;int have_cursor=0;double time_origin=-1;const char *process_name="HashLink";pf_export pf={0};
	for(int i=2;i<argc;i++){
		if(!strcmp(argv[i],"--top")&&++i<argc&&!exporting)top=atoi(argv[i]);
		else if(!strcmp(argv[i],"--lines"))show_lines=1;
		else if(!strcmp(argv[i],"--raw-leaf")&&!exporting)raw_leaf=1;
		else if(!strcmp(argv[i],"--start-ms")&&++i<argc)start_ns=(uint64_t)strtoull(argv[i],NULL,10)*1000000ULL;
		else if(!strcmp(argv[i],"--end-ms")&&++i<argc)end_ns=(uint64_t)strtoull(argv[i],NULL,10)*1000000ULL;
		else if(!strcmp(argv[i],"--format")&&++i<argc&&exporting){if(!strcmp(argv[i],"folded"))format=1;else if(!strcmp(argv[i],"perfetto"))format=2;else if(!strcmp(argv[i],"pftrace"))format=3;else{fprintf(stderr,"Unsupported export format %s\n",argv[i]);goto done;}}
		else if(!strcmp(argv[i],"--output")&&++i<argc&&exporting)output_path=argv[i];
		else if(!strcmp(argv[i],"--process-name")&&++i<argc&&exporting)process_name=argv[i];
		else if(argv[i][0]=='-'||path){usage(argv[0]);goto done;}else path=argv[i];
	}
	if(!path||top<=0||(exporting&&!format)||(format>=2&&!output_path)){usage(argv[0]);goto done;}
	if(format>=2&&!strcmp(path,output_path)){fprintf(stderr,"Perfetto output must differ from the capture path\n");goto done;}
	file=fopen(path,"rb");if(!file){fprintf(stderr,"Could not open capture %s\n",path);goto done;}
	if(fread(header,1,24,file)!=24||memcmp(header,"HLPC",4)||(u16(header+4)!=1&&u16(header+4)!=2)||u16(header+6)!=24){fprintf(stderr,"Invalid or unsupported HLPC capture\n");goto done;}
	if(format==2){perfetto=fopen(output_path,"wb");if(!perfetto){fprintf(stderr,"Could not open Perfetto output %s\n",output_path);goto done;}fputs("{\"traceEvents\":[",perfetto);}
	if(format==3){uint32_t rate=u32(header+16);pf.weight_ns=rate?1000000000ULL/rate:1000000ULL;pf.trace=pftrace_open(output_path,u32(header+12)?u32(header+12):1,process_name);if(!pf.trace){fprintf(stderr,"Could not open Perfetto output %s\n",output_path);goto done;}}
	pending=(unsigned char*)malloc(pending_cap);if(!pending)goto done;
	if(u16(header+4)==2){
		if(!read_v2(file,&table,start_ns,end_ns,&samples,&unresolved,format==1?&folded_stacks:NULL,show_lines,raw_leaf,perfetto,&perfetto_first,&time_origin,u32(header+12),pf.trace?&pf:NULL,&complete))goto done;
		if(!complete)fprintf(stderr,"warning: partial capture; reporting complete records only\n");
		if(format!=1)short_calls_report(&table,format?10:top);
		if(format==1)folded_write(&folded_stacks);else if(!format)report(&table,samples,unresolved,dropped,top,show_lines);
		code=0;goto done;
	}
	while(!complete){
		size_t got=fread(record_header,1,16,file);uint32_t type,size;uint64_t elapsed;
		if(got==0)break;
		if(got!=16){fprintf(stderr,"warning: truncated capture record header\n");break;}
		type=u32(record_header);size=u32(record_header+4);elapsed=u64(record_header+8);if(size>(64U<<20)||elapsed<last_time){fprintf(stderr,"Malformed capture record\n");goto done;}last_time=elapsed;
		payload=size?(unsigned char*)malloc(size):NULL;if(size&&(!payload||fread(payload,1,size,file)!=size)){fprintf(stderr,"warning: truncated capture record payload\n");free(payload);payload=NULL;break;}
		if(type==1){if(!parse_symbols(payload,size,&table)){fprintf(stderr,"Malformed symbol metadata\n");goto done;}metadata_dirty=0;if(pending_len&&!consume(&table,pending,&pending_len,&samples,&unresolved,format==1?&folded_stacks:NULL,show_lines,raw_leaf,&metadata_dirty,perfetto,&perfetto_first,&time_origin,u32(header+12),pf.trace?&pf:NULL)){fprintf(stderr,"Malformed profiler stream\n");goto done;}if(perfetto){perfetto_begin_event(perfetto,&perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"g\",\"cat\":\"hl.metadata\",\"name\":\"symbols refreshed\",\"pid\":%u,\"tid\":0,\"ts\":%.3f,\"args\":{\"symbols\":%zu}}",u32(header+12),elapsed/1000.0,table.count);}}
		else if(type==2){uint64_t requested,next;if(size<24||!table.count){fprintf(stderr,"Malformed sample chunk\n");goto done;}requested=u64(payload);next=u64(payload+8);dropped=u64(payload+16);if((have_cursor&&requested!=cursor)||next<requested){fprintf(stderr,"Non-contiguous capture cursor\n");goto done;}cursor=next;have_cursor=1;
			if(pf.trace&&dropped>reported_dropped)pftrace_counter(pf.trace,pf.last_ns?pf.last_ns:1,"Profile records dropped",NULL,(double)dropped);
			if(perfetto&&dropped>reported_dropped){perfetto_begin_event(perfetto,&perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"g\",\"cat\":\"hl.diagnostics\",\"name\":\"profile records dropped\",\"pid\":%u,\"tid\":0,\"ts\":%.3f,\"args\":{\"dropped\":%llu}}",u32(header+12),elapsed/1000.0,(unsigned long long)(dropped-reported_dropped));reported_dropped=dropped;}
			if(pf.trace)reported_dropped=dropped;
			if(elapsed<start_ns||elapsed>end_ns){free(payload);payload=NULL;continue;}if(pending_len+size-24>pending_cap){size_t cap=pending_cap;while(cap<pending_len+size-24)cap*=2;unsigned char *next_buffer=(unsigned char*)realloc(pending,cap);if(!next_buffer){goto done;}pending=next_buffer;pending_cap=cap;}memcpy(pending+pending_len,payload+24,size-24);pending_len+=size-24;
			if(!consume(&table,pending,&pending_len,&samples,&unresolved,format==1?&folded_stacks:NULL,show_lines,raw_leaf,&metadata_dirty,perfetto,&perfetto_first,&time_origin,u32(header+12),pf.trace?&pf:NULL)){fprintf(stderr,"Malformed profiler stream\n");goto done;}
		}else if(type==3){if(size!=16||u64(payload)!=cursor){fprintf(stderr,"Malformed completion record\n");goto done;}dropped=u64(payload+8);complete=1;}
		free(payload);payload=NULL;
	}
	if(!complete)fprintf(stderr,"warning: partial capture; reporting complete records only\n");
	if(pending_len)fprintf(stderr,"warning: ignored %zu trailing profiler bytes\n",pending_len);
	if(format==1)folded_write(&folded_stacks);else if(!format)report(&table,samples,unresolved,dropped,top,show_lines);
	code=0;
done:
	free(payload);free(pending);if(file)fclose(file);if(perfetto){fputs("],\"displayTimeUnit\":\"ms\"}\n",perfetto);if(fclose(perfetto)!=0)code=1;}if(pf.trace)pf_stacks_finish(&pf);if(pf.trace&&!pftrace_close(pf.trace)){fprintf(stderr,"Perfetto output write failed\n");code=1;}free(pf.frames);folded_free(&folded_stacks);free_native();memset(&perfetto_gc,0,sizeof(perfetto_gc));memset(perfetto_threads,0,sizeof(perfetto_threads));free_symbols(&table);return code;
}

int main( int argc,char **argv ) {
	const char *host="127.0.0.1",*port=NULL,*output_path=NULL,*source_list="sampling";int rate=1000,allocation_interval=0,interval=2000,duration=0,connect_timeout=0,pool_mib=64,sources,code=1;socket_t sock=INVALID_SOCKET;
	unsigned char hello[16],*reply=NULL;uint32_t reply_size;
	if(argc>1&&!strcmp(argv[1],"report"))return offline(argc,argv,0);
	if(argc>1&&!strcmp(argv[1],"export"))return offline(argc,argv,1);
	for(int i=1;i<argc;i++){if(!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")){usage(argv[0]);return 0;}else if(!strcmp(argv[i],"--host")&&++i<argc)host=argv[i];else if(!strcmp(argv[i],"--sources")&&++i<argc)source_list=argv[i];else if(!strcmp(argv[i],"--rate")&&++i<argc)rate=atoi(argv[i]);else if(!strcmp(argv[i],"--alloc-interval")&&++i<argc)allocation_interval=atoi(argv[i]);else if(!strcmp(argv[i],"--pool")&&++i<argc)pool_mib=atoi(argv[i]);else if(!strcmp(argv[i],"--interval")&&++i<argc)interval=atoi(argv[i]);else if(!strcmp(argv[i],"--duration")&&++i<argc)duration=atoi(argv[i]);else if(!strcmp(argv[i],"--max-size")&&++i<argc)max_bytes=(uint64_t)strtoull(argv[i],NULL,10)<<20;else if(!strcmp(argv[i],"--paused"))start_paused=1;else if(!strcmp(argv[i],"--min-call-us")&&++i<argc){double us=atof(argv[i]);if(us<0||us>4000000){usage(argv[0]);return 2;}min_call_ns=(uint32_t)(us*1000.0+0.5);}else if(!strcmp(argv[i],"--connect-timeout")&&++i<argc)connect_timeout=atoi(argv[i]);else if(!strcmp(argv[i],"--output")&&++i<argc)output_path=argv[i];else if(argv[i][0]=='-'||port){usage(argv[0]);return 2;}else port=argv[i];}
	sources=parse_sources(source_list);
	if(!port||sources<0||rate<=0||allocation_interval<0||pool_mib<=0||interval<0||duration<0||connect_timeout<0){usage(argv[0]);return 2;}
	/* An allocation interval asks for allocation samples even when the source list leaves them out. */
	if(allocation_interval>0)sources|=SOURCE_ALLOC;else if(sources&SOURCE_ALLOC)allocation_interval=65536;
#ifdef _WIN32
	{WSADATA w;if(WSAStartup(MAKEWORD(2,2),&w)){fprintf(stderr,"Winsock initialization failed\n");return 1;}}
#endif
	#ifndef _WIN32
	signal(SIGPIPE,SIG_IGN);
	#endif
	sock=open_socket_until(host,port,connect_timeout);if(sock==INVALID_SOCKET){fprintf(stderr,"Could not connect to %s:%s\n",host,port);goto done;}
	if(!recv_all(sock,hello,16)||memcmp(hello,"HLDI",4)||u16(hello+4)!=2||(u16(hello+6)&3)!=3){fprintf(stderr,"Endpoint lacks HLDI/2 profiler symbols\n");goto done;}
	if(u16(hello+6)&4){const char *token=getenv("HL_DIAGNOSTICS_TOKEN");if(!token||!*token||!request_service(sock,0,2,1000,token,(uint32_t)strlen(token),&reply,&reply_size)){fprintf(stderr,"HLDI authentication failed; set HL_DIAGNOSTICS_TOKEN\n");goto done;}free(reply);reply=NULL;}
	code=record_session(sock,output_path,u32(hello+12),sources,rate,allocation_interval,pool_mib,duration,interval);
done:
	if(sock!=INVALID_SOCKET)CLOSE_SOCKET(sock);
#ifdef _WIN32
	WSACleanup();
#endif
	return code;
}
