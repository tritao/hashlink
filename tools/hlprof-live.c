/* Standalone HLDI sampling-profiler client. */
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
typedef SOCKET socket_t;
#define CLOSE_SOCKET closesocket
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define CLOSE_SOCKET close
#endif

enum { SVC_PROFILE=2, P_STATUS=1, P_CONFIGURE=2, P_READ=3, P_METADATA=4 };
enum { F_RESPONSE=1, F_ERROR=2, CAP_PROFILE=1, CAP_SYMBOLS=2 };

typedef struct { uint32_t offset,line; char *file; uint64_t self,total; } source_line;
typedef struct { uint64_t start,end,self,total; uint32_t function_id; char *name; source_line *lines; uint32_t line_count; } symbol;
typedef struct { symbol *items; size_t count,capacity; } symbols;
typedef struct { const unsigned char *data; size_t length,pos; } reader;
typedef struct { FILE *file; double started; int failed; } capture;
typedef struct folded folded;
struct folded { char *stack; uint64_t count; folded *next; };
typedef struct { folded *buckets[4096]; } folded_table;
static volatile sig_atomic_t interrupted;

static uint16_t u16( const unsigned char *p ) { return (uint16_t)(p[0]|((uint16_t)p[1]<<8)); }
static uint32_t u32( const unsigned char *p ) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t u64( const unsigned char *p ) { return (uint64_t)u32(p)|((uint64_t)u32(p+4)<<32); }
static void put32( unsigned char *p,uint32_t v ) { p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24); }
static void put64( unsigned char *p,uint64_t v ) { put32(p,(uint32_t)v);put32(p+4,(uint32_t)(v>>32)); }
static void stop_signal( int sig ) { (void)sig; interrupted=1; }

static double monotime( void ) {
#ifdef _WIN32
	return GetTickCount64()/1000.0;
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
static int request( socket_t s,unsigned char type,uint32_t id,const void *body,uint32_t size,unsigned char **reply,uint32_t *reply_size ) {
	unsigned char h[16];h[0]=SVC_PROFILE;h[1]=type;h[2]=h[3]=0;put32(h+4,id);put32(h+8,size);put32(h+12,0);
	if(!send_all(s,h,16)||(size&&!send_all(s,body,size))||!recv_all(s,h,16))return 0;
	*reply_size=u32(h+8);
	if(h[0]!=SVC_PROFILE||h[1]!=type||u32(h+4)!=id||(u16(h+2)&F_RESPONSE)==0||(u16(h+2)&F_ERROR)||*reply_size>(64U<<20))return 0;
	*reply=*reply_size?(unsigned char*)malloc(*reply_size):NULL;
	if(*reply_size&&(!*reply||!recv_all(s,*reply,*reply_size))){free(*reply);*reply=NULL;return 0;}return 1;
}
static int get32( reader *r,uint32_t *v ){if(r->length-r->pos<4)return 0;*v=u32(r->data+r->pos);r->pos+=4;return 1;}
static int get64( reader *r,uint64_t *v ){if(r->length-r->pos<8)return 0;*v=u64(r->data+r->pos);r->pos+=8;return 1;}

static void free_symbols( symbols *s ){for(size_t i=0;i<s->count;i++){free(s->items[i].name);for(uint32_t j=0;j<s->items[i].line_count;j++)free(s->items[i].lines[j].file);free(s->items[i].lines);}free(s->items);memset(s,0,sizeof(*s));}
static symbol *add_symbol( symbols *s,uint64_t start,uint64_t end,uint32_t id,const unsigned char *name,uint32_t length ) {
	if(s->count==s->capacity){size_t cap=s->capacity?s->capacity*2:1024;symbol *p=(symbol*)realloc(s->items,cap*sizeof(symbol));if(!p)return NULL;s->items=p;s->capacity=cap;}
	symbol *x=s->items+s->count++;memset(x,0,sizeof(*x));x->start=start;x->end=end;x->function_id=id;x->name=(char*)malloc((size_t)length+1);if(!x->name)return NULL;memcpy(x->name,name,length);x->name[length]=0;return x;
}
static int by_address( const void *a,const void *b ){const symbol *x=a,*y=b;return x->start<y->start?-1:x->start>y->start?1:0;}
static symbol *resolve( symbols *s,uint64_t pc ){size_t lo=0,hi=s->count;while(lo<hi){size_t m=(lo+hi)>>1;if(s->items[m].start<=pc)lo=m+1;else hi=m;}return lo&&pc<s->items[lo-1].end?s->items+lo-1:NULL;}
static source_line *resolve_line( symbol *s,uint64_t pc ){uint32_t offset=(uint32_t)(pc-s->start),lo=0,hi=s->line_count;while(lo<hi){uint32_t m=(lo+hi)>>1;if(s->lines[m].offset<=offset)lo=m+1;else hi=m;}return lo?s->lines+lo-1:NULL;}
static int parse_symbols( const unsigned char *data,uint32_t size,symbols *current ) {
	uint32_t schema,nmodules;reader r;symbols next={0};char **files=NULL;uint32_t file_count=0;
	r.data=data;r.length=size;r.pos=0;
	if(!get32(&r,&schema)||(schema!=1&&schema!=2)||!get32(&r,&nmodules))goto fail;
	for(uint32_t m=0;m<nmodules;m++){
		uint64_t module_id;uint32_t revision,nregions;if(!get64(&r,&module_id)||!get32(&r,&revision)||!get32(&r,&nregions))goto fail;
		if(schema>=2){if(!get32(&r,&file_count))goto fail;files=(char**)calloc(file_count,sizeof(char*));if(file_count&&!files)goto fail;for(uint32_t i=0;i<file_count;i++){uint32_t length;if(!get32(&r,&length)||length>r.length-r.pos)goto fail;files[i]=(char*)malloc((size_t)length+1);if(!files[i])goto fail;memcpy(files[i],r.data+r.pos,length);files[i][length]=0;r.pos+=length;}}
		for(uint32_t g=0;g<nregions;g++){
			uint64_t base,region_size;uint32_t flags,nfunctions;if(!get64(&r,&base)||!get64(&r,&region_size)||!get32(&r,&flags)||!get32(&r,&nfunctions))goto fail;
			for(uint32_t f=0;f<nfunctions;f++){
				uint32_t fid,off,len,nlen;if(!get32(&r,&fid)||!get32(&r,&off)||!get32(&r,&len)||!get32(&r,&nlen)||nlen>r.length-r.pos||!len||(uint64_t)off+len>region_size)goto fail;
				symbol *added=add_symbol(&next,base+off,base+off+len,fid,r.data+r.pos,nlen);if(!added)goto fail;
				r.pos+=nlen;
				if(schema>=2){uint32_t lines;if(!get32(&r,&lines))goto fail;added->lines=(source_line*)calloc(lines,sizeof(source_line));if(lines&&!added->lines)goto fail;added->line_count=lines;for(uint32_t i=0;i<lines;i++){uint32_t offset,file,line;if(!get32(&r,&offset)||!get32(&r,&file)||!get32(&r,&line)||offset>=len||file>=file_count||(i&&offset<added->lines[i-1].offset))goto fail;added->lines[i].offset=offset;added->lines[i].line=line;added->lines[i].file=(char*)malloc(strlen(files[file])+1);if(!added->lines[i].file)goto fail;strcpy(added->lines[i].file,files[file]);}}
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
static int consume( symbols *s,unsigned char *pending,size_t *length,uint64_t *samples,uint64_t *unresolved,folded_table *folded_stacks,int show_lines,FILE *perfetto,int *perfetto_first,double *time_origin,uint32_t pid ) {
	size_t pos=0;while(*length-pos>=4){uint32_t body=u32(pending+pos);if(body<20||body>(8U<<20))return 0;if(*length-pos<(size_t)body+4)break;
		double event_time=0;if(perfetto){uint64_t time_bits=u64(pending+pos+8);memcpy(&event_time,&time_bits,sizeof(event_time));if(*time_origin<0)*time_origin=event_time;}
		if(pending[pos+4]==1){uint32_t frames=u32(pending+pos+20),tid=u32(pending+pos+16);if(body!=20+frames*8U)return 0;symbol *leaf=NULL;source_line *leaf_line=NULL;char *stack=NULL;size_t stack_len=0,stack_cap=0;(*samples)++;for(uint32_t i=0;i<frames;i++){uint64_t pc=u64(pending+pos+24+i*8);symbol *x=resolve(s,pc);if(x){source_line *line=resolve_line(x,pc);x->total++;if(line)line->total++;if(!leaf){leaf=x;leaf_line=line;}}else(*unresolved)++;}
			if(leaf)leaf->self++;
			if(leaf_line)leaf_line->self++;
			if(folded_stacks||perfetto){for(uint32_t i=frames;i>0;i--){uint64_t pc=u64(pending+pos+24+(i-1)*8);symbol *x=resolve(s,pc);source_line *line=x?resolve_line(x,pc):NULL;char label[1536];const char *name;if(show_lines&&line){snprintf(label,sizeof(label),"%s (%s:%u)",x->name,line->file,line->line);name=label;}else name=x?x->name:"[unknown]";size_t n=strlen(name),need=stack_len+n+(stack_len?1:0)+1;if(need>stack_cap){size_t cap=stack_cap?stack_cap*2:256;while(cap<need)cap*=2;char *next=(char*)realloc(stack,cap);if(!next){free(stack);return 0;}stack=next;stack_cap=cap;}if(stack_len)stack[stack_len++]=';';memcpy(stack+stack_len,name,n);stack_len+=n;stack[stack_len]=0;}}
			if(folded_stacks&&stack&&!folded_add(folded_stacks,stack)){free(stack);return 0;}
			if(perfetto){perfetto_begin_event(perfetto,perfetto_first);fputs("{\"ph\":\"i\",\"s\":\"t\",\"cat\":\"hl.sample\",\"name\":",perfetto);json_string(perfetto,leaf?leaf->name:"sample");fprintf(perfetto,",\"pid\":%u,\"tid\":%u,\"ts\":%.3f,\"args\":{\"stack\":",pid,tid,(event_time-*time_origin)*1000000.0);json_string(perfetto,stack?stack:"");fprintf(perfetto,",\"gc_stop\":%s",(pending[pos+5]&1)?"true":"false");if(leaf_line){fputs(",\"file\":",perfetto);json_string(perfetto,leaf_line->file);fprintf(perfetto,",\"line\":%u",leaf_line->line);}fputs("}}",perfetto);}
			free(stack);
		}else if(pending[pos+4]==2&&perfetto){uint32_t tid=u32(pending+pos+16),event_id=u32(pending+pos+20);perfetto_begin_event(perfetto,perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"t\",\"cat\":\"hl.event\",\"name\":\"event %u\",\"pid\":%u,\"tid\":%u,\"ts\":%.3f,\"args\":{\"payload\":\"",event_id,pid,tid,(event_time-*time_origin)*1000000.0);for(uint32_t i=0;i<body-20;i++)fprintf(perfetto,"%02x",pending[pos+24+i]);fputs("\"}}",perfetto);}
		pos+=body+4;}
	if(pos){memmove(pending,pending+pos,*length-pos);*length-=pos;}return 1;
}
static void usage( const char *p ){fprintf(stderr,"Usage:\n  %s [--host HOST] [--rate HZ] [--interval MS] [--duration SEC] [--top N] [--lines] [--output FILE] PORT\n  %s report [--top N] [--lines] CAPTURE\n  %s export --format folded [--lines] CAPTURE\n  %s export --format perfetto [--lines] --output FILE CAPTURE\n",p,p,p,p);}

static int offline( int argc,char **argv,int exporting ) {
	const char *path=NULL,*output_path=NULL;int top=15,code=1,complete=0,format=0,show_lines=0,perfetto_first=1;FILE *file=NULL,*perfetto=NULL;symbols table={0};folded_table folded_stacks={0};unsigned char header[24],record_header[16],*payload=NULL,*pending=NULL;size_t pending_len=0,pending_cap=512*1024;uint64_t samples=0,unresolved=0,dropped=0,cursor=0,last_time=0,reported_dropped=0;int have_cursor=0;double time_origin=-1;
	for(int i=2;i<argc;i++){
		if(!strcmp(argv[i],"--top")&&++i<argc&&!exporting)top=atoi(argv[i]);
		else if(!strcmp(argv[i],"--lines"))show_lines=1;
		else if(!strcmp(argv[i],"--format")&&++i<argc&&exporting){if(!strcmp(argv[i],"folded"))format=1;else if(!strcmp(argv[i],"perfetto"))format=2;else{fprintf(stderr,"Unsupported export format %s\n",argv[i]);goto done;}}
		else if(!strcmp(argv[i],"--output")&&++i<argc&&exporting)output_path=argv[i];
		else if(argv[i][0]=='-'||path){usage(argv[0]);goto done;}else path=argv[i];
	}
	if(!path||top<=0||(exporting&&!format)||(format==2&&!output_path)){usage(argv[0]);goto done;}
	if(format==2&&!strcmp(path,output_path)){fprintf(stderr,"Perfetto output must differ from the capture path\n");goto done;}
	file=fopen(path,"rb");if(!file){fprintf(stderr,"Could not open capture %s\n",path);goto done;}
	if(fread(header,1,24,file)!=24||memcmp(header,"HLPC",4)||u16(header+4)!=1||u16(header+6)!=24){fprintf(stderr,"Invalid or unsupported HLPC capture\n");goto done;}
	if(format==2){perfetto=fopen(output_path,"wb");if(!perfetto){fprintf(stderr,"Could not open Perfetto output %s\n",output_path);goto done;}fputs("{\"traceEvents\":[",perfetto);}
	pending=(unsigned char*)malloc(pending_cap);if(!pending)goto done;
	while(!complete){
		size_t got=fread(record_header,1,16,file);uint32_t type,size;uint64_t elapsed;
		if(got==0)break;
		if(got!=16){fprintf(stderr,"warning: truncated capture record header\n");break;}
		type=u32(record_header);size=u32(record_header+4);elapsed=u64(record_header+8);if(size>(64U<<20)||elapsed<last_time){fprintf(stderr,"Malformed capture record\n");goto done;}last_time=elapsed;
		payload=size?(unsigned char*)malloc(size):NULL;if(size&&(!payload||fread(payload,1,size,file)!=size)){fprintf(stderr,"warning: truncated capture record payload\n");free(payload);payload=NULL;break;}
		if(type==1){if(!parse_symbols(payload,size,&table)){fprintf(stderr,"Malformed symbol metadata\n");goto done;}if(perfetto){perfetto_begin_event(perfetto,&perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"g\",\"cat\":\"hl.metadata\",\"name\":\"symbols refreshed\",\"pid\":%u,\"tid\":0,\"ts\":%.3f,\"args\":{\"symbols\":%zu}}",u32(header+12),elapsed/1000.0,table.count);}}
		else if(type==2){uint64_t requested,next;if(size<24||!table.count){fprintf(stderr,"Malformed sample chunk\n");goto done;}requested=u64(payload);next=u64(payload+8);dropped=u64(payload+16);if((have_cursor&&requested!=cursor)||next<requested){fprintf(stderr,"Non-contiguous capture cursor\n");goto done;}cursor=next;have_cursor=1;
			if(perfetto&&dropped>reported_dropped){perfetto_begin_event(perfetto,&perfetto_first);fprintf(perfetto,"{\"ph\":\"i\",\"s\":\"g\",\"cat\":\"hl.diagnostics\",\"name\":\"profile records dropped\",\"pid\":%u,\"tid\":0,\"ts\":%.3f,\"args\":{\"dropped\":%llu}}",u32(header+12),elapsed/1000.0,(unsigned long long)(dropped-reported_dropped));reported_dropped=dropped;}
			if(pending_len+size-24>pending_cap){size_t cap=pending_cap;while(cap<pending_len+size-24)cap*=2;unsigned char *next_buffer=(unsigned char*)realloc(pending,cap);if(!next_buffer){goto done;}pending=next_buffer;pending_cap=cap;}memcpy(pending+pending_len,payload+24,size-24);pending_len+=size-24;
			if(!consume(&table,pending,&pending_len,&samples,&unresolved,format==1?&folded_stacks:NULL,show_lines,perfetto,&perfetto_first,&time_origin,u32(header+12))){fprintf(stderr,"Malformed profiler stream\n");goto done;}
		}else if(type==3){if(size!=16||!have_cursor||u64(payload)!=cursor){fprintf(stderr,"Malformed completion record\n");goto done;}dropped=u64(payload+8);complete=1;}
		free(payload);payload=NULL;
	}
	if(!complete)fprintf(stderr,"warning: partial capture; reporting complete records only\n");
	if(pending_len)fprintf(stderr,"warning: ignored %zu trailing profiler bytes\n",pending_len);
	if(format==1)folded_write(&folded_stacks);else if(!format)report(&table,samples,unresolved,dropped,top,show_lines);
	code=0;
done:
	free(payload);free(pending);if(file)fclose(file);if(perfetto){fputs("],\"displayTimeUnit\":\"ms\"}\n",perfetto);if(fclose(perfetto)!=0)code=1;}folded_free(&folded_stacks);free_symbols(&table);return code;
}

int main( int argc,char **argv ) {
	const char *host="127.0.0.1",*port=NULL,*output_path=NULL;int rate=1000,interval=1000,duration=0,top=15,code=1,show_lines=0;socket_t sock=INVALID_SOCKET;symbols table={0};capture output={0};
	unsigned char hello[16],config[8],read_body[12],*reply=NULL,*pending=NULL;uint32_t reply_size,id=1;uint64_t cursor=0,dropped=0,samples=0,unresolved=0;size_t pending_len=0;double started,next_report,next_metadata;
	if(argc>1&&!strcmp(argv[1],"report"))return offline(argc,argv,0);
	if(argc>1&&!strcmp(argv[1],"export"))return offline(argc,argv,1);
	for(int i=1;i<argc;i++){if(!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")){usage(argv[0]);return 0;}else if(!strcmp(argv[i],"--host")&&++i<argc)host=argv[i];else if(!strcmp(argv[i],"--rate")&&++i<argc)rate=atoi(argv[i]);else if(!strcmp(argv[i],"--interval")&&++i<argc)interval=atoi(argv[i]);else if(!strcmp(argv[i],"--duration")&&++i<argc)duration=atoi(argv[i]);else if(!strcmp(argv[i],"--top")&&++i<argc)top=atoi(argv[i]);else if(!strcmp(argv[i],"--lines"))show_lines=1;else if(!strcmp(argv[i],"--output")&&++i<argc)output_path=argv[i];else if(argv[i][0]=='-'||port){usage(argv[0]);return 2;}else port=argv[i];}
	if(!port||rate<=0||interval<=0||duration<0||top<=0){usage(argv[0]);return 2;}
#ifdef _WIN32
	{WSADATA w;if(WSAStartup(MAKEWORD(2,2),&w)){fprintf(stderr,"Winsock initialization failed\n");return 1;}}
#endif
	sock=open_socket(host,port);if(sock==INVALID_SOCKET){fprintf(stderr,"Could not connect to %s:%s\n",host,port);goto done;}
	if(!recv_all(sock,hello,16)||memcmp(hello,"HLDI",4)||u16(hello+4)!=1||(u16(hello+6)&3)!=3){fprintf(stderr,"Endpoint lacks HLDI/1 profiler symbols\n");goto done;}
	if(!capture_open(&output,output_path,u32(hello+12),(uint32_t)rate)){fprintf(stderr,"Could not open capture file %s\n",output_path);goto done;}
	if(!fetch_symbols(sock,&table,id++,&output)||!table.count){fprintf(stderr,"Could not load symbols\n");goto done;}
	put32(config,(uint32_t)rate);put32(config+4,1);if(!request(sock,P_CONFIGURE,id++,config,8,&reply,&reply_size)||reply_size!=32){fprintf(stderr,"Could not start profiler\n");goto done;}
	cursor=u64(reply+8);dropped=u64(reply+16);free(reply);reply=NULL;pending=(unsigned char*)malloc(512*1024);if(!pending)goto done;
	printf("Connected to HashLink process %u, %zu symbols, sampling at %d Hz\n",u32(hello+12),table.count,rate);signal(SIGINT,stop_signal);
#ifdef SIGTERM
	signal(SIGTERM,stop_signal);
#endif
	started=monotime();next_report=started+interval/1000.0;next_metadata=started+5.0;
	while(!interrupted&&(!duration||monotime()-started<duration)){
		put64(read_body,cursor);put32(read_body+8,256*1024);if(!request(sock,P_READ,id++,read_body,12,&reply,&reply_size)||reply_size<16){fprintf(stderr,"Profiler connection closed\n");goto done;}
		if(!capture_record_parts(&output,2,read_body,8,reply,reply_size)){fprintf(stderr,"Capture write failed\n");goto done;}cursor=u64(reply);dropped=u64(reply+8);if(pending_len+reply_size-16>512*1024){fprintf(stderr,"Local buffer overflow\n");goto done;}memcpy(pending+pending_len,reply+16,reply_size-16);pending_len+=reply_size-16;free(reply);reply=NULL;
		if(!consume(&table,pending,&pending_len,&samples,&unresolved,NULL,show_lines,NULL,NULL,NULL,0)){fprintf(stderr,"Malformed profile record\n");goto done;}
		if(monotime()>=next_metadata){if(!fetch_symbols(sock,&table,id++,&output)){fprintf(stderr,"Metadata refresh failed\n");goto done;}next_metadata=monotime()+5;}
		if(monotime()>=next_report){report(&table,samples,unresolved,dropped,top,show_lines);samples=unresolved=0;next_report=monotime()+interval/1000.0;}sleep_ms(interval<100?interval:100);
	}
	if(samples)report(&table,samples,unresolved,dropped,top,show_lines);
	code=0;
done:
	if(sock!=INVALID_SOCKET){if(code==0){put32(config,(uint32_t)rate);put32(config+4,0);request(sock,P_CONFIGURE,id++,config,8,&reply,&reply_size);free(reply);}CLOSE_SOCKET(sock);}free(pending);free_symbols(&table);
	capture_close(&output,cursor,dropped,code==0);if(output.failed&&code==0){fprintf(stderr,"Capture finalization failed\n");code=1;}
#ifdef _WIN32
	WSACleanup();
#endif
	return code;
}
