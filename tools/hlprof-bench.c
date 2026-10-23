/*
 * Measures what the profiler recorder costs the program: an enter/exit pair and a span with recording off and on, on
 * one and several threads, while a consumer drains concurrently. Run it after changing src/prof.c.
 */
#include "../src/hlprof.h"
#include <stdio.h>
#ifdef _WIN32
#	undef _GUID
#	include <windows.h>
#else
#	include <pthread.h>
#	include <time.h>
#endif

static volatile int consumer_running;
static volatile unsigned long long consumed;

static double now_seconds( void ) {
	return (double)hl_prof_monotonic_ns() / 1e9;
}

static void count_segment( void *context, unsigned int tid, const unsigned char *data, unsigned int length ) {
	(void)context; (void)tid; (void)data;
	consumed += length;
}

#ifdef _WIN32
static DWORD WINAPI consumer_main( LPVOID unused ) {
#else
static void *consumer_main( void *unused ) {
#endif
	(void)unused;
	/* Paced like the diagnostics consumer: polling positions continuously would pull every producer's write position
	   across cores on every record. */
	while( consumer_running ) {
		hl_prof_drain(count_segment,NULL);
#ifdef _WIN32
		Sleep(1);
#else
		{ struct timespec wait = { 0, 1000000 }; nanosleep(&wait,NULL); }
#endif
	}
	return 0;
}

typedef struct { int kind; int iterations; double seconds; } job;

static const unsigned short span_name[] = { 'b','e','n','c','h','.','s','p','a','n' };

static void run_job( job *j ) {
	double started = now_seconds();
	int n = j->iterations;
	switch( j->kind ) {
	case 0:
		for(int i=0;i<n;i++) { hl_prof_enter((unsigned long long)i); hl_prof_exit(); }
		break;
	case 1:
		for(int i=0;i<n;i++) { hl_prof_span_begin(span_name,10,HL_PROF_UTF16); hl_prof_span_end(); }
		break;
	case 2:
		{ volatile unsigned long long sink = 0; for(int i=0;i<n;i++) { sink += hl_prof_ticks(); sink += hl_prof_ticks(); } }
		break;
	}
	j->seconds = now_seconds() - started;
}

#ifdef _WIN32
static DWORD WINAPI worker_main( LPVOID arg ) { run_job((job*)arg); hl_prof_thread_exit(); return 0; }
#else
static void *worker_main( void *arg ) { run_job((job*)arg); hl_prof_thread_exit(); return NULL; }
#endif

/* ns per operation, the slowest thread's time over its share of the work */
static double measure( int kind, int threads, int iterations ) {
	job jobs[16];
	double worst = 0;
#ifdef _WIN32
	HANDLE handles[16];
#else
	pthread_t handles[16];
#endif
	for(int i=0;i<threads;i++) { jobs[i].kind = kind; jobs[i].iterations = iterations; jobs[i].seconds = 0; }
	if( threads == 1 ) run_job(jobs);
	else {
		for(int i=0;i<threads;i++) {
#ifdef _WIN32
			handles[i] = CreateThread(NULL,0,worker_main,jobs + i,0,NULL);
#else
			pthread_create(handles + i,NULL,worker_main,jobs + i);
#endif
		}
		for(int i=0;i<threads;i++) {
#ifdef _WIN32
			WaitForSingleObject(handles[i],INFINITE);
			CloseHandle(handles[i]);
#else
			pthread_join(handles[i],NULL);
#endif
		}
	}
	for(int i=0;i<threads;i++) if( jobs[i].seconds > worst ) worst = jobs[i].seconds;
	return worst * 1e9 / iterations;
}

static void report( const char *label, int kind, int threads, int iterations ) {
	double ns = measure(kind,threads,iterations);
	printf("  %-34s %2d thread%s %8.2f ns\n",label,threads,threads == 1 ? " " : "s",ns);
}

int main( int argc, char **argv ) {
	int iterations = argc > 1 ? atoi(argv[1]) : 20000000;
	hl_prof_stats stats;
	double started, seconds;
#ifdef _WIN32
	HANDLE consumer;
#else
	pthread_t consumer;
#endif
	printf("clock: kind %d, %.3f GHz\n",hl_prof_tick_kind(),hl_prof_nominal_hz() / 1e9);

	printf("recording off:\n");
	report("enter/exit pair",0,1,iterations);
	report("span begin/end",1,1,iterations);
	report("two clock reads",2,1,iterations);

	/* Recording without a consumer: the pool holds everything, so this is the producer's own cost. */
	if( !hl_prof_start(1024) ) { fprintf(stderr,"could not start a session\n"); return 1; }
	printf("recording, not drained:\n");
	report("enter/exit pair",0,1,iterations);
	hl_prof_stop();
	hl_prof_drain(count_segment,NULL);
	consumed = 0;

	if( !hl_prof_start(1024) ) { fprintf(stderr,"could not start a session\n"); return 1; }
	consumer_running = 1;
#ifdef _WIN32
	consumer = CreateThread(NULL,0,consumer_main,NULL,0,NULL);
#else
	pthread_create(&consumer,NULL,consumer_main,NULL);
#endif
	printf("recording, drained concurrently:\n");
	started = now_seconds();
	report("enter/exit pair",0,1,iterations);
	report("enter/exit pair",0,4,iterations / 4);
	report("span begin/end",1,1,iterations);
	seconds = now_seconds() - started;
	hl_prof_stop();
	consumer_running = 0;
#ifdef _WIN32
	WaitForSingleObject(consumer,INFINITE);
#else
	pthread_join(consumer,NULL);
#endif
	hl_prof_drain(count_segment,NULL);
	hl_prof_get_stats(&stats);
	printf("consumer: %.1f MiB drained in %.2f s (%.0f MiB/s); stalls %llu (%.2f ms)\n",consumed / 1048576.0,seconds,
		consumed / 1048576.0 / seconds,stats.stalls,stats.stall_ticks * 1000.0 / (double)hl_prof_nominal_hz());
	return 0;
}
