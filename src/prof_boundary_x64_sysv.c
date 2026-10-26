/*
 * The stubs and the common thunk of the boundary hooks on Linux x86-64 (see prof_boundary_linux.c); prof_boundary_x64.asm
 * is the Windows version. They are top-level assembly in a C file, so the build needs no assembler language.
 *
 * Every hooked function has one of 1024 stubs. The stub leaves its index in r11 and jumps to hl_prof_boundary_thunk with
 * the caller's arguments and return address untouched. The stubs are code in this file, not generated at run time, so
 * nothing needs executable memory; a hook's key is its stub's address. Each is 16 bytes: endbr64, mov imm32, jmp rel32.
 *
 * The thunk records an enter, calls the real function with the same arguments (the six integer registers, the eight
 * vector registers, rax as the count of vector registers a variadic callee reads, and up to twelve stack arguments,
 * copied into its own frame), records an exit and returns the real function's result in rax, rdx, xmm0 and xmm1. The
 * stack arguments it copies are read from the caller's frame, which is always mapped. It carries unwind information, so a
 * C++ exception or a thread cancellation unwinds through it; the exit it skips is then missing, as on Windows.
 *
 * Thunk frame, from rsp: the 12 stack arguments (0..95), rdi rsi rdx rcx r8 r9 rax (96..151), xmm0-xmm7 (160..287), the
 * real function's rax and rdx (288, 296) and xmm0 and xmm1 (304, 320). rbx holds the descriptor and r12d whether the enter
 * was recorded. The caller's first stack argument is at rbp + 16.
 */
#if defined(__linux__) && defined(__x86_64__)

__asm__(
	".pushsection .text,\"ax\",@progbits\n"
	".globl hl_prof_boundary_stubs\n"
	".hidden hl_prof_boundary_stubs\n"
	".type hl_prof_boundary_stubs,@function\n"
	".balign 16\n"
	"hl_prof_boundary_stubs:\n"
	".set stub_index, 0\n"
	".rept 1024\n"
	".balign 16\n"
	"	endbr64\n"
	"	movl $stub_index, %r11d\n"
	"	jmp hl_prof_boundary_thunk\n"
	".set stub_index, stub_index + 1\n"
	".endr\n"
	".size hl_prof_boundary_stubs, . - hl_prof_boundary_stubs\n"
	".globl hl_prof_boundary_thunk\n"
	".hidden hl_prof_boundary_thunk\n"
	".type hl_prof_boundary_thunk,@function\n"
	"hl_prof_boundary_thunk:\n"
	".cfi_startproc\n"
	"	endbr64\n"
	"	push %rbp\n"
	".cfi_def_cfa_offset 16\n"
	".cfi_offset 6, -16\n"
	"	mov %rsp, %rbp\n"
	".cfi_def_cfa_register 6\n"
	"	push %rbx\n"
	"	push %r12\n"
	".cfi_offset 3, -24\n"
	".cfi_offset 12, -32\n"
	"	sub $336, %rsp\n"
	"	shl $4, %r11\n"
	"	lea hl_prof_boundary_descs(%rip), %rbx\n"
	"	add %r11, %rbx\n"
	"	mov %rdi, 96(%rsp)\n"
	"	mov %rsi, 104(%rsp)\n"
	"	mov %rdx, 112(%rsp)\n"
	"	mov %rcx, 120(%rsp)\n"
	"	mov %r8, 128(%rsp)\n"
	"	mov %r9, 136(%rsp)\n"
	"	mov %rax, 144(%rsp)\n"
	"	movaps %xmm0, 160(%rsp)\n"
	"	movaps %xmm1, 176(%rsp)\n"
	"	movaps %xmm2, 192(%rsp)\n"
	"	movaps %xmm3, 208(%rsp)\n"
	"	movaps %xmm4, 224(%rsp)\n"
	"	movaps %xmm5, 240(%rsp)\n"
	"	movaps %xmm6, 256(%rsp)\n"
	"	movaps %xmm7, 272(%rsp)\n"
	"	mov %rbx, %rdi\n"
	"	call hl_prof_boundary_enter\n"
	"	mov %eax, %r12d\n"
	".set stack_argument, 0\n"
	".rept 12\n"
	"	mov 16 + stack_argument * 8(%rbp), %rax\n"
	"	mov %rax, stack_argument * 8(%rsp)\n"
	".set stack_argument, stack_argument + 1\n"
	".endr\n"
	"	mov 96(%rsp), %rdi\n"
	"	mov 104(%rsp), %rsi\n"
	"	mov 112(%rsp), %rdx\n"
	"	mov 120(%rsp), %rcx\n"
	"	mov 128(%rsp), %r8\n"
	"	mov 136(%rsp), %r9\n"
	"	movaps 160(%rsp), %xmm0\n"
	"	movaps 176(%rsp), %xmm1\n"
	"	movaps 192(%rsp), %xmm2\n"
	"	movaps 208(%rsp), %xmm3\n"
	"	movaps 224(%rsp), %xmm4\n"
	"	movaps 240(%rsp), %xmm5\n"
	"	movaps 256(%rsp), %xmm6\n"
	"	movaps 272(%rsp), %xmm7\n"
	"	mov 144(%rsp), %rax\n"
	"	call *(%rbx)\n"
	"	mov %rax, 288(%rsp)\n"
	"	mov %rdx, 296(%rsp)\n"
	"	movaps %xmm0, 304(%rsp)\n"
	"	movaps %xmm1, 320(%rsp)\n"
	"	test %r12d, %r12d\n"
	"	jz 1f\n"
	"	call hl_prof_boundary_exit\n"
	"1:\n"
	"	mov 288(%rsp), %rax\n"
	"	mov 296(%rsp), %rdx\n"
	"	movaps 304(%rsp), %xmm0\n"
	"	movaps 320(%rsp), %xmm1\n"
	"	add $336, %rsp\n"
	"	pop %r12\n"
	"	pop %rbx\n"
	"	pop %rbp\n"
	".cfi_def_cfa 7, 8\n"
	"	ret\n"
	".cfi_endproc\n"
	".size hl_prof_boundary_thunk, . - hl_prof_boundary_thunk\n"
	".popsection\n"
);

#endif
