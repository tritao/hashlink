; hl_prof_boundary_thunk: the common body of every boundary hook's stub (see prof_boundary.c). The stub leaves the
; hook's descriptor in r10 and jumps here with the caller's arguments and return address untouched.
;
; The thunk records an enter, calls the real function with the same arguments (the four register arguments and up to
; twelve stack arguments, copied into its own frame), records an exit and returns the real function's result. The
; extra stack arguments it copies are read from the caller's frame, which is always mapped.

EXTERN hl_prof_boundary_enter:PROC
EXTERN hl_prof_boundary_exit:PROC

; Frame, from rsp: 32 shadow bytes, 12 stack arguments (32..127), rcx rdx r8 r9 (128..159), xmm0-xmm3 (160..223),
; whether the enter was recorded (224), padding. The caller's fifth argument is at rsp + 288.
FRAME_SIZE EQU 240
CALLER_ARGS EQU FRAME_SIZE + 8 + 8 + 32

.code

hl_prof_boundary_thunk PROC FRAME
	push rbx
	.pushreg rbx
	sub rsp, FRAME_SIZE
	.allocstack FRAME_SIZE
	.endprolog
	mov rbx, r10
	mov [rsp + 128], rcx
	mov [rsp + 136], rdx
	mov [rsp + 144], r8
	mov [rsp + 152], r9
	movdqa [rsp + 160], xmm0
	movdqa [rsp + 176], xmm1
	movdqa [rsp + 192], xmm2
	movdqa [rsp + 208], xmm3
	mov rcx, rbx
	call hl_prof_boundary_enter
	mov [rsp + 224], eax
	ARG = 0
	REPEAT 12
		mov rax, [rsp + CALLER_ARGS + ARG * 8]
		mov [rsp + 32 + ARG * 8], rax
		ARG = ARG + 1
	ENDM
	mov rcx, [rsp + 128]
	mov rdx, [rsp + 136]
	mov r8, [rsp + 144]
	mov r9, [rsp + 152]
	movdqa xmm0, [rsp + 160]
	movdqa xmm1, [rsp + 176]
	movdqa xmm2, [rsp + 192]
	movdqa xmm3, [rsp + 208]
	call qword ptr [rbx]
	mov [rsp + 128], rax
	movdqa [rsp + 160], xmm0
	cmp dword ptr [rsp + 224], 0
	je done
	call hl_prof_boundary_exit
done:
	mov rax, [rsp + 128]
	movdqa xmm0, [rsp + 160]
	add rsp, FRAME_SIZE
	pop rbx
	ret
hl_prof_boundary_thunk ENDP

END
