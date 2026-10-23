; _penter and _pexit, the hooks MSVC calls from functions compiled with /Gh and /GH (see prof_penter.c).
;
; _penter runs before the function's prolog and _pexit before its epilog, so both preserve every register the
; function may still need: the argument registers on entry, the return registers on exit, and all other volatile
; registers either way. While nothing records, each hook is a load, a test and a return.

EXTERN hlprof_penter_on:QWORD
EXTERN hlprof_penter_record_enter:PROC
EXTERN hlprof_penter_record_exit:PROC

; Saves the volatile registers in an aligned frame (rbp is the frame register, since the stack is 16-byte aligned at
; _penter but not at _pexit), calls target with rcx = the hook's return address, and returns to the hooked function.
CALL_SAVED MACRO target
	push rbp
	.pushreg rbp
	mov rbp, rsp
	.setframe rbp, 0
	.endprolog
	and rsp, -16
	sub rsp, 192
	mov [rsp + 128], rax
	mov [rsp + 136], rcx
	mov [rsp + 144], rdx
	mov [rsp + 152], r8
	mov [rsp + 160], r9
	mov [rsp + 168], r10
	mov [rsp + 176], r11
	movdqa [rsp + 32], xmm0
	movdqa [rsp + 48], xmm1
	movdqa [rsp + 64], xmm2
	movdqa [rsp + 80], xmm3
	movdqa [rsp + 96], xmm4
	movdqa [rsp + 112], xmm5
	mov rcx, [rbp + 8]
	call target
	movdqa xmm5, [rsp + 112]
	movdqa xmm4, [rsp + 96]
	movdqa xmm3, [rsp + 80]
	movdqa xmm2, [rsp + 64]
	movdqa xmm1, [rsp + 48]
	movdqa xmm0, [rsp + 32]
	mov r11, [rsp + 176]
	mov r10, [rsp + 168]
	mov r9, [rsp + 160]
	mov r8, [rsp + 152]
	mov rdx, [rsp + 144]
	mov rcx, [rsp + 136]
	mov rax, [rsp + 128]
	mov rsp, rbp
	pop rbp
	ret
ENDM

; Tests the recording flag; jumps to slow with the stack as the hook found it.
HOOK MACRO slow
	LOCAL recording
	push rax
	.pushreg rax
	.endprolog
	mov rax, hlprof_penter_on
	cmp dword ptr [rax], 0
	jne recording
	pop rax
	ret
recording:
	pop rax
	jmp slow
ENDM

.code

penter_record PROC FRAME
	CALL_SAVED hlprof_penter_record_enter
penter_record ENDP

pexit_record PROC FRAME
	CALL_SAVED hlprof_penter_record_exit
pexit_record ENDP

_penter PROC FRAME
	HOOK penter_record
_penter ENDP

_pexit PROC FRAME
	HOOK pexit_record
_pexit ENDP

END
