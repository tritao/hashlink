#define HL_NAME(n) crash_test_##n
#include <hl.h>
#include <stdint.h>

HL_PRIM void HL_NAME(fault)( int address ) {
	*(volatile int*)(uintptr_t)address = 0;
}

static int consume_stack( unsigned int depth ) {
	volatile unsigned char block[4096];
	unsigned int index = depth & (sizeof(block) - 1);
	block[index] = (unsigned char)depth;
	return block[index] + consume_stack(depth + 1);
}

HL_PRIM void HL_NAME(stack_overflow)() {
	consume_stack(0);
}

DEFINE_PRIM(_VOID, fault, _I32);
DEFINE_PRIM(_VOID, stack_overflow, _NO_ARG);
