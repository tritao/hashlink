#!/bin/sh

set -eu

gdb=$1
hl=$2
bytecode=$3
output=$(mktemp "${TMPDIR:-/tmp}/hashlink-gdb-jit.XXXXXX")
trap 'rm -f "$output"' EXIT HUP INT TERM

"$gdb" -q -batch \
	-ex "break __jit_debug_register_code" \
	-ex "run $bytecode exit" \
	-ex 'printf "REGISTER_ACTION=%u\n", __jit_debug_descriptor.action_flag' \
	-ex "finish" \
	-ex "info address .init" \
	-ex "info line CrashSignals.hx:3" \
	-ex "continue" \
	-ex 'printf "FIRST_ENTRY=%p\n", __jit_debug_descriptor.first_entry' \
	"$hl" > "$output" 2>&1

grep -F 'REGISTER_ACTION=1' "$output" >/dev/null \
	&& grep -F 'Symbol ".init" is at ' "$output" >/dev/null \
	&& grep -F 'Line 3 of "CrashSignals.hx" starts at address ' "$output" >/dev/null \
	&& grep -F 'FIRST_ENTRY=(nil)' "$output" >/dev/null || {
	echo "GDB JIT registration lifecycle was not observed" >&2
	cat "$output" >&2
	exit 1
}
