#!/bin/sh

set -eu

gdb=$1
hl=$2
bytecode=$3
output=$(mktemp "${TMPDIR:-/tmp}/hashlink-gdb-jit.XXXXXX")
crash_output=$(mktemp "${TMPDIR:-/tmp}/hashlink-gdb-crash.XXXXXX")
core_file=$(mktemp "${TMPDIR:-/tmp}/hashlink-gdb-core.XXXXXX")
core_output=$(mktemp "${TMPDIR:-/tmp}/hashlink-gdb-core-output.XXXXXX")
rm -f "$core_file"
trap 'rm -f "$output" "$crash_output" "$core_file" "$core_output"' EXIT HUP INT TERM

"$gdb" -q -batch \
	-ex "break __jit_debug_register_code" \
	-ex "run $bytecode exit" \
	-ex 'printf "REGISTER_ACTION=%u\n", __jit_debug_descriptor.action_flag' \
	-ex "finish" \
	-ex 'printf "METADATA_COMPACT=%d\n", __jit_debug_descriptor.relevant_entry->symfile_size < m->codesize' \
	-ex "info functions CrashSignals.main" \
	-ex "info line CrashSignals.hx:3" \
	-ex "maintenance info sections -all-objects .debug_frame" \
	-ex "continue" \
	-ex 'printf "FIRST_ENTRY=%p\n", __jit_debug_descriptor.first_entry' \
	"$hl" > "$output" 2>&1

grep -F 'REGISTER_ACTION=1' "$output" >/dev/null \
	&& grep -F 'METADATA_COMPACT=1' "$output" >/dev/null \
	&& grep -F 'CrashSignals.main' "$output" >/dev/null \
	&& grep -F 'Line 3 of "CrashSignals.hx" starts at address ' "$output" >/dev/null \
	&& grep -F 'FIRST_ENTRY=(nil)' "$output" >/dev/null || {
	echo "GDB JIT registration lifecycle was not observed" >&2
	cat "$output" >&2
	exit 1
}

case $(uname -m) in
	x86_64|amd64)
		grep -F '.debug_frame READONLY HAS_CONTENTS' "$output" >/dev/null || {
			echo "GDB JIT unwind metadata was not observed" >&2
			cat "$output" >&2
			exit 1
		}
		;;
esac

"$gdb" -q -batch \
	-ex "run $bytecode fault" \
	-ex "backtrace 3" \
	"$hl" > "$crash_output" 2>&1 || true

grep -F 'CrashSignals.main () at CrashSignals.hx:4' "$crash_output" >/dev/null || {
	echo "GDB could not unwind through the crashing JIT frame" >&2
	cat "$crash_output" >&2
	exit 1
}

"$gdb" -q -batch \
	-ex "run $bytecode fault" \
	-ex "generate-core-file $core_file" \
	"$hl" >/dev/null 2>&1

"$gdb" -q -batch "$hl" "$core_file" \
	-ex "backtrace 3" > "$core_output" 2>&1

grep -F 'crash_test_fault (address=1)' "$core_output" >/dev/null \
	&& grep -F 'CrashSignals.main () at CrashSignals.hx:4' "$core_output" >/dev/null \
	&& grep -E 'in (__entry|init) \(\) at (\?|<generated>):1' "$core_output" >/dev/null || {
	echo "A fresh GDB process could not symbolize the JIT core" >&2
	cat "$core_output" >&2
	exit 1
}
