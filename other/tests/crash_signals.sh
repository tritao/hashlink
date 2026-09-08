#!/bin/sh

set -u

hl=$1
bytecode=$2
output=$(mktemp "${TMPDIR:-/tmp}/hashlink-crash-signals.XXXXXX") || exit 1
trap 'rm -f "$output"' EXIT HUP INT TERM
ulimit -c 0 2>/dev/null || true

fail() {
	echo "crash signal test failed: $1" >&2
	cat "$output" >&2
	exit 1
}

run_signal() {
	signal=$1
	expected_status=$2
	expected_output=$3
	: > "$output"
	"$hl" "$bytecode" wait > "$output" 2>&1 &
	pid=$!
	sleep 1
	if ! kill -0 "$pid" 2>/dev/null; then
		wait "$pid"
		fail "VM exited before $signal could be delivered"
	fi
	kill -"$signal" "$pid" || fail "could not deliver $signal"
	wait "$pid"
	status=$?
	[ "$status" -eq "$expected_status" ] || fail "$signal exited with $status instead of $expected_status"
	if [ -n "$expected_output" ]; then
		grep -F "$expected_output" "$output" >/dev/null || fail "$signal diagnostic was missing"
	elif [ -s "$output" ]; then
		fail "$signal unexpectedly produced a diagnostic"
	fi
}

run_signal TERM 143 ""
run_signal SEGV 139 "HashLink fatal error: SIGSEGV (signal 11), sent externally, pid"
run_signal ABRT 134 "HashLink fatal error: SIGABRT (signal 6), sent externally, pid"

: > "$output"
"$hl" "$bytecode" fault > "$output" 2>&1
status=$?
[ "$status" -eq 139 ] || fail "null dereference exited with $status instead of 139"
grep -E "HashLink fatal error: SIGSEGV \(signal 11\) at 0x[0-9a-f]+, pid [0-9]+" "$output" >/dev/null \
	|| fail "null dereference did not report its fault address"
if [ "$(uname -s)" = Linux ]; then
	grep -E "Inspect a retained core with: coredumpctl debug [0-9]+" "$output" >/dev/null \
		|| fail "null dereference did not report core inspection guidance"
fi

: > "$output"
"$hl" "$bytecode" worker-overflow > "$output" 2>&1
status=$?
[ "$status" -eq 139 ] || fail "worker stack overflow exited with $status instead of 139"
grep -E "HashLink fatal error: SIGSEGV \(signal 11\) at 0x[0-9a-f]+, pid [0-9]+" "$output" >/dev/null \
	|| fail "worker stack overflow did not run the crash handler"
