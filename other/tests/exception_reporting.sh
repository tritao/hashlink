#!/bin/sh

set -u

hl=$1
bytecode=$2
stdout=$(mktemp "${TMPDIR:-/tmp}/hashlink-exception-stdout.XXXXXX") || exit 1
stderr=$(mktemp "${TMPDIR:-/tmp}/hashlink-exception-stderr.XXXXXX") || exit 1
trap 'rm -f "$stdout" "$stderr"' EXIT HUP INT TERM

fail() {
	echo "exception reporting test failed: $1" >&2
	echo "stdout:" >&2
	cat "$stdout" >&2
	echo "stderr:" >&2
	cat "$stderr" >&2
	exit 1
}

"$hl" "$bytecode" main >"$stdout" 2>"$stderr"
status=$?
[ "$status" -eq 1 ] || fail "main-thread exception exited with $status instead of 1"
[ ! -s "$stdout" ] || fail "main-thread exception was written to stdout"
grep -F 'Uncaught exception: main exception' "$stderr" >/dev/null \
	|| fail "main-thread exception message was missing"
grep -F '  at ExceptionReporting.main (ExceptionReporting.hx:3)' "$stderr" >/dev/null \
	|| fail "main-thread exception frame was missing"
grep -F '  at <entry> (<generated>:1)' "$stderr" >/dev/null \
	|| fail "generated entry frame was not normalized"

: >"$stdout"
: >"$stderr"
"$hl" "$bytecode" worker >"$stdout" 2>"$stderr" &
pid=$!
found=false
for attempt in 1 2 3 4 5; do
	if grep -F 'Uncaught exception: worker exception' "$stderr" >/dev/null; then
		found=true
		break
	fi
	sleep 1
done
kill -TERM "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
[ "$found" = true ] || fail "worker-thread exception message was missing"
[ ! -s "$stdout" ] || fail "worker-thread exception was written to stdout"
grep -F '  at ExceptionReporting.' "$stderr" >/dev/null \
	|| fail "worker-thread exception frame was missing"
