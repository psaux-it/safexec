#!/bin/sh
# SPDX-License-Identifier: MIT
#
# smoke/regression suite for safexec
#
# Invocation (matches Makefile's `check` target):
#   ./tests/run.sh [path-to-safexec-binary]
#
# Exit code: 0 if all executed tests passed (SKIPs do not count as failure),
# non-zero otherwise.

set -u

# Predictable perms on anything we create below. This matters because
# safexec's privilege-drop branch triggers on geteuid()==0 alone — it does
# not check whether the binary is actually installed setuid-root. That means
# if THIS SCRIPT is itself invoked as root (common in minimal-distro CI
# containers that default to a root shell), safexec will still drop to
# 'nobody' before touching our fixture files. umask 022 + explicit chmod
# below ensure 'nobody' can read/execute what it needs to either way.
umask 022

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

SAFEXEC_ARG="${1:-}"
if [ -z "$SAFEXEC_ARG" ]; then
    if [ -x "./build/safexec" ]; then
        SAFEXEC_ARG="./build/safexec"
    elif [ -x "build/safexec" ]; then
        SAFEXEC_ARG="build/safexec"
    else
        echo "FATAL: no safexec binary given and build/safexec not found" >&2
        echo "Usage: $0 /path/to/safexec" >&2
        exit 2
    fi
fi

# Resolve to an absolute path up front — several tests below deliberately
# manipulate PATH/cwd, and a relative SAFEXEC_ARG would break under that.
case "$SAFEXEC_ARG" in
    /*) SAFEXEC="$SAFEXEC_ARG" ;;
    *)  SAFEXEC="$(pwd)/$SAFEXEC_ARG" ;;
esac

if [ ! -x "$SAFEXEC" ]; then
    echo "FATAL: '$SAFEXEC' is not an executable file" >&2
    exit 2
fi

WORKDIR="$(mktemp -d 2>/dev/null || echo /tmp/safexec-test.$$)"
mkdir -p "$WORKDIR" 2>/dev/null
# mktemp -d defaults to 0700; if safexec ends up dropping to 'nobody' (see
# umask note above), 'nobody' still needs to traverse into this directory.
chmod 755 "$WORKDIR" 2>/dev/null
cleanup() {
    rm -rf "$WORKDIR" 2>/dev/null
}
trap cleanup EXIT INT TERM HUP

PASS=0
FAIL=0
SKIP=0
FAILED_NAMES=""

pass() {
    PASS=$((PASS + 1))
    printf 'PASS: %s\n' "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    FAILED_NAMES="$FAILED_NAMES
  - $1"
    printf 'FAIL: %s\n' "$1"
    if [ -n "${2:-}" ]; then
        printf '      %s\n' "$2"
    fi
}

skip() {
    SKIP=$((SKIP + 1))
    printf 'SKIP: %s (%s)\n' "$1" "$2"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# Run safexec with args, capturing stdout, stderr, and exit code into
# $OUT, $ERR, $RC. Avoids bash-only `$(...)`+PIPESTATUS gymnastics.
run_safexec() {
    _out_f="$WORKDIR/stdout.$$"
    _err_f="$WORKDIR/stderr.$$"
    "$SAFEXEC" "$@" >"$_out_f" 2>"$_err_f"
    RC=$?
    OUT="$(cat "$_out_f" 2>/dev/null)"
    ERR="$(cat "$_err_f" 2>/dev/null)"
    rm -f "$_out_f" "$_err_f"
}

# contains HAYSTACK NEEDLE -> 0 if found
contains() {
    case "$1" in
        *"$2"*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# 1. Basic CLI surface: usage / help / version
# ---------------------------------------------------------------------------

run_safexec
if [ "$RC" -eq 1 ] && contains "$OUT$ERR" "Usage"; then
    pass "no-args prints usage and exits 1"
else
    fail "no-args prints usage and exits 1" "rc=$RC out=[$OUT] err=[$ERR]"
fi

run_safexec --help
if [ "$RC" -eq 0 ] && contains "$OUT" "Usage"; then
    pass "--help exits 0 and prints usage"
else
    fail "--help exits 0 and prints usage" "rc=$RC out=[$OUT]"
fi

run_safexec -h
if [ "$RC" -eq 0 ] && contains "$OUT" "Usage"; then
    pass "-h exits 0 and prints usage"
else
    fail "-h exits 0 and prints usage" "rc=$RC out=[$OUT]"
fi

run_safexec --version
if [ "$RC" -eq 0 ] && contains "$OUT" "safexec"; then
    pass "--version exits 0 and prints name"
else
    fail "--version exits 0 and prints name" "rc=$RC out=[$OUT]"
fi

run_safexec -v
if [ "$RC" -eq 0 ] && contains "$OUT" "safexec"; then
    pass "-v exits 0 and prints name"
else
    fail "-v exits 0 and prints name" "rc=$RC out=[$OUT]"
fi

# ---------------------------------------------------------------------------
# 2. Argument-shape rejections (checked before any tool resolution)
# ---------------------------------------------------------------------------

run_safexec 123
if [ "$RC" -eq 1 ]; then
    pass "purely-numeric first arg rejected"
else
    fail "purely-numeric first arg rejected" "rc=$RC"
fi

run_safexec --bogus-flag
if [ "$RC" -eq 1 ]; then
    pass "leading-dash first arg rejected"
else
    fail "leading-dash first arg rejected" "rc=$RC"
fi

run_safexec --kill
if [ "$RC" -eq 1 ]; then
    pass "--kill without '=' rejected"
else
    fail "--kill without '=' rejected" "rc=$RC"
fi

run_safexec --kill=abc
if [ "$RC" -eq 1 ] && contains "$ERR" "Invalid PID"; then
    pass "--kill=<non-numeric> rejected"
else
    fail "--kill=<non-numeric> rejected" "rc=$RC err=[$ERR]"
fi

run_safexec --kill=0
if [ "$RC" -eq 1 ]; then
    pass "--kill=0 rejected"
else
    fail "--kill=0 rejected" "rc=$RC"
fi

run_safexec --kill=-5
if [ "$RC" -eq 1 ]; then
    pass "--kill=<negative> rejected"
else
    fail "--kill=<negative> rejected" "rc=$RC"
fi

# A PID that (almost certainly) does not exist right now.
run_safexec --kill=2147483647
if [ "$RC" -eq 1 ]; then
    pass "--kill=<nonexistent pid> rejected"
else
    fail "--kill=<nonexistent pid> rejected" "rc=$RC"
fi

# ---------------------------------------------------------------------------
# 3. Allowlist enforcement
# ---------------------------------------------------------------------------

# `cat` is deliberately NOT in ALLOWED_BINS.
run_safexec cat /etc/hostname
if [ "$RC" -eq 1 ] && contains "$ERR" "not allowed"; then
    pass "disallowed binary (cat) rejected"
else
    fail "disallowed binary (cat) rejected" "rc=$RC err=[$ERR]"
fi

# Shells must never be reachable as the *target* program.
run_safexec sh -c 'echo pwned'
if [ "$RC" -eq 1 ]; then
    pass "bare shell as target rejected"
else
    fail "bare shell as target rejected" "rc=$RC out=[$OUT]"
fi

# Shell must also be rejected when disguised ahead of an allowed tool.
if have sha256sum; then
    run_safexec sh -c 'sha256sum /etc/hostname'
    if [ "$RC" -eq 1 ]; then
        pass "shell prelude before allowed tool rejected"
    else
        fail "shell prelude before allowed tool rejected" "rc=$RC out=[$OUT]"
    fi
else
    skip "shell prelude before allowed tool rejected" "sha256sum not installed"
fi

# ---------------------------------------------------------------------------
# 4. Environment-assignment prelude filtering
# ---------------------------------------------------------------------------

if have sha256sum; then
    echo "safexec-test-payload" > "$WORKDIR/sample.txt"

    # Dangerous assignment before the tool must be rejected outright.
    run_safexec LD_PRELOAD=/tmp/whatever.so sha256sum "$WORKDIR/sample.txt"
    if [ "$RC" -eq 1 ]; then
        pass "dangerous env assignment (LD_PRELOAD=) in prelude rejected"
    else
        fail "dangerous env assignment (LD_PRELOAD=) in prelude rejected" "rc=$RC out=[$OUT]"
    fi

    run_safexec PATH=/tmp sha256sum "$WORKDIR/sample.txt"
    if [ "$RC" -eq 1 ]; then
        pass "dangerous env assignment (PATH=) in prelude rejected"
    else
        fail "dangerous env assignment (PATH=) in prelude rejected" "rc=$RC out=[$OUT]"
    fi

    # An explicitly allowlisted proxy assignment must clear the prelude
    # *security filter* (i.e. must NOT produce the "rejecting dangerous
    # assignment" message that LD_PRELOAD=/PATH= trigger above).
    #
    # Note: this only tests the allowlist gate itself. A bare "VAR=val" token
    # with no actual wrapper (e.g. no "env" ahead of it) is not turned into a
    # real environment variable by safexec — nothing in ALLOWED_BINS/
    # is_wrapper_name consumes it that way, so the final execvp() still
    # targets argv[1] literally and can fail for unrelated plumbing reasons.
    # That's a separate, non-security codepath and out of scope here.
    run_safexec HTTPS_PROXY=http://127.0.0.1:0 sha256sum "$WORKDIR/sample.txt"
    if ! contains "$ERR" "rejecting dangerous assignment"; then
        pass "allowlisted env assignment (HTTPS_PROXY=) clears prelude security filter"
    else
        fail "allowlisted env assignment (HTTPS_PROXY=) clears prelude security filter" "rc=$RC err=[$ERR]"
    fi
else
    skip "env-assignment prelude filtering (3 cases)" "sha256sum not installed"
fi

# ---------------------------------------------------------------------------
# 5. Absolute-path pinning / PATH-hijack resistance
#
# This is the core security property of safexec: even if PATH is poisoned
# with a malicious same-named binary ahead of the real one, safexec must
# resolve and exec the trusted-directory copy, never the attacker's.
# ---------------------------------------------------------------------------

if have sha256sum; then
    HIJACK_DIR="$WORKDIR/hijack"
    mkdir -p "$HIJACK_DIR"
    chmod 755 "$HIJACK_DIR"
    cat > "$HIJACK_DIR/sha256sum" <<'EOF'
#!/bin/sh
echo "PWNED-BY-FAKE-BINARY"
exit 0
EOF
    chmod 755 "$HIJACK_DIR/sha256sum"

    echo "safexec-test-payload" > "$WORKDIR/sample.txt"

    # Run with the poisoned dir first in PATH and cwd set there too, to give
    # the hijack every possible advantage a real attacker would have.
    ( cd "$HIJACK_DIR" && PATH="$HIJACK_DIR:$PATH" "$SAFEXEC" sha256sum "$WORKDIR/sample.txt" >"$WORKDIR/hj.out" 2>"$WORKDIR/hj.err" )
    HJ_RC=$?
    HJ_OUT="$(cat "$WORKDIR/hj.out" 2>/dev/null)"

    if [ "$HJ_RC" -eq 0 ] && ! contains "$HJ_OUT" "PWNED"; then
        pass "PATH-hijacked sha256sum ignored; trusted binary executed"
    else
        fail "PATH-hijacked sha256sum ignored; trusted binary executed" "rc=$HJ_RC out=[$HJ_OUT]"
    fi
else
    skip "PATH-hijack resistance" "sha256sum not installed"
fi

# Explicit wrapper path outside trusted dirs must be refused.
run_safexec "$HIJACK_DIR/nohup" sha256sum "$WORKDIR/sample.txt" 2>/dev/null
if [ "$RC" -eq 1 ]; then
    pass "explicit wrapper path outside trusted dirs rejected"
else
    fail "explicit wrapper path outside trusted dirs rejected" "rc=$RC"
fi

# ---------------------------------------------------------------------------
# 6. Wrapper prelude (nohup/nice/timeout/...) — only if actually installed
# ---------------------------------------------------------------------------

if have nohup && have sha256sum; then
    run_safexec nohup sha256sum "$WORKDIR/sample.txt"
    if [ "$RC" -eq 0 ] && contains "$ERR" "pinned wrapper"; then
        pass "nohup wrapper prelude accepted and pinned"
    else
        fail "nohup wrapper prelude accepted and pinned" "rc=$RC err=[$ERR]"
    fi
else
    skip "nohup wrapper prelude" "nohup or sha256sum not installed"
fi

# ---------------------------------------------------------------------------
# 7. Successful pass-through execution + SAFEXEC_QUIET behavior
# ---------------------------------------------------------------------------

if have sha256sum; then
    run_safexec sha256sum "$WORKDIR/sample.txt"
    if [ "$RC" -eq 0 ] && [ -n "$OUT" ]; then
        pass "allowed tool executes successfully and produces output"
    else
        fail "allowed tool executes successfully and produces output" "rc=$RC out=[$OUT]"
    fi

    SAFEXEC_QUIET=1 "$SAFEXEC" sha256sum "$WORKDIR/sample.txt" >"$WORKDIR/q.out" 2>"$WORKDIR/q.err"
    Q_RC=$?
    Q_OUT="$(cat "$WORKDIR/q.out" 2>/dev/null)"
    Q_ERR="$(cat "$WORKDIR/q.err" 2>/dev/null)"
    if [ "$Q_RC" -eq 0 ] && [ -n "$Q_OUT" ] && [ -z "$Q_ERR" ]; then
        pass "SAFEXEC_QUIET=1 suppresses Info/Summary lines, keeps stdout"
    else
        fail "SAFEXEC_QUIET=1 suppresses Info/Summary lines, keeps stdout" "rc=$Q_RC out=[$Q_OUT] err=[$Q_ERR]"
    fi
else
    skip "pass-through execution + SAFEXEC_QUIET (2 cases)" "sha256sum not installed"
fi

# ---------------------------------------------------------------------------
# 8. Optional-bucket tools — probe, never assume present
# ---------------------------------------------------------------------------

for tool in wget curl gzip xz zip unzip tar; do
    if have "$tool"; then
        case "$tool" in
            wget) run_safexec wget --version ;;
            curl) run_safexec curl --version ;;
            gzip) run_safexec gzip --version ;;
            xz)   run_safexec xz --version ;;
            zip)  run_safexec zip --version ;;
            unzip) run_safexec unzip -v ;;
            tar)  run_safexec tar --version ;;
        esac
        if [ "$RC" -eq 0 ]; then
            pass "optional allowed tool '$tool' resolves and runs"
        else
            fail "optional allowed tool '$tool' resolves and runs" "rc=$RC err=[$ERR]"
        fi
    else
        skip "optional allowed tool '$tool'" "not installed"
    fi
done

# ---------------------------------------------------------------------------
# 9. Root-only behavior (privilege drop, cgroup/rlimit isolation)
#
# Only meaningful when this script itself runs as root AND the binary under
# test is actually installed setuid-root (build/safexec fresh off `make` is
# neither). Self-skips otherwise rather than reporting false failures.
# ---------------------------------------------------------------------------

CAN_TEST_ROOT=0
if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    OWNER_UID="$(stat -c '%u' "$SAFEXEC" 2>/dev/null || stat -f '%u' "$SAFEXEC" 2>/dev/null || echo "?")"
    PERM_MODE="$(stat -c '%a' "$SAFEXEC" 2>/dev/null || stat -f '%Lp' "$SAFEXEC" 2>/dev/null || echo "?")"
    case "$PERM_MODE" in
        4*|*7[0-7][0-7]) : ;;
    esac
    if [ "$OWNER_UID" = "0" ]; then
        case "$PERM_MODE" in
            4[0-7][0-7][0-7]) CAN_TEST_ROOT=1 ;;
        esac
    fi
fi

if [ "$CAN_TEST_ROOT" = "1" ] && have sha256sum; then
    run_safexec sha256sum "$WORKDIR/sample.txt"
    if [ "$RC" -eq 0 ] && contains "$ERR" "dropping to"; then
        pass "setuid-root binary drops privileges before exec"
    else
        fail "setuid-root binary drops privileges before exec" "rc=$RC err=[$ERR]"
    fi
else
    skip "privilege-drop (root/setuid-specific)" "not running as root against a setuid-root binary"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "-----------------------------------------"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed tests:$FAILED_NAMES"
    exit 1
fi
exit 0
