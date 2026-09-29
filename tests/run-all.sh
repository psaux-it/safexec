#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Full safexec test run: build -> fixtures -> parser fuzz -> smoke -> functional.
#
#   SAFEXEC_TEST_CONTAINER=1 tests/run-all.sh
#
# Host-modifying (see tests/setup-fixtures.sh): disposable containers only.
# Exit status is non-zero if ANY stage fails.
#
# Env:
#   SXTEST_RESULTS   output dir for logs      (default /tmp/safexec-test-results)
#   FUZZ_RUNS        parser-fuzz repetitions  (default 3; each run seeds from time())

set -uo pipefail

[[ "${SAFEXEC_TEST_CONTAINER:-}" == 1 ]] || {
    echo "Run inside a disposable container/VM with SAFEXEC_TEST_CONTAINER=1." >&2
    exit 2
}

[[ $EUID -eq 0 ]] || {
    echo "Must run as root to install dependencies and prepare fixtures." >&2
    exit 2
}

cd "$(dirname "$(readlink -f "$0")")/.."

RESULTS="${SXTEST_RESULTS:-/tmp/safexec-test-results}"
FUZZ_RUNS="${FUZZ_RUNS:-3}"
mkdir -p "$RESULTS"
export SXTEST_LOG="$RESULTS/test-suite.log"

declare -A STAGE
run_stage() { # name cmd...
    local name=$1; shift
    printf '\n######## %s ########\n' "$name"
    "$@" > >(tee "$RESULTS/$name.log") 2>&1
    STAGE[$name]=$?
}

CFLAGS_SAN="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"
FULL_BUCKETS="-DSAFEXEC_WITH_GS -DSAFEXEC_WITH_POPPLER -DSAFEXEC_WITH_DB -DSAFEXEC_WITH_RSYNC_GIT"

install_deps() {
    command -v apt-get >/dev/null 2>&1 || {
        echo "Automatic dependency installation requires apt-get." >&2
        return 1
    }

    apt-get update || return 1

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential python3 git time curl wget zip unzip xz-utils \
        ffmpeg imagemagick wkhtmltopdf pdftk-java pandoc poppler-utils \
        ripgrep rsync ghostscript redis-tools mariadb-client postgresql-client \
        || return 1
}

build() {
    make clean >/dev/null && make >/dev/null || return 1
    make BUILDDIR=build-full EXTRA_CPPFLAGS="$FULL_BUCKETS" build-full/safexec >/dev/null || return 1
    # parser-fuzz.c #includes safexec.c so static functions are reachable
    gcc -D_GNU_SOURCE -DSRC='"../safexec.c"' -O2 -Wall -Wextra \
        tests/parser-fuzz.c -o build/parser-fuzz || return 1
    # shellcheck disable=SC2086
    gcc -D_GNU_SOURCE -DSRC='"../safexec.c"' $CFLAGS_SAN \
        tests/parser-fuzz.c -o build/parser-fuzz-asan || return 1
    ls -l build/safexec build-full/safexec build/parser-fuzz build/parser-fuzz-asan
}

fuzz() {
    local rc=0 i
    for ((i = 1; i <= FUZZ_RUNS; i++)); do
        ./build/parser-fuzz || rc=1
        sleep 1   # harness seeds from time(NULL): avoid identical seeds
    done
    ./build/parser-fuzz-asan || rc=1
    return $rc
}

run_stage deps      install_deps
[[ ${STAGE[deps]} -eq 0 ]] || {
    echo "dependency installation failed; aborting"
    exit 1
}

run_stage build     build
[[ ${STAGE[build]} -eq 0 ]] || { echo "build failed; aborting"; exit 1; }

run_stage fuzz      fuzz
run_stage fixtures  tests/setup-fixtures.sh build/safexec build-full/safexec
[[ ${STAGE[fixtures]} -eq 0 ]] || { echo "fixture setup failed; aborting"; exit 1; }

run_stage smoke     sh tests/run.sh ./build/safexec
run_stage functional bash tests/test-suite.sh

printf '\n======== OVERALL ========\n'
overall=0
for s in deps build fuzz fixtures smoke functional; do
    printf '%-12s %s\n' "$s" "$([[ ${STAGE[$s]} -eq 0 ]] && echo OK || echo "FAILED (rc=${STAGE[$s]})")"
    [[ ${STAGE[$s]} -eq 0 ]] || overall=1
done
echo "logs: $RESULTS"
exit $overall
