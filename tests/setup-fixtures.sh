#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Creates everything tests/test-suite.sh expects to find on the machine.
#
#   SAFEXEC_TEST_CONTAINER=1 tests/setup-fixtures.sh <default-binary> <full-binary>
#
# WARNING: this is host-modifying. It creates users (tester, alice), writes
# under /srv and /home, and installs SETUID-ROOT binaries into /usr/local/bin.
# Run it only in a disposable container/VM. It refuses to run otherwise.
#
# Idempotent: safe to re-run.

set -euo pipefail

if [[ "${SAFEXEC_TEST_CONTAINER:-}" != 1 ]]; then
    echo "REFUSING: this script adds users and installs setuid-root binaries." >&2
    echo "Re-run inside a disposable container with SAFEXEC_TEST_CONTAINER=1." >&2
    exit 2
fi
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }

SX_DEFAULT="${1:?usage: $0 <default-binary> <full-binary>}"
SX_FULL="${2:?usage: $0 <default-binary> <full-binary>}"
[[ -x "$SX_DEFAULT" && -x "$SX_FULL" ]] || { echo "binary not executable" >&2; exit 2; }

IN=/srv/sxtest/in
OUT=/srv/sxtest/out

# --- users (uid/gid values are what test-suite.sh hardcodes) ----------------
ensure_user() { # name uid gid
    local name=$1 uid=$2 gid=$3
    if getent passwd "$uid" >/dev/null && [[ "$(getent passwd "$uid" | cut -d: -f1)" != "$name" ]]; then
        echo "uid $uid is already taken by another user; cannot create '$name'" >&2
        exit 2
    fi
    getent group "$gid" >/dev/null || groupadd -g "$gid" "$name"
    getent passwd "$name" >/dev/null || useradd -m -u "$uid" -g "$gid" -s /bin/bash "$name"
    chmod 0755 "/home/$name"   # useradd may default to 0700/0750; safexec drops uid and must traverse
}
ensure_user tester 1001 1002
ensure_user alice  1003 1003

# --- data fixtures ----------------------------------------------------------
install -d -m 0755 /srv /srv/sxtest "$IN"
install -d -m 1777 "$OUT"

printf 'hello safexec\n'                       > "$IN/hello.txt"
printf '# Title\n\nSome *markdown* text.\n'     > "$IN/sample.md"
printf '<html><body><h1>safexec</h1><p>fixture page</p></body></html>\n' > "$IN/sample.html"
# 64x64 on purpose: the suite resizes by 50% and expects '32x32'
convert -size 64x64 gradient:red-blue "$IN/sample.png"
# 2-page PDF (suite asserts Pages: 2). Rectangles only -> no font dependency.
ps=$(mktemp); trap 'rm -f "$ps"' EXIT
printf '72 700 100 20 rectfill showpage\n72 700 100 20 rectfill showpage\n' > "$ps"
gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile="$IN/sample.pdf" "$ps"
chmod 0644 "$IN"/*

# rg owner-drop fixtures
install -d -o tester -g 1002 -m 0755 /home/tester/proj
printf 'tester needle\n' > /home/tester/proj/a.txt
chown tester:1002 /home/tester/proj/a.txt
# 0700 so 'tester' can NOT read it directly; only a drop-to-owner can
install -d -o alice -g alice -m 0700 /home/alice/proj
printf 'alice-secret needle\n' > /home/alice/proj/a.txt
chown alice:alice /home/alice/proj/a.txt

install -d -m 0755 /srv/rootdir                     # root-owned -> must be refused
if getent passwd 4242 >/dev/null; then echo "uid 4242 must not exist (orphan fixture)" >&2; exit 2; fi
install -d -o 4242 -g 4242 -m 0755 /srv/orphan      # uid absent from passwd -> must be refused

# --- binaries under test ----------------------------------------------------
install -o root -g root -m 4755 "$SX_DEFAULT" /usr/local/bin/safexec        # setuid, default buckets
install -o root -g root -m 4755 "$SX_FULL"    /usr/local/bin/safexec-full   # setuid, all optional buckets
install -o root -g root -m 0755 "$SX_DEFAULT" /usr/local/bin/safexec-plain  # NOT setuid: pass-through mode

echo "fixtures ready:"
ls -l /usr/local/bin/safexec /usr/local/bin/safexec-full /usr/local/bin/safexec-plain
