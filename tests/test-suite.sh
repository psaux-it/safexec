#!/bin/bash
# safexec functional + security test-suite. Runs as root, invokes safexec as uid 1001 (tester).
SX=/usr/local/bin/safexec; SXF=/usr/local/bin/safexec-full; SXP=/usr/local/bin/safexec-plain
export SX SXF SXP
AS=(setpriv --reuid=1001 --regid=1002 --clear-groups)
IN=/srv/sxtest/in; OUTD=/srv/sxtest/out
PASS=0; FAIL=0; FAILS=(); LOG="${SXTEST_LOG:-/tmp/safexec-test-results/test-suite.log}"; mkdir -p "$(dirname "$LOG")"; : > "$LOG"
python3 "$(dirname "$(readlink -f "$0")")/srv.py" >/dev/null 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; pkill -f "ffmpeg.*testsrc" 2>/dev/null' EXIT
sleep 1
cd /srv/sxtest

T() { # name want_rc|any pattern(!neg ok) cmd...
  local name="$1" want="$2" pat="$3"; shift 3
  _t0=$SECONDS; OUT=$("$@" 2>&1); RC=$?; ((SECONDS-_t0>10)) && echo "  (slow test: $((SECONDS-_t0))s: $name)"
  local good=1 why=""
  if [[ "$want" != any && "$RC" != "$want" ]]; then good=0; why="rc=$RC want=$want"; fi
  if [[ -n "$pat" ]]; then
    if [[ "$pat" == '!'* ]]; then grep -Eq -- "${pat#!}" <<<"$OUT" && { good=0; why+=" unexpected /${pat#!}/"; }
    else grep -Eq -- "$pat" <<<"$OUT" || { good=0; why+=" missing /$pat/"; }; fi
  fi
  if ((good)); then PASS=$((PASS+1)); printf 'PASS  %s\n' "$name"; printf 'PASS %s\n' "$name" >>$LOG
  else FAIL=$((FAIL+1)); FAILS+=("$name"); printf 'FAIL  %s  [%s]\n' "$name" "$why"; { printf 'FAIL %s [%s]\n' "$name" "$why"; echo "$OUT" | head -15 | sed 's/^/    | /'; } | tee -a $LOG | tail -n +2 | head -8; fi
}
sec() { printf '\n===== %s =====\n' "$1"; }
A() { timeout 120 "${AS[@]}" "$@"; }     # run as tester

sec "1. CLI surface & argument validation"
T "version"                0 'safexec 1\.9\.6'         A $SX --version
T "version -v"             0 'safexec 1\.9\.6'         A $SX -v
T "help"                   0 'Usage'                    A $SX --help
T "help -h"                0 'Usage'                    A $SX -h
T "no args -> 3"           3 'Usage'                    A $SX
T "--kill w/o = -> 3"      3 'Usage'                    A $SX --kill
T "--kill 123 (space)->3"  3 'Usage'                    A $SX --kill 123
T "--kill=abc -> 1"        1 'Invalid PID'              A $SX --kill=abc
T "--kill=0 -> 1"          1 'Invalid PID'              A $SX --kill=0
T "--kill=-5 -> 1"         1 'Invalid PID'              A $SX --kill=-5
T "--kill=huge -> 1"       1 'Invalid PID'              A $SX --kill=99999999999
T "--kill=nonexistent"     1 'does not exist'           A $SX --kill=4194000
T "--kill=1 (init) refused" 1 'Refusing'                A $SX --kill=1
T "option-first -> 3"      3 'Usage'                    A $SX -x curl
T "digits-first -> 3"      3 'Usage'                    A $SX 123 curl
T "empty tool name -> 3"   3 ''                         A $SX ""

sec "2. Allowlist enforcement / shells / prelude smuggling"
for s in sh bash dash zsh ksh fish ash; do T "reject shell: $s" 3 'not allowed|rejecting shell' A $SX $s -c 'id'; done
T "reject /bin/sh -c"          3 'not allowed|rejecting shell' A $SX /bin/sh -c id
T "reject ls"                  3 'not allowed'  A $SX ls /
T "reject id"                  3 'not allowed'  A $SX id
T "reject env (not a wrapper)" 3 'not allowed'  A $SX env id
T "reject nice bash"           3 'rejecting shell|not allowed' A $SX nice bash -c id
T "reject timeout 5 sh"        3 'rejecting shell|not allowed' A $SX timeout 5 sh -c id
# Pin the shell detector itself: the allowlist would also reject this, so the looser
# 'not allowed|rejecting shell' patterns above cannot tell whether the detector still fires.
T "shell before allowed tool: detector fires (defense in depth)" 3 'rejecting shell interpreter' A $SX sh -c 'sha256sum /srv/sxtest/in/hello.txt'
T "reject python3"             3 'not allowed'  A $SX python3 -c 'print(1)'
T "reject perl"                3 'not allowed'  A $SX perl -e 1
T "reject PATH= assignment"    3 'dangerous assignment|not allowed' A $SX PATH=/tmp curl --version
T "reject LD_PRELOAD="         3 'dangerous assignment|not allowed' A $SX LD_PRELOAD=/tmp/x.so curl --version
T "reject unknown FOO=bar"     3 'dangerous assignment|not allowed' A $SX FOO=bar curl --version
T "reject DYLD_ prefix"        3 'dangerous assignment|not allowed' A $SX DYLD_INSERT_LIBRARIES=x curl --version
T "assign after wrapper (nice PATH=)" 3 'dangerous assignment|not allowed' A $SX nice PATH=/tmp curl --version
T "reject magick (not installed => unresolvable)" 3 'cannot resolve trusted path' A $SX magick -version
T "buckets OFF: gs"            3 'not allowed'  A $SX gs --version
T "buckets OFF: pdfinfo"       3 'not allowed'  A $SX pdfinfo -v
T "buckets OFF: mysql"         3 'not allowed'  A $SX mysql --version
T "buckets OFF: rsync"         3 'not allowed'  A $SX rsync --version
T "buckets OFF: git"           3 'not allowed'  A $SX git --version
T "buckets OFF: redis-cli"     3 'not allowed'  A $SX redis-cli --version

sec "3. Path pinning (fake binaries / PATH hijack / traversal)"
rm -rf /tmp/evil; mkdir -p /tmp/evil; chmod 755 /tmp/evil
printf '#!/bin/sh\ntouch /tmp/evil/PWNED_curl\necho FAKE-CURL\n' > /tmp/evil/curl
printf '#!/bin/sh\ntouch /tmp/evil/PWNED_nice\necho FAKE-NICE\nexec "$@"\n' > /tmp/evil/nice
chmod 755 /tmp/evil/*
T "explicit /tmp/evil/curl is re-pinned" 0 'curl [0-9]+\.[0-9]+' A $SX /tmp/evil/curl --version
[[ ! -e /tmp/evil/PWNED_curl ]] && { PASS=$((PASS+1)); echo "PASS  fake curl never executed"; } || { FAIL=$((FAIL+1)); FAILS+=("fake curl executed"); echo "FAIL  fake curl executed"; }
T "PATH=/tmp/evil in caller env ignored (bare wrapper)" 0 'curl [0-9]+\.' A env PATH=/tmp/evil:/usr/bin $SX nice curl --version
[[ ! -e /tmp/evil/PWNED_nice ]] && { PASS=$((PASS+1)); echo "PASS  fake nice never executed"; } || { FAIL=$((FAIL+1)); FAILS+=("fake nice executed"); echo "FAIL  fake nice executed"; }
T "wrapper explicit /tmp/evil/nice rejected" 3 'outside trusted' A $SX /tmp/evil/nice curl --version
T "wrapper ./nice rejected"    3 'outside trusted' bash -c "cd /tmp/evil && ${AS[*]} $SX ./nice curl --version"
T "wrapper /usr/bin/../bin/nice rejected" 3 'outside trusted' A $SX /usr/bin/../bin/nice curl --version
T "wrapper /usr/bin/x/nice rejected"      3 'outside trusted' A $SX /usr/bin/x/nice curl --version
T "wrapper /usr/bin/nice accepted"        0 'curl [0-9]+\.' A $SX /usr/bin/nice curl --version
T "wrapper /bin/nice accepted (symlinked /bin)" 0 'curl [0-9]+\.' A $SX /bin/nice curl --version
ln -sf /tmp/evil/nice /tmp/evil/nice.lnk
T "cwd holding fake 'curl' ignored" 0 'curl [0-9]+\.' bash -c "cd /tmp/evil && ${AS[*]} $SX curl --version"
[[ ! -e /tmp/evil/PWNED_curl ]] && { PASS=$((PASS+1)); echo "PASS  cwd fake curl not executed"; } || { FAIL=$((FAIL+1)); FAILS+=("cwd fake curl"); }

sec "4. Privilege drop, environment scrubbing, fd hygiene (setuid mode)"
T "uid/gid = nobody"      0 'Uid:.65534.65534.65534.65534'  A $SX curl -s file:///proc/self/status
T "supplementary groups cleared" 0 'Groups:\s*$'  bash -c "${AS[*]} $SX curl -s file:///proc/self/status | grep Groups"
T "NoNewPrivs=1"          0 'NoNewPrivs:.1'  A $SX curl -s file:///proc/self/status
T "umask 077"             0 'Umask:.0077'    A $SX curl -s file:///proc/self/status
T "caps dropped (CapEff=0)" 0 'CapEff:.0+$'  bash -c "${AS[*]} $SX curl -s file:///proc/self/status | grep CapEff"
T "env whitelist only"    0 '^PATH=.*' bash -c "${AS[*]} env LD_PRELOAD=/tmp/x.so LD_LIBRARY_PATH=/tmp FOO=bar IFS=x PYTHONPATH=/tmp HTTP_PROXY=http://1.2.3.4:1 $SX curl -s file:///proc/self/environ | tr '\\0' '\\n'"
T "env: no LD_PRELOAD leak" 0 '!LD_PRELOAD|FOO=|PYTHONPATH|HTTP_PROXY|IFS=' bash -c "${AS[*]} env LD_PRELOAD=/tmp/x.so FOO=bar IFS=x PYTHONPATH=/tmp HTTP_PROXY=http://1.2.3.4:1 $SX curl -s file:///proc/self/environ | tr '\\0' '\\n'"
T "env: UTF-8 locale set" 0 'LANG=C.UTF-8' bash -c "${AS[*]} $SX curl -s file:///proc/self/environ | tr '\\0' '\\n'"
T "fd 9 leaked in pass-through (control)" 0 'hello safexec' bash -c "exec 9<$IN/hello.txt; ${AS[*]/setpriv/setpriv} $SXP curl -s file:///proc/self/fd/9" 
T "fd 9 CLOSED in setuid mode" any '!hello safexec' bash -c "exec 9<$IN/hello.txt; ${AS[*]} $SX curl -s file:///proc/self/fd/9"
T "exit code passthrough: curl conn refused (7)" 7 '' A $SX curl -s http://127.0.0.1:1/
T "exit code passthrough: sha256sum missing (1)" 1 '' A $SX sha256sum /nonexistent
T "DETACH=rlimits from unprivileged caller is IGNORED (secure_getenv/AT_SECURE)" 0 '!falling back to RLIMITs' bash -c "${AS[*]} env SAFEXEC_DETACH=rlimits $SX curl --version"
T "DETACH=off from unprivileged caller cannot disable isolation" 0 'using cgroup v2 child' bash -c "${AS[*]} env SAFEXEC_DETACH=off $SX curl --version"
T "DETACH=rlimits honoured when run by real root" 0 'falling back to RLIMITs' env SAFEXEC_DETACH=rlimits $SXP curl --version
T "DETACH=off honoured when run by real root" 0 '!falling back|using cgroup' env SAFEXEC_DETACH=off $SXP curl --version
T "DETACH=cgv2 (root) uses cgroup" 0 'using cgroup v2 child' env SAFEXEC_DETACH=cgv2 $SXP curl --version
T "DETACH=bogus -> auto"     0 'curl [0-9]+\.' bash -c "${AS[*]} env SAFEXEC_DETACH=bogus $SX curl --version"
T "QUIET=1 silences info"    0 '!Info:|Summary:' bash -c "${AS[*]} env SAFEXEC_QUIET=1 $SX curl --version"
T "QUIET=1 still prints tool output" 0 'curl [0-9]+\.' bash -c "${AS[*]} env SAFEXEC_QUIET=1 $SX curl --version"
T "SAFE_CWD=1 from unwritable cwd" 0 'switching to /tmp' bash -c "cd /usr && ${AS[*]} env SAFEXEC_SAFE_CWD=1 $SX curl --version"
T "SAFE_CWD=0 keeps cwd" 0 '!switching to /tmp' bash -c "cd /usr && ${AS[*]} env SAFEXEC_SAFE_CWD=0 $SX curl --version"

sec "5. Pass-through mode (no setuid)"
T "pass-through banner"      0 'Pass-Through Mode' A $SXP curl --version
T "pass-through keeps uid"   0 'Uid:.1001' A $SXP curl -s file:///proc/self/status
T "pass-through NNP not set" 0 'NoNewPrivs:.0' A $SXP curl -s file:///proc/self/status
T "pass-through still enforces allowlist" 3 'not allowed' A $SXP bash -c id
T "pass-through still pins path" 0 'curl [0-9]+\.' A $SXP /tmp/evil/curl --version

sec "6. Prelude wrappers"
T "nohup"               0 'hello safexec' bash -c "cd /tmp && ${AS[*]} $SX nohup sha256sum $IN/hello.txt >/dev/null 2>&1; ${AS[*]} $SX nohup curl -s file://$IN/hello.txt"
T "nice -n 7 effective" 0 '^7$' bash -c "${AS[*]} $SX nice -n 7 curl -s file:///proc/self/stat | awk '{print \$19}'"
T "nice 5 (legacy form)" any 'curl [0-9]+\.' A $SX nice -5 curl --version
T "timeout 20 (integer)" 0 'curl [0-9]+\.' A $SX timeout 20 curl --version
T "timeout kills slow (124)" 124 '' A $SX timeout 2 curl -s http://127.0.0.1:8099/slow
T "timeout -sKILL 20 (attached form)" 0 'curl [0-9]+\.' A $SX timeout -sKILL 20 curl --version
T "[limitation] timeout -s KILL (separate word) still rejected" 3 "'KILL' is not allowed" A $SX timeout -s KILL 20 curl --version
T "timeout 5s (suffix)"  0 'curl [0-9]+\.' A $SX timeout 5s curl --version
T "timeout 1.5 (decimal)" 0 'curl [0-9]+\.' A $SX timeout 1.5 curl --version
T "stdbuf -o0"          0 'curl [0-9]+\.' A $SX stdbuf -o0 curl --version
T "stdbuf -oL -eL"      0 'curl [0-9]+\.' A $SX stdbuf -oL -eL curl --version
T "ionice -c3"          0 'curl [0-9]+\.' A $SX ionice -c3 curl --version
T "ionice -c 2 -n 7"    0 'curl [0-9]+\.' A $SX ionice -c 2 -n 7 curl --version
T "taskset 1 (int mask)" 0 'curl [0-9]+\.' A $SX taskset 1 curl --version
T "taskset -c 0"        0 'curl [0-9]+\.' A $SX taskset -c 0 curl --version
T "taskset 0x1 (hex mask)" 0 'curl [0-9]+\.' A $SX taskset 0x1 curl --version
T "taskset -c 0,1"      0 'curl [0-9]+\.' A $SX taskset -c 0,1 curl --version
T "setsid"              0 'curl [0-9]+\.' A $SX setsid curl --version
T "setsid -w"           0 'curl [0-9]+\.' A $SX setsid -w curl --version
T "chrt -o 0"           0 'curl [0-9]+\.' A $SX chrt -o 0 curl --version
T "time (/usr/bin/time)" 0 'curl [0-9]+\.' A $SX time curl --version
T "chain: nohup nice timeout stdbuf" 0 'curl [0-9]+\.' A $SX nohup nice -n 3 timeout 10 stdbuf -o0 curl --version
T "chain: setsid ionice taskset chrt time" 0 'curl [0-9]+\.' A $SX setsid -w ionice -c3 taskset -c 0 chrt -o 0 time curl --version
T "all wrappers pinned in log" 0 "pinned wrapper 'nohup'.*|pinned wrapper 'nice'" A $SX nohup nice curl --version
T "HTTP_PROXY= assignment then tool (documented feature)" 0 'curl [0-9]+\.' A $SX HTTP_PROXY=http://127.0.0.1:9 curl --version
T "assignment after wrapper: nice HTTP_PROXY=.. curl" 0 'curl [0-9]+\.' A $SX nice HTTP_PROXY=http://127.0.0.1:9 curl --version

sec "7. Every allowlisted tool, real work, as nobody (default build)"
rm -rf $OUTD/*; 
REF256=$(sha256sum $IN/hello.txt | cut -d' ' -f1); REF512=$(sha512sum $IN/hello.txt | cut -d' ' -f1)
REFB2=$(b2sum $IN/hello.txt | cut -d' ' -f1); REFCK=$(cksum $IN/hello.txt | cut -d' ' -f1)
T "curl http fetch"     0 'hello safexec' A $SX curl -s http://127.0.0.1:8099/hello.txt
T "curl -o file (owner=nobody)" 0 '' A $SX curl -s -o $OUTD/curl.txt http://127.0.0.1:8099/hello.txt
[[ "$(stat -c %u $OUTD/curl.txt 2>/dev/null)" == 65534 ]] && { PASS=$((PASS+1)); echo "PASS  curl output owned by nobody"; } || { FAIL=$((FAIL+1)); FAILS+=("curl owner"); echo "FAIL  curl output owner"; }
T "curl ignores caller proxy env" 0 'hello safexec' bash -c "${AS[*]} env http_proxy=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 $SX curl -s http://127.0.0.1:8099/hello.txt"
T "wget fetch"          0 '' A $SX wget -q -O $OUTD/wget.txt http://127.0.0.1:8099/hello.txt
T "wget content ok"     0 'hello safexec' cat $OUTD/wget.txt
T "tar create"          0 '' A $SX tar -czf $OUTD/a.tgz -C $IN hello.txt sample.md
T "tar list"            0 'hello.txt' A $SX tar -tzf $OUTD/a.tgz
T "tar extract"         0 '' A $SX tar -xzf $OUTD/a.tgz -C $OUTD
T "gzip -c"             0 '' bash -c "${AS[*]} $SX gzip -c $IN/hello.txt > $OUTD/h.gz"
T "gunzip -c roundtrip" 0 'hello safexec' A $SX gunzip -c $OUTD/h.gz
T "xz -c"               0 '' bash -c "${AS[*]} $SX xz -c $IN/hello.txt > $OUTD/h.xz"
T "unxz -c roundtrip"   0 'hello safexec' A $SX unxz -c $OUTD/h.xz
T "zip create"          0 '' A $SX zip -q -j $OUTD/a.zip $IN/hello.txt $IN/sample.md
T "unzip -l"            0 'hello.txt' A $SX unzip -l $OUTD/a.zip
T "unzip extract"       0 '' A $SX unzip -q -o $OUTD/a.zip -d $OUTD/unz
T "sha256sum matches"   0 "$REF256" A $SX sha256sum $IN/hello.txt
T "sha512sum matches"   0 "$REF512" A $SX sha512sum $IN/hello.txt
T "shasum -a 256 matches" 0 "$REF256" A $SX shasum -a 256 $IN/hello.txt
T "b2sum matches"       0 "$REFB2" A $SX b2sum $IN/hello.txt
T "cksum matches"       0 "^$REFCK " A $SX cksum $IN/hello.txt
T "ffmpeg encode"       0 '' A $SX ffmpeg -v error -y -f lavfi -i testsrc=d=1:s=64x64:r=10 -pix_fmt yuv420p $OUTD/t.mp4
T "ffprobe"             0 'duration=1\.' A $SX ffprobe -v error -show_entries format=duration -of default=nw=1 $OUTD/t.mp4
T "convert resize"      0 '' A $SX convert $IN/sample.png -resize 50% $OUTD/small.png
T "identify"            0 '32x32' A $SX identify $OUTD/small.png
T "wkhtmltopdf"         0 '' A $SX wkhtmltopdf -q $IN/sample.html $OUTD/w.pdf
T "wkhtmltopdf output valid" 0 'PDF' file $OUTD/w.pdf
T "pdftk cat 1"         0 '' A $SX pdftk $IN/sample.pdf cat 1 output $OUTD/p1.pdf
T "pdftk dump_data"     0 'NumberOfPages: 2' A $SX pdftk $IN/sample.pdf dump_data
T "pandoc md->html"     0 '' A $SX pandoc $IN/sample.md -o $OUTD/s.html
T "pandoc output"       0 '<em>markdown</em>' cat $OUTD/s.html
T "rg on tester dir (owner==caller, no drop)" 0 'tester needle' A $SX rg needle /home/tester/proj
T "rg with -m 1 --text pattern path" 0 'tester needle' A $SX rg -m 1 --text needle /home/tester/proj

sec "8. Optional buckets (full build): gs, poppler, DB clients, rsync/git"
T "gs render"           0 '' A $SXF gs -q -dNOPAUSE -dBATCH -sDEVICE=png16m -r20 -sOutputFile=$OUTD/g.png $IN/sample.pdf
T "gs output valid"     0 'PNG' file $OUTD/g.png
T "pdfinfo"             0 'Pages:\s+2' A $SXF pdfinfo $IN/sample.pdf
T "pdftoppm"            0 '' A $SXF pdftoppm -png -r 20 $IN/sample.pdf $OUTD/pp
T "pdftoppm output"     0 'pp-1.png' ls $OUTD
T "pdftocairo"          0 '' A $SXF pdftocairo -svg $IN/sample.pdf $OUTD/pc.svg
T "mysqldump"           0 'mysqldump|Ver' A $SXF mysqldump --version
T "mysql"               0 'mysql|Ver' A $SXF mysql --version
T "mariadb-dump"        0 'mariadb-dump|Ver' A $SXF mariadb-dump --version
T "mariadb"             0 'mariadb|Ver' A $SXF mariadb --version
T "[limitation] pg_dump (Debian pg_wrapper symlink outside trusted dirs)"    3 'resolves outside trusted dirs' A $SXF pg_dump --version
T "[limitation] pg_restore (Debian pg_wrapper symlink outside trusted dirs)" 3 'resolves outside trusted dirs' A $SXF pg_restore --version
T "[limitation] psql (Debian pg_wrapper symlink outside trusted dirs)"       3 'resolves outside trusted dirs' A $SXF psql --version
T "redis-cli"           0 'redis-cli' A $SXF redis-cli --version
mkdir -p $OUTD/rs_src $OUTD/rs_dst; echo x > $OUTD/rs_src/f; chmod 777 $OUTD/rs_src $OUTD/rs_dst
T "rsync local copy"    0 '' A $SXF rsync -a $OUTD/rs_src/ $OUTD/rs_dst/
T "rsync result"        0 'f' ls $OUTD/rs_dst
T "git --version"       0 'git version' A $SXF git --version
mkdir -p $OUTD/repo; chmod 777 $OUTD/repo
T "git init"            0 'Initialized' A $SXF git init -b main $OUTD/repo
T "git status (safe.directory given: nobody != dir owner)" 0 'On branch main' A $SXF git -c safe.directory='*' -C $OUTD/repo status

sec "9. rg owner-drop logic"
T "rg root-owned dir refused"        3 'owned by root|refusing' A $SX rg needle /srv/rootdir
T "rg uid-not-in-passwd refused"     3 'not in passwd' A $SX rg needle /srv/orphan
ln -sfn /home/tester/proj /home/tester/link
T "rg symlink dir refused"           3 'symlink' A $SX rg needle /home/tester/link
T "rg relative path refused"         3 'invalid path|refusing' bash -c "cd /home/tester && ${AS[*]} $SX rg needle proj"
T "rg no path arg refused"           3 'invalid path|refusing' A $SX rg needle
T "rg file (not dir) refused"        3 'not a directory' A $SX rg needle /home/tester/proj/a.txt
T "rg nonexistent refused"           3 'lstat|refusing' A $SX rg needle /home/tester/nope
T "rg /tmp (root-owned sticky) refused" 3 'owned by root' A $SX rg needle /tmp
T "rg / refused"                     3 'owned by root' A $SX rg needle /

sec "10. --kill semantics"
( "${AS[@]}" $SX ffmpeg -v quiet -f lavfi -i testsrc=s=64x64:r=5 -f null - >/dev/null 2>&1 & ) ; sleep 3
NPID=$(pgrep -u 65534 -x ffmpeg | head -1); echo "  (nobody ffmpeg pid=$NPID)"
[[ -n "$NPID" ]] && { PASS=$((PASS+1)); echo "PASS  background ffmpeg running as nobody"; } || { FAIL=$((FAIL+1)); FAILS+=("bg ffmpeg not running"); echo "FAIL  bg ffmpeg not running"; }
T "cgroup of running tool shows safexec-run" 0 'safexec-run' cat /proc/$NPID/cgroup
T "--kill legit nobody+safexec process" 0 'Success: Killed' A $SX --kill=$NPID
sleep 1; ST=$(grep -E '^State' /proc/$NPID/status 2>/dev/null | awk '{print $2}'); { [[ -z "$ST" || "$ST" == Z ]] && { PASS=$((PASS+1)); echo "PASS  target actually terminated (state=${ST:-gone})"; } || { FAIL=$((FAIL+1)); FAILS+=("process survived --kill"); echo "FAIL  target survived state=$ST"; }; }
setpriv --reuid=65534 --regid=65534 --clear-groups sleep 300 & FAKE=$!; sleep 0.5
T "--kill refuses nobody proc w/o NNP/cgroup" 1 'Refusing' A $SX --kill=$FAKE
kill $FAKE 2>/dev/null
setpriv --reuid=1001 --regid=1002 --clear-groups sleep 300 & OWN=$!; sleep 0.5
T "--kill refuses caller's own non-nobody proc" 1 'not owned by .nobody' A $SX --kill=$OWN
kill $OWN 2>/dev/null
T "--kill refuses root proc (pid 1)" 1 'Refusing' A $SX --kill=1

sec "11. wget -P /tmp fallback (mount-ns: /tmp 0755 => nobody cannot write)"
cat > /tmp/ns_wget.sh <<'NS'
mount -t tmpfs -o mode=0755 tmpfs /tmp
setpriv --reuid=1001 --regid=1002 --clear-groups /usr/local/bin/safexec wget -q -P /tmp http://127.0.0.1:8099/hello.txt 2>/tmp/.err; echo "rc=$?"
cat /tmp/.err 2>/dev/null | grep -E 'Rewriting|Warning' 
ls -ld /tmp/safexec-work /tmp/safexec-work/65534; ls -l /tmp/safexec-work/65534/
NS
T "wget -P /tmp rewritten to /tmp/safexec-work/65534" 0 "Rewriting wget -P '/tmp' -> '/tmp/safexec-work/65534'" unshare -m bash /tmp/ns_wget.sh
T "  ...file landed in per-user dir"     0 'hello.txt' unshare -m bash /tmp/ns_wget.sh
T "  ...parent is root 01777, sub is 0700 nobody" 0 'drwxrwxrwt.*root root.*safexec-work|drwx------.*nobody.*65534' unshare -m bash /tmp/ns_wget.sh

sec "12. Concurrency / leaks"
BEFORE=$(ls /sys/fs/cgroup/unified/safexec-run 2>/dev/null | grep -c 'safexec-run\.')
seq 100 | xargs -P 25 -I{} "${AS[@]}" $SX sha256sum $IN/hello.txt >/tmp/conc.out 2>/dev/null
N=$(grep -c "$REF256" /tmp/conc.out); [[ $N -eq 100 ]] && { PASS=$((PASS+1)); echo "PASS  100 parallel launches OK ($N/100)"; } || { FAIL=$((FAIL+1)); FAILS+=("concurrency $N/100"); echo "FAIL  concurrency $N/100"; }
"${AS[@]}" $SX curl --version >/dev/null 2>&1
AFTER=$(ls /sys/fs/cgroup/unified/safexec-run 2>/dev/null | grep -c 'safexec-run\.')
echo "  cgroup dirs before=$BEFORE after=$AFTER (stale empty ones are pruned on next launch)"
[[ $AFTER -le 3 ]] && { PASS=$((PASS+1)); echo "PASS  no cgroup leak accumulation"; } || { FAIL=$((FAIL+1)); FAILS+=("cgroup leak $AFTER"); echo "FAIL  cgroup leak: $AFTER"; }
LEFT=$(ls -d /tmp/safexec-work* 2>/dev/null | head -3); echo "  /tmp leftovers: ${LEFT:-none}"


sec "13. Fix verification: allowlist bypass, prelude assignments, prelude value grammar"
rm -rf /tmp/evil2; mkdir -p /tmp/evil2/-/tmp; cp /usr/bin/id /tmp/evil2/-/tmp/x; chmod -R 755 /tmp/evil2
T "BYPASS nice -- -/tmp/x curl must be rejected"     3 '!uid=|no such user' bash -c "cd /tmp/evil2 && ${AS[*]} $SX nice -- -/tmp/x curl"
T "BYPASS timeout 5 -/tmp/x curl must be rejected"   3 '!uid=|no such user' bash -c "cd /tmp/evil2 && ${AS[*]} $SX timeout 5 -/tmp/x curl"
T "BYPASS via rg (run as alice) must be rejected"    3 '!uid=|no such user' bash -c "cd /tmp/evil2 && ${AS[*]} $SX nice -- -/tmp/x rg needle /home/alice/proj"
T "path-like option message"                          3 'path-like option' bash -c "cd /tmp/evil2 && ${AS[*]} $SX timeout 5 -/tmp/x curl"
T "proxy assignment reaches the tool's env"           0 'HTTP_PROXY=http://127.0.0.1:9' bash -c "${AS[*]} $SX HTTP_PROXY=http://127.0.0.1:9 curl -s file:///proc/self/environ | tr '\\0' '\\n'"
T "assignment after wrapper reaches env"              0 'https_proxy=http://p:2' bash -c "${AS[*]} $SX nice https_proxy=http://p:2 curl -s file:///proc/self/environ | tr '\\0' '\\n'"
T "assignment NOT leaked into tool argv"              0 '!HTTP_PROXY' bash -c "${AS[*]} $SX HTTP_PROXY=http://q:3 curl -s file:///proc/self/cmdline | tr '\\0' ' '"
T "http_proxy actually honoured by curl (bad proxy => rc 7, not DNS rc 6)" 7 '' A $SX http_proxy=http://127.0.0.1:9 curl -s -m 5 http://example.invalid/
T "ALL_PROXY actually honoured by curl" 7 '' A $SX ALL_PROXY=http://127.0.0.1:9 curl -s -m 5 http://example.invalid/
T "PATH= still rejected"                              3 'dangerous assignment|not allowed' A $SX PATH=/tmp curl --version
T "LD_PRELOAD= after wrapper still rejected"          3 'dangerous assignment|not allowed' A $SX nice LD_PRELOAD=/x curl --version
T "too many assignments rejected (17)"                3 'too many' A $SX $(for i in $(seq 17); do echo -n "HTTP_PROXY=x "; done) curl --version
T "assignment works in pass-through mode too"         0 'HTTP_PROXY=http://z:9' bash -c "${AS[*]} $SXP HTTP_PROXY=http://z:9 curl -s file:///proc/self/environ | tr '\\0' '\\n'"
T "rg still works with a leading assignment"          0 'tester needle' A $SX HTTP_PROXY=http://x:1 rg needle /home/tester/proj
T "rg + wrapper + assignment as alice"                0 'alice-secret' A $SX nice HTTP_PROXY=http://x:1 rg -N needle /home/alice/proj

printf '\n==================== SUMMARY ====================\nPASS=%d FAIL=%d\n' $PASS $FAIL
((FAIL)) && printf 'FAILED: %s\n' "${FAILS[@]}"
exit $((FAIL > 0))
