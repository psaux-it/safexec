# safexec

`safexec` runs a fixed set of command-line tools on behalf of a less-trusted
caller. It is installed setuid root. It checks the request against a
compile-time allowlist, pins the tool to a trusted absolute path, scrubs the
environment, places the process in its own cgroup v2 group, drops privileges,
and then `exec`s the tool. It never starts a shell and never runs a tool as root.

Typical callers are web applications, schedulers, and job runners that must
invoke tools such as `curl`, `tar`, or `ffmpeg` without a shell and without
inheriting the caller's environment or file descriptors.

## Synopsis

```
safexec [wrapper ...] <tool> [args ...]
safexec --kill=<pid>
safexec --help | -h
safexec --version | -v
```

## Description

`safexec` processes a request in four steps.

1. **Allowlist.** The tool is matched by basename against the allowlist.
   Shells (`sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `fish`) are rejected in
   the prelude. Anything not on the list is refused.
2. **Pinning.** The tool and every bare-name wrapper are resolved to absolute
   paths under trusted directories. The caller's `PATH` and working directory
   are never consulted.
3. **Isolation.** With effective uid 0, the environment is cleared, the process
   joins a fresh cgroup v2 group (or falls back to rlimits), and the process
   state is hardened (see [Privileged mode](#privileged-mode)).
4. **Drop and exec.** Privileges are dropped, `PR_SET_NO_NEW_PRIVS` is set,
   inherited descriptors are closed, and the tool is executed.

There is no shell in the exec path. Characters such as `;`, `|` and `` ` ``
inside an argument reach the tool literally.

### Privileged mode

Applies whenever the effective uid is 0, that is, when the binary is setuid
root or is run by root. In order:

- the environment is cleared; `PATH` is set to a fixed value and a UTF-8
  locale is set (`C.UTF-8`, then `en_US.UTF-8`, then `C`)
- `umask` is set to `077` and `PR_SET_DUMPABLE` to `0`
- the process joins `<cgroup root>/safexec-run/safexec-run.<pid>`; if cgroup v2
  is unavailable it falls back to rlimits
- supplementary groups are cleared and the uid/gid are set to `nobody`
  (or to the directory owner for `rg`, see below)
- `PR_SET_NO_NEW_PRIVS` is set and all file descriptors above 2 are closed
- the tool is executed

If the drop to the target user fails, `safexec` falls back to the invoking
user's real uid/gid. If the effective uid is still 0 after that, it aborts.

### Pass-through mode

If the effective uid is not 0 (no setuid bit, `nosuid` mount, or the binary was
copied without its mode), only the allowlist and path pinning apply. The
environment is not sanitized, privileges are not dropped, and no isolation is
set up. The tool runs as the invoking user. A notice is printed to stderr.

## Allowlisted programs

Always available:

| Group     | Programs                                                  |
|-----------|-----------------------------------------------------------|
| Search    | `rg`                                                      |
| Fetch     | `wget`, `curl`                                            |
| Archives  | `tar`, `gzip`, `gunzip`, `xz`, `unxz`, `zip`, `unzip`     |
| Checksums | `sha256sum`, `sha512sum`, `shasum`, `b2sum`, `cksum`      |
| Media     | `ffmpeg`, `ffprobe`, `magick`, `convert`, `identify`      |
| Documents | `wkhtmltopdf`, `pdftk`, `pandoc`                          |

Optional groups, enabled at compile time (see [Build](#build)):

| Macro                      | Adds                                                                                     |
|----------------------------|------------------------------------------------------------------------------------------|
| `SAFEXEC_WITH_GS`          | `gs`                                                                                     |
| `SAFEXEC_WITH_POPPLER`     | `pdfinfo`, `pdftoppm`, `pdftocairo`                                                      |
| `SAFEXEC_WITH_DB`          | `mysqldump`, `mysql`, `mariadb-dump`, `mariadb`, `pg_dump`, `pg_restore`, `psql`, `redis-cli` |
| `SAFEXEC_WITH_RSYNC_GIT`   | `rsync`, `git`                                                                           |

`gs` has a long history of sandbox-escape vulnerabilities. `rsync` and `git`
can start `ssh`, which is outside the closed set of tools the allowlist assumes.
Enable these groups only if you control how the tools are invoked.

A tool that is on the allowlist but not installed is refused with
`cannot resolve trusted path`. On Debian, `pg_dump`, `pg_restore` and `psql`
are symlinks to `/usr/share/postgresql-common/pg_wrapper`, which is outside the
trusted directories, so they are refused there.

## Prelude

Tokens before the tool name form the prelude. Each token must be one of:

- **A wrapper:** `nohup`, `nice`, `timeout`, `stdbuf`, `ionice`, `taskset`,
  `setsid`, `chrt`, `time`. A bare name is pinned like the tool. An explicit
  path must be exactly `<trusted directory>/<name>`; `..` and extra path
  components are rejected.
- **An option:** a token starting with `-`, or `--`. An option containing a `/`
  is rejected, so `timeout 5 -dir/prog` cannot smuggle a path.
- **A number or value:** a signed integer, a duration (`5`, `1.5`, `2m`), a CPU
  mask (`0x3`, `0,1`, `0-3`).
- **A proxy assignment:** `NAME=VALUE` where `NAME` is `HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` or the lowercase form. At most 16 are
  accepted. They are removed from `argv` and exported to the tool.

Any other assignment (`PATH=`, `LD_*`, `DYLD_*`, `IFS=`, `PYTHONPATH=`, ...) is
rejected. Wrapper options that take a separate value word are not recognized:
write `timeout -sKILL 20`, not `timeout -s KILL 20`.

## Examples

```sh
# Fetch through the allowlist
safexec curl -fsS -o /var/tmp/page.html https://example.com/

# Wrapper chain and a proxy variable
safexec HTTP_PROXY=http://127.0.0.1:3128 nice -n 10 timeout 30 curl -fsSL https://example.com/

# Checksum
safexec sha256sum /srv/data/archive.tar.gz

# Refused: not on the allowlist
safexec ls /
# Error: 'ls' is not allowed by safexec.

# Refused: shell in the prelude
safexec /bin/sh -c id
# Info: rejecting shell interpreter before tool: '/bin/sh'
# Error: 'sh' is not allowed by safexec.
```

In privileged mode, diagnostics go to stderr:

```
Info: pinned tool 'sha256sum' -> '/usr/bin/sha256sum'
Info: using cgroup v2 child /sys/fs/cgroup/safexec-run/safexec-run.<pid>
Summary: user=65534:65534 (ruid=65534 rgid=65534) cwd=... tool=/usr/bin/sha256sum
Summary: no_new_privs=on
Summary: cgroup=/sys/fs/cgroup/safexec-run/safexec-run.<pid>
```

Set `SAFEXEC_QUIET=1` to suppress them.

## Tool-specific behavior

### rg

The last argument must be an absolute path to a directory. It must not be a
symlink and must not be owned by root. `rg` runs as the owner of that
directory, so it can read exactly what that user can read. If the owner is
already the invoking user, no drop is performed. A relative or missing path, a
non-directory, a symlink, a root-owned directory, or an owner absent from the
passwd database is refused with exit status 3.

```sh
safexec rg -m 1 --text 'pattern' /home/alice/project
```

### wget

If `-P /tmp` is given and `/tmp` is not writable by the final user, it is
rewritten to `/tmp/safexec-work/<uid>`. `/tmp/safexec-work` is root-owned with
mode `1777`; the per-user subdirectory has mode `0700`.

## --kill

```
safexec --kill=<pid>
```

Sends `SIGTERM` to a process that `safexec` started. The target must:

- be owned by `nobody`, and
- be in a `safexec-run` cgroup, or, when cgroup delegation is unavailable,
  have `NoNewPrivs` set.

The signal is sent with `pidfd_send_signal` where available, otherwise with
`kill(2)`. Because `nobody`-owned processes can only be signalled by a
privileged sender, use it through the setuid binary. Linux only.

## Exit status

| Status        | Meaning                                                                       |
|---------------|-------------------------------------------------------------------------------|
| tool's status | `safexec` replaces itself with the tool, so its status is returned unchanged |
| 3             | Refused or failed before exec: usage, not allowed, unresolvable path, rejected prelude |
| `--kill`      | 0 on success, 1 otherwise                                                     |

Status 3 is also a valid exit status of some tools, so callers that need to
distinguish the two should also inspect stderr.

## Environment

These are read before the environment is cleared.

| Variable            | Values                              | Default | Effect |
|---------------------|-------------------------------------|---------|--------|
| `SAFEXEC_DETACH`    | `auto`, `cgv2`, `rlimits`, `off`    | `auto`  | Isolation mode. `auto` uses cgroup v2 and falls back to rlimits. Read with `secure_getenv()` on glibc, so it is ignored when an unprivileged user runs the setuid binary. |
| `SAFEXEC_QUIET`     | `0`, `1`                            | `0`     | Suppress informational messages on stderr. |
| `SAFEXEC_SAFE_CWD`  | `-1`, `0`, `1`                      | `-1`    | If the working directory is not writable, change to `/tmp` (or `/`). `-1` does this only when stdio is attached to a terminal. |

Compile-time defaults: `-DSAFEXEC_QUIET_DEFAULT=0|1`,
`-DSAFEXEC_SAFE_CWD_DEFAULT=-1|0|1`.

Isolation groups and tracks the process; by default it does not cap CPU,
memory or I/O. Resource ceilings are set in `safexec_default_limits()` in
`safexec.c` and take effect after rebuilding.

## Build

Requirements: a C compiler, `make` and `install`. Linux is fully supported.
Other POSIX systems get the allowlist, pinning, rlimits and descriptor
closing, without cgroups, `pidfd` or `--kill`. The Linux kernel headers
(`linux-libc-dev`, `linux-headers`) are optional: without `<linux/ioprio.h>`
the I/O priority support is compiled out.

```sh
make                                  # build/safexec
make EXTRA_CPPFLAGS="-DSAFEXEC_WITH_POPPLER -DSAFEXEC_WITH_DB"
make clean
```

`CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS` and `LDLIBS` are honored, from the
environment or the command line.

If `CPPFLAGS`, `CFLAGS` and `LDFLAGS` are not set, hardened defaults are
used: PIE, stack protector, stack-clash protection, RELRO, `-z now`,
`_FORTIFY_SOURCE=2`, and CET (x86) or BTI/PAC (aarch64) when the compiler
supports them for its target. If they are set, they replace these defaults.
Only `-D_GNU_SOURCE`, `-fno-strict-overflow` and
`-fno-delete-null-pointer-checks` are always added.

### Cross compilation

```sh
make CC=aarch64-linux-gnu-gcc
```

Architecture-specific hardening options are probed with the selected
compiler, not with the build host. `make check` runs the built binary and
cannot be used in a cross build.

### musl

Build natively on a musl system (for example Alpine) with plain `make`, or
with `make CC=musl-gcc` elsewhere.

### Static release binaries

```sh
make static            # build/safexec-x86_64-linux-musl
make static-aarch64    # build/safexec-aarch64-linux-musl
```

These require `zig cc` (`make ZIG="python3 -m ziglang" static` to use another
invocation). They are intended for upstream releases, not for distribution
packages. musl does not load NSS modules, so users provided by LDAP or SSSD
are not resolved; this affects the `rg` owner drop.

## Install

```sh
sudo make install
sudo chown root:root /usr/local/sbin/safexec
sudo chmod 4755 /usr/local/sbin/safexec
```

`make install` installs the binary to `$(SBINDIR)` and the manual page to
`$(MAN1DIR)`. It needs no root privileges and never changes ownership. Do not
install on a `nosuid` mount. To limit who can invoke the binary, use mode
`4750` with a dedicated group.

| Variable   | Default                | Meaning                                    |
|------------|------------------------|--------------------------------------------|
| `DESTDIR`  | empty                  | Staging root                               |
| `PREFIX`   | `/usr/local`           | Installation prefix                        |
| `SBINDIR`  | `$(PREFIX)/sbin`       | Binary directory                           |
| `DATADIR`  | `$(PREFIX)/share`      |                                            |
| `MANDIR`   | `$(DATADIR)/man`       | Manual page root                           |
| `MAN1DIR`  | `$(MANDIR)/man1`       | Section 1 directory                        |
| `BINMODE`  | `0755`                 | Binary mode; `4755` for setuid             |
| `BINOWN`   | unset                  | Passed to `install -o` when set            |
| `BINGRP`   | unset                  | Passed to `install -g` when set            |

```sh
sudo make uninstall
```

## Packaging

The default `make install` does not set the setuid bit, so that unprivileged
package builds work. The package must set it, either with
`make install BINMODE=4755` under `fakeroot`, or in the package metadata.
Without it `safexec` runs in pass-through mode.

Debian's `dh_fixperms` removes setuid bits, so restore the mode afterwards:

```make
override_dh_auto_install:
	dh_auto_install -- PREFIX=/usr

override_dh_fixperms:
	dh_fixperms
	chmod 4755 debian/safexec/usr/sbin/safexec
```

Arch Linux (`sbin` is a symlink to `bin`):

```sh
package() {
	cd "$pkgname-$pkgver"
	make DESTDIR="$pkgdir" PREFIX=/usr SBINDIR=/usr/bin BINMODE=4755 install
}
```

Gentoo:

```sh
inherit toolchain-funcs

src_compile() {
	emake CC="$(tc-getCC)"
}

src_install() {
	emake DESTDIR="${D}" PREFIX="${EPREFIX}/usr" install
	fperms 4755 /usr/sbin/safexec
}
```

Alpine (`makedepends="linux-headers"`):

```sh
package() {
	make DESTDIR="$pkgdir" PREFIX=/usr BINMODE=4755 install
}
```

`make check` runs `tests/run.sh`. It needs no root and skips the privilege
drop test when not run as root against a setuid binary. Skip it when cross
compiling. The end-to-end suite in `tests/run-all.sh` modifies the host and
must not be run from a package build.

## Tests

```sh
make check
```

Runs `tests/run.sh` against `build/safexec`: argument handling, allowlist and
prelude rejection, path pinning, and basic execution. The privilege-drop test
runs only when the tests are run as root against a setuid-root binary;
otherwise it is skipped.

The full end-to-end suite builds a default and a full-bucket binary, runs the
parser fuzzer (400,000 iterations per run, plus an ASan/UBSan build), installs
setuid binaries, and exercises every allowlisted tool, privilege dropping,
environment scrubbing, `rg` owner-drop, `--kill`, the `wget` fallback, and
concurrency.

```sh
SAFEXEC_TEST_CONTAINER=1 bash tests/run-all.sh
```

**This suite modifies the host.** It installs packages with `apt-get`, creates
the users `tester` and `alice`, writes under `/srv` and `/home`, and installs
setuid-root binaries in `/usr/local/bin`. It refuses to run unless
`SAFEXEC_TEST_CONTAINER=1` is set and the effective uid is 0. Run it only in a
disposable container or VM with a writable cgroup v2 hierarchy, for example
`docker run --privileged --cgroupns=host --init ubuntu:24.04`.

| Variable           | Default                       | Meaning                          |
|--------------------|-------------------------------|----------------------------------|
| `SXTEST_RESULTS`   | `/tmp/safexec-test-results`   | Directory for logs               |
| `FUZZ_RUNS`        | `3`                           | Parser-fuzz repetitions          |

The exit status is non-zero if any stage (deps, build, fuzz, fixtures, smoke,
functional) fails. CI runs the same suite (`.github/workflows/tests.yml`).

##
