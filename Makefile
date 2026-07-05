# SPDX-License-Identifier: MIT
#
# Makefile for safexec — secure privilege-dropping exec wrapper
#
# Makefile respects standard environment overrides
# (CC, CFLAGS, CPPFLAGS, LDFLAGS, DESTDIR, PREFIX) and does NOT force static
# linking or a specific compiler — override CC=zig cc only if you explicitly
# want that toolchain; default is the system cc.

PREFIX      ?= /usr/local
SBINDIR     ?= $(PREFIX)/sbin
MANDIR      ?= $(PREFIX)/share/man/man1
DESTDIR     ?=
CC          ?= cc
BUILDDIR     = build
TARGET       = $(BUILDDIR)/safexec
SRC          = safexec.c
MANPAGE      = safexec.1

# Optional build-time tool buckets (all off by default). Combine any subset:
#   make EXTRA_CPPFLAGS="-DSAFEXEC_WITH_POPPLER -DSAFEXEC_WITH_DB"
#
#   -DSAFEXEC_WITH_GS         Ghostscript (gs) for PS/PDF rasterization.
#                             Riskier — gs has a long history of sandbox
#                             escape / RCE CVEs via crafted PS/PDF input.
#                             Off by default upstream too; only enable if you
#                             specifically need PS/PDF rasterization and
#                             understand the exposure.
#   -DSAFEXEC_WITH_POPPLER    pdfinfo, pdftoppm, pdftocairo.
#   -DSAFEXEC_WITH_DB         mysqldump, mysql, mariadb-dump, mariadb,
#                             pg_dump, pg_restore, psql, redis-cli.
#   -DSAFEXEC_WITH_RSYNC_GIT  rsync, git.
#                             Both can indirectly invoke ssh (rsync -e,
#                             git+ssh:// remotes), which escapes the
#                             allowlist's assumption of a closed set of
#                             non-networked/no-shell-out tools. Enable only
#                             if you control how these binaries get invoked.
EXTRA_CPPFLAGS ?=

CPPFLAGS    += -D_GNU_SOURCE $(EXTRA_CPPFLAGS)
CFLAGS      ?= -O2 -pipe -fPIE \
               -Wall -Wextra -Wformat=2 -Werror=format-security \
               -fstack-protector-strong \
               -fstack-clash-protection \
               -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2

# Setuid-root specific; always appended, not left to distro CFLAGS.
CFLAGS      += -fno-strict-overflow -fno-delete-null-pointer-checks
LDFLAGS     ?= -pie -Wl,-z,relro,-z,now

# Optional LD_PRELOAD shim (libnpp_norm.so) — opt-in only
#   make norm && make install-norm
SOTARGET     = $(BUILDDIR)/libnpp_norm.so
NORMSRC      = libnpp_norm.c

# make norm EXTRA_NORM_CPPFLAGS=-DWGET_FASTPATH
# Disables send()/sendto()/sendmsg()/writev() hooks; write() and TLS hooks
# (SSL_write/gnutls_record_send) stay on regardless. Net effect: wget (any
# scheme) and curl-HTTPS still normalized; curl-plain-HTTP is not (libcurl
# writes cleartext via send()/sendto()). Leave empty unless you're sure
# curl-over-http:// never happens in your workflow.
EXTRA_NORM_CPPFLAGS ?=

NORM_CFLAGS  ?= -O2 -pipe -fPIC \
                -Wall -Wextra -Wformat=2 -Werror=format-security \
                -fstack-protector-strong \
                -fstack-clash-protection \
                -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
NORM_LDFLAGS ?= -shared -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
                -Wl,-soname,libnpp_norm.so -Wl,--as-needed
NORM_LIBS     = -ldl -lpthread

# safexec.c's is_secure_so() only trusts .so files realpath()-resolving under
# /usr/lib, /lib, /usr/lib64, /lib64 — NOT derived from PREFIX. Installing
# elsewhere (e.g. $(PREFIX)/lib) makes safexec silently skip LD_PRELOAD
# injection (no error — just an "Info: Not injecting..." log line).
NPP_LIBDIR  ?= /usr/lib

# Arch-conditional CET (x86) / BTI+PAC (aarch64) hardening for native builds.
# Not folded into CFLAGS/NORM_CFLAGS defaults so it doesn't collide with the
# fixed-target `static`/`static-aarch64` recipes below, which set their own.
UNAME_M := $(shell uname -m)
ifneq (,$(filter x86_64 i386 i486 i586 i686,$(UNAME_M)))
  CF_HARDENING := -fcf-protection=full
else ifneq (,$(filter aarch64 arm64,$(UNAME_M)))
  CF_HARDENING := -mbranch-protection=standard
else
  CF_HARDENING :=
endif

.PHONY: all clean install uninstall check test static static-aarch64 norm install-norm

all: $(TARGET)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(TARGET): $(SRC) | $(BUILDDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CF_HARDENING) $(SRC) -o $(TARGET) $(LDFLAGS)

# Not intended for distro packages (see README/INSTALL: static binaries are
# discouraged by Debian/Fedora policy). Requires zig or a musl cross toolchain.
#
# LDFLAGS is deliberately overridden (not just CFLAGS) to drop the global
# default's `-pie`. The global LDFLAGS carries -pie for the normal dynamic
# `all` build; combined with -static here it would produce a static-PIE
# binary, which is NOT what the CI-built release artifacts you ship are
# (CI passes -fPIE at compile but never -pie at link for the static target).
# Keep this in sync with .github/workflows/build-and-commit-safexec.yml —
# if you deliberately want to move to static-PIE, do it in both places at
# once and validate the setuid-root execve/AT_SECURE path before shipping.
static: CC = zig cc -target x86_64-linux-musl
static: CFLAGS += -static -fcf-protection=full -s
static: LDFLAGS = -Wl,-z,relro,-z,now
static: | $(BUILDDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) -o $(BUILDDIR)/safexec-x86_64-linux-musl $(LDFLAGS)

# aarch64 counterpart — CI builds both arches; this target existed only for
# x86_64 before, so `make static` locally could not reproduce the aarch64
# release artifact at all.
static-aarch64: CC = zig cc -target aarch64-linux-musl
static-aarch64: CFLAGS += -static -mbranch-protection=standard -s
static-aarch64: LDFLAGS = -Wl,-z,relro,-z,now
static-aarch64: | $(BUILDDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) -o $(BUILDDIR)/safexec-aarch64-linux-musl $(LDFLAGS)

# Optional LD_PRELOAD normalization shim — opt-in, not part of `all`.
norm: $(SOTARGET)

$(SOTARGET): $(NORMSRC) | $(BUILDDIR)
	$(CC) $(EXTRA_NORM_CPPFLAGS) $(NORM_CFLAGS) $(CF_HARDENING) \
		$(NORMSRC) -o $(SOTARGET) $(NORM_LDFLAGS) $(NORM_LIBS)

check: $(TARGET)
	@./tests/run.sh ./$(TARGET)

# Alias
test: check

install: $(TARGET)
	install -d -m 0755 $(DESTDIR)$(SBINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(SBINDIR)/safexec
	install -d -m 0755 $(DESTDIR)$(MANDIR)
	install -m 0644 $(MANPAGE) $(DESTDIR)$(MANDIR)/safexec.1
	@echo ""
	@echo "safexec installed to $(DESTDIR)$(SBINDIR)/safexec"
	@echo "To enable privilege-dropping mode, run as root:"
	@echo "  chown root:root $(DESTDIR)$(SBINDIR)/safexec"
	@echo "  chmod 4755 $(DESTDIR)$(SBINDIR)/safexec"
	@echo "(Ensure the install path is not on a nosuid-mounted filesystem.)"

# Must land in a path trusted by TRUSTED_LIB_ROOTS or injection is refused.
install-norm: $(SOTARGET)
	install -d -m 0755 $(DESTDIR)$(NPP_LIBDIR)
	install -m 0644 $(SOTARGET) $(DESTDIR)$(NPP_LIBDIR)/libnpp_norm.so
	@echo ""
	@echo "libnpp_norm.so installed to $(DESTDIR)$(NPP_LIBDIR)/libnpp_norm.so"
	@echo "If safexec doesn't pick it up automatically, set:"
	@echo "  SAFEXEC_PCTNORM_SO=$(NPP_LIBDIR)/libnpp_norm.so"
	@echo "Confirm this path resolves under safexec.c's TRUSTED_LIB_ROOTS"
	@echo "(/usr/lib, /lib, /usr/lib64, /lib64) or injection will be refused."

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/safexec
	rm -f $(DESTDIR)$(MANDIR)/safexec.1
	rm -f $(DESTDIR)$(NPP_LIBDIR)/libnpp_norm.so

clean:
	rm -rf $(BUILDDIR)
