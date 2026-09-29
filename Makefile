# SPDX-License-Identifier: MIT
#
# Makefile for safexec
#
# Notes for packagers
#
#   Build flags   CC, CPPFLAGS, CFLAGS, LDFLAGS and LDLIBS are honoured, from
#                 the environment or from the command line. If CPPFLAGS,
#                 CFLAGS or LDFLAGS are not set at all, hardened defaults
#                 are used. If they are set, they replace those defaults and
#                 only options required for correct code generation are
#                 appended. The default hardening options that depend on the
#                 target architecture are probed with $(CC), so
#                 cross-compiling works: make CC=aarch64-linux-gnu-gcc
#
#   Install       GNU directory variables are honoured: PREFIX, SBINDIR,
#                 DATADIR, MANDIR (the man/ parent), MAN1DIR, DESTDIR.
#                 Install never changes ownership and needs no root. The
#                 binary mode is BINMODE (default 0755). safexec only
#                 provides its privilege drop when installed setuid root:
#                 set BINMODE=4755 (e.g. under fakeroot) or set the mode in
#                 the package metadata. Optional BINOWN and BINGRP are
#                 passed to install(1) when set.
#
#   Optional tool buckets (all off by default). Combine any subset:
#     make EXTRA_CPPFLAGS="-DSAFEXEC_WITH_POPPLER -DSAFEXEC_WITH_DB"
#
#   -DSAFEXEC_WITH_GS         Ghostscript (gs) for PS/PDF rasterization.
#                             Riskier: gs has a long history of sandbox
#                             escape / RCE CVEs via crafted PS/PDF input.
#                             Enable only if you specifically need it and
#                             understand the exposure.
#   -DSAFEXEC_WITH_POPPLER    pdfinfo, pdftoppm, pdftocairo.
#   -DSAFEXEC_WITH_DB         mysqldump, mysql, mariadb-dump, mariadb,
#                             pg_dump, pg_restore, psql, redis-cli.
#   -DSAFEXEC_WITH_RSYNC_GIT  rsync, git. Both can indirectly invoke ssh
#                             (rsync -e, git+ssh:// remotes), which escapes
#                             the allowlist's assumption of a closed set of
#                             tools. Enable only if you control how these
#                             binaries are invoked.
#
#   Build dependencies: a C compiler, make, install(1), and the Linux kernel
#   headers (linux/ioprio.h), e.g. linux-libc-dev, linux-headers.

PREFIX      ?= /usr/local
SBINDIR     ?= $(PREFIX)/sbin
DATADIR     ?= $(PREFIX)/share
MANDIR      ?= $(DATADIR)/man
MAN1DIR     ?= $(MANDIR)/man1
DESTDIR     ?=

BINMODE     ?= 0755
BINOWN      ?=
BINGRP      ?=

CC          ?= cc
INSTALL     ?= install
BUILDDIR    ?= build
TARGET       = $(BUILDDIR)/safexec
SRC          = safexec.c
MANPAGE      = safexec.1

EXTRA_CPPFLAGS ?=

# Returns the option if $(CC) accepts it for its current target, else nothing.
cc-option = $(shell $(CC) $(1) -Werror -x c -c /dev/null -o /dev/null >/dev/null 2>&1 && echo $(1))

# Defaults, used only if the variable is not set by the environment or the
# command line.
ifeq ($(origin CPPFLAGS),undefined)
CPPFLAGS := -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif
ifeq ($(origin CFLAGS),undefined)
CFLAGS   := -O2 -pipe -fPIE \
            -Wall -Wextra -Wformat=2 -Werror=format-security \
            -fstack-protector-strong -fstack-clash-protection \
            $(call cc-option,-fcf-protection=full) \
            $(call cc-option,-mbranch-protection=standard)
endif
ifeq ($(origin LDFLAGS),undefined)
LDFLAGS  := -pie -Wl,-z,relro,-z,now
endif

# Always applied. 'override' keeps them when CPPFLAGS/CFLAGS come from the
# make command line.
override CPPFLAGS += -D_GNU_SOURCE $(EXTRA_CPPFLAGS)
override CFLAGS   += -fno-strict-overflow -fno-delete-null-pointer-checks

# Static musl release builds (maintainer targets, not for distro packages).
# They use zig cc as the cross toolchain and their own flags, independent of
# CC/CFLAGS/LDFLAGS. To use another toolchain: make ZIG="python3 -m ziglang"
#
# With zig 0.16 the result is a static-PIE executable. It was verified to
# work installed setuid root (privilege drop, NoNewPrivs, environment
# scrubbing). Re-verify the setuid execve/AT_SECURE path when changing the
# zig version or the link flags.
ZIG                ?= zig
STATIC_CFLAGS       = -O2 -pipe -static -s -fPIE \
                      -Wall -Wextra -Wformat=2 -Werror=format-security \
                      -fstack-protector-strong -fstack-clash-protection \
                      -fno-strict-overflow -fno-delete-null-pointer-checks
STATIC_LDFLAGS      = -Wl,-z,relro,-z,now
STATIC_X86_64       = $(BUILDDIR)/safexec-x86_64-linux-musl
STATIC_AARCH64      = $(BUILDDIR)/safexec-aarch64-linux-musl

INSTALL_BIN_OPTS    = -m $(BINMODE) $(if $(BINOWN),-o $(BINOWN)) $(if $(BINGRP),-g $(BINGRP))

.PHONY: all clean install uninstall check test static static-aarch64

all: $(TARGET)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(TARGET): $(SRC) | $(BUILDDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)

static: $(STATIC_X86_64)
static-aarch64: $(STATIC_AARCH64)

$(STATIC_X86_64): $(SRC) | $(BUILDDIR)
	$(ZIG) cc -target x86_64-linux-musl $(CPPFLAGS) $(STATIC_CFLAGS) \
		-fcf-protection=full $(SRC) -o $@ $(STATIC_LDFLAGS)

$(STATIC_AARCH64): $(SRC) | $(BUILDDIR)
	$(ZIG) cc -target aarch64-linux-musl $(CPPFLAGS) $(STATIC_CFLAGS) \
		-mbranch-protection=standard $(SRC) -o $@ $(STATIC_LDFLAGS)

# The tests run the built binary, so they cannot run in a cross build.
# tests/run.sh is invoked through sh: it is not executable in the repository.
check: $(TARGET)
	@sh ./tests/run.sh ./$(TARGET)

test: check

install: $(TARGET)
	$(INSTALL) -d -m 0755 $(DESTDIR)$(SBINDIR) $(DESTDIR)$(MAN1DIR)
	$(INSTALL) $(INSTALL_BIN_OPTS) $(TARGET) $(DESTDIR)$(SBINDIR)/safexec
	$(INSTALL) -m 0644 $(MANPAGE) $(DESTDIR)$(MAN1DIR)/safexec.1
	$(if $(filter 4% 04%,$(BINMODE)),,@echo "safexec installed without the setuid bit (mode $(BINMODE)): pass-through mode only."; \
	echo "To enable privilege dropping: chown root:root $(SBINDIR)/safexec && chmod 4755 $(SBINDIR)/safexec"; \
	echo "(do not install on a nosuid mount)")

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/safexec
	rm -f $(DESTDIR)$(MAN1DIR)/safexec.1

clean:
	rm -rf $(BUILDDIR)
