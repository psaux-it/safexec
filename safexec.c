// SPDX-License-Identifier: GPL-2.0-only
/*
 * safexec - privilege-dropping exec wrapper for a fixed set of tools
 *
 * Purpose
 *   Lets an unprivileged service (web application, scheduler, job runner,
 *   automation agent) launch a small, fixed set of command-line tools
 *   without ever running them as root and without handing the caller a
 *   general shell. safexec is installed setuid root, validates the request,
 *   pins the tool to a trusted absolute path, isolates the process, drops
 *   privileges and only then execs the tool.
 *
 * Usage
 *   safexec [wrapper ...] <tool> [args ...]
 *   safexec --kill=<pid>
 *   safexec --help | -h
 *   safexec --version | -v
 *
 * Exit status
 *   3               Refused or failed before exec (rg itself uses 0/1/2).
 *   --kill          0 on success, 1 otherwise.
 *   anything else   The tool's own exit status (safexec execs the tool, so
 *                   its status is what the caller sees).
 *
 * Allowlist
 *   Always available: rg, wget, curl; archives (tar, gzip, gunzip, xz, unxz,
 *   zip, unzip); checksums (sha256sum, sha512sum, shasum, b2sum, cksum);
 *   media (ffmpeg, ffprobe, magick, convert, identify); documents
 *   (wkhtmltopdf, pdftk, pandoc). Optional buckets, enabled at compile time:
 *     -DSAFEXEC_WITH_GS         gs
 *     -DSAFEXEC_WITH_POPPLER    pdfinfo, pdftoppm, pdftocairo
 *     -DSAFEXEC_WITH_DB         mysqldump, mysql, mariadb-dump, mariadb,
 *                               pg_dump, pg_restore, psql, redis-cli
 *     -DSAFEXEC_WITH_RSYNC_GIT  rsync, git
 *   Prelude wrappers: nohup, nice, timeout, stdbuf, ionice, taskset, setsid,
 *   chrt, time.
 *   Other compile-time defaults: -DSAFEXEC_QUIET_DEFAULT=0|1 and
 *   -DSAFEXEC_SAFE_CWD_DEFAULT=-1|0|1 (see Environment below).
 *
 * Installation
 *   chown root:root safexec && chmod 4755 safexec
 *   Do not place it on a nosuid mount; without the setuid bit safexec runs in
 *   pass-through mode (see step 4 below).
 *
 * Execution model
 *   1. Allowlist    The tool is matched by basename against the allowlist.
 *                   Shells (sh, bash, dash, ash, zsh, ksh, fish) are rejected
 *                   in the prelude. The prelude may hold wrapper names,
 *                   options, signed integers and NAME=VALUE assignments;
 *                   assignments are limited to proxy variables (HTTP_PROXY,
 *                   HTTPS_PROXY, ALL_PROXY, NO_PROXY and their lower-case
 *                   forms), and loader/interpreter knobs such as PATH, IFS,
 *                   LD_*, DYLD_*, PYTHONPATH are refused.
 *   2. Pinning      The tool and every bare-name wrapper are resolved to
 *                   absolute paths under trusted bin dirs (/usr/bin, /bin,
 *                   /usr/local/{bin,sbin}, /usr/sbin, /sbin, NixOS
 *                   /run/current-system/sw/bin, pkgsrc /usr/pkg/{bin,sbin};
 *                   Homebrew/MacPorts on macOS). A symlink is accepted only
 *                   if its realpath is also trusted; the symlink path is what
 *                   gets exec'd, so multi-call binaries (BusyBox, coreutils)
 *                   keep the right argv[0]. Wrappers given with an explicit
 *                   path must be exactly "<trusted dir>/<name>".
 *   3. Setuid       With euid 0: clear the environment, set a fixed PATH and
 *                   a UTF-8 locale, umask 077, PR_SET_DUMPABLE=0; join a
 *                   cgroup v2 child <cgroup root>/safexec-run/safexec-run.<pid>
 *                   or fall back to rlimits plus optional nice/ionice; drop
 *                   privileges; PR_SET_NO_NEW_PRIVS; close fds >= 3; exec.
 *                   The drop target is 'nobody', except for rg (below). If
 *                   the drop fails, safexec falls back to the invoking user
 *                   (real uid/gid) and aborts if euid is still 0. safexec
 *                   never execs a tool as root.
 *   4. Pass-through Without setuid root (euid != 0) only steps 1-2 apply: no
 *                   environment sanitizing, privilege drop or isolation. The
 *                   tool runs as the invoking user.
 *
 * Tool-specific behavior
 *   rg      The last argument must be an absolute path to a directory that
 *           is not a symlink and not root-owned. rg runs as that directory's
 *           owner; if the owner is already the invoking user no drop is
 *           needed.
 *   wget    If /tmp is not writable by the final euid, "-P /tmp" is
 *           rewritten to /tmp/safexec-work/<euid> (the parent directory is
 *           root-owned with sticky mode 01777; the per-user subdirectory is
 *           mode 0700).
 *   --kill  Linux only. Sends SIGTERM if the target process is owned by
 *           'nobody' and sits in a "safexec-run" cgroup; without cgroup
 *           delegation, NoNewPrivs=1 is accepted instead. Uses
 *           pidfd_send_signal when available, otherwise kill().
 *
 * Environment (read before the environment is cleared)
 *   SAFEXEC_DETACH=auto|cgv2|rlimits|off   Isolation mode (default auto).
 *                  Read with secure_getenv() on glibc, getenv() on musl.
 *   SAFEXEC_QUIET=0|1                      Suppress info messages (0).
 *   SAFEXEC_SAFE_CWD=-1|0|1                chdir to /tmp (or /) when the
 *                  CWD is not writable; -1 = only if a stdio fd is a TTY (-1).
 *
 * Files and kernel objects used
 *   <cgroup root>/safexec-run/            Base cgroup v2 parent (created).
 *   <cgroup root>/safexec-run/safexec-run.<pid>   Per-run child cgroup;
 *                                         empty stale ones are removed.
 *   /tmp/safexec-work/                    Root-owned 01777 fallback parent
 *                                         for wget's download directory.
 *
 * Diagnostics
 *   Informational, warning and error messages go to stderr and are
 *   suppressed by SAFEXEC_QUIET=1.
 *
 * Platforms
 *   Linux gets the full feature set. Other POSIX systems get the allowlist,
 *   pinning, rlimits and fd closing, but no cgroup, pidfd or --kill.
 *
 * Limits
 *   Not a general-purpose sandbox. It constrains only the process it
 *   launches (and its descendants), and only allowlisted tools may run.
 *   The tool's own arguments are not filtered: options such as rg --pre or
 *   wget --execute make those tools run programs or change files with the
 *   drop target's privileges. Expose the setuid binary only to callers that
 *   are trusted with that (e.g. via file mode/group ownership).
 *
 * Copyright (C) 2025-2026 Hasan Calisir <hasan.calisir@psauxit.com>
 */

#define _GNU_SOURCE 1

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <locale.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <limits.h>
#include <dirent.h>
#include <stdarg.h>
#include <sys/resource.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#ifdef __linux__
#  ifndef __NR_pidfd_open
#    define SAFEXEC_NO_PIDFD 1
#  endif
#  ifndef __NR_pidfd_send_signal
#    define SAFEXEC_NO_PIDFD 1
#  endif
#else
#  define SAFEXEC_NO_PIDFD 1
#endif

#if defined(__linux__) && (!defined(__has_include) || __has_include(<linux/ioprio.h>))
#include <linux/ioprio.h>
#endif
#ifdef __linux__
#ifndef IOPRIO_WHO_PROCESS
#define IOPRIO_WHO_PROCESS 1
#endif
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

// Metadata
#define SAFEXEC_NAME     "safexec"
#define SAFEXEC_VERSION  "1.9.6"
#define SAFEXEC_AUTHOR   "Hasan Calisir"

// safexec-detected failure before exec; distinct from normal rg statuses 0/1/2.
// Other tools may independently return 3. --kill retains its 0/1 contract.
#define SAFEXEC_LAUNCH_FAIL 3

// Safe DIR
#ifndef SAFEXEC_SAFE_CWD_DEFAULT
#define SAFEXEC_SAFE_CWD_DEFAULT (-1)
#endif

// Quiet
#ifndef SAFEXEC_QUIET_DEFAULT
#define SAFEXEC_QUIET_DEFAULT 0
#endif

// Optional buckets (compile-time)
// Enable at build time e.g. -DSAFEXEC_WITH_GS -DSAFEXEC_WITH_DB -DSAFEXEC_WITH_RSYNC_GIT

#ifdef SAFEXEC_WITH_GS
  // Ghostscript (PS/PDF rasterize) – riskier, off by default
  #define SAFEXEC_GS_TOOLS  "gs",
#else
  #define SAFEXEC_GS_TOOLS
#endif

#ifdef SAFEXEC_WITH_POPPLER
  #define SAFEXEC_POPPLER_TOOLS  "pdfinfo","pdftoppm","pdftocairo",
#else
  #define SAFEXEC_POPPLER_TOOLS
#endif

#ifdef SAFEXEC_WITH_DB
  // Database clients/dumpers (enable only where intended)
  #define SAFEXEC_DB_TOOLS  "mysqldump","mysql","mariadb-dump","mariadb","pg_dump","pg_restore","psql","redis-cli",
#else
  #define SAFEXEC_DB_TOOLS
#endif

#ifdef SAFEXEC_WITH_RSYNC_GIT
  // File sync / VCS (can indirectly use ssh; be careful)
  #define SAFEXEC_SYNC_VCS_TOOLS  "rsync","git",
#else
  #define SAFEXEC_SYNC_VCS_TOOLS
#endif


// Rebuild the final table including optional buckets
static const char *const ALLOWED_BINS[] = {
    // Scan
    "rg",
    // Fetch
    "wget","curl",
    // Archives
    "tar","gzip","gunzip","xz","unxz","zip","unzip",
    // Checksums
    "sha256sum","sha512sum","shasum","b2sum","cksum",
    // Media / images
    "ffmpeg","ffprobe","magick","convert","identify",
    // Docs
    "wkhtmltopdf","pdftk","pandoc",

    // Optional buckets:
    SAFEXEC_GS_TOOLS
    SAFEXEC_POPPLER_TOOLS
    SAFEXEC_DB_TOOLS
    SAFEXEC_SYNC_VCS_TOOLS

    NULL
};


static int is_allowed_bin(const char *base) {
    for (size_t i = 0; ALLOWED_BINS[i]; ++i)
        if (strcmp(base, ALLOWED_BINS[i]) == 0) return 1;
    return 0;
}

// Env flag
static int env_flag(const char *name, int dflt) {
    const char *v = getenv(name);
    if (!v || !*v) return dflt;
    if (!strcmp(v,"0") || !strcasecmp(v,"false") || !strcasecmp(v,"no")  || !strcasecmp(v,"off")) return 0;
    if (!strcmp(v,"1") || !strcasecmp(v,"true")  || !strcasecmp(v,"yes") || !strcasecmp(v,"on"))  return 1;
    return dflt;
}

// Set quiet
static int env_quiet_enabled(void) {
    return env_flag("SAFEXEC_QUIET", SAFEXEC_QUIET_DEFAULT) == 1;
}

// Quiet-aware logging layer
static int QUIET = 0;
static int s_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static int s_printf(const char *fmt, ...) {
    if (QUIET) return 0;
    va_list ap; va_start(ap, fmt);
    int r = vfprintf(stdout, fmt, ap);
    va_end(ap);
    return r;
}
static int s_fprintf(FILE *stream, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int s_fprintf(FILE *stream, const char *fmt, ...) {
    if (QUIET) return 0;
    va_list ap; va_start(ap, fmt);
    int r = vfprintf(stream, fmt, ap);
    va_end(ap);
    return r;
}
static void s_perror(const char *s) {
    if (!QUIET) perror(s);
}

// snprintf wrapper that errors on truncation to quiet -Wformat-truncation
static int safe_snprintf(char *dst, size_t dstsz, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static int safe_snprintf(char *dst, size_t dstsz, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst, dstsz, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= dstsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int is_bytes_or_max(const char *s) {
    if (!s || !*s) return 0;
    if (!strcasecmp(s, "max")) return 1;
    for (const char *p=s; *p; ++p) if (*p < '0' || *p > '9') return 0;
    return 1;
}

static void clearenv_portable(void) {
#if defined(__GLIBC__) || defined(__linux__)
    clearenv();
#else
    extern char **environ;
    if (!environ) return;

    size_t cnt = 0;
    for (char **p = environ; *p; ++p) ++cnt;

    // Collect names (before unsetting)
    char **names = (char**)calloc(cnt, sizeof *names);
    if (!names) {
        unsetenv("PATH"); unsetenv("IFS"); unsetenv("LD_LIBRARY_PATH");
        unsetenv("DYLD_LIBRARY_PATH"); unsetenv("PYTHONPATH");
        return;
    }

    size_t i = 0;
    for (char **p = environ; *p && i < cnt; ++p) {
        char *eq = strchr(*p, '=');
        if (!eq) continue;
        size_t n = (size_t)(eq - *p);
        names[i] = (char*)malloc(n + 1);
        if (!names[i]) break;
        memcpy(names[i], *p, n);
        names[i][n] = '\0';
        ++i;
    }

    for (size_t j = 0; j < i; ++j) { unsetenv(names[j]); free(names[j]); }
    free(names);
#endif
}

// Check whether a given PID lives under /safexec-run or matches safexec-run.* in cgroup v2 path
static int proc_in_safexec_cgroup(pid_t pid) {
#ifndef __linux__
    (void)pid; return 0;
#else
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/cgroup", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512]; int ok = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "0::", 3) != 0) continue;   /* v2 only */
        const char *p = line + 3;
        if (strstr(p, "/safexec-run/") || strstr(p, "/safexec-run.")) { ok = 1; break; }
    }
    fclose(f);
    return ok;
#endif
}

static long gettid_portable(void) {
#ifdef __linux__
  #ifdef __NR_gettid
    return syscall(__NR_gettid);
  #else
    return (long)getpid();
  #endif
#else
    return (long)getpid();
#endif
}

static int pidfd_open_wrap(pid_t pid) {
#ifdef SAFEXEC_NO_PIDFD
    (void)pid;
    errno = ENOSYS;
    return -1;
#else
    errno = 0;
    return (int)syscall(__NR_pidfd_open, pid, 0);
#endif
}

static int pidfd_send_signal_wrap(int pidfd, int sig) {
#ifdef SAFEXEC_NO_PIDFD
    (void)pidfd; (void)sig;
    errno = ENOSYS;
    return -1;
#else
    return (int)syscall(__NR_pidfd_send_signal, pidfd, sig, NULL, 0);
#endif
}

// Limits
typedef struct {
    const char *mem_max_v2;                  // bytes or "max" (e.g., "268435456" or "max")
    int pids_max;                            // -1 unlimited
    int cpu_weight_v2;                       // 1..10000 (default 100)
    const char *io_max;                      // e.g. "8:0 rbps=1048576 wbps=1048576" (bytes/sec, optional)
    int rlimit_cpu_secs;                     // <0 => unlimited, 0 => skip, >0 => set
    unsigned long long rlimit_as_bytes;      // 0 => unlimited, >0 => set
    int rlimit_nofile;                       // <0 => unlimited, 0 => skip, >0 => set
    int rlimit_nproc;                        // <0 => unlimited, 0 => skip, >0 => set
    int nice_adj;                            // 0 => leave as-is
    int ioprio_class;                        // 0 => leave as-is; 1=RT,2=BE,3=IDLE
    int ioprio_data;                         // 0..7
} safexec_limits;

static safexec_limits safexec_default_limits(void) {
    safexec_limits L = {
        .mem_max_v2 = NULL,                  // v2: explicitly unlimited
        .pids_max = -1,                      // unlimited
        .cpu_weight_v2 = 0,                  // don't write -> kernel default (100)
        .io_max = NULL,
        .rlimit_cpu_secs = -1,               // unlimited CPU time
        .rlimit_as_bytes = 0,                // unlimited address space
        .rlimit_nofile = -1,                 // unlimited (clamped by nr_open)
        .rlimit_nproc = -1,                  // unlimited
        .nice_adj = 0,                       // leave priority unchanged
        .ioprio_class = 0, .ioprio_data = 0  // leave IO priority unchanged
    };
    return L;
}

static int write_all_str(const char *path, const char *s) {
    int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) return -1;
    size_t n = strlen(s);
    ssize_t w = write(fd, s, n);
    int saved = errno;
    int rc = (w == (ssize_t)n) ? 0 : -1;
    errno = saved;
    close(fd);
    return rc;
}

// Write a line (auto-append newline)
static int write_all_line(const char *path, const char *s) {
    int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t w1 = write(fd, s, strlen(s));
    ssize_t w2 = (w1 >= 0) ? write(fd, "\n", 1) : -1;
    int rc = (w1 == (ssize_t)strlen(s) && w2 == 1) ? 0 : -1;
    close(fd);
    return rc;
}

static int write_all_u64(const char *path, unsigned long long v) {
    char buf[64];
    int len = snprintf(buf, sizeof buf, "%llu\n", v);
    (void)len;
    return write_all_str(path, buf);
}

static int is_dir_nosym(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

// Read back first token/line from a controller file (for logging)
static int read_token(const char *path, char *out, size_t outsz) {
    int fd = open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, (ssize_t)outsz - 1);
    close(fd);
    if (n < 0) return -1;
    size_t len = (n > 0) ? (size_t)n : 0;
    out[len] = '\0';
    char *nl = strchr(out, '\n'); if (nl) *nl = 0;
    return 0;
}

// cgroup v2
static const char *cgv2_root(void) {
    static const char *root = NULL;
    if (root) return root;
    if (access("/sys/fs/cgroup/cgroup.controllers", R_OK) == 0)
        root = "/sys/fs/cgroup";
    else if (access("/sys/fs/cgroup/unified/cgroup.controllers", R_OK) == 0)
        root = "/sys/fs/cgroup/unified";
    else
        root = NULL;
    return root;
}

static int cgv2_available(void) {
    return cgv2_root() != NULL;
}

static int cgv2_enable_one(const char *tok) {
    const char *root = cgv2_root(); if (!root) return -1;
    char path[PATH_MAX];
    if (safe_snprintf(path, sizeof path, "%s/cgroup.subtree_control", root) != 0) return -1;
    int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) {
        if (errno != EROFS && errno != EPERM && errno != EACCES)
            s_fprintf(stderr, "Info: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    char buf[32]; int len = snprintf(buf, sizeof buf, "%s\n", tok);
    ssize_t w = write(fd, buf, len);
    int e = errno; close(fd);
    if (w != (ssize_t)len) {
        if (e == EROFS || e == EPERM || e == EACCES) {
            return -1;
        }
        if (strcmp(tok, "+cpu") == 0 && e == EINVAL) {
            s_fprintf(stderr, "Info: enabling +cpu failed (EINVAL). "
                               "Hint: v2 cpu controller needs all RT threads in root.\n");
        } else {
            s_fprintf(stderr, "Info: cannot enable %s on subtree_control: %s\n",
                      tok, strerror(e));
        }
        return -1;
    }
    return 0;
}

static void cgv2_enable_controllers(void) {
    // Try each; failures are non-fatal
    (void)cgv2_enable_one("+memory");
    (void)cgv2_enable_one("+pids");
    (void)cgv2_enable_one("+cpu");
    (void)cgv2_enable_one("+io");
    (void)cgv2_enable_one("+cpuset");
}

// Remove empty stale groups matching prefix (e.g., "safexec-run.")
static void cgv2_cleanup_stale(const char *prefix) {
    const char *root = cgv2_root(); if (!root) return;
    DIR *d = opendir(root); if (!d) return;
    struct dirent *de;
    size_t plen = strlen(prefix);
    while ((de = readdir(d))) {
        if (de->d_type != DT_DIR) {
            if (de->d_type != DT_UNKNOWN) continue;
            /* fall back to lstat when d_type is unknown */
            char probe[PATH_MAX];
            if (safe_snprintf(probe, sizeof probe, "%s/%s", root, de->d_name) != 0) continue;
            struct stat st;
            if (lstat(probe, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        }
        if (de->d_name[0] == '.') continue;
        if (strncmp(de->d_name, prefix, plen) != 0) continue;
        char dir[PATH_MAX];
        if (safe_snprintf(dir, sizeof dir, "%s/%s", root, de->d_name) != 0) continue;
        // Try to remove; will only succeed if empty
        if (rmdir(dir) == 0) {
            s_fprintf(stderr, "Info: removed empty stale cgroup v2 '%s'\n", dir);
        }
    }
    closedir(d);
}

// Cleanup under the current parent subtree instead of only the global root
static void cgv2_cleanup_stale_at(const char *parent, const char *prefix) {
    DIR *d = opendir(parent); if (!d) return;
    struct dirent *de; size_t plen = strlen(prefix);
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (strncmp(de->d_name, prefix, plen) != 0) continue;
        char dir[PATH_MAX];
        if (safe_snprintf(dir, sizeof dir, "%s/%s", parent, de->d_name) != 0) continue;
        /* Only remove if empty */
        (void)rmdir(dir);
    }
    closedir(d);
}

// Read the absolute cgroup v2 dir of the current process: /sys/fs/cgroup + self path
static int cgv2_self_dir(char *out, size_t outsz) {
    const char *root = cgv2_root(); if (!root) return -1;
    int fd = open("/proc/self/cgroup", O_RDONLY|O_CLOEXEC); if (fd < 0) return -1;
    FILE *f = fdopen(fd, "r"); if (!f) { close(fd); return -1; }
    char line[4096]; int rc = -1;
    while (fgets(line, sizeof line, f)) {
        // v2 line format: 0::/user.slice/...
        if (strncmp(line, "0::", 3) == 0) {
            char *p = line + 3;
            char *nl = strchr(p, '\n'); if (nl) *nl = 0;
            if (safe_snprintf(out, outsz, "%s%s", root, p) == 0) rc = 0;
            break;
        }
    }
    fclose(f);
    return rc;
}

// Summary report
static void report_summary(const char *abs_tool, const char *cgroup_hint) {
    uid_t ruid = getuid(), euid = geteuid();
    gid_t rgid = getgid(), egid = getegid();

    // Resolve cwd
    char cwd[PATH_MAX]; const char *cwdp = getcwd(cwd, sizeof cwd) ? cwd : "(unavailable)";

    s_fprintf(stderr,
      "Summary: user=%ld:%ld (ruid=%ld rgid=%ld) cwd=%s tool=%s\n",
      (long)euid, (long)egid, (long)ruid, (long)rgid, cwdp, abs_tool);

#ifdef __linux__
    int nnpr = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    s_fprintf(stderr, "Summary: no_new_privs=%s\n", (nnpr == 1) ? "on" : "off");
#endif

    if (cgroup_hint && *cgroup_hint)
        s_fprintf(stderr, "Summary: cgroup=%s\n", cgroup_hint);

    // Print effective cgroup v2 limits if present
    char cgdir[PATH_MAX];
    if (cgv2_self_dir(cgdir, sizeof cgdir) == 0) {
        #define SHOW(file,label) \
            do { \
                char pathbuf[PATH_MAX]; \
                if (safe_snprintf(pathbuf, sizeof pathbuf, "%s/" file, cgdir) == 0) { \
                    char tok[256] = {0}; \
                    if (read_token(pathbuf, tok, sizeof tok) == 0) \
                        s_fprintf(stderr, "Summary: " label "=%s\n", tok); \
                } \
            } while (0)
        SHOW("memory.max","memory.max");
        SHOW("pids.max","pids.max");
        SHOW("cpu.weight","cpu.weight");
        SHOW("io.max","io.max");
        SHOW("cpuset.cpus","cpuset.cpus");
        SHOW("cpuset.mems","cpuset.mems");
        #undef SHOW
    } else {
        s_fprintf(stderr, "Summary: cgroup=(none; rlimits in effect)\n");
    }
}

static int cgv2_enable_one_at(const char *parent, const char *tok) {
    char path[PATH_MAX];
    if (safe_snprintf(path, sizeof path, "%s/cgroup.subtree_control", parent) != 0) return -1;
    int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) return -1;
    char buf[32]; int len = snprintf(buf, sizeof buf, "%s\n", tok);
    ssize_t w = write(fd, buf, len);
    int saved = errno;
    close(fd);
    if (w != (ssize_t)len) { errno = saved; return -1; }
    return 0;
}

static int cgv2_controller_available_at(const char *parent, const char *name) {
    char path[PATH_MAX], buf[1024];
    if (safe_snprintf(path, sizeof path, "%s/cgroup.controllers", parent) != 0) return 0;
    int fd = open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    return strstr(buf, name) != NULL;
}

// Read cgroup.type and check if a cgroup is in a threaded subtree
static int cgv2_is_threaded(const char *dir) {
    char path[PATH_MAX], t[64] = {0};
    if (safe_snprintf(path, sizeof path, "%s/cgroup.type", dir) != 0) return 0;
    if (read_token(path, t, sizeof t) != 0) return 0;
    /* parent considered threaded if "threaded" or "domain threaded" */
    return (strcmp(t, "threaded") == 0) || (strcmp(t, "domain threaded") == 0);
}


static void cgv2_copy_cpuset_from_parent(const char *parent, const char *child) {
    char from[PATH_MAX], to[PATH_MAX], tok[8192];
    // cpuset.cpus
    if (safe_snprintf(to, sizeof to,   "%s/cpuset.cpus", child) == 0 &&
        safe_snprintf(from, sizeof from,"%s/cpuset.cpus", parent) == 0) {
        if (read_token(to, tok, sizeof tok) == 0 && tok[0] == '\0') {
            if (read_token(from, tok, sizeof tok) == 0 && tok[0] != '\0')
                (void)write_all_line(to, tok);
        }
    }
    // cpuset.mems
    if (safe_snprintf(to, sizeof to,   "%s/cpuset.mems", child) == 0 &&
        safe_snprintf(from, sizeof from,"%s/cpuset.mems", parent) == 0) {
        if (read_token(to, tok, sizeof tok) == 0 && tok[0] == '\0') {
            if (read_token(from, tok, sizeof tok) == 0 && tok[0] != '\0')
                (void)write_all_line(to, tok);
        }
    }
}

// Read cgroup.events and return 1 if populated, 0 if not, -1 on error
static int cgv2_events_populated(const char *dir) {
    char p[PATH_MAX];
    if (safe_snprintf(p, sizeof p, "%s/cgroup.events", dir) != 0) return -1;

    int fd = open(p, O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) return -1;
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    int saved = errno; close(fd); errno = saved;
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Look for "populated <0/1>" anywhere */
    const char *k = strstr(buf, "populated");
    if (!k) return -1;
    while (*k && (*k < '0' || *k > '9')) k++;
    return (*k == '1') ? 1 : 0;
}

// Remove dir only if empty/unpopulated
static void cgv2_try_rmdir_if_empty(const char *dir) {
    if (!is_dir_nosym(dir)) return;
    int pop = cgv2_events_populated(dir);
    if (pop == 0) {
        (void)rmdir(dir);
    }
}

// Always use <cgroup root>/safexec-run as base parent
static int cgv2_root_base(char *out, size_t outsz) {
    const char *root = cgv2_root();
    if (!root) return -1;
    if (safe_snprintf(out, outsz, "%s/%s", root, "safexec-run") != 0) return -1;
    if (mkdir(out, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int cgv2_join_group(const char *name, const safexec_limits *L) {
    if (!cgv2_available()) return -1;

    // Discover where we START (session/service subtree), and our TARGET parent (<cgroup root>/safexec-run)
    char self_parent[PATH_MAX], parent[PATH_MAX];
    if (cgv2_self_dir(self_parent, sizeof self_parent) != 0) return -1;
    if (cgv2_root_base(parent, sizeof parent) != 0) return -1;

    // Prune empty safexec-run.* both under the session subtree and our global parent
    cgv2_cleanup_stale_at(self_parent, "safexec-run.");
    cgv2_cleanup_stale_at(parent,      "safexec-run.");

    // Enable controllers on the global parent when possible (ignore failures)
    int parent_threaded = cgv2_is_threaded(parent);
    if (!parent_threaded) {
        (void)cgv2_enable_one_at(parent, "+memory");
        (void)cgv2_enable_one_at(parent, "+pids");
        (void)cgv2_enable_one_at(parent, "+cpu");
        (void)cgv2_enable_one_at(parent, "+io");
        (void)cgv2_enable_one_at(parent, "+cpuset");
    }

    // Create child under the GLOBAL parent (always-detach)
    char dir[PATH_MAX];
    if (safe_snprintf(dir, sizeof dir, "%s/%s", parent, name) != 0) return -1;
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) return -1;

    // If we *had* created a same-named child in the session subtree in earlier builds, remember it
    char legacy_in_session[PATH_MAX];
    int have_legacy = (safe_snprintf(legacy_in_session, sizeof legacy_in_session, "%s/%s", self_parent, name) == 0) &&
                      is_dir_nosym(legacy_in_session);

    // If parent is threaded (unexpected at root), mark child threaded so thread-move works
    if (parent_threaded) {
        char p[PATH_MAX];
        if (safe_snprintf(p, sizeof p, "%s/cgroup.type", dir) == 0)
            (void)write_all_line(p, "threaded");
    }

    // Apply optional limits only when meaningful
    char p[PATH_MAX];
    int applied = 0;
    if (!parent_threaded && L->mem_max_v2 && *L->mem_max_v2) {
        if (!is_bytes_or_max(L->mem_max_v2)) {
            s_fprintf(stderr, "Error: memory.max must be decimal bytes or 'max' (got '%s')\n",
                  L->mem_max_v2);
            return -1;
        }
        if (safe_snprintf(p, sizeof p, "%s/memory.max", dir) != 0) return -1;
        if (write_all_line(p, L->mem_max_v2) == 0) applied++;
    }
    if (!parent_threaded && cgv2_controller_available_at(parent, "memory")) {
        if (safe_snprintf(p, sizeof p, "%s/memory.swap.max", dir) == 0)
            (void)write_all_line(p, "max");
    }
    if (!parent_threaded && cgv2_controller_available_at(parent, "pids") && L->pids_max != 0) {
        if (safe_snprintf(p, sizeof p, "%s/pids.max", dir) != 0) return -1;
        if (L->pids_max < 0)  { if (write_all_line(p, "max") == 0) applied++; }
        else                  { if (write_all_u64(p, (unsigned long long)L->pids_max) == 0) applied++; }
    }
    if (!parent_threaded && cgv2_controller_available_at(parent, "cpu") && L->cpu_weight_v2 > 0) {
        if (safe_snprintf(p, sizeof p, "%s/cpu.weight", dir) != 0) return -1;
        if (write_all_u64(p, (unsigned long long)L->cpu_weight_v2) == 0) applied++;
    }
    if (!parent_threaded && L->io_max && cgv2_controller_available_at(parent, "io")) {
        if (safe_snprintf(p, sizeof p, "%s/io.max", dir) != 0) return -1;
        if (write_all_line(p, L->io_max) == 0) applied++;
    }
    if (!parent_threaded && cgv2_controller_available_at(parent, "cpuset"))
        cgv2_copy_cpuset_from_parent(parent, dir);

    // Safety: avoid memory.max=0
    if (!parent_threaded && safe_snprintf(p, sizeof p, "%s/memory.max", dir) == 0) {
        char v[32];
        if (read_token(p, v, sizeof v) == 0 && strcmp(v, "0") == 0) {
            s_fprintf(stderr, "Error: memory.max=0 in child; aborting cgroup join.\n");
            (void)rmdir(dir);
            return -1;
        }
    }

    // Move into the new child
    if (parent_threaded) {
        if (safe_snprintf(p, sizeof p, "%s/cgroup.threads", dir) != 0) return -1;
        char tidbuf[64]; snprintf(tidbuf, sizeof tidbuf, "%ld\n", gettid_portable());
        if (write_all_str(p, tidbuf) != 0) {
            s_fprintf(stderr, "Error: cannot move thread to '%s': %s\n", dir, strerror(errno));
            return -1;
        }
    } else {
        if (safe_snprintf(p, sizeof p, "%s/cgroup.procs", dir) != 0) return -1;
        char pidbuf[64]; snprintf(pidbuf, sizeof pidbuf, "%ld\n", (long)getpid());
        if (write_all_str(p, pidbuf) != 0) {
            int saved = errno;
            if (saved == EOPNOTSUPP && safe_snprintf(p, sizeof p, "%s/cgroup.threads", dir) == 0) {
                char tidbuf[64]; snprintf(tidbuf, sizeof tidbuf, "%ld\n", gettid_portable());
                if (write_all_str(p, tidbuf) != 0) {
                    s_fprintf(stderr, "Error: cannot move to '%s': %s\n", dir, strerror(errno));
                    return -1;
                }
            } else {
                s_fprintf(stderr, "Error: cannot move to '%s': %s\n", dir, strerror(saved));
                errno = saved;
                return -1;
            }
        }
    }

    // AFTER we moved out: try to remove a same-named legacy cgroup under the session subtree
    if (have_legacy) cgv2_try_rmdir_if_empty(legacy_in_session);

    (void)applied;
    return 0;
}

static void apply_rlimits_and_sched(const safexec_limits *L) {
    struct rlimit r;

    // Address space (portable: RLIMIT_AS or RLIMIT_VMEM)
#if defined(RLIMIT_AS)
    if (L->rlimit_as_bytes == 0) {
        r.rlim_cur = r.rlim_max = RLIM_INFINITY;
        (void)setrlimit(RLIMIT_AS, &r);
    } else if (L->rlimit_as_bytes > 0) {
        r.rlim_cur = r.rlim_max = (rlim_t)L->rlimit_as_bytes;
        (void)setrlimit(RLIMIT_AS, &r);
    }
#elif defined(RLIMIT_VMEM)
    if (L->rlimit_as_bytes == 0) {
        r.rlim_cur = r.rlim_max = RLIM_INFINITY;
        (void)setrlimit(RLIMIT_VMEM, &r);
    } else if (L->rlimit_as_bytes > 0) {
        r.rlim_cur = r.rlim_max = (rlim_t)L->rlimit_as_bytes;
        (void)setrlimit(RLIMIT_VMEM, &r);
    }
#endif

    // CPU time
#ifdef RLIMIT_CPU
    if (L->rlimit_cpu_secs < 0) {
        r.rlim_cur = r.rlim_max = RLIM_INFINITY;
        (void)setrlimit(RLIMIT_CPU, &r);
    } else if (L->rlimit_cpu_secs > 0) {
        r.rlim_cur = r.rlim_max = (rlim_t)L->rlimit_cpu_secs;
        (void)setrlimit(RLIMIT_CPU, &r);
    }
#endif

    // NOFILE
#ifdef RLIMIT_NOFILE
    if (L->rlimit_nofile < 0) {
        r.rlim_cur = r.rlim_max = RLIM_INFINITY;
        (void)setrlimit(RLIMIT_NOFILE, &r);
    } else if (L->rlimit_nofile > 0) {
        r.rlim_cur = r.rlim_max = (rlim_t)L->rlimit_nofile;
        (void)setrlimit(RLIMIT_NOFILE, &r);
    }
#endif

    // NPROC
#ifdef RLIMIT_NPROC
    if (L->rlimit_nproc < 0) {
        r.rlim_cur = r.rlim_max = RLIM_INFINITY;
        (void)setrlimit(RLIMIT_NPROC, &r);
    } else if (L->rlimit_nproc > 0) {
        r.rlim_cur = r.rlim_max = (rlim_t)L->rlimit_nproc;
        (void)setrlimit(RLIMIT_NPROC, &r);
    }
#endif

    // Only adjust nice/ionice if requested
    if (L->nice_adj != 0) {
        errno = 0;
        (void)setpriority(PRIO_PROCESS, 0, L->nice_adj);
    }

#if defined(__linux__) && defined(IOPRIO_WHO_PROCESS) && defined(__NR_ioprio_set) && defined(IOPRIO_PRIO_VALUE)
    if (L->ioprio_class > 0) {
        int prio = IOPRIO_PRIO_VALUE(L->ioprio_class, L->ioprio_data);
        (void)syscall(__NR_ioprio_set, IOPRIO_WHO_PROCESS, 0 /*self*/, prio);
    }
#endif
}

enum detach_mode { DET_AUTO, DET_CGV2, DET_RLIMITS, DET_OFF };
static enum detach_mode parse_detach_mode(void) {
    const char *s =
#ifdef __GLIBC__
        secure_getenv("SAFEXEC_DETACH");
#else
        getenv("SAFEXEC_DETACH");
#endif

    if (!s || !*s) return DET_AUTO;
    if (!strcasecmp(s, "auto"))    return DET_AUTO;
    if (!strcasecmp(s, "cgv2"))    return DET_CGV2;
    if (!strcasecmp(s, "rlimits")) return DET_RLIMITS;
    if (!strcasecmp(s, "off"))     return DET_OFF;
    return DET_AUTO;
}

// Safe DIR
static void chdir_safe_if_cwd_inaccessible(void) {
    if (access(".", W_OK) == 0) return;
    s_fprintf(stderr, "Info: CWD not accessible; switching to /tmp\n");
    if (chdir("/tmp") != 0) {
        int rc = chdir("/");
        if (rc != 0) {
            int e = errno;
            s_fprintf(stderr, "Warning: failed to chdir to /tmp and /: %s\n",
                strerror(e));
        }
    }
}

// Print version
static void print_version(void) {
    printf(
        "%s %s\n"
        "Copyright (C) 2025 %s.\n"
        ,
        SAFEXEC_NAME, SAFEXEC_VERSION, SAFEXEC_AUTHOR
    );
}

static const char *base_of(const char *p) {
    const char *b = strrchr(p, '/');
    return b ? b + 1 : p;
}

static int is_prog(const char *arg, const char *name) {
    return strcmp(base_of(arg), name) == 0;
}

// Trusted path resolution (pin allowed tool to an absolute path)
static const char *const TRUSTED_BIN_DIRS[] = {
    /* Linux */
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/sbin",

    /* NixOS */
    "/run/current-system/sw/bin",

    /* BSDs */
    "/usr/pkg/bin",
    "/usr/pkg/sbin",

#ifdef __APPLE__
    /* macOS package managers */
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/opt/local/bin",
    "/opt/local/sbin",
#endif

    NULL
};

static int find_in_trusted_path(const char *base, char *out, size_t outsz) {
    for (const char *const *d = TRUSTED_BIN_DIRS; *d; ++d) {
        char cand[PATH_MAX];
        if (safe_snprintf(cand, sizeof cand, "%s/%s", *d, base) != 0) continue;

        struct stat st;
        if (lstat(cand, &st) != 0) continue;
        if (access(cand, X_OK) != 0) continue;

        if (S_ISREG(st.st_mode)) {
            /* Direct regular file — no symlink, fastest path. */
            if (safe_snprintf(out, outsz, "%s", cand) == 0) return 0;
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            /*
             * Symlink — common on Alpine/BusyBox/coreutils multi-call binaries
             * (e.g. /usr/bin/nohup -> ../../bin/coreutils). Resolve with
             * realpath() and verify the final target still lives under a
             * trusted directory before accepting. Security validation uses the
             * resolved real path; the symlink path (cand) is returned for exec
             * so the kernel sets argv[0] correctly for multi-call binaries.
             */
            char real[PATH_MAX];
            if (!realpath(cand, real)) continue;

            struct stat rst;
            if (stat(real, &rst) != 0) continue;
            if (!S_ISREG(rst.st_mode)) continue;
            if (access(real, X_OK) != 0) continue;

            /* Final target must still be under a trusted bin dir. */
            int trusted = 0;
            for (const char *const *td = TRUSTED_BIN_DIRS; *td; ++td) {
                size_t n = strlen(*td);
                if (strncmp(real, *td, n) == 0 &&
                    (real[n] == '/' || real[n] == '\0')) {
                    trusted = 1;
                    break;
                }
            }
            if (!trusted) {
                s_fprintf(stderr,
                    "Info: symlink '%s' -> '%s' resolves outside trusted dirs, skipping\n",
                    cand, real);
                continue;
            }

            /* Return the symlink path (cand), not the resolved real path.
             * Multi-call binaries (coreutils, busybox) use argv[0] to
             * determine their mode — execing /usr/bin/nohup lets the kernel
             * follow the symlink while preserving the correct argv[0]. */
            if (safe_snprintf(out, outsz, "%s", cand) == 0) return 0;
        }
    }
    return -1;
}

// Simple wrapper finder
static int is_signed_int(const char *s) {
    if (!s || !*s) return 0;
    if (*s == '+' || *s == '-') ++s;
    if (!*s) return 0;
    for (const unsigned char *p=(const unsigned char*)s; *p; ++p)
        if (*p < '0' || *p > '9') return 0;
    return 1;
}

static int is_name_eq_value(const char *s) {
    if (!s) return 0;
    const char *eq = strchr(s, '=');
    return (eq && eq != s);
}

static int looks_like_option(const char *s) {
    if (!s || !*s) return 0;
    if (strcmp(s, "--") == 0) return 1;
    return (s[0] == '-' && s[1] != '\0');
}

static int is_shell_name(const char *b) {
    return strcmp(b, "sh")   == 0 ||
           strcmp(b, "bash") == 0 ||
           strcmp(b, "dash") == 0 ||
           strcmp(b, "ash")  == 0 ||
           strcmp(b, "zsh")  == 0 ||
           strcmp(b, "ksh")  == 0 ||
           strcmp(b, "fish") == 0;
}


static int is_wrapper_name(const char *b) {
    return strcmp(b, "nohup")   == 0 ||
           strcmp(b, "nice")    == 0 ||
           strcmp(b, "timeout") == 0 ||
           strcmp(b, "stdbuf")  == 0 ||
           strcmp(b, "ionice")  == 0 ||
           strcmp(b, "taskset") == 0 ||
           strcmp(b, "setsid")  == 0 ||
           strcmp(b, "chrt")    == 0 ||
           strcmp(b, "time")    == 0;
}


// Return 1 if NAME=VALUE is allowed to appear in the prelude; 0 => reject.
static int is_assignment_allowed(const char *s) {
    const char *eq = strchr(s, '=');
    if (!eq || eq == s) return 0;
    size_t n = (size_t)(eq - s);

    // Forbid known-dangerous knobs
    static const char *deny[] = {
        "PATH","IFS",
        "LD_PRELOAD","LD_AUDIT","LD_LIBRARY_PATH","LD_DEBUG",
        "LD_ASSUME_KERNEL","LD_ORIGIN_PATH","LD_BIND_NOW",
        "DYLD_*",
        "PYTHONPATH","PERL5OPT","RUBYOPT","GEM_HOME","GEM_PATH",
        "GCONV_PATH","LOCPATH","TZDIR","MALLOC_CONF",
        NULL
    };

    for (int i = 0; deny[i]; ++i) {
        const char *d = deny[i];
        size_t dn = strlen(d);
        if (dn && d[dn-1] == '*') {
            /* prefix match for patterns like DYLD_* */
            if (strncmp(s, d, dn-1) == 0) return 0;
        } else if (n == dn && strncmp(s, d, n) == 0) {
            return 0;
        }
    }

    // Minimal allowlist for proxy envs (upper & lower)
    static const char *allow[] = {
        "HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY",
        "http_proxy","https_proxy","all_proxy","no_proxy",
        NULL
    };
    for (int i = 0; allow[i]; ++i) {
        const char *a = allow[i];
        if (strlen(a) == n && strncmp(s, a, n) == 0) return 1;
    }

    /* Default: reject unknown assignments (safer) */
    return 0;
}

// Values used by timeout (5s, 1.5, 2m), taskset (0x3, 0,1, 0-3) and friends
static int is_prelude_value(const char *s) {
    if (!s || !*s) return 0;
    const unsigned char *p = (const unsigned char *)s;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        if (!*p) return 0;
        for (; *p; ++p)
            if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
                return 0;
        return 1;
    }
    if (*p < '0' || *p > '9') return 0;
    while (*p && ((*p >= '0' && *p <= '9') || *p == '.' || *p == ',' || *p == '-')) ++p;
    if (!*p) return 1;
    return (p[1] == '\0' && (*p == 's' || *p == 'm' || *p == 'h' || *p == 'd'));
}

// Find first allowed tool
static int find_target_prog_index(int argc, char **argv) {
    int i = 1;
    for (; i < argc; ++i) {
        const char *tok = argv[i];
        const char *b = base_of(tok);

        // If this token is an allowed tool name, stop here -> target found
        if (is_allowed_bin(b)) return i;

        // Explicitly deny shells in the prelude (env sh -c …, /bin/sh -c …, etc.)
        if (is_shell_name(b)) {
            s_fprintf(stderr, "Info: rejecting shell interpreter before tool: '%s'\n", tok);
            break;
        }

        // Otherwise allow it as part of the prelude if it looks benign:
        if (is_wrapper_name(b)) {
            if (strchr(tok, '/') != NULL) {
                /* Explicit path supplied — validate it is inside a trusted dir */
                /* The path must be exactly "<trusted dir>/<name>": no extra path
                 * components, so ".." or a symlinked directory inside a trusted
                 * dir cannot redirect it, and no attacker-writable component
                 * exists that could be swapped between this check and exec. */
                int trusted = 0;
                for (const char *const *d = TRUSTED_BIN_DIRS; *d; ++d) {
                    size_t n = strlen(*d);
                    if (strncmp(tok, *d, n) == 0 && tok[n] == '/' &&
                        strchr(tok + n + 1, '/') == NULL) {
                        trusted = 1; break;
                    }
                }
                if (!trusted) {
                    s_fprintf(stderr,
                        "Error: wrapper path '%s' is outside trusted directories\n",
                        tok);
                    return argc;
                }
                /* Validate explicit path — same logic as find_in_trusted_path.
                 * Regular files are accepted directly. Symlinks are followed
                 * via realpath() and the target must also be under a trusted dir
                 * (handles Alpine/BusyBox multi-call binaries). */
                struct stat st1;
                if (lstat(tok, &st1) != 0 || access(tok, X_OK) != 0) {
                    s_fprintf(stderr,
                        "Error: wrapper path '%s' failed trust validation\n", tok);
                    return argc;
                }
                if (S_ISLNK(st1.st_mode)) {
                    char real[PATH_MAX];
                    struct stat rst;
                    if (!realpath(tok, real) || stat(real, &rst) != 0 ||
                        !S_ISREG(rst.st_mode) || access(real, X_OK) != 0) {
                        s_fprintf(stderr,
                            "Error: wrapper path '%s' failed trust validation\n", tok);
                        return argc;
                    }
                    int tgt_trusted = 0;
                    for (const char *const *td = TRUSTED_BIN_DIRS; *td; ++td) {
                        size_t tn = strlen(*td);
                        if (strncmp(real, *td, tn) == 0 &&
                            (real[tn] == '/' || real[tn] == '\0')) {
                            tgt_trusted = 1; break;
                        }
                    }
                    if (!tgt_trusted) {
                        s_fprintf(stderr,
                            "Error: wrapper path '%s' -> '%s' resolves outside trusted dirs\n",
                            tok, real);
                        return argc;
                    }
                } else if (!S_ISREG(st1.st_mode)) {
                    s_fprintf(stderr,
                        "Error: wrapper path '%s' failed trust validation\n", tok);
                    return argc;
                }
            }
            continue;
        }
        if (looks_like_option(tok)) {
            /* An option must never name a path: "timeout 5 -dir/prog" or
             * "nice -- -dir/prog" would make the wrapper exec ./-dir/prog. */
            if (strchr(tok, '/') != NULL) {
                s_fprintf(stderr, "Info: rejecting path-like option before tool: '%s'\n", tok);
                break;
            }
            continue;
        }
        if (is_name_eq_value(tok)) {
            if (!is_assignment_allowed(tok)) {
                s_fprintf(stderr, "Info: rejecting dangerous assignment before tool: '%s'\n", tok);
                break;
            }
            continue;
        }
        if (is_signed_int(tok))        continue;
        if (is_prelude_value(tok))     continue;
        break;
    }
    return i;
}

// Usage
static void print_usage(const char *argv0) {
    s_printf(
        "Usage:\n"
        "  %s <program> [args...]\n"
        "  %s --kill=<pid>\n"
        "  %s --help | -h\n"
        "  %s --version | -v\n",
        argv0, argv0, argv0, argv0);
}

static int is_all_digits(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *p=(const unsigned char*)s; *p; ++p)
        if (*p < '0' || *p > '9') return 0;
    return 1;
}

/* Try C.UTF-8 → en_US.UTF-8 → C, and keep env consistent. */
static void set_locale_utf8_best_effort(void) {
    /* Try C.UTF-8 first (works on modern glibc & musl/Alpine) */
    if (setlocale(LC_CTYPE, "C.UTF-8")) {
        setenv("LANG", "C.UTF-8", 1);
        setenv("LC_CTYPE", "C.UTF-8", 1);
        setenv("CHARSET", "UTF-8", 1);  /* helps BusyBox wget */
        return;
    }
    /* Fallback for older glibc (e.g., CentOS 7) */
    if (setlocale(LC_CTYPE, "en_US.UTF-8")) {
        setenv("LANG", "en_US.UTF-8", 1);
        setenv("LC_CTYPE", "en_US.UTF-8", 1);
        setenv("CHARSET", "UTF-8", 1);
        return;
    }
    /* Last resort: plain C (ASCII). Still deterministic. */
    setlocale(LC_CTYPE, "C");
    setenv("LANG", "C", 1);
    setenv("LC_CTYPE", "C", 1);
    setenv("CHARSET", "ASCII", 1);
}

/*
 * Resolve the UID that owns the scan target by lstat()-ing the path itself.
 * This is the most reliable cross-environment method: the owner of the
 * directory is, by definition, the user who can read it.
 *
 *   Bare metal:  lstat(<dir>) returns the owner uid directly.
 *   Containers:  when the directory is bind-mounted into the container,
 *                lstat() still works and returns the owner uid.
 *
 * No /proc scan or service-configuration parsing is needed — the path owner
 * IS the user who can read it. Returns (uid_t)-1 on any failure.
 * Refuses symlinks (world-writable directories such as /tmp or /dev/shm
 * are mode 1777; any local user could plant one).
 * Refuses to return uid 0 (root) — we never run a tool as root, so a
 * root-owned path is rejected.
 */
static uid_t resolve_scan_path_owner(const char *scan_path) {
    if (!scan_path || !*scan_path) return (uid_t)-1;

    struct stat st;
    if (lstat(scan_path, &st) != 0) {
        s_fprintf(stderr,
            "Error: safexec: lstat('%s') failed: %s\n", scan_path, strerror(errno));
        return (uid_t)-1;
    }

    /* Reject symlinks unconditionally */
    if (S_ISLNK(st.st_mode)) {
        s_fprintf(stderr,
            "Error: safexec: '%s' is a symlink\n", scan_path);
        return (uid_t)-1;
    }

    /* Must be a directory */
    if (!S_ISDIR(st.st_mode)) {
        s_fprintf(stderr,
            "Error: safexec: '%s' is not a directory\n", scan_path);
        return (uid_t)-1;
    }

    /* Refuse root — we cannot drop to root */
    if (st.st_uid == 0) {
        s_fprintf(stderr,
            "Error: safexec: '%s' is owned by root\n", scan_path);
        return (uid_t)-1;
    }

    s_fprintf(stderr,
        "Info: safexec: '%s' owned by uid=%lu\n",
        scan_path, (unsigned long)st.st_uid);

    return st.st_uid;
}

/*
 * Find the path argument from rg's argv.
 *
 * rg is called as:
 *   safexec rg -m 1 --text ... '<pattern>' '<path>'
 *
 */
static const char *find_rg_scan_path(int argc, char **argv, int prog_i) {
    if (argc <= prog_i + 1) return NULL;

    const char *last = argv[argc - 1];

    /* Must be absolute path */
    if (!last || last[0] != '/') return NULL;

    return last;
}


// Sanitize environment & process state early
static void sanitize_process_early(void) {
    clearenv_portable();
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin", 1);
    set_locale_utf8_best_effort();
    umask(077);
#ifdef __linux__
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

// Close all inherited fds >= 3
static void closefrom_safe(int lowfd) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) {
        long max = sysconf(_SC_OPEN_MAX);
        if (max < 0 || max > 65536) max = 1024;
        for (int fd = lowfd; fd < max; ++fd) close(fd);
        return;
    }
    int dirfdno = dirfd(d);
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char *end = NULL;
        long fd = strtol(de->d_name, &end, 10);
        if (end && *end) continue;
        if (fd >= lowfd && fd != dirfdno) close((int)fd);
    }
    closedir(d);
}

// Pre-drop: ensure /tmp/safexec-work exists always
static int ensure_tmp_fallback_root(void) {
    struct stat st;

    if (lstat("/tmp", &st) != 0 || !S_ISDIR(st.st_mode)) return -1;

    struct stat stc;
    if (lstat("/tmp/safexec-work", &stc) == 0) {
        if (S_ISLNK(stc.st_mode)) return -1;
        if (!S_ISDIR(stc.st_mode)) return -1;
        if (stc.st_uid != 0 || stc.st_gid != 0) return -1;
        if (chmod("/tmp/safexec-work", 01777) != 0)
            s_perror("chmod /tmp/safexec-work");
        if (chown("/tmp/safexec-work", 0, 0) != 0)
            s_perror("chown /tmp/safexec-work");
        return 0;
    }
    if (errno != ENOENT) return -1;

    if (mkdir("/tmp/safexec-work", 0700) != 0) return -1;
    if (chown("/tmp/safexec-work", 0, 0) != 0)
        s_perror("chown /tmp/safexec-work");
    if (chmod("/tmp/safexec-work", 01777) != 0)
        s_perror("chmod /tmp/safexec-work");
    if (lstat("/tmp/safexec-work", &stc) != 0 || !S_ISDIR(stc.st_mode) ||
        stc.st_uid != 0 || stc.st_gid != 0) return -1;
    return 0;
}

static int parent_fallback_is_safe(void) {
    struct stat pc;
    if (lstat("/tmp/safexec-work", &pc) != 0) return 0;
    if (S_ISLNK(pc.st_mode)) return 0;
    if (!S_ISDIR(pc.st_mode)) return 0;
    if (pc.st_uid != 0 || pc.st_gid != 0) return 0;
    return 1;
}

// Post-drop: /tmp isn't writable by the final euid, rewrite -P to /tmp/safexec-work/<euid>
static void fix_wget_tmp_if_tmp_blocked(int argc, char **argv) {
    if (argc < 2) return;

    int prog_i = find_target_prog_index(argc, argv);
    if (prog_i >= argc) return;
    if (!is_prog(argv[prog_i], "wget")) return;

    for (int i = prog_i + 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "-P") == 0 && strcmp(argv[i + 1], "/tmp") == 0) {
            if (access("/tmp", W_OK) == 0) return;

            if (!parent_fallback_is_safe() || access("/tmp/safexec-work", W_OK) != 0) {
                s_fprintf(stderr, "Warning: /tmp not writable. No safe fallback. Keeping '-P /tmp'.\n");
                return;
            }

            char sub[PATH_MAX];
            if (safe_snprintf(sub, sizeof sub, "/tmp/safexec-work/%lu", (unsigned long)geteuid()) != 0) {
                s_fprintf(stderr, "Warning: failed to compose fallback path. Keeping '-P /tmp'.\n");
                return;
            }

            if (mkdir(sub, 0700) != 0 && errno != EEXIST) {
                s_fprintf(stderr, "Warning: failed to create '%s'. Keeping '-P /tmp'.\n", sub);
                return;
            }

            struct stat ss;
            if (lstat(sub, &ss) != 0 || !S_ISDIR(ss.st_mode) || ss.st_uid != geteuid()) {
                s_fprintf(stderr, "Warning: unsafe fallback '%s'. Keeping '-P /tmp'.\n", sub);
                return;
            }

            if (access(sub, W_OK) != 0) {
                s_fprintf(stderr, "Warning: fallback '%s' not writable. Keeping '-P /tmp'.\n", sub);
                return;
            }

            argv[i + 1] = strdup(sub);
            s_fprintf(stderr, "Info: Rewriting wget -P '/tmp' -> '%s'\n", sub);
            return;
        }
    }
}

static int try_kill_mode(const char *arg) {
    if (strncmp(arg, "--kill=", 7) != 0)
        return 0;

    char *endp = NULL;
    errno = 0;
    long tmp = strtol(arg + 7, &endp, 10);
    if (errno || !endp || *endp || tmp <= 0 || tmp > (long)INT_MAX) {
        s_fprintf(stderr, "Error: Invalid PID '%s'\n", arg + 7);
        return 1;
    }
    pid_t pid = (pid_t)tmp;

#ifndef __linux__
    s_fprintf(stderr, "Error: --kill is only supported on Linux.\n");
    return 1;
#else
    // Check if process exists
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        s_fprintf(stderr, "Error: PID %d does not exist or already exited\n", pid);
        return 1;
    }

    // Parse UID from /proc/<pid>/status
    char line[256];
    int uid = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            if (sscanf(line, "Uid:\t%d", &uid) != 1) {
                s_fprintf(stderr, "Error: failed to parse UID from /proc/%d/status\n", (int)pid);
                fclose(fp);
                return 1;
            }
            break;
        }
    }

    fclose(fp);

    // Dynamically resolve 'nobody' instead of hardcoding 65534
    struct passwd *npw = getpwnam("nobody");
    if (!npw) {
        s_fprintf(stderr, "Warning: 'nobody' user not found\n");
        return 1;
    }

    if (uid != (int)npw->pw_uid) {
        s_fprintf(stderr, "Info: Refusing to kill PID %d: not owned by 'nobody' (uid=%d)\n", pid, uid);
        return 1;
    }

    // inside Linux branch of try_kill_mode
    if (!proc_in_safexec_cgroup(pid)) {
        /* cgroup check failed — container may not allow cgroup delegation.
         * Fall back: accept kill if NoNewPrivs=1 (set by safexec before exec,
         * kernel-enforced one-way flag). /proc/pid/status is already open
         * above so we just re-read it here. */
        int nnp = 0;
        FILE *fp2 = fopen(path, "r");
        if (fp2) {
            while (fgets(line, sizeof(line), fp2)) {
                if (strncmp(line, "NoNewPrivs:", 11) == 0) {
                    nnp = atoi(line + 11);
                    break;
                }
            }
            fclose(fp2);
        }
        if (!nnp) {
            s_fprintf(stderr,
                "Info: Refusing to kill PID %d: not in safexec cgroup "
                "and NoNewPrivs not set\n", pid);
            return 1;
        }
        s_fprintf(stderr,
            "Info: cgroup check skipped (no delegation); "
            "killing PID %d via NoNewPrivs fallback\n", pid);
    }

    // Use pidfd if available to avoid PID reuse races
    int pfd = pidfd_open_wrap(pid);
    if (pfd >= 0) {
        if (pidfd_send_signal_wrap(pfd, SIGTERM) != 0) {
            s_perror("pidfd_send_signal(SIGTERM)");
            close(pfd);
            return 1;
        }
        close(pfd);
    } else {
        // Fallback: best-effort kill()
        if (kill(pid, SIGTERM) != 0) {
            s_perror("kill SIGTERM");
            return 1;
        }
    }

    // Not quiet
    printf("Success: Killed PID %d\n", pid);
    return 2;
#endif
}

// Export allowed prelude NAME=VALUE assignments (already validated) into the environment
static void apply_prelude_env(const char *const *kv, int n) {
    for (int i = 0; i < n; ++i) {
        char *dup = strdup(kv[i]);
        if (!dup) continue;
        char *eq = strchr(dup, '=');
        if (eq) { *eq = '\0'; (void)setenv(dup, eq + 1, 1); }
        free(dup);
    }
}

int main(int argc, char *argv[]) {
    QUIET = env_quiet_enabled();

    // capture SAFE_CWD policy before any sanitize() clears env
    int safe_cwd_pref = env_flag("SAFEXEC_SAFE_CWD", SAFEXEC_SAFE_CWD_DEFAULT);

    // Version/help handler
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0)) {
        print_version();
        return 0;
    }

    if (argc < 2) { print_usage(argv[0]); return SAFEXEC_LAUNCH_FAIL; }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    // Reject --kill without '=' (e.g., "--kill" or "--kill 123")
    if (strncmp(argv[1], "--kill", 6) == 0 && argv[1][6] != '=') {
        print_usage(argv[0]);
        return SAFEXEC_LAUNCH_FAIL;
    }

    {
        // Handle --kill=<pid>
        int k = try_kill_mode(argv[1]);
        if (k != 0)
            return (k == 2) ? 0 : 1;
    }

    // From here, only "<program> [args...]" is allowed.
    if (argv[1][0] == '-' || is_all_digits(argv[1])) {
        print_usage(argv[0]);
        return SAFEXEC_LAUNCH_FAIL;
    }

    // Enforce the tool allowlist, handling preludes such as "safexec nohup wget ..."
    int prog_i = find_target_prog_index(argc, argv);
    if (prog_i >= argc) {
        print_usage(argv[0]);
        return SAFEXEC_LAUNCH_FAIL;
    }
    const char *prog_base = base_of(argv[prog_i]);
    if (!is_allowed_bin(prog_base)) {
        s_fprintf(stderr, "Error: '%s' is not allowed by safexec.\n", prog_base);
        return SAFEXEC_LAUNCH_FAIL;
    }

    // Resolve allowed tool to an absolute, trusted path and pin argv[prog_i]
    char abs_tool[PATH_MAX];
    if (find_in_trusted_path(prog_base, abs_tool, sizeof abs_tool) != 0) {
        s_fprintf(stderr, "Error: cannot resolve trusted path for '%s'\n", prog_base);
        return SAFEXEC_LAUNCH_FAIL;
    }

    /* Pin the argv token so wrappers (env/timeout/nice) exec the same path */
    argv[prog_i] = strdup(abs_tool);
    if (!argv[prog_i]) {
        s_fprintf(stderr, "Error: OOM while pinning tool path\n");
        return SAFEXEC_LAUNCH_FAIL;
    }

    s_fprintf(stderr, "Info: pinned tool '%s' -> '%s'\n", prog_base, abs_tool);

    /* Pin all wrapper positions (argv[1]..argv[prog_i-1]) to trusted paths.
     * Layer 1 already rejected untrusted slashed wrappers; this ensures bare-name
     * wrappers resolve to known-good binaries regardless of inherited PATH.
     * Handles chains: safexec nohup nice wget → pins both nohup AND nice. */
    for (int wi = 1; wi < prog_i; ++wi) {
        const char *wb = base_of(argv[wi]);
        if (!is_wrapper_name(wb)) continue;   /* skip options/assignments */
        /* If already an absolute trusted path (passed as explicit path), keep it */
        if (strchr(argv[wi], '/') != NULL) continue;
        char abs_wrapper[PATH_MAX];
        if (find_in_trusted_path(wb, abs_wrapper, sizeof abs_wrapper) != 0) {
            s_fprintf(stderr,
                "Error: cannot resolve trusted path for wrapper '%s'\n", wb);
            return SAFEXEC_LAUNCH_FAIL;
        }
        argv[wi] = strdup(abs_wrapper);
        if (!argv[wi]) {
            s_fprintf(stderr, "Error: OOM while pinning wrapper path\n");
            return SAFEXEC_LAUNCH_FAIL;
        }
        s_fprintf(stderr, "Info: pinned wrapper '%s' -> '%s'\n", wb, abs_wrapper);
    }

    /* Prelude NAME=VALUE assignments (proxy variables only): no allowed wrapper
     * interprets them, so exec used to fail with ENOENT. Strip them from argv
     * and export them for the exec'd chain instead. */
    const char *prelude_env[16];
    int n_prelude_env = 0;
    {
        int w = 1;
        for (int r = 1; r < argc; ++r) {
            if (r < prog_i && !is_wrapper_name(base_of(argv[r])) &&
                !looks_like_option(argv[r]) && is_name_eq_value(argv[r])) {
                if (n_prelude_env >= 16) {
                    s_fprintf(stderr, "Error: too many environment assignments\n");
                    return SAFEXEC_LAUNCH_FAIL;
                }
                prelude_env[n_prelude_env++] = argv[r];
                continue;
            }
            argv[w++] = argv[r];
        }
        prog_i -= (argc - w);
        argc = w;
        argv[argc] = NULL;
    }

    // PASS-THROUGH MODE
    if (geteuid() != 0) {
        // Safe DIR
        int use_safe_cwd = safe_cwd_pref;
        if (use_safe_cwd < 0) {
            // Auto mode: enable only when running interactively (a TTY is attached)
            use_safe_cwd = isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) || isatty(STDERR_FILENO);
        }
        if (use_safe_cwd) {
            chdir_safe_if_cwd_inaccessible();
        }

        s_fprintf(stderr, "Info: safexec: Pass-Through Mode (euid=%ld)\n", (long)geteuid());
        s_fprintf(stderr, "Info: safexec: Starting '%s' as original user\n", argv[1]);

        s_fprintf(stderr,
            "Note: To enable hardening: chown root:root %s && chmod 4755 %s (avoid nosuid)\n",
            argv[0], argv[0]);

        apply_prelude_env(prelude_env, n_prelude_env);
        execvp(argv[1], &argv[1]);
        s_perror("safexec: execvp");
        _exit(SAFEXEC_LAUNCH_FAIL);
    }

    // Read isolation preferences & limits
    safexec_limits LIM = safexec_default_limits();
    enum detach_mode mode = parse_detach_mode();

    // Sanitize env and process state before any NSS/library lookups
    sanitize_process_early();
    apply_prelude_env(prelude_env, n_prelude_env);

    int isolated = 0;

    // Fresh group name to avoid stale limits from previous runs
    char cgname[64];
    if (safe_snprintf(cgname, sizeof cgname, "safexec-run.%ld", (long)getpid()) != 0) {
        s_fprintf(stderr, "Error: failed to compose cgroup name\n");
        return SAFEXEC_LAUNCH_FAIL;
    }

    // Cleanup empty stale groups first, enable controllers
    if (cgv2_available()) {
        cgv2_cleanup_stale("safexec-run.");
        cgv2_enable_controllers();
    }

    // cgroup v2
    if (!isolated && (mode == DET_AUTO || mode == DET_CGV2)) {
        if (cgv2_available()) {
            if (cgv2_join_group(cgname, &LIM) == 0) {
                char selfcg[PATH_MAX];
                if (cgv2_self_dir(selfcg, sizeof selfcg) == 0)
                    s_fprintf(stderr, "Info: using cgroup v2 child %s\n", selfcg);
                else {
                    s_fprintf(stderr, "Info: using cgroup v2 child (path unknown)\n");
                }
                isolated = 1;
            } else if (mode == DET_CGV2) {
                s_fprintf(stderr, "Error: cgroup v2 requested but join failed\n");
                return SAFEXEC_LAUNCH_FAIL;
            }
        } else if (mode == DET_CGV2) {
            s_fprintf(stderr, "Error: cgroup v2 requested but not available\n");
            return SAFEXEC_LAUNCH_FAIL;
        }
    }

    // Apply RLIMITs
    if (!isolated && mode != DET_OFF) {
        s_fprintf(stderr, "Info: falling back to RLIMITs + nice/ionice\n");
        apply_rlimits_and_sched(&LIM);
        isolated = 1;
    }

    // Create /tmp/safexec-work (01777) if possible, idempotent
    (void)ensure_tmp_fallback_root();

    // Remember original caller IDs for safe fallback
    uid_t ruid = getuid();
    gid_t rgid = getgid();
    int   was_root = (geteuid() == 0);

    /*
     * For rg: resolve the target drop UID from the scan path's owner.
     * This works on bare metal and in containers alike because the path
     * is always accessible to root (us), and its owner uid is exactly the
     * user rg needs to run as.
     *
     * For all other tools: drop to 'nobody' as usual.
     */
    struct passwd *pw = NULL;

    if (is_prog(argv[prog_i], "rg")) {

        const char *rg_scan_path = find_rg_scan_path(argc, argv, prog_i);
        uid_t scan_owner = (rg_scan_path)
            ? resolve_scan_path_owner(rg_scan_path)
            : (uid_t)-1;

        if (scan_owner == (uid_t)-1) {
            s_fprintf(stderr,
                "Error: safexec: root-owned or invalid path; refusing exec\n");
            return SAFEXEC_LAUNCH_FAIL;
        }

        if (scan_owner == ruid) {
            s_fprintf(stderr,
                "Info: safexec: path owner matches caller (uid=%lu); skipping drop\n",
                (unsigned long)ruid);
            goto drop_to_invoking_user;
        }


        pw = getpwuid(scan_owner);
        if (!pw) {
            s_fprintf(stderr,
                "Error: safexec: uid %lu not in passwd; refusing exec\n",
                (unsigned long)scan_owner);
            return SAFEXEC_LAUNCH_FAIL;
        }

        s_fprintf(stderr,
            "Info: safexec: dropping to '%s' (uid=%lu)\n",
            pw->pw_name, (unsigned long)pw->pw_uid);
    } else {
        pw = getpwnam("nobody");
    }

    if (pw) {
        if (setgroups(0, NULL) != 0) { s_perror("setgroups (nobody)"); goto drop_to_invoking_user; }
        if (setgid(pw->pw_gid) != 0) { s_perror("setgid (nobody)");    goto drop_to_invoking_user; }
        if (setuid(pw->pw_uid) != 0) { s_perror("setuid (nobody)");    goto drop_to_invoking_user; }
    } else {
        s_fprintf(stderr, "Warning: 'nobody' user not found, continuing as original user\n");
    }

    // Ensure we never exec as root; if still euid==0, drop to the invoking user
    if (geteuid() == 0) { goto drop_to_invoking_user; }

post_drop:

    // Never, ever exec as root. If privilege drop didn’t stick, bail out.
    if (geteuid() == 0) {
        s_fprintf(stderr, "Fatal: safexec cannot be used as root; refusing to exec (privilege drop failed).\n");
        return SAFEXEC_LAUNCH_FAIL;
    }

    // Safe DIR
    int use_safe_cwd = safe_cwd_pref;
    if (use_safe_cwd < 0) {
        // Auto mode: enable only when running interactively (a TTY is attached)
        use_safe_cwd = isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) || isatty(STDERR_FILENO);
    }
    if (use_safe_cwd) {
        chdir_safe_if_cwd_inaccessible();
    }

    // If /tmp isn't writable by the final euid
    fix_wget_tmp_if_tmp_blocked(argc, argv);

    // Prevent privilege regain in the child
#ifdef __linux__
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        s_perror("prctl PR_SET_NO_NEW_PRIVS");
    }
#endif

    // Summary
    char selfcg[PATH_MAX] = {0};
    if (cgv2_self_dir(selfcg, sizeof selfcg) != 0) selfcg[0] = '\0';
     report_summary(abs_tool, selfcg);

    // Close all inherited fds except stdio before exec
    closefrom_safe(3);

    fflush(NULL);


    execvp(argv[1], &argv[1]);

    s_perror("safexec: execvp");
    _exit(SAFEXEC_LAUNCH_FAIL);

drop_to_invoking_user:

    // Drop to the invoking user (ruid/rgid). If this fails, refuse to run.
    if (was_root) {
        if (setgroups(0, NULL) != 0) { s_perror("setgroups (fallback)"); return SAFEXEC_LAUNCH_FAIL; }
        if (setgid(rgid) != 0)       { s_perror("setgid (fallback)");    return SAFEXEC_LAUNCH_FAIL; }
        if (setuid(ruid) != 0)       { s_perror("setuid (fallback)");    return SAFEXEC_LAUNCH_FAIL; }
    }

    // If not was_root, we’re already the caller; nothing to do
    goto post_drop;
}
