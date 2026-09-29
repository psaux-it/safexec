/* Parser fuzz harness: includes safexec.c so static functions are reachable. */
#define main safexec_real_main
#include SRC
#undef main
#include <time.h>
static const char *POOL[] = {
 "rg","wget","curl","tar","gzip","sha256sum","ffmpeg","convert","pandoc","unzip",
 "nohup","nice","timeout","stdbuf","ionice","taskset","setsid","chrt","time",
 "sh","bash","dash","zsh","/bin/sh","/usr/bin/bash","env","ls","id","python3",
 "-n","-5","--","-","-c","--adjustment=3","-s","5","+7","0","123","5s","1.5","0x3","0,1","0-3",
 "PATH=/tmp","LD_PRELOAD=/x","HTTP_PROXY=http://a:1","https_proxy=x","FOO=bar","=x","NO_PROXY=","DYLD_FOO=1","IFS=x",
 "-/tmp/x","-dir/prog","-x/curl","/usr/bin/nice","/tmp/nice","./nice","/usr/bin/../bin/nice","/usr/bin/a/nice",
 "/tmp/evil/curl","/usr/bin/curl","","x","--output=/etc/passwd","-o/tmp/f","KILL", "a/b/c",
};
#define NPOOL (sizeof POOL/sizeof *POOL)
static unsigned long long s;
static unsigned rnd(void){ s = s*6364136223846793005ULL + 1442695040888963407ULL; return (unsigned)(s>>33); }
/* Independent oracles. They are deliberately NOT derived from safexec.c's own
 * predicates: checking is_assignment_allowed()/is_allowed_bin() with themselves
 * is tautological and cannot detect a regression in either (verified by
 * mutation: disabling either function passed the original harness clean). */
static const char *NEVER_TARGET[] = {"sh","bash","dash","zsh","ksh","fish","ash","env","ls","id","python3","perl",NULL};
static const char *PROXY_OK[] = {"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY",
                                 "http_proxy","https_proxy","all_proxy","no_proxy",NULL};
static int in_list(const char *const *l, const char *x) {
  for (; *l; ++l) if (!strcmp(*l, x)) return 1;
  return 0;
}
/* A prelude token is an assignment if it does not start with '-' and its first
 * '=' precedes any '/'. It is only acceptable if NAME is a proxy variable. */
static int bad_assignment(const char *t) {
  const char *eq = strchr(t, '='), *sl = strchr(t, '/');
  if (t[0] == '-' || !eq || (sl && sl < eq)) return 0;
  char name[64]; size_t n = (size_t)(eq - t);
  if (n == 0 || n >= sizeof name) return 1;
  memcpy(name, t, n); name[n] = 0;
  return !in_list(PROXY_OK, name);
}
int main(int argc_, char **argv_) {
  (void)argc_; (void)argv_;
  QUIET = 1; s = (unsigned long long)time(NULL);
  long accepted=0, rejected=0, iters = 400000, slash_viol = 0, shell_viol = 0, allowed_viol = 0, range_viol = 0, assign_viol = 0,
       oracle_target = 0, oracle_prelude = 0, oracle_assign = 0;
  for (long it = 0; it < iters; ++it) {
    int n = 2 + (int)(rnd() % 8);
    char *av[16]; av[0] = (char*)"safexec";
    for (int i = 1; i < n; ++i) av[i] = (char*)POOL[rnd() % NPOOL];
    av[n] = NULL;
    int r = find_target_prog_index(n, av);
    if (r < 1 || r > n) { range_viol++; continue; }
    /* main() semantics: accepted only if r<n and target basename is allowlisted */
    if (r >= n || !is_allowed_bin(base_of(av[r]))) { rejected++; continue; }
    accepted++;
    if (in_list(NEVER_TARGET, base_of(av[r]))) oracle_target++;
    for (int j = 1; j < r; ++j) {
      const char *b = base_of(av[j]);
      if (!strchr(av[j], '=') && in_list(NEVER_TARGET, b)) oracle_prelude++;
      if (bad_assignment(av[j])) oracle_assign++;
      if (is_shell_name(b)) shell_viol++;
      if (is_allowed_bin(b)) allowed_viol++;
      if (is_name_eq_value(av[j]) && !looks_like_option(av[j]) && !is_wrapper_name(b) && !is_assignment_allowed(av[j])) assign_viol++;
      if (strchr(av[j], '/') && !is_wrapper_name(b) && !is_name_eq_value(av[j])) slash_viol++;
    }
  }
  printf("iters=%ld accepted=%ld rejected=%ld range=%ld allowed=%ld shell=%ld bad_assign=%ld slash_path_in_prelude=%ld oracle_target=%ld oracle_prelude=%ld oracle_assign=%ld\n",
         iters, accepted, rejected, range_viol, allowed_viol, shell_viol, assign_viol, slash_viol,
         oracle_target, oracle_prelude, oracle_assign);
  return (range_viol|allowed_viol|shell_viol|assign_viol|oracle_target|oracle_prelude|oracle_assign) ? 1 : 0;
}
