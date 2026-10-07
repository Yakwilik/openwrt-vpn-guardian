/* Exercise the real dnsmasq parser, server arrays and reload lifecycle without
 * opening network sockets. The transport suite exercises the daemon separately. */
#include "dnsmasq.h"
#include <assert.h>

static unsigned checks;
static unsigned regex_live, regex_compilations;
static int fail_regcomp, fail_regexec;
static size_t fail_array_size;

#ifdef GUARDIAN_TEST_GLINET
static unsigned socket_mark_calls, observed_socket_mark;
static int fail_socket_mark;

int guardian_test_setsockopt(int fd, int level, int option,
                            const void *value, socklen_t size)
{
  (void)fd;
  assert(level == SOL_SOCKET && option == SO_MARK);
  assert(size == sizeof(unsigned int));
  observed_socket_mark = *(const unsigned int *)value;
  socket_mark_calls++;
  if (fail_socket_mark)
    {
      errno = EPERM;
      return -1;
    }
  return 0;
}

static void test_outgoing_mark(void)
{
  union mysockaddr source;
  int family, tcp, saved_max_port = daemon->max_port;
  assert(daemon->packet_mark == 0x1000);
  daemon->max_port = 0; /* Keep native local_bind off actual bind syscalls. */
  for (family = 0; family < 2; family++)
    for (tcp = 0; tcp < 2; tcp++)
      {
        memset(&source, 0, sizeof(source));
        source.sa.sa_family = family ? AF_INET6 : AF_INET;
        daemon->packet_mark = 0x1000;
        socket_mark_calls = 0;
        assert(local_bind(17, &source, "", 0, tcp));
        assert(socket_mark_calls == 1 && observed_socket_mark == 0x1000);
        checks++;
        fail_socket_mark = 1;
        assert(!local_bind(17, &source, "", 0, tcp) && errno == EPERM);
        fail_socket_mark = 0;
        checks++;
        daemon->packet_mark = 0;
        socket_mark_calls = 0;
        assert(local_bind(17, &source, "", 0, tcp));
        assert(socket_mark_calls == 0);
        checks++;
      }
  daemon->max_port = saved_max_port;
  daemon->packet_mark = 0x1000;
}
#endif

void *guardian_test_option_malloc(size_t size)
{
  if (fail_array_size && size == fail_array_size)
    {
      fail_array_size = 0;
      return NULL;
    }
  return whine_malloc(size);
}

/* Count successful libc compilations/frees independently of server ownership.
 * This verifies reload cleanup even when LeakSanitizer cannot inspect /proc. */
int guardian_test_regcomp(regex_t *compiled, const char *pattern, int flags)
{
  int rc;
  if (fail_regcomp)
    {
      fail_regcomp = 0;
      return REG_ESPACE;
    }
  rc = regcomp(compiled, pattern, flags);
  if (!rc)
    {
      regex_live++;
      regex_compilations++;
    }
  return rc;
}

int guardian_test_regexec(const regex_t *compiled, const char *name, size_t count,
                          regmatch_t matches[], int flags)
{
  if (fail_regexec)
    {
      fail_regexec = 0;
      return REG_ESPACE;
    }
  return regexec(compiled, name, count, matches, flags);
}

void guardian_test_regfree(regex_t *compiled)
{
  assert(regex_live > 0);
  regex_live--;
  regfree(compiled);
}

/* read_servers_file calls this after parsing. Network discovery/socket setup
 * is outside this unit test; keep the actual array rebuild. */
void check_servers(int no_loop_call)
{
  (void)no_loop_call;
  build_server_array();
}

static void expect_port(const char *query, unsigned short port)
{
  int first = -1, last = -1;
  char name[(MAXDNAME * 2) + 1];
  strcpy(name, query);
  if (!lookup_domain(name, F_IPV4, &first, &last) || first >= last ||
      (daemon->serverarray[first]->flags & (SERV_LITERAL_ADDRESS | SERV_USE_RESOLV)) ||
      ntohs(daemon->serverarray[first]->addr.in.sin_port) != port)
    {
      fprintf(stderr, "wrong route for [%s], expected port %u\n", query, port);
      exit(1);
    }
  checks++;
}

static void expect_local(const char *query)
{
  int first, last;
  char name[(MAXDNAME * 2) + 1];
  strcpy(name, query);
  if (!lookup_domain(name, F_IPV4, &first, &last) || first >= last ||
      !(daemon->serverarray[first]->flags & SERV_LITERAL_ADDRESS))
    {
      fprintf(stderr, "local zone forwarded: %s\n", query);
      exit(1);
    }
  checks++;
}

static void selectors(const char *path, int revision)
{
  FILE *f = fopen(path, "w");
  assert(f);
  if (revision == 0)
    {
      fputs("server=/suffix.test/127.0.0.1#2053\n", f);
      fputs("server=/regex:^exact[.]test$/127.0.0.1#2053\n", f);
      fputs("server=/regex:^proxy[0123456789]+[.]test$/127.0.0.1#2053\n", f);
      fputs("server=/regex:^proxy[0123456789]+[.]exact[.]test$/127.0.0.1#2053\n", f);
      fputs("server=/regex:^github-production-release-asset-[0-9a-zA-Z]{6}\\.s3\\.amazonaws\\.com$/127.0.0.1#2053\n", f);
      fputs("server=/regex:(^)chatgpt-async-webps-prod-([^ ])+-([0123456789])+\\.webpubsub\\.azure\\.com($)/127.0.0.1#2053\n", f);
      fputs("server=/regex:^.*[.]private[.]test$/127.0.0.1#2053\n", f);
      fputs("server=/regex:^.*[.]home[.]arpa$/127.0.0.1#2053\n", f);
      fputs("server=/regex:^.*[.]direct[.]test$/127.0.0.1#2053\n", f);
      /* First declared matching selector wins, irrespective of lexical order. */
      fputs("server=/regex:^z.*[.]order[.]test$/127.0.0.1#2053\n", f);
      fputs("server=/regex:^.*[.]order[.]test$/127.0.0.1#15556\n", f);
      /* Equivalent servers stay in the same native group. */
      fputs("server=/regex:^group[.]test$/127.0.0.1#2053\n", f);
      fputs("server=/regex:^group[.]test$/127.0.0.1#2054\n", f);
      fputs("server=/regex:^nonspace-[^ ]+[.]test$/127.0.0.1#2053\n", f);
      fputs("server=/regex:(^)symbols-([][\\\\^-])+[.]test($)/127.0.0.1#2053\n", f);
      fputs("server=/regex:^dot-a\\\\[.]b[.]test$/127.0.0.1#2053\n", f);
    }
  else
    fputs("server=/regex:^new-proxy[.]test$/127.0.0.1#2053\n", f);
  assert(fclose(f) == 0);
}

int main(int argc, char **argv)
{
  char conf[4096], managed[4096], confarg[4120];
  char *options[3];
  FILE *f;
  int i;
  assert(argc == 2);
  snprintf(conf, sizeof(conf), "%s/main.conf", argv[1]);
  snprintf(managed, sizeof(managed), "%s/managed.conf", argv[1]);
  snprintf(confarg, sizeof(confarg), "--conf-file=%s", conf);
  f = fopen(conf, "w");
  assert(f);
  fprintf(f, "no-resolv\nno-hosts\nserver=127.0.0.1#15555\nservers-file=%s\n", managed);
#ifdef GUARDIAN_TEST_GLINET
  fputs("mark=0x1000\n", f);
#endif
  fputs("server=/private.test/127.0.0.1#15556\n", f);
  fputs("server=/example.com/127.0.0.1#2053\n", f);
  fputs("server=/direct.test/#\n", f);
  fputs("local=/home.arpa/\n", f);
  fputs("address=/local-address.test/192.0.2.99\n", f);
  /* Exact stock suffix semantics remain available when no extension is needed. */
  fputs("server=/native-exact.test/127.0.0.1#2053\n", f);
  fputs("server=/*.native-exact.test/#\n", f);
  assert(fclose(f) == 0);
  selectors(managed, 0);
  options[0] = "dnsmasq-test";
  options[1] = confarg;
  options[2] = NULL;
  read_opts(2, options, "regex-server");
#ifdef GUARDIAN_TEST_GLINET
  test_outgoing_mark();
#endif
  read_servers_file();

  expect_port("plain.test", 15555);
  expect_port("olvbkozcufcbptfogatw.supabase.co", 15555);
  expect_port("suffix.test", 2053);
  expect_port("child.suffix.test", 2053);
  expect_port("notsuffix.test", 15555);
  expect_port("exact.test", 2053);
  expect_port("EXACT.TEST", 2053);
  expect_port("child.exact.test", 15555);
  expect_port("proxy12.exact.test", 2053);
  expect_port("native-exact.test", 2053);
  expect_port("child.native-exact.test", 15555);
  expect_port("proxy9.test", 2053);
  expect_port("proxyx.test", 15555);
  expect_port("github-production-release-asset-aB09Z1.s3.amazonaws.com", 2053);
  expect_port("github-production-release-asset-aB09Z.s3.amazonaws.com", 15555);
  expect_port("github-production-release-asset-aB09Z12.s3.amazonaws.com", 15555);
  expect_port("unrelated.s3.amazonaws.com", 15555);
  expect_port("chatgpt-async-webps-prod-abc-def-12.webpubsub.azure.com", 2053);
  expect_port("chatgpt-async-webps-prod-abc-def-x.webpubsub.azure.com", 15555);
  expect_port("unrelated.webpubsub.azure.com", 15555);
  expect_port("child.private.test", 15556);
  expect_port("child.direct.test", 15555);
  expect_local("child.home.arpa");
  expect_local("local-address.test");
  expect_port("z.order.test", 2053);
  expect_port("a.order.test", 15556);
  expect_port("group.test", 2053);
  {
    int low, high;
    char group[] = "group.test";
    assert(lookup_domain(group, F_IPV6, &low, &high));
    assert(high - low == 2);
    checks++;
  }
  /* Raw DNS bytes are converted to precisely the old matcher presentation. */
  expect_port("nonspace-a\tb.test", 2053);
  expect_port("nonspace-a\nb.test", 2053);
  expect_port("nonspace-a\vb.test", 2053);
  expect_port("nonspace-a b.test", 15555);
  expect_port("nonspace-\xff.test", 2053);
  expect_port("nonspace-\x01\x01.test", 2053); /* embedded NUL */
  expect_port("dot-a\x01\x2f" "b.test", 2053); /* escaped dot in one label */
  expect_port("dot-a.b.test", 15555);
  expect_port("symbols-].test", 2053);
  expect_port("symbols-[.test", 2053);
  expect_port("symbols-^.test", 2053);
  expect_port("symbols--.test", 2053);
  expect_port("symbols-\\.test", 2053);
  expect_port("symbols-x.test", 15555);

  /* Suffix selectors inspect actual wire-label boundaries. Regex selectors
     deliberately retain the escaped-presentation semantics of the old matcher. */
  expect_port("x.example.com", 2053);
  expect_port("x\x01\x2f" "example.com", 15555);
  {
    FILE *append = fopen(managed, "a");
    assert(append);
    fputs("server=/regex:(^|[.])example[.]com$/127.0.0.1#2053\n", append);
    assert(fclose(append) == 0);
    read_servers_file();
    expect_port("x\x01\x2f" "example.com", 2053);
  }

  /* Execution errors refuse the query; they must not pick default upstream. */
  fail_regexec = 1;
  assert(!lookup_domain("proxy9.test", F_IPV4, NULL, NULL));
  checks++;
  expect_port("proxy9.test", 2053);

  /* A daemon-side compilation failure preserves the previous complete policy. */
  selectors(managed, 1);
  fail_regcomp = 1;
  read_servers_file();
  expect_port("proxy9.test", 2053);
  expect_port("new-proxy.test", 15555);
  {
    unsigned before = regex_live;
    FILE *bad = fopen(managed, "w");
    assert(bad);
    fputs("server=/regex:^partially-loaded[.]test$/127.0.0.1#2053\n", bad);
    fputs("server=/regex:[bad-pattern/127.0.0.1#2053\n", bad);
    assert(fclose(bad) == 0);
    read_servers_file();
    assert(regex_live == before);
    expect_port("proxy9.test", 2053);
    expect_port("partially-loaded.test", 15555);
    checks++;
  }

  /* Growing a candidate array must also succeed before the old policy is freed. */
  {
    unsigned before = regex_live;
    int count = 200 + 10;
    struct server *serv;
    FILE *large = fopen(managed, "w");
    assert(large);
    for (serv = daemon->servers; serv; serv = serv->next)
      if (!(serv->flags & SERV_FROM_FILE))
        count++;
    for (serv = daemon->local_domains; serv; serv = serv->next)
      if (!(serv->flags & SERV_FROM_FILE))
        count++;
    for (i = 0; i < 200; i++)
      fprintf(large, "server=/regex:^large-%d[.]test$/127.0.0.1#2053\n", i);
    assert(fclose(large) == 0);
    fail_array_size = (size_t)count * sizeof(struct server *);
    read_servers_file();
    assert(fail_array_size == 0);
    assert(regex_live == before);
    expect_port("proxy9.test", 2053);
    expect_port("large-1.test", 15555);
    checks++;
  }

  /* Same parsing path as SIGHUP: removal, replacement, identical recompiles. */
  for (i = 0; i < 100; i++)
    {
      selectors(managed, 1);
      read_servers_file();
      expect_port("proxy9.test", 15555);
      expect_port("exact.test", 15555);
      expect_port("new-proxy.test", 2053);
      selectors(managed, 0);
      read_servers_file();
      expect_port("proxy9.test", 2053);
      expect_port("new-proxy.test", 15555);
      expect_port("child.direct.test", 15555);
      expect_local("child.home.arpa");
    }

  /* Only regex upstreams: no native prefix must not enter an empty search. */
  {
    struct server *serv;
    for (serv = daemon->servers; serv; serv = serv->next)
      serv->flags |= SERV_FROM_FILE;
  }
  mark_servers(-1);
  cleanup_servers();
  {
    union mysockaddr address, source;
    memset(&address, 0, sizeof(address));
    memset(&source, 0, sizeof(source));
    address.in.sin_family = AF_INET;
    address.in.sin_port = htons(2053);
    address.in.sin_addr.s_addr = htonl(0x7f000001);
    source.in.sin_family = AF_INET;
    assert(add_update_server(SERV_FROM_FILE, &address, &source, NULL,
                             "regex:^only[.]test$", NULL));
    build_server_array();
    assert(daemon->serverarray_native == 0);
    expect_port("only.test", 2053);
    assert(!lookup_domain("unmatched.test", F_IPV4, NULL, NULL));
    checks++;
  }
  mark_servers(-1);
  cleanup_servers();
  build_server_array();
  assert(!lookup_domain("empty.test", F_IPV4, NULL, NULL));
  free(daemon->serverarray);
  assert(regex_live == 0);
  printf("PASS: %u native selector/parser/reload checks; %u regex compilations, zero live handles\n",
         checks + 2, regex_compilations);
  return 0;
}
