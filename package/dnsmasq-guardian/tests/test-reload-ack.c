/* Exercise the actual UBus callback without opening a network listener.
 * Parsing/commit and cache hooks are isolated; process and pipe retirement use libc. */
#include "dnsmasq.h"
#include <libubus.h>
#include <assert.h>

struct daemon *daemon;
static int accept_file, reads, cache_flushes, retired;
int read_servers_file(void) { reads++; return accept_file; }
void cache_reload(void) { cache_flushes++; }
void server_gone(struct server *server) {
  struct frec *f;
  retired++;
  for (f = daemon->frec_list; f; f = f->next)
    if (f->sentto == server) f->sentto = NULL;
}
int ubus_handle_reload_servers(struct ubus_context *, struct ubus_object *,
                              struct ubus_request_data *, const char *, struct blob_attr *);
int main(void) {
  int fd[2], rc;
  pid_t child;
  struct server server = {0};
  struct frec first = {0}, second = {0};
  daemon = calloc(1, sizeof(*daemon));
  assert(daemon);
  rc = ubus_handle_reload_servers(NULL, NULL, NULL, NULL, NULL);
  assert(rc == UBUS_STATUS_NOT_SUPPORTED && reads == 0);
  daemon->port = 53;
  daemon->servers_file = "managed.servers";
  daemon->max_procs = 1;
  daemon->tcp_pids = calloc(1, sizeof(pid_t));
  daemon->tcp_pipes = calloc(1, sizeof(int));
  daemon->metrics[METRIC_TCP_CONNECTIONS] = 1;
  assert(pipe(fd) == 0);
  child = fork();
  assert(child >= 0);
  if (child == 0) { alarm(10); for (;;) pause(); }
  close(fd[1]);
  daemon->tcp_pids[0] = child;
  daemon->tcp_pipes[0] = fd[0];
  first.sentto = second.sentto = &server;
  first.next = &second;
  daemon->frec_list = &first;
  rc = ubus_handle_reload_servers(NULL, NULL, NULL, NULL, NULL);
  assert(rc != UBUS_STATUS_OK && reads == 1 && cache_flushes == 0 && retired == 0);
  assert(daemon->tcp_pids[0] == child && kill(child, 0) == 0);
  accept_file = 1;
  rc = ubus_handle_reload_servers(NULL, NULL, NULL, NULL, NULL);
  assert(rc == UBUS_STATUS_OK && reads == 2 && cache_flushes == 1 && retired == 1);
  assert(daemon->tcp_pids[0] == 0 && daemon->tcp_pipes[0] == -1);
  assert(daemon->metrics[METRIC_TCP_CONNECTIONS] == 0);
  assert(first.sentto == NULL && second.sentto == NULL);
  assert(waitpid(child, NULL, WNOHANG) == -1 && errno == ECHILD);
  assert(fcntl(fd[0], F_GETFD) == -1 && errno == EBADF);
  puts("PASS: actual UBus callback rejects failed reload; successful ack waits for TCP worker exit, discards old cache pipe, cancels in-flight UDP, flushes cache");
  free(daemon->tcp_pids);
  free(daemon->tcp_pipes);
  free(daemon);
  return 0;
}
