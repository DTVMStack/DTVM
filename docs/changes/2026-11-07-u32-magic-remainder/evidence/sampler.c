#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <ucontext.h>
#include <unistd.h>
static volatile sig_atomic_t output_fd = -1;
static void sample(int sig, siginfo_t *info, void *ctx) {
  (void)sig; (void)info;
  uint64_t record[2] = {(uint64_t)((ucontext_t *)ctx)->uc_mcontext.gregs[REG_RIP],
                        (uint64_t)syscall(SYS_gettid)};
  int fd = output_fd;
  if (fd >= 0) (void)write(fd, record, sizeof(record));
}
__attribute__((constructor)) static void start(void) {
  const char *path = getenv("DTVM_RESEARCH_SAMPLES");
  if (!path) return;
  output_fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_APPEND, 0600);
  if (output_fd < 0) return;
  char maps[4096]; snprintf(maps, sizeof(maps), "%s.maps", path);
  int in = open("/proc/self/maps", O_RDONLY), out = open(maps,O_CREAT|O_TRUNC|O_WRONLY,0600);
  if (in >= 0 && out >= 0) {
    char buf[4096]; ssize_t n;
    while ((n=read(in,buf,sizeof(buf)))>0) (void)write(out,buf,(size_t)n);
  }
  if (in>=0) close(in); if (out>=0) close(out);
  struct sigaction action = {0}; action.sa_sigaction=sample;
  action.sa_flags=SA_RESTART|SA_SIGINFO; sigemptyset(&action.sa_mask);
  if(sigaction(SIGPROF,&action,0)!=0) return;
  struct itimerval timer = {{0,1000},{0,1000}};
  (void)setitimer(ITIMER_PROF,&timer,0);
}
__attribute__((destructor)) static void stop(void) {
  struct itimerval timer = {{0,0},{0,0}}; (void)setitimer(ITIMER_PROF,&timer,0);
  int fd=output_fd;output_fd=-1;if(fd>=0)close(fd);
}
