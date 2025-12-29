/*
 * sys.c - system calls
 * Copyright (C) 2017-2019  Vivien Didelot
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE /* for signalfd */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/signalfd.h>
#endif

#ifdef __FreeBSD__
#include <sys/event.h>
#endif

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "sys.h"

#define sys_errno(msg, ...) trace(msg ": %s", ##__VA_ARGS__, strerror(errno))

#ifdef __linux__
static int sys_poll_create(int *poll_fd, int *signal_fd,
                           const sigset_t *sigset);
static int sys_poll_add_fd(int poll_fd, int fd);
static int sys_poll_del_fd(int poll_fd, int fd);
static int sys_poll_wait(int poll_fd, int signal_fd, struct sys_event *event,
                         int timeout_ms);
static int sys_poll_destroy(int poll_fd);
#endif

#ifdef __FreeBSD__
static int sys_kqueue_create(int *kqueue_fd, int *signal_fd,
                             const sigset_t *sigset);
static int sys_kqueue_add_fd(int kqueue_fd, int fd);
static int sys_kqueue_del_fd(int kqueue_fd, int fd);
static int sys_kqueue_wait(int kqueue_fd, int signal_fd,
                           struct sys_event *event, int timeout_ms);
static int sys_kqueue_destroy(int kqueue_fd);
#endif

int sys_chdir(const char *path) {
  int rc;

  rc = chdir(path);
  if (rc == -1) {
    sys_errno("chdir(%s)", path);
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_gettime(unsigned long *interval) {
  struct timespec ts;
  int rc;

  rc = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rc == -1) {
    sys_errno("clock_gettime(CLOCK_MONOTONIC)");
    rc = -errno;
    return rc;
  }

  *interval = ts.tv_sec;

  return 0;
}

int sys_setitimer(unsigned long interval) {
  struct itimerval itv = {
      .it_value.tv_sec = interval,
      .it_interval.tv_sec = interval,
  };
  int rc;

  rc = setitimer(ITIMER_REAL, &itv, NULL);
  if (rc == -1) {
    sys_errno("setitimer(ITIMER_REAL, %ld)", interval);
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_waitid(pid_t *pid) {
  siginfo_t infop;
  int rc;

  /* Non-blocking check for dead child(ren) */
  rc = waitid(P_ALL, 0, &infop, WEXITED | WNOHANG | WNOWAIT);
  if (rc == -1) {
    sys_errno("waitid()");
    rc = -errno;
    return rc;
  }

  if (infop.si_pid == 0)
    return -ECHILD;

  *pid = infop.si_pid;

  return 0;
}

int sys_waitpid(pid_t pid, int *code) {
  int status;
  pid_t w;
  int rc;

  w = waitpid(pid, &status, 0);
  if (w == -1) {
    sys_errno("waitpid(%d)", pid);
    rc = -errno;
    return rc;
  }

  if (w == 0)
    return -ECHILD;

  if (code)
    *code = WEXITSTATUS(status);

  return 0;
}

int sys_waitanychild(void) {
  int err;

  for (;;) {
    err = sys_waitpid(-1, NULL);
    if (err) {
      if (err == -ECHILD)
        break;
      return err;
    }
  }

  return 0;
}

int sys_setenv(const char *name, const char *value) {
  int rc;

  rc = setenv(name, value, 1);
  if (rc == -1) {
    sys_errno("setenv(%s=%s)", name, value);
    rc = -errno;
    return rc;
  }

  return 0;
}

const char *sys_getenv(const char *name) { return getenv(name); }

int sys_sigemptyset(sigset_t *set) {
  int rc;

  rc = sigemptyset(set);
  if (rc == -1) {
    sys_errno("sigemptyset()");
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_sigfillset(sigset_t *set) {
  int rc;

  rc = sigfillset(set);
  if (rc == -1) {
    sys_errno("sigfillset()");
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_sigaddset(sigset_t *set, int sig) {
  int rc;

  rc = sigaddset(set, sig);
  if (rc == -1) {
    sys_errno("sigaddset(%d (%s))", sig, strsignal(sig));
    rc = -errno;
    return rc;
  }

  return 0;
}

static int sys_sigprocmask(const sigset_t *set, int how) {
  int rc;

  rc = sigprocmask(how, set, NULL);
  if (rc == -1) {
    sys_errno("sigprocmask()");
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_sigunblock(const sigset_t *set) {
  return sys_sigprocmask(set, SIG_UNBLOCK);
}

int sys_sigsetmask(const sigset_t *set) {
  return sys_sigprocmask(set, SIG_SETMASK);
}

int sys_open(const char *path, int *fd) {
  int rc;

  rc = open(path, O_RDONLY | O_NONBLOCK);
  if (rc == -1) {
    sys_errno("open(%s)", path);
    rc = -errno;
    return rc;
  }

  *fd = rc;

  return 0;
}

int sys_close(int fd) {
  int rc;

  rc = close(fd);
  if (rc == -1) {
    sys_errno("close(%d)", fd);
    rc = -errno;
    return rc;
  }

  return 0;
}

/* Read up to size bytes and store the positive count on success */
int sys_read(int fd, void *buf, size_t size, size_t *count) {
  ssize_t rc;

  rc = read(fd, buf, size);
  if (rc == -1) {
    sys_errno("read(%d, %ld)", fd, size);
    rc = -errno;
    if (rc == -EWOULDBLOCK)
      rc = -EAGAIN;
    return rc;
  }

  /* End of file or pipe */
  if (rc == 0)
    return -EAGAIN;

  if (count)
    *count = rc;

  return 0;
}

int sys_dup(int fd1, int fd2) {
  int rc;

  /* Defensive check */
  if (fd1 == fd2)
    return 0;

  /* Close fd2, and reopen bound to fd1 */
  rc = dup2(fd1, fd2);
  if (rc == -1) {
    sys_errno("dup2(%d, %d)", fd1, fd2);
    rc = -errno;
    return rc;
  }

  return 0;
}

static int sys_getfd(int fd, int *flags) {
  int rc;

  rc = fcntl(fd, F_GETFD);
  if (rc == -1) {
    sys_errno("fcntl(%d, F_GETFD)", fd);
    rc = -errno;
    return rc;
  }

  *flags = rc;

  return 0;
}

static int sys_setfd(int fd, int flags) {
  int rc;

  rc = fcntl(fd, F_SETFD, flags);
  if (rc == -1) {
    sys_errno("fcntl(%d, F_SETFD, %d)", fd, flags);
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_cloexec(int fd) {
  int flags;
  int err;

  err = sys_getfd(fd, &flags);
  if (err)
    return err;

  return sys_setfd(fd, flags | FD_CLOEXEC);
}

#ifdef __FreeBSD__
/* Portable polling API using epoll + signalfd on Linux */
int sys_kqueue_create(int *kqueue_fd, int *signal_fd, const sigset_t *sigset) {
  (void)signal_fd; // we don't use it, added as arg for linux API compatibility
  struct kevent ev;
  int kq;
  int rc;

  kq = kqueue1(O_CLOEXEC);
  if (kq == -1) {
    sys_errno("kq::create kqueue(O_CLOEXEC)");
    rc = -errno;
    return rc;
  }

  // block signals so they are only delivered via kqueue
  sigset_t oldmask;
  rc = sigprocmask(SIG_BLOCK, sigset, &oldmask);

  if (rc == -1) {
    sys_errno("kq::create sigprocmask failed");
    rc = -errno;
    return rc;
  }

  for (int signo = 1; signo < NSIG; ++signo) {
    if (!sigismember(sigset, signo))
      continue;

    // EVFILT_SIGNAL (probably something else too)
    EV_SET(&ev, signo, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, NULL);
    rc = kevent(kq, &ev, 1, NULL, 0, NULL);
    if (rc == -1) {
      sys_errno("kq::create kevent failed");
      rc = -errno;
      close(kq);
      return rc;
    }
  }

  *kqueue_fd = kq;
  return 0;
}

int sys_kqueue_add_fd(int kqueue_fd, int fd) {
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
  if (kevent(kqueue_fd, &ev, 1, NULL, 0, NULL) == -1) {
    sys_errno("add_fd::kevent failed");
    return -errno;
  }
  return 0;
}

int sys_kqueue_del_fd(int kqueue_fd, int fd) {
  int rc;
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  rc = kevent(kqueue_fd, &ev, 1, NULL, 0, NULL);
  if (rc == -1) {
    if (errno == ENOENT) {
      return 0;
    }
    sys_errno("kqueue::del_fd failed for fd=%d\n", fd);
    rc = -errno;
    return rc;
  }
  return 0;
}

int sys_kqueue_wait(int kqueue_fd, int signal_fd, struct sys_event *event,
                    int timeout_ms) {
  (void)signal_fd; // don't have it in FreeBSD
  struct kevent ev;
  struct timespec ts;
  struct timespec *pts = NULL;
  int rc;

  if (timeout_ms >= 0) {
    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = 0; // I don't care because
    pts = &ts;
  }

  rc = kevent(kqueue_fd, NULL, 0, &ev, 1, pts);
  if (rc == -1) {
    sys_errno("kqueue_wait::kevent failed");
    return -errno;
  }

  if (rc == 0) {
    // timeout
    return -EAGAIN;
  }

  if (ev.filter == EVFILT_SIGNAL) {
    event->type = SYS_EVENT_SIGNAL;
    event->sig = (int)ev.ident; // signal num
    event->fd = -1;
    return 0;
  }

  if (ev.filter == EVFILT_READ) {
    event->type = SYS_EVENT_FD;
    event->sig = 0;
    event->fd = (int)ev.ident; // read fd
    return 0;
  }

  return -EINVAL;
}

int sys_kqueue_destroy(int kqueue_fd) { return sys_close(kqueue_fd); }
#endif

#ifdef __linux__
int sys_poll_create(int *poll_fd, int *signal_fd, const sigset_t *sigset) {
  struct epoll_event ev;
  int epoll_fd, sig_fd;
  int rc;

  /* Create epoll instance */
  epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd == -1) {
    sys_errno("epoll_create1(EPOLL_CLOEXEC)");
    rc = -errno;
    return rc;
  }

  /* Create signalfd from the signal mask */
  sig_fd = signalfd(-1, sigset, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sig_fd == -1) {
    sys_errno("signalfd()");
    close(epoll_fd);
    rc = -errno;
    return rc;
  }

  /* Add signalfd to epoll */
  ev.events = EPOLLIN;
  ev.data.fd = sig_fd;
  rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sig_fd, &ev);
  if (rc == -1) {
    sys_errno("epoll_ctl(EPOLL_CTL_ADD, signalfd=%d)", sig_fd);
    close(sig_fd);
    close(epoll_fd);
    rc = -errno;
    return rc;
  }

  *poll_fd = epoll_fd;
  *signal_fd = sig_fd;

  return 0;
}

int sys_poll_add_fd(int poll_fd, int fd) {
  struct epoll_event ev;
  int rc;

  ev.events = EPOLLIN;
  ev.data.fd = fd;

  rc = epoll_ctl(poll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    sys_errno("epoll_ctl(EPOLL_CTL_ADD, fd=%d)", fd);
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_poll_del_fd(int poll_fd, int fd) {
  int rc;

  rc = epoll_ctl(poll_fd, EPOLL_CTL_DEL, fd, NULL);
  if (rc == -1) {
    sys_errno("epoll_ctl(EPOLL_CTL_DEL, fd=%d)", fd);
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_poll_wait(int poll_fd, int signal_fd, struct sys_event *event,
                  int timeout_ms) {
  struct epoll_event ev;
  struct signalfd_siginfo si;
  ssize_t n;
  int rc;

  rc = epoll_wait(poll_fd, &ev, 1, timeout_ms);
  if (rc == -1) {
    sys_errno("epoll_wait()");
    rc = -errno;
    return rc;
  }

  if (rc == 0) {
    /* Timeout */
    return -EAGAIN;
  }

  /* Check if this is a signal or a regular fd */
  if (ev.data.fd == signal_fd) {
    /* Read signal info from signalfd */
    n = read(signal_fd, &si, sizeof(si));
    if (n != sizeof(si)) {
      sys_errno("read(signalfd)");
      return -errno;
    }

    event->type = SYS_EVENT_SIGNAL;
    event->sig = si.ssi_signo;
    event->fd = si.ssi_fd; /* May be useful for some signals */
  } else {
    /* Regular fd is readable */
    event->type = SYS_EVENT_FD;
    event->fd = ev.data.fd;
    event->sig = 0;
  }

  return 0;
}

int sys_poll_destroy(int poll_fd) { return sys_close(poll_fd); }
#endif

int sys_pipe(int *fds) {
  int rc;

  rc = pipe(fds);
  if (rc == -1) {
    sys_errno("pipe()");
    rc = -errno;
    return rc;
  }

  return 0;
}

int sys_fork(pid_t *pid) {
  int rc;

  rc = fork();
  if (rc == -1) {
    sys_errno("fork()");
    rc = -errno;
    return rc;
  }

  *pid = rc;

  return 0;
}

void sys_exit(int status) { _exit(status); }

int sys_execsh(const char *command) {
  int rc;

  static const char *const shell = "/bin/sh";

  rc = execl(shell, shell, "-c", command, (char *)NULL);
  if (rc == -1) {
    sys_errno("execl(%s -c \"%s\")", shell, command);
    rc = -errno;
    return rc;
  }

  /* Unreachable */
  return 0;
}

int sys_isatty(int fd) {
  int rc;

  rc = isatty(fd);
  if (rc == 0) {
    sys_errno("isatty(%d)", fd);
    rc = -errno;
    if (rc == -EINVAL)
      rc = -ENOTTY;
    return rc;
  }

  return 0;
}

struct sys_event_queue_vptr sys_event_queue_vptr(void) {
  static struct sys_event_queue_vptr res;
#ifdef __linux__
  res.create = sys_poll_create;
  res.add_fd = sys_poll_add_fd;
  res.del_fd = sys_poll_del_fd;
  res.wait = sys_poll_wait;
  res.destroy = sys_poll_destroy;
#endif

#ifdef __FreeBSD__
  res.create = sys_kqueue_create;
  res.add_fd = sys_kqueue_add_fd;
  res.del_fd = sys_kqueue_del_fd;
  res.wait = sys_kqueue_wait;
  res.destroy = sys_kqueue_destroy;
#endif
  return res;
}
