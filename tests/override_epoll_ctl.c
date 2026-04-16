#define _GNU_SOURCE
#include "config.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>

static int (*orig_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event) = NULL;
static int add_calls = 0;
static int fail_add_at = 0;

static void resolve_epoll_ctl(void) {
    if (orig_epoll_ctl == NULL) {
        orig_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
    }
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    resolve_epoll_ctl();

    if (op == EPOLL_CTL_ADD) {
        ++add_calls;
        if (fail_add_at > 0 && add_calls == fail_add_at) {
            errno = ENOMEM;
            return -1;
        }
    }

    return orig_epoll_ctl(epfd, op, fd, event);
}

static void __attribute__((constructor)) init_override_epoll_ctl(void) {
    const char *const val = getenv("RSYSLOG_TEST_EPOLL_FAIL_ADD_AT");

    if (val != NULL) {
        fail_add_at = atoi(val);
    }
}
