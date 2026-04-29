#define _POSIX_C_SOURCE 200809L

#include "secure_mem.h"
#include "util.h"

#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define MAX_LIVE_SECRETS 32

struct live_secret {
    void  *p;
    size_t n;
};

static struct live_secret g_live[MAX_LIVE_SECRETS];
static pthread_mutex_t   g_mu = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int signum)
{
    // We can't take the mutex from a signal handler. sodium_memzero is
    // async-signal-safe (volatile-pointer loop), and we accept a small race
    // against concurrent register/unregister — worst case we miss wiping a
    // buffer that was just allocated mid-signal.
    for (size_t i = 0; i < MAX_LIVE_SECRETS; i++) {
        void *p = g_live[i].p;
        size_t n = g_live[i].n;
        if (p) sodium_memzero(p, n);
    }
    // Re-raise with the default handler to terminate normally.
    struct sigaction sa = { 0 };
    sa.sa_handler = SIG_DFL;
    sigaction(signum, &sa, NULL);
    raise(signum);
}

int secure_init(void)
{
    if (sodium_init() < 0) {
        log_error("libsodium initialization failed");
        return -1;
    }

    struct sigaction sa = { 0 };
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);

    return 0;
}

void *secure_alloc(size_t n)
{
    void *p = sodium_malloc(n);
    if (!p) return NULL;
    sodium_memzero(p, n);
    return p;
}

void secure_free(void *p)
{
    if (!p) return;
    secure_unregister(p);
    sodium_free(p);
}

void secure_wipe(void *p, size_t n)
{
    if (!p) return;
    sodium_memzero(p, n);
}

int secure_eq(const void *a, const void *b, size_t n)
{
    return sodium_memcmp(a, b, n) == 0;
}

int secure_readonly(void *p)  { return sodium_mprotect_readonly(p); }
int secure_readwrite(void *p) { return sodium_mprotect_readwrite(p); }

int secure_register(void *p, size_t n)
{
    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < MAX_LIVE_SECRETS; i++) {
        if (g_live[i].p == NULL) {
            g_live[i].p = p;
            g_live[i].n = n;
            pthread_mutex_unlock(&g_mu);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return -1;
}

void secure_unregister(void *p)
{
    if (!p) return;
    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < MAX_LIVE_SECRETS; i++) {
        if (g_live[i].p == p) {
            g_live[i].p = NULL;
            g_live[i].n = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
}
