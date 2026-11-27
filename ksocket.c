/*
 * ksocket.c - KTP library implementation
 * Provides k_socket, k_bind, k_sendto, k_recvfrom, k_close, dropMessage
 * and helpers for shared memory / sequence arithmetic.
 */

#define _GNU_SOURCE
#include "ksocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

int k_errno = 0;

/* -------------------- Shared memory helpers -------------------- */

static ktp_shared_t *g_shm = NULL;
static int g_shm_fd = -1;

ktp_shared_t *ktp_get_shared(void)
{
    return g_shm;
}

int ktp_attach_shared(void)
{
    if (g_shm)
        return 0;

    g_shm_fd = shm_open(KTP_SHM_NAME, O_RDWR, 0666);
    if (g_shm_fd < 0)
        return -1;

    g_shm = mmap(NULL, sizeof(ktp_shared_t), PROT_READ | PROT_WRITE,
                 MAP_SHARED, g_shm_fd, 0);
    if (g_shm == MAP_FAILED) {
        close(g_shm_fd);
        g_shm_fd = -1;
        g_shm = NULL;
        return -1;
    }
    return 0;
}

void ktp_detach_shared(void)
{
    if (g_shm && g_shm != MAP_FAILED) {
        munmap(g_shm, sizeof(ktp_shared_t));
        g_shm = NULL;
    }
    if (g_shm_fd >= 0) {
        close(g_shm_fd);
        g_shm_fd = -1;
    }
}

/* -------------------- Sequence number helpers (mod 256) -------------------- */

/* Distance from a to b in forward direction modulo 256 */
static int seq_dist(uint8_t a, uint8_t b)
{
    return (int)((b - a) & 0xFF);
}

/* a is "less than" b if forward distance a->b is in (0,128) */
int seq_lt(uint8_t a, uint8_t b)
{
    int d = seq_dist(a, b);
    return d > 0 && d < 128;
}

int seq_leq(uint8_t a, uint8_t b)
{
    return a == b || seq_lt(a, b);
}

int seq_in_window(uint8_t seq, uint8_t base, int size)
{
    if (size <= 0)
        return 0;
    int d = seq_dist(base, seq);
    return d < size;
}

/* -------------------- Checksum -------------------- */

uint32_t ktp_checksum(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++)
        sum += p[i];
    return sum;
}

/* -------------------- dropMessage -------------------- */

int dropMessage(float p)
{
    if (p <= 0.0f)
        return 0;
    if (p >= 1.0f)
        return 1;
    /* thread-safe-ish random; for reproducibility seed once in init */
    double r = (double)rand() / ((double)RAND_MAX + 1.0);
    return (r < (double)p) ? 1 : 0;
}

/* -------------------- Control channel helpers (FD passing) -------------------- */

static int send_fd(int ctrl_fd, int fd_to_send, int sock_id)
{
    struct msghdr msg = {0};
    struct iovec iov;
    char buf[8];
    snprintf(buf, sizeof(buf), "%d", sock_id);
    iov.iov_base = buf;
    iov.iov_len  = strlen(buf) + 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    if (sendmsg(ctrl_fd, &msg, 0) < 0)
        return -1;
    return 0;
}

static int connect_ctrl(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, KTP_CTRL_PATH, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* -------------------- k_socket -------------------- */

int k_socket(int domain, int type, int protocol)
{
    (void)protocol;
    if (type != SOCK_KTP) {
        errno = EINVAL;
        return -1;
    }
    if (domain != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (ktp_attach_shared() < 0) {
        k_errno = ENOSPACE;
        return -1;
    }

    pthread_mutex_lock(&g_shm->global_lock);

    int id = -1;
    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        if (g_shm->socks[i].allocated == KTP_FREE) {
            id = i;
            break;
        }
    }
    if (id < 0) {
        pthread_mutex_unlock(&g_shm->global_lock);
        k_errno = ENOSPACE;
        return -1;
    }

    ktp_sock_entry_t *e = &g_shm->socks[id];
    memset(e, 0, sizeof(*e));
    e->allocated = KTP_ALLOCATED;
    e->pid = getpid();
    e->udp_fd_app = -1;
    e->udp_fd_init = -1;
    e->init_fd_valid = 0;
    e->bound = 0;
    e->next_seq_to_send = 1;            /* start from 1 */
    e->swnd.size = WINDOW_SIZE;
    e->swnd.base = 1;
    e->swnd.next_seq = 1;
    e->swnd.count = 0;
    e->rwnd.size = RECV_BUF_SIZE;
    e->rwnd.base = 1;                   /* next expected */
    e->expected_seq = 1;
    e->next_deliver = 1;
    e->last_ack_sent = 0;
    e->nospace = 0;
    e->need_window_update = 0;
    e->send_head = e->send_tail = e->send_count = 0;
    e->recv_count = 0;

    /* Create UDP socket in the application process */
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) {
        e->allocated = KTP_FREE;
        pthread_mutex_unlock(&g_shm->global_lock);
        return -1;
    }
    e->udp_fd_app = udp;

    /* Initialize process-shared mutex for this entry */
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&e->lock, &attr);
    pthread_mutexattr_destroy(&attr);

    pthread_mutex_unlock(&g_shm->global_lock);

    /* Pass the UDP FD to the init process via Unix domain socket */
    int ctrl = connect_ctrl();
    if (ctrl < 0) {
        /* Init may not be running yet; still allow local use, but R/S won't see it */
        fprintf(stderr, "[k_socket] warning: cannot connect to init control socket\n");
        return id;
    }
    if (send_fd(ctrl, udp, id) < 0) {
        fprintf(stderr, "[k_socket] warning: FD pass failed: %s\n", strerror(errno));
    }
    close(ctrl);

    /* Wait briefly for init to install the FD */
    for (int i = 0; i < 50; i++) {
        if (e->init_fd_valid)
            break;
        usleep(10000);
    }

    return id;
}

/* -------------------- k_bind -------------------- */

int k_bind(int sockfd, const char *src_ip, int src_port,
           const char *dest_ip, int dest_port)
{
    if (ktp_attach_shared() < 0)
        return -1;
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS) {
        errno = EBADF;
        return -1;
    }

    ktp_sock_entry_t *e = &g_shm->socks[sockfd];
    pthread_mutex_lock(&e->lock);

    if (e->allocated == KTP_FREE || e->pid != getpid()) {
        pthread_mutex_unlock(&e->lock);
        errno = EBADF;
        return -1;
    }

    struct sockaddr_in local, remote;
    memset(&local, 0, sizeof(local));
    memset(&remote, 0, sizeof(remote));
    local.sin_family = AF_INET;
    local.sin_port = htons(src_port);
    if (inet_pton(AF_INET, src_ip, &local.sin_addr) != 1) {
        pthread_mutex_unlock(&e->lock);
        errno = EINVAL;
        return -1;
    }
    remote.sin_family = AF_INET;
    remote.sin_port = htons(dest_port);
    if (inet_pton(AF_INET, dest_ip, &remote.sin_addr) != 1) {
        pthread_mutex_unlock(&e->lock);
        errno = EINVAL;
        return -1;
    }

    if (e->udp_fd_app < 0) {
        pthread_mutex_unlock(&e->lock);
        return -1;
    }

    int yes = 1;
    setsockopt(e->udp_fd_app, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(e->udp_fd_app, (struct sockaddr *)&local, sizeof(local)) < 0) {
        pthread_mutex_unlock(&e->lock);
        return -1;
    }

    e->local_addr = local;
    e->remote_addr = remote;
    e->bound = 1;
    e->allocated = KTP_BOUND;

    pthread_mutex_unlock(&e->lock);
    return 0;
}

/* -------------------- k_sendto -------------------- */

ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags,
                 const struct sockaddr *dest_addr, socklen_t addrlen)
{
    (void)flags;
    (void)addrlen;
    if (ktp_attach_shared() < 0)
        return -1;
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS) {
        errno = EBADF;
        return -1;
    }

    ktp_sock_entry_t *e = &g_shm->socks[sockfd];
    pthread_mutex_lock(&e->lock);

    if (e->allocated < KTP_BOUND || e->pid != getpid()) {
        pthread_mutex_unlock(&e->lock);
        errno = EBADF;
        return -1;
    }

    /* Destination must match bound remote */
    if (dest_addr) {
        const struct sockaddr_in *d = (const struct sockaddr_in *)dest_addr;
        if (d->sin_addr.s_addr != e->remote_addr.sin_addr.s_addr ||
            d->sin_port != e->remote_addr.sin_port) {
            pthread_mutex_unlock(&e->lock);
            k_errno = ENOTBOUND;
            return -1;
        }
    }

    if (len > MSG_SIZE)
        len = MSG_SIZE;

    if (e->send_count >= SEND_BUF_SIZE) {
        pthread_mutex_unlock(&e->lock);
        k_errno = ENOSPACE;
        return -1;
    }

    int idx = e->send_head;
    ktp_msg_t *m = &e->send_buf[idx];
    memcpy(m->data, buf, len);
    m->len = (uint16_t)len;
    m->seq = e->next_seq_to_send;
    m->flags = 0;
    m->valid = 1;
    memset(&m->sent_time, 0, sizeof(m->sent_time));

    e->next_seq_to_send = (e->next_seq_to_send + 1) & 0xFF;
    e->send_head = (e->send_head + 1) % SEND_BUF_SIZE;
    e->send_count++;

    pthread_mutex_unlock(&e->lock);
    return (ssize_t)len;
}

/* -------------------- k_recvfrom -------------------- */

ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags,
                   struct sockaddr *src_addr, socklen_t *addrlen)
{
    (void)flags;
    if (ktp_attach_shared() < 0)
        return -1;
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS) {
        errno = EBADF;
        return -1;
    }

    ktp_sock_entry_t *e = &g_shm->socks[sockfd];
    pthread_mutex_lock(&e->lock);

    if (e->allocated < KTP_BOUND || e->pid != getpid()) {
        pthread_mutex_unlock(&e->lock);
        errno = EBADF;
        return -1;
    }

    /* Find the next in-order message for the application */
    int found = -1;
    for (int i = 0; i < RECV_BUF_SIZE; i++) {
        if (e->recv_buf[i].valid && e->recv_buf[i].seq == e->next_deliver) {
            found = i;
            break;
        }
    }

    if (found < 0) {
        pthread_mutex_unlock(&e->lock);
        k_errno = ENOMESSAGE;
        return -1;
    }

    ktp_msg_t *m = &e->recv_buf[found];
    size_t copy = m->len;
    if (copy > len)
        copy = len;
    memcpy(buf, m->data, copy);

    if (src_addr && addrlen) {
        memcpy(src_addr, &e->remote_addr, sizeof(e->remote_addr));
        *addrlen = sizeof(e->remote_addr);
    }

    /* Free the slot */
    m->valid = 0;
    e->recv_count--;
    e->next_deliver = (e->next_deliver + 1) & 0xFF;

    /* Update rwnd size = free slots */
    int free_slots = RECV_BUF_SIZE - e->recv_count;
    e->rwnd.size = free_slots;
    if (e->nospace && free_slots > 0) {
        e->need_window_update = 1;      /* ask Thread R to send window update */
        e->nospace = 0;
    }

    pthread_mutex_unlock(&e->lock);
    return (ssize_t)copy;
}

/* -------------------- k_close -------------------- */

int k_close(int sockfd)
{
    if (ktp_attach_shared() < 0)
        return -1;
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS) {
        errno = EBADF;
        return -1;
    }

    ktp_sock_entry_t *e = &g_shm->socks[sockfd];
    pthread_mutex_lock(&e->lock);

    if (e->allocated == KTP_FREE) {
        pthread_mutex_unlock(&e->lock);
        return 0;
    }

    e->allocated = KTP_CLOSING;
    if (e->udp_fd_app >= 0) {
        close(e->udp_fd_app);
        e->udp_fd_app = -1;
    }
    /* Init process will close udp_fd_init and mark free via GC or explicit */

    e->allocated = KTP_FREE;
    e->pid = 0;
    e->init_fd_valid = 0;
    e->bound = 0;

    pthread_mutex_unlock(&e->lock);
    return 0;
}
