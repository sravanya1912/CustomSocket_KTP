/*
 * initksocket.c - KTP background service
 * Creates shared memory, starts Thread R (receiver), Thread S (sender/timeout),
 * garbage collector, and Unix-domain control socket for FD passing.
 */

#define _GNU_SOURCE
#include "ksocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static volatile sig_atomic_t g_running = 1;
static ktp_shared_t *g_shm = NULL;
static int g_shm_fd = -1;
static int g_ctrl_listen = -1;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* -------------------- Shared memory creation -------------------- */

static int create_shared(void)
{
    shm_unlink(KTP_SHM_NAME);
    g_shm_fd = shm_open(KTP_SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (g_shm_fd < 0) {
        perror("shm_open");
        return -1;
    }
    if (ftruncate(g_shm_fd, sizeof(ktp_shared_t)) < 0) {
        perror("ftruncate");
        return -1;
    }
    g_shm = mmap(NULL, sizeof(ktp_shared_t), PROT_READ | PROT_WRITE,
                 MAP_SHARED, g_shm_fd, 0);
    if (g_shm == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
    memset(g_shm, 0, sizeof(ktp_shared_t));

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&g_shm->global_lock, &attr);
    pthread_mutexattr_destroy(&attr);

    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        g_shm->socks[i].allocated = KTP_FREE;
        g_shm->socks[i].udp_fd_app = -1;
        g_shm->socks[i].udp_fd_init = -1;
        g_shm->socks[i].init_fd_valid = 0;
    }
    g_shm->initialized = 1;
    g_shm->init_pid = getpid();
    return 0;
}

/* -------------------- Control socket: receive FD -------------------- */

static int recv_fd(int conn, int *out_fd, int *out_id)
{
    struct msghdr msg = {0};
    struct iovec iov;
    char buf[32];
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    ssize_t n = recvmsg(conn, &msg, 0);
    if (n <= 0)
        return -1;

    *out_id = atoi(buf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
        return -1;
    memcpy(out_fd, CMSG_DATA(cmsg), sizeof(int));
    return 0;
}

static void *ctrl_thread(void *arg)
{
    (void)arg;
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_ctrl_listen, &rfds);
        struct timeval tv = {1, 0};
        int rv = select(g_ctrl_listen + 1, &rfds, NULL, NULL, &tv);
        if (rv <= 0)
            continue;
        int conn = accept(g_ctrl_listen, NULL, NULL);
        if (conn < 0)
            continue;
        int fd = -1, id = -1;
        if (recv_fd(conn, &fd, &id) == 0) {
            if (id >= 0 && id < MAX_KTP_SOCKETS && fd >= 0) {
                ktp_sock_entry_t *e = &g_shm->socks[id];
                pthread_mutex_lock(&e->lock);
                if (e->udp_fd_init >= 0)
                    close(e->udp_fd_init);
                e->udp_fd_init = fd;
                e->init_fd_valid = 1;
                pthread_mutex_unlock(&e->lock);
                fprintf(stderr, "[init] received FD %d for socket %d\n", fd, id);
            } else {
                if (fd >= 0) close(fd);
            }
        }
        close(conn);
    }
    return NULL;
}

/* -------------------- Packet helpers -------------------- */

static void build_header(ktp_header_t *h, uint8_t type, uint8_t seq,
                         uint8_t ack, uint8_t rwnd, uint16_t len, uint16_t flags)
{
    memset(h, 0, sizeof(*h));
    h->type = type;
    h->seq  = seq;
    h->ack  = ack;
    h->rwnd = rwnd;
    h->len  = htons(len);
    h->flags = htons(flags);
    h->checksum = 0;
}

static uint32_t compute_pkt_checksum(const ktp_header_t *h, const void *payload, size_t plen)
{
    ktp_header_t tmp = *h;
    tmp.checksum = 0;
    uint32_t s = ktp_checksum(&tmp, sizeof(tmp));
    if (payload && plen)
        s += ktp_checksum(payload, plen);
    return s;
}

static int send_ack(ktp_sock_entry_t *e, uint8_t ack_num, uint8_t rwnd)
{
    if (!e->init_fd_valid || e->udp_fd_init < 0)
        return -1;
    ktp_header_t h;
    build_header(&h, PKT_ACK, 0, ack_num, rwnd, 0, 0);
    h.checksum = htonl(compute_pkt_checksum(&h, NULL, 0));
    ssize_t n = sendto(e->udp_fd_init, &h, sizeof(h), 0,
                       (struct sockaddr *)&e->remote_addr, sizeof(e->remote_addr));
    return (n == (ssize_t)sizeof(h)) ? 0 : -1;
}

static int send_data(ktp_sock_entry_t *e, ktp_msg_t *m)
{
    if (!e->init_fd_valid || e->udp_fd_init < 0)
        return -1;
    char buf[UDP_PAYLOAD_MAX];
    ktp_header_t *h = (ktp_header_t *)buf;
    build_header(h, PKT_DATA, m->seq, e->last_ack_sent, (uint8_t)e->rwnd.size,
                 m->len, m->flags);
    memcpy(buf + HEADER_SIZE, m->data, m->len);
    h->checksum = htonl(compute_pkt_checksum(h, buf + HEADER_SIZE, m->len));
    size_t total = HEADER_SIZE + m->len;
    ssize_t n = sendto(e->udp_fd_init, buf, total, 0,
                       (struct sockaddr *)&e->remote_addr, sizeof(e->remote_addr));
    if (n == (ssize_t)total) {
        clock_gettime(CLOCK_MONOTONIC, &m->sent_time);
        e->total_tx++;
        return 0;
    }
    return -1;
}

/* -------------------- Thread R -------------------- */

static void process_data_pkt(ktp_sock_entry_t *e, const ktp_header_t *h,
                             const char *payload, uint16_t plen)
{
    uint8_t seq = h->seq;

    /* Duplicate of already delivered (seq < expected) -> re-ACK */
    if (seq_lt(seq, e->expected_seq) || seq == e->expected_seq) {
        /* if equal to expected we will accept; if less, pure duplicate */
    }

    if (seq_lt(seq, e->expected_seq)) {
        /* already delivered -> send cumulative ACK again (lost-ACK recovery) */
        send_ack(e, (uint8_t)((e->expected_seq - 1) & 0xFF), (uint8_t)e->rwnd.size);
        return;
    }

    /* Outside receive window? drop */
    if (!seq_in_window(seq, e->expected_seq, e->rwnd.size)) {
        return;
    }

    /* Already buffered? drop duplicate */
    for (int i = 0; i < RECV_BUF_SIZE; i++) {
        if (e->recv_buf[i].valid && e->recv_buf[i].seq == seq)
            return;
    }

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < RECV_BUF_SIZE; i++) {
        if (!e->recv_buf[i].valid) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        e->nospace = 1;
        e->rwnd.size = 0;
        send_ack(e, (uint8_t)((e->expected_seq - 1) & 0xFF), 0);
        return;
    }

    ktp_msg_t *m = &e->recv_buf[slot];
    memcpy(m->data, payload, plen);
    m->len = plen;
    m->seq = seq;
    m->flags = ntohs(h->flags);
    m->valid = 1;
    e->recv_count++;
    e->rwnd.size = RECV_BUF_SIZE - e->recv_count;
    if (e->rwnd.size == 0)
        e->nospace = 1;

    /* Only ACK if this is the next expected (in-order). Assignment:
       "If the receiver receives an out of order message, it keeps the
        message ... but does not send any ACK message."
       For in-order we ACK the last contiguous. */
    if (seq == e->expected_seq) {
        /* Advance expected over any contiguous buffered messages */
        while (1) {
            int found = 0;
            for (int i = 0; i < RECV_BUF_SIZE; i++) {
                if (e->recv_buf[i].valid && e->recv_buf[i].seq == e->expected_seq) {
                    found = 1;
                    break;
                }
            }
            if (!found)
                break;
            e->expected_seq = (e->expected_seq + 1) & 0xFF;
        }
        /* Note: expected_seq is advanced, but messages stay until k_recvfrom.
           Actually for in-order delivery the application pulls them.
           We ACK the highest contiguous received. */
        uint8_t last_inorder = (e->expected_seq - 1) & 0xFF;
        e->last_ack_sent = last_inorder;
        send_ack(e, last_inorder, (uint8_t)e->rwnd.size);
    }
    /* else: out-of-order, buffered, no ACK (per assignment) */
}

static void process_ack_pkt(ktp_sock_entry_t *e, const ktp_header_t *h)
{
    uint8_t ack = h->ack;
    uint8_t new_rwnd = h->rwnd;

    /* Always update advertised receiver window */
    e->swnd.size = new_rwnd;

    /* Only accept ACK that is within or just at the edge of outstanding window */
    /* Ignore stale ACKs (ack < base-1 in modular sense with large distance) */
    if (e->swnd.count > 0) {
        /* free messages with seq <= ack that have been transmitted */
        int freed = 0;
        for (int i = 0; i < SEND_BUF_SIZE; i++) {
            ktp_msg_t *m = &e->send_buf[i];
            if (!m->valid) continue;
            if (!(m->sent_time.tv_sec || m->sent_time.tv_nsec)) continue;
            if (seq_leq(m->seq, ack)) {
                m->valid = 0;
                freed++;
            }
        }
        if (freed > 0) {
            e->send_count -= freed;
            if (e->send_count < 0) e->send_count = 0;
            e->swnd.base = (ack + 1) & 0xFF;
        }
    } else {
        /* no outstanding: still allow base advance if ack matches previous */
        if (seq_leq(e->swnd.base, (ack + 1) & 0xFF) || ack == ((e->swnd.base - 1) & 0xFF))
            e->swnd.base = (ack + 1) & 0xFF;
    }
    /* recalculate outstanding count */
    e->swnd.count = 0;
    for (int i = 0; i < SEND_BUF_SIZE; i++) {
        if (e->send_buf[i].valid &&
            (e->send_buf[i].sent_time.tv_sec || e->send_buf[i].sent_time.tv_nsec))
            e->swnd.count++;
    }
}

static void handle_packet(int sock_id, const char *buf, ssize_t n,
                          struct sockaddr_in *from)
{
    if (n < (ssize_t)HEADER_SIZE)
        return;
    const ktp_header_t *h = (const ktp_header_t *)buf;
    uint16_t plen = ntohs(h->len);
    if (n < (ssize_t)(HEADER_SIZE + plen))
        return;

    /* Optional checksum check */
    uint32_t recv_ck = ntohl(h->checksum);
    ktp_header_t tmp = *h;
    tmp.checksum = 0;
    uint32_t calc = compute_pkt_checksum(&tmp, buf + HEADER_SIZE, plen);
    if (calc != recv_ck) {
        /* ignore corrupted */
        return;
    }

    ktp_sock_entry_t *e = &g_shm->socks[sock_id];
    pthread_mutex_lock(&e->lock);
    if (e->allocated < KTP_BOUND) {
        pthread_mutex_unlock(&e->lock);
        return;
    }

    /* Verify peer (optional strictness) */
    (void)from;

    if (h->type == PKT_DATA) {
        process_data_pkt(e, h, buf + HEADER_SIZE, plen);
    } else if (h->type == PKT_ACK) {
        process_ack_pkt(e, h);
    }

    /* Window-update probe from nospace recovery */
    if (e->need_window_update) {
        send_ack(e, e->last_ack_sent, (uint8_t)e->rwnd.size);
        e->need_window_update = 0;
    }

    pthread_mutex_unlock(&e->lock);
}

static void *thread_R(void *arg)
{
    (void)arg;
    fprintf(stderr, "[R] receiver thread started\n");
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;

        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            ktp_sock_entry_t *e = &g_shm->socks[i];
            if (e->init_fd_valid && e->udp_fd_init >= 0 && e->allocated >= KTP_BOUND) {
                FD_SET(e->udp_fd_init, &rfds);
                if (e->udp_fd_init > maxfd)
                    maxfd = e->udp_fd_init;
            }
        }

        struct timeval tv = {0, 200000}; /* 200 ms */
        int rv = 0;
        if (maxfd >= 0)
            rv = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        else
            usleep(200000);

        if (rv > 0) {
            for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
                ktp_sock_entry_t *e = &g_shm->socks[i];
                if (!e->init_fd_valid || e->udp_fd_init < 0)
                    continue;
                if (!FD_ISSET(e->udp_fd_init, &rfds))
                    continue;

                char buf[UDP_PAYLOAD_MAX];
                struct sockaddr_in from;
                socklen_t flen = sizeof(from);
                ssize_t n = recvfrom(e->udp_fd_init, buf, sizeof(buf), 0,
                                     (struct sockaddr *)&from, &flen);
                if (n <= 0)
                    continue;

                /* Simulate loss */
                if (dropMessage(P_DROP))
                    continue;

                handle_packet(i, buf, n, &from);
            }
        }

        /* On timeout also check nospace recovery for all sockets */
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            ktp_sock_entry_t *e = &g_shm->socks[i];
            if (e->allocated < KTP_BOUND || !e->init_fd_valid)
                continue;
            pthread_mutex_lock(&e->lock);
            if (e->need_window_update || (e->nospace && e->rwnd.size > 0)) {
                e->nospace = 0;
                e->need_window_update = 0;
                send_ack(e, e->last_ack_sent, (uint8_t)e->rwnd.size);
            }
            pthread_mutex_unlock(&e->lock);
        }
    }
    fprintf(stderr, "[R] exiting\n");
    return NULL;
}

/* -------------------- Thread S -------------------- */

static void *thread_S(void *arg)
{
    (void)arg;
    fprintf(stderr, "[S] sender/timeout thread started (T=%d)\n", T);
    while (g_running) {
        /* Wake frequently so new data is sent promptly; timeout still uses T */
        struct timespec sleep_ts = {0, 100000000L}; /* 100 ms */
        nanosleep(&sleep_ts, NULL);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            ktp_sock_entry_t *e = &g_shm->socks[i];
            if (e->allocated < KTP_BOUND || !e->init_fd_valid)
                continue;

            pthread_mutex_lock(&e->lock);

            /* 1. Retransmit timed-out outstanding messages */
            int retransmit = 0;
            for (int j = 0; j < SEND_BUF_SIZE; j++) {
                ktp_msg_t *m = &e->send_buf[j];
                if (!m->valid)
                    continue;
                if (m->sent_time.tv_sec == 0 && m->sent_time.tv_nsec == 0)
                    continue; /* not yet sent */
                double elapsed = (now.tv_sec - m->sent_time.tv_sec) +
                                 (now.tv_nsec - m->sent_time.tv_nsec) / 1e9;
                if (elapsed >= (double)T) {
                    retransmit = 1;
                    break;
                }
            }
            if (retransmit) {
                for (int j = 0; j < SEND_BUF_SIZE; j++) {
                    ktp_msg_t *m = &e->send_buf[j];
                    if (!m->valid)
                        continue;
                    if (m->sent_time.tv_sec == 0 && m->sent_time.tv_nsec == 0)
                        continue;
                    if (send_data(e, m) == 0)
                        e->total_retrans++;
                }
            }

            /* 2. Send new pending messages respecting advertised rwnd */
            int outstanding = 0;
            for (int j = 0; j < SEND_BUF_SIZE; j++) {
                ktp_msg_t *m = &e->send_buf[j];
                if (m->valid && (m->sent_time.tv_sec || m->sent_time.tv_nsec))
                    outstanding++;
            }
            e->swnd.count = outstanding;
            int can_send = e->swnd.size - outstanding;
            if (can_send < 0) can_send = 0;
            /* Send unsent messages in sequence order */
            while (can_send > 0) {
                int best = -1;
                uint8_t best_seq = 0;
                for (int j = 0; j < SEND_BUF_SIZE; j++) {
                    ktp_msg_t *m = &e->send_buf[j];
                    if (!m->valid) continue;
                    if (m->sent_time.tv_sec || m->sent_time.tv_nsec) continue;
                    if (best < 0 || seq_lt(m->seq, best_seq)) {
                        best = j;
                        best_seq = m->seq;
                    }
                }
                if (best < 0) break;
                if (send_data(e, &e->send_buf[best]) == 0) {
                    e->swnd.count++;
                    can_send--;
                } else break;
            }

            /* 3. Persist timer: if rwnd==0, probe with a pure ACK request
               by retransmitting the oldest outstanding (or a zero-window probe).
               Simple approach: if window is zero and we have outstanding,
               the normal timeout will keep probing. If no outstanding and
               rwnd==0 we still need a probe; send a duplicate of last data
               or a pure window probe. For simplicity we rely on timeout
               retransmits of outstanding data; when buffer empties while
               rwnd=0 the receiver's periodic window-update (need_window_update)
               handles reopening. */

            pthread_mutex_unlock(&e->lock);
        }
    }
    fprintf(stderr, "[S] exiting\n");
    return NULL;
}

/* -------------------- Garbage collector -------------------- */

static int process_alive(pid_t pid)
{
    if (pid <= 0)
        return 0;
    if (kill(pid, 0) == 0)
        return 1;
    return (errno == EPERM); /* exists but not owned by us */
}

static void *gc_thread(void *arg)
{
    (void)arg;
    fprintf(stderr, "[GC] garbage collector started\n");
    while (g_running) {
        sleep(2);
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            ktp_sock_entry_t *e = &g_shm->socks[i];
            pthread_mutex_lock(&e->lock);
            if (e->allocated != KTP_FREE && e->pid > 0 &&
                !process_alive(e->pid)) {
                fprintf(stderr, "[GC] reclaiming socket %d (dead pid %d)\n",
                        i, (int)e->pid);
                if (e->udp_fd_init >= 0) {
                    close(e->udp_fd_init);
                    e->udp_fd_init = -1;
                }
                e->init_fd_valid = 0;
                e->allocated = KTP_FREE;
                e->pid = 0;
                e->bound = 0;
            }
            pthread_mutex_unlock(&e->lock);
        }
    }
    return NULL;
}

/* -------------------- main -------------------- */

int main(void)
{
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    srand((unsigned)time(NULL) ^ getpid());

    if (create_shared() < 0)
        return 1;

    unlink(KTP_CTRL_PATH);
    g_ctrl_listen = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_ctrl_listen < 0) {
        perror("socket ctrl");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, KTP_CTRL_PATH, sizeof(addr.sun_path) - 1);
    if (bind(g_ctrl_listen, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind ctrl");
        return 1;
    }
    listen(g_ctrl_listen, 8);

    fprintf(stderr, "[init] shared memory ready, control socket at %s\n", KTP_CTRL_PATH);

    pthread_t th_r, th_s, th_ctrl, th_gc;
    pthread_create(&th_ctrl, NULL, ctrl_thread, NULL);
    pthread_create(&th_r, NULL, thread_R, NULL);
    pthread_create(&th_s, NULL, thread_S, NULL);
    pthread_create(&th_gc, NULL, gc_thread, NULL);

    fprintf(stderr, "[init] threads started. Press Ctrl+C to stop.\n");

    while (g_running)
        sleep(1);

    fprintf(stderr, "[init] shutting down...\n");
    pthread_join(th_r, NULL);
    pthread_join(th_s, NULL);
    /* ctrl and gc may be blocked; cancel */
    pthread_cancel(th_ctrl);
    pthread_cancel(th_gc);

    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        if (g_shm->socks[i].udp_fd_init >= 0)
            close(g_shm->socks[i].udp_fd_init);
    }
    close(g_ctrl_listen);
    unlink(KTP_CTRL_PATH);
    munmap(g_shm, sizeof(ktp_shared_t));
    close(g_shm_fd);
    shm_unlink(KTP_SHM_NAME);

    fprintf(stderr, "[init] cleaned up\n");
    return 0;
}
