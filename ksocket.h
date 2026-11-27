/*
 * ksocket.h - KTP (Reliable Message-Oriented Transport over UDP)
 * Assignment: Emulating End-to-End Reliable Flow Control over Unreliable Channels
 */

#ifndef KSOCKET_H
#define KSOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

/* -------------------- Configuration -------------------- */
#define SOCK_KTP            3           /* custom socket type */
#define T                   5           /* timeout in seconds */
#ifndef P_DROP
#define P_DROP              0.0f
#endif
#define MAX_KTP_SOCKETS     10          /* N: max concurrent KTP sockets */
#define MSG_SIZE            512         /* application message size (bytes) */
#define RECV_BUF_SIZE       10          /* receiver buffer capacity (messages) */
#define SEND_BUF_SIZE       50          /* sender buffer capacity (messages) - > window */
#define MAX_SEQ             256         /* 8-bit sequence space */
#define WINDOW_SIZE         10          /* initial / max window size */
#define HEADER_SIZE         12          /* fixed KTP header size */
#define MAX_PAYLOAD         MSG_SIZE
#define UDP_PAYLOAD_MAX     (HEADER_SIZE + MAX_PAYLOAD)

/* Control socket path for FD passing */
#define KTP_CTRL_PATH       "/tmp/ktp_ctrl.sock"
#define KTP_SHM_NAME        "/ktp_shared_mem"

/* Packet types */
#define PKT_DATA            0x01
#define PKT_ACK             0x02

/* Socket states */
#define KTP_FREE            0
#define KTP_ALLOCATED       1
#define KTP_BOUND           2
#define KTP_CLOSING         3

/* Custom errors (avoid clash with system errno) */
#define ENOSPACE            2001
#define ENOTBOUND           2002
#define ENOMESSAGE          2003

extern int k_errno;                     /* KTP-specific error variable */

/* -------------------- Packet format (wire) -------------------- */
/*
 * Fixed 12-byte header (network byte order where multi-byte):
 *   uint8_t  type;       // PKT_DATA or PKT_ACK
 *   uint8_t  seq;        // data sequence number (DATA) or last ack'd (ACK)
 *   uint8_t  ack;        // cumulative ACK number
 *   uint8_t  rwnd;       // advertised receiver window size
 *   uint16_t len;        // payload length (0 for pure ACK; <=512 for DATA)
 *   uint16_t flags;      // bit 0: FIN / last-message of transfer
 *   uint32_t checksum;   // simple checksum over header+payload (optional integrity)
 */
typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  seq;
    uint8_t  ack;
    uint8_t  rwnd;
    uint16_t len;
    uint16_t flags;
    uint32_t checksum;
} ktp_header_t;

#define KTP_FLAG_FIN        0x0001

/* -------------------- Shared-memory structures -------------------- */

typedef struct {
    char     data[MSG_SIZE];
    uint16_t len;                       /* actual payload length */
    uint8_t  seq;
    uint8_t  flags;                     /* FIN etc. */
    int      valid;                     /* 1 if occupied */
    struct timespec sent_time;          /* last transmission time (monotonic) */
} ktp_msg_t;

typedef struct {
    int      size;                      /* current advertised / allowed window */
    uint8_t  base;                      /* lowest unacked seq (sender) or next expected (recv) */
    uint8_t  next_seq;                  /* next seq to assign (sender) */
    uint8_t  seqs[WINDOW_SIZE];         /* outstanding seqs (sender) or buffered (recv) */
    int      count;                     /* number of outstanding / buffered */
} ktp_window_t;

typedef struct {
    int             allocated;          /* 0 free, 1 allocated, 2 bound, 3 closing */
    pid_t           pid;                /* owner process */
    int             udp_fd_app;         /* FD in application process (info only) */
    int             udp_fd_init;        /* FD in init process (valid for R/S) */
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    int             bound;

    /* Sender side */
    ktp_msg_t       send_buf[SEND_BUF_SIZE];
    int             send_head;          /* next free slot to write */
    int             send_tail;          /* oldest unacked / to send */
    int             send_count;         /* messages currently in buffer */
    ktp_window_t    swnd;
    uint8_t         next_seq_to_send;   /* next sequence number to assign */
    uint64_t        total_tx;           /* total DATA transmissions (incl retrans) */
    uint64_t        total_retrans;

    /* Receiver side */
    ktp_msg_t       recv_buf[RECV_BUF_SIZE];
    int             recv_count;         /* messages currently buffered (any order) */
    ktp_window_t    rwnd;
    uint8_t         expected_seq;       /* next seq expected from network (window base) */
    uint8_t         next_deliver;       /* next seq to give to application via k_recvfrom */
    int             nospace;            /* flag: buffer was full */
    int             last_ack_sent;      /* last cumulative ACK number sent */
    int             need_window_update; /* force duplicate ACK with new rwnd */

    /* Sync */
    pthread_mutex_t lock;               /* process-shared mutex for this entry */
    int             init_fd_valid;      /* 1 if udp_fd_init is usable by Thread R/S */
} ktp_sock_entry_t;

typedef struct {
    ktp_sock_entry_t socks[MAX_KTP_SOCKETS];
    pthread_mutex_t  global_lock;       /* protects allocation of free slots */
    int              initialized;
    pid_t            init_pid;
} ktp_shared_t;

/* -------------------- Public API -------------------- */

/*
 * k_socket - create a KTP socket
 * domain, type, protocol: same as socket(); type must be SOCK_KTP
 * Returns KTP socket id (>=0) or -1 on error (sets k_errno)
 */
int k_socket(int domain, int type, int protocol);

/*
 * k_bind - bind local address and record remote peer
 * src_ip, src_port, dest_ip, dest_port: null-terminated strings / host order ports
 * Returns 0 on success, -1 on error
 */
int k_bind(int sockfd, const char *src_ip, int src_port,
           const char *dest_ip, int dest_port);

/*
 * k_sendto - enqueue a 512-byte (or less for last) message for reliable delivery
 * Returns number of bytes accepted, or -1 (ENOTBOUND / ENOSPACE)
 */
ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags,
                 const struct sockaddr *dest_addr, socklen_t addrlen);

/*
 * k_recvfrom - dequeue next in-order message
 * Returns number of bytes, or -1 with ENOMESSAGE if none available
 */
ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags,
                   struct sockaddr *src_addr, socklen_t *addrlen);

/*
 * k_close - close KTP socket and free shared entry
 */
int k_close(int sockfd);

/*
 * dropMessage - simulate packet loss (called inside Thread R)
 * Returns 1 if message should be dropped, 0 otherwise
 */
int dropMessage(float p);

/* Internal helpers (used by init process / library) */
ktp_shared_t *ktp_get_shared(void);
int  ktp_attach_shared(void);
void ktp_detach_shared(void);
uint32_t ktp_checksum(const void *data, size_t len);
int  seq_in_window(uint8_t seq, uint8_t base, int size);
int  seq_lt(uint8_t a, uint8_t b);          /* a < b in modular sense (distance < 128) */
int  seq_leq(uint8_t a, uint8_t b);

#endif /* KSOCKET_H */
