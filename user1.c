/*
 * user1.c - KTP sender application
 * Transfers a file larger than 100 KB using KTP sockets.
 *
 * Usage: ./user1 <src_ip> <src_port> <dest_ip> <dest_port> <input_file>
 */

#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>

int main(int argc, char *argv[])
{
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <src_ip> <src_port> <dest_ip> <dest_port> <file>\n",
                argv[0]);
        return 1;
    }
    const char *src_ip = argv[1];
    int src_port = atoi(argv[2]);
    const char *dest_ip = argv[3];
    int dest_port = atoi(argv[4]);
    const char *filename = argv[5];

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("[user1] file size = %ld bytes\n", fsize);

    int sock = k_socket(AF_INET, SOCK_KTP, 0);
    if (sock < 0) {
        fprintf(stderr, "k_socket failed, k_errno=%d errno=%d\n", k_errno, errno);
        return 1;
    }
    printf("[user1] KTP socket id = %d\n", sock);

    if (k_bind(sock, src_ip, src_port, dest_ip, dest_port) < 0) {
        perror("k_bind");
        k_close(sock);
        return 1;
    }
    printf("[user1] bound %s:%d -> %s:%d\n", src_ip, src_port, dest_ip, dest_port);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &dest.sin_addr);

    char buf[MSG_SIZE];
    long sent_bytes = 0;
    int msg_count = 0;

    while (1) {
        size_t n = fread(buf, 1, MSG_SIZE, fp);
        if (n == 0)
            break;

        while (1) {
            ssize_t r = k_sendto(sock, buf, n, 0,
                                 (struct sockaddr *)&dest, sizeof(dest));
            if (r >= 0) {
                sent_bytes += r;
                msg_count++;
                break;
            }
            if (k_errno == ENOSPACE) {
                usleep(50000); /* wait for window / buffer space */
                continue;
            }
            fprintf(stderr, "k_sendto error k_errno=%d\n", k_errno);
            k_close(sock);
            fclose(fp);
            return 1;
        }
        if (msg_count % 50 == 0)
            printf("[user1] queued %d messages (%ld bytes)\n", msg_count, sent_bytes);
    }
    fclose(fp);
    printf("[user1] all %d messages queued (%ld bytes). Waiting for delivery...\n",
           msg_count, sent_bytes);

    /* Wait until sender buffer is drained (all ACKed). Poll shared state. */
    if (ktp_attach_shared() == 0) {
        ktp_shared_t *shm = ktp_get_shared();
        for (int wait = 0; wait < 300; wait++) { /* up to ~5 min with T=5 */
            pthread_mutex_lock(&shm->socks[sock].lock);
            int remaining = shm->socks[sock].send_count;
            uint64_t tx = shm->socks[sock].total_tx;
            uint64_t rt = shm->socks[sock].total_retrans;
            pthread_mutex_unlock(&shm->socks[sock].lock);
            if (remaining == 0) {
                printf("[user1] transfer complete. total_tx=%llu retrans=%llu\n",
                       (unsigned long long)tx, (unsigned long long)rt);
                break;
            }
            if (wait % 10 == 0)
                printf("[user1] waiting... remaining in send buffer: %d\n", remaining);
            sleep(1);
        }
    }

    k_close(sock);
    printf("[user1] done\n");
    return 0;
}
