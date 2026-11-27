/*
 * user2.c - KTP receiver application
 * Receives a file sent by user1 and writes it to disk.
 *
 * Usage: ./user2 <src_ip> <src_port> <dest_ip> <dest_port> <output_file>
 *   (src = local, dest = remote peer = user1)
 */

#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

int main(int argc, char *argv[])
{
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <src_ip> <src_port> <dest_ip> <dest_port> <outfile>\n",
                argv[0]);
        return 1;
    }
    const char *src_ip = argv[1];
    int src_port = atoi(argv[2]);
    const char *dest_ip = argv[3];
    int dest_port = atoi(argv[4]);
    const char *outfile = argv[5];

    FILE *fp = fopen(outfile, "wb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    int sock = k_socket(AF_INET, SOCK_KTP, 0);
    if (sock < 0) {
        fprintf(stderr, "k_socket failed, k_errno=%d\n", k_errno);
        return 1;
    }
    printf("[user2] KTP socket id = %d\n", sock);

    if (k_bind(sock, src_ip, src_port, dest_ip, dest_port) < 0) {
        perror("k_bind");
        k_close(sock);
        return 1;
    }
    printf("[user2] bound %s:%d <- %s:%d\n", src_ip, src_port, dest_ip, dest_port);

    char buf[MSG_SIZE];
    long total = 0;
    int msg_count = 0;
    int idle_rounds = 0;
    const int max_idle = 300; /* ~60 s of silence after last message => done */

    printf("[user2] waiting for data...\n");
    while (idle_rounds < max_idle) {
        ssize_t n = k_recvfrom(sock, buf, MSG_SIZE, 0, NULL, NULL);
        if (n > 0) {
            fwrite(buf, 1, (size_t)n, fp);
            total += n;
            msg_count++;
            idle_rounds = 0;
            if (msg_count % 50 == 0)
                printf("[user2] received %d messages (%ld bytes)\n", msg_count, total);
        } else if (k_errno == ENOMESSAGE) {
            idle_rounds++;
            usleep(200000); /* 200 ms */
        } else {
            fprintf(stderr, "k_recvfrom error k_errno=%d\n", k_errno);
            break;
        }
    }

    fclose(fp);
    printf("[user2] finished. messages=%d bytes=%ld -> %s\n", msg_count, total, outfile);
    k_close(sock);
    return 0;
}
