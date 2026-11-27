# KTP — Reliable Flow Control over UDP

College Computer Networks assignment: message-oriented reliable transport
with window-based flow control on top of UDP.

## Quick start

```bash
make all
# Run from a executable filesystem (project dir may be noexec)
cp initksocket user1 user2 /tmp && chmod +x /tmp/initksocket /tmp/user1 /tmp/user2
/tmp/initksocket &
# Terminal 2
/tmp/user2 127.0.0.1 5001 127.0.0.1 5000 /tmp/out.bin
# Terminal 3
/tmp/user1 127.0.0.1 5000 127.0.0.1 5001 largefile.bin
sha256sum largefile.bin /tmp/out.bin
```

## Configuration (`ksocket.h`)

| Macro            | Default | Meaning                          |
|------------------|---------|----------------------------------|
| `T`              | 5       | Retransmission timeout (seconds) |
| `P_DROP`         | 0.0     | Packet loss probability          |
| `MAX_KTP_SOCKETS`| 10      | Max concurrent KTP sockets (N)   |
| `MSG_SIZE`       | 512     | Application message size         |
| `RECV_BUF_SIZE`  | 10      | Receiver buffer / window         |

Override drop probability: `gcc ... -DP_DROP=0.15`

## API

Same spirit as UDP sockets, but type `SOCK_KTP`:

- `k_socket(AF_INET, SOCK_KTP, 0)`
- `k_bind(sock, src_ip, src_port, dest_ip, dest_port)`
- `k_sendto` / `k_recvfrom` / `k_close`
- Errors: `k_errno` ∈ {`ENOSPACE`, `ENOTBOUND`, `ENOMESSAGE`}

See `documentation.txt` for protocol, shared-memory layout, and the nospace fix.
