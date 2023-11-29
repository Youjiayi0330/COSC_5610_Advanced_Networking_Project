#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <quiche.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define VIDEO_BUFFER_SIZE 262144


struct conn_io {
    ev_timer timer;

    int sock;

    quiche_conn *conn;
};

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

static void rand_buf(uint8_t *buf, int size) {
    for (int i = 0; i < size; ++i) {
        buf[i] = rand() * 255;
    }
}

static void send_video_with_dtp(quiche_conn *conn, FILE *video_file, size_t stream_id, bool *end_of_file) {
    uint8_t buffer[VIDEO_BUFFER_SIZE];

    if (!*end_of_file) {
        size_t bytes_read = fread(buffer, 1, VIDEO_BUFFER_SIZE, video_file);
        if (bytes_read == 0) {
            if (feof(video_file)) {
                *end_of_file = true;
                if (quiche_conn_is_established(conn)) {
                    quiche_conn_stream_send_full(conn, stream_id, NULL, 0, true, 0, 0, 0);
                }
            } else {
                perror("failed to read video file");
                exit(-1);
            }
        }

        // DTP 设置
        uint64_t deadline = 200;
        uint8_t priority = 1;
        uint64_t depend_block = 0;

        if(quiche_conn_is_established(conn)){
            fprintf(stderr, "quic成功连接\n");
        } else {
            fprintf(stderr, "quic连接失败\n");
        }
        if(quiche_conn_is_established(conn)){
            ssize_t sent = quiche_conn_stream_send_full(conn, stream_id, buffer, bytes_read, end_of_file, deadline, priority, depend_block);
        }
            
        if (sent < 0) {
            fprintf(stderr, "failed to send data with DTP\n");
            exit(-1);
        }
    }
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = send(conn_io->sock, out, written, 0);
        if (sent != written) {
            perror("failed to send");
            return;
        }

        fprintf(stderr, "sent %zd bytes\n", sent);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
    static bool req_sent = false;

    static bool hello_fin = false;
    static bool string_fin = false;

    struct conn_io *conn_io = w->data;

    static uint8_t buf[65535];

    while (1) {
        ssize_t read = recv(conn_io->sock, buf, sizeof(buf), 0);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read);

        if (done < 0) {
            fprintf(stderr, "failed to process packet\n");
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);
    }

    fprintf(stderr, "done reading\n");

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn) && !req_sent) {
        const uint8_t *app_proto;
        size_t app_proto_len;

        quiche_conn_application_proto(conn_io->conn, &app_proto,
                                      &app_proto_len);

        fprintf(stderr, "connection established: %.*s\n", (int)app_proto_len,
                app_proto);

        const static uint8_t r[] = "hello\r\n";
        if (quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), true) < 0) {
            fprintf(stderr, "failed to send hello\n");
            return;
        }

        printf("send: %s", r);

        req_sent = true;
    }

    if (quiche_conn_is_established(conn_io->conn)) {
        uint64_t s = 0;

        quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

        while (quiche_stream_iter_next(readable, &s)) {
            fprintf(stderr, "stream %" PRIu64 " is readable\n", s);

            bool fin = false;
            ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s, buf,
                                                       sizeof(buf), &fin);
            if (recv_len < 0) {
                break;
            }

            printf("recv: %.*s", (int)recv_len, buf);

            if (fin) {
                if (s == 4) {
                    hello_fin = true;
                } 
                if (hello_fin ) {
                    if (quiche_conn_close(conn_io->conn, true, 0, NULL, 0) < 0) {
                        fprintf(stderr, "failed to close connection\n");
                    }
                }
            }
        }

        quiche_stream_iter_free(readable);
    }

    flush_egress(loop, conn_io);
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;

        quiche_conn_stats(conn_io->conn, &stats);

        fprintf(stderr,
                "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64
                "ns\n",
                stats.recv, stats.sent, stats.lost, stats.rtt);

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

int main(int argc, char *argv[]) {
    const char *host = argv[1];
    const char *port = argv[2];
    const char *video_path = argv[3];

    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};

    quiche_enable_debug_logging(debug_log, NULL);
    quiche_set_debug_logging_level(Debug);

    struct addrinfo *peer;
    if (getaddrinfo(host, port, &hints, &peer) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (connect(sock, peer->ai_addr, peer->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    quiche_config *config = quiche_config_new(0xbabababa);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_set_application_protos(
        config, (uint8_t *)"\x05hq-28\x05hq-27\x08http/0.9", 21);

    quiche_config_set_max_idle_timeout(config, 5000);
    quiche_config_set_max_packet_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_set_disable_active_migration(config, true);

    quiche_config_set_cc_algorithm(
        config, Aitrans_CC_TRIGGER);  // switch to interface CC
    // quiche_config_set_redundancy_rate(config, 1.0); // FEC setting 1: set
    // rate. This is set in the C function

    if (getenv("SSLKEYLOGFILE")) {
        quiche_config_log_keys(config);
    }

    uint8_t scid[LOCAL_CONN_ID_LEN];
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return -1;
    }

    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return -1;
    }

    quiche_conn *conn =
        quiche_connect(host, (const uint8_t *)scid, sizeof(scid), config);
    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return -1;
    }

    // FEC setting 2: set tail size (pkts)
    quiche_conn_set_tail(conn, 5);

    FILE *video_file = fopen(video_path, "rb");
    if (video_file == NULL) {
        perror("failed to open video file");
        return -1;
    }

    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return -1;
    }

    conn_io->sock = sock;
    conn_io->conn = conn;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, conn_io->sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = conn_io;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    flush_egress(loop, conn_io);


    bool end_of_file = false;
    size_t stream_id = 5;  // 假设使用流 ID 5

    while (ev_run(loop, 0)) {
        if (!end_of_file ) {
            send_video_with_dtp(conn_io->conn, video_file, stream_id, &end_of_file);
        }

        flush_egress(loop, conn_io);

        if (end_of_file) {
            break;
        }
    }

    fclose(video_file); // 关闭视频文件

    freeaddrinfo(peer);

    quiche_conn_free(conn);

    quiche_config_free(config);

    return 0;
}




