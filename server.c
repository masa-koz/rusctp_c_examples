/*
	Simple UDP Server
*/
#include <stdint.h>
#include <stdio.h>
#include <winsock2.h>

#include <uv.h>

#include <rusctp.h>

#define BUFLEN 2048 //Max length of buffer

struct associations
{
    SOCKET sock;
    rusctp_assoc *assoc;
};

static rusctp_init_config *config = NULL;

static struct associations *assocs = NULL;

uv_loop_t *loop;
uv_udp_t udp_socket;

static void my_log(const char *line, void *argp)
{
    fprintf(stderr, "%s\n", line);
    fflush(stderr);
}

void dump_pkt(uint8_t *buf, size_t len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        fprintf(stderr, "%02X", buf[i]);
        if ((i % 16) < 15)
        {
            fprintf(stderr, ", ");
        }
        else
        {
            fprintf(stderr, "\n");
        }
    }
    if ((i % 16) < 15)
        fprintf(stderr, "\n");

    fflush(stderr);
}

#if 0
static void recv_cb(EV_P_ ev_io *w, int revents)
{
    struct sockaddr_in raddr_sin;
    char rbuf[BUFLEN], sbuf[BUFLEN], secret[32];

    fprintf(stderr, "recv_cb\n");
    fflush(stderr);

    while (1)
    {

        int slen = sizeof(raddr_sin);

        int recv_len = recvfrom(assocs->sock, rbuf, rbuf_len, 0, (struct sockaddr *)&raddr_sin, &slen);
        if (recv_len == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                break;
            }
            fprintf(stderr, "recvfrom: %d\n", WSAGetLastError());
            fflush(stderr);
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "Received packet from %s:%d\n", inet_ntoa(raddr_sin.sin_addr), ntohs(raddr_sin.sin_port));
        fflush(stderr);

        dump_pkt(rbuf, recv_len);

    }
}
#endif

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

void on_send(uv_udp_send_t *req, int status)
{
    fprintf(stderr, "Write\n");
}

void on_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t *rbuf, const struct sockaddr *addr, unsigned flags)
{
    if (nread < 0)
    {
        fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t *)req, NULL);
        free(rbuf->base);
        return;
    }

    char sender[17] = {0};
    uv_ip4_name((const struct sockaddr_in *)addr, sender, 16);
    fprintf(stderr, "Recv from %s\n", sender);

    dump_pkt(rbuf->base, nread);

    uint16_t src_port = 0, dst_port = 0;
    uint32_t vtag = 0;

    int rc = rusctp_header_info(rbuf->base, nread, &src_port, &dst_port, &vtag);
    if (rc < 0)
    {
        return;
    }

    fprintf(stderr, "src_port=%u, dst_port=%u, vtag=%u\n", src_port, dst_port, vtag);

    size_t rbuf_len = nread;
    size_t rbuf_off = 0;

    uv_buf_t sbuf = uv_buf_init((char *)malloc(BUFLEN), BUFLEN);
    size_t sbuf_len = BUFLEN;
    if (sbuf.base == NULL)
    {
        return;
    }

    size_t salen;
    switch (addr->sa_family)
    {
    case AF_INET:
        salen = sizeof(struct sockaddr_in);
        break;
    case AF_INET6:
        salen = sizeof(struct sockaddr_in6);
        break;
    default:
        return;
    }

    rusctp_assoc *assoc = NULL;
    assoc = rusctp_accept(addr, salen, rbuf->base, &rbuf_len, sbuf.base, &sbuf.len, config);
    if (assoc == NULL)
    {
        rbuf_off += rbuf_len;
        if (sbuf_len > 0)
        {
            dump_pkt(sbuf.base, sbuf.len);

            uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
            if (send_req == NULL)
            {
                return;
            }
            uv_udp_send(send_req, &udp_socket, &sbuf, 1, addr, on_send);
        }
    }
    else
    {
        printf("Association established.\n");
        rusctp_assoc_free(assoc);
    }

    free(rbuf->base);
}

int main()
{
    rusctp_enable_logging(my_log, NULL, RUSCTP_LOGLEVEL_TRACE);

    config = rusctp_config_new(10001);
    if (config == NULL)
    {
        fprintf(stderr, "rusctp_config_new\n");
        exit(EXIT_FAILURE);
    }

    char secret[32];
    memset(secret, 0, sizeof(secret));

    rusctp_config_set_secret_key(config, secret, sizeof(secret));

    loop = uv_default_loop();

    uv_udp_init(loop, &udp_socket);
    struct sockaddr_in recv_addr;
    uv_ip4_addr("0.0.0.0", 10009, &recv_addr);
    uv_udp_bind(&udp_socket, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
    uv_udp_recv_start(&udp_socket, on_alloc, on_recv);

    int rc = uv_run(loop, UV_RUN_DEFAULT);

    rusctp_config_free(config);

    return rc;
}