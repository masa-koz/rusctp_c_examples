/*
	Simple UDP Server
*/
#include <stdint.h>
#include <stdio.h>
#include <winsock2.h>

#include <rusctp.h>

#define BUFLEN 2048 //Max length of buffer

static void log(const char *line, void *argp)
{
    fprintf(stderr, "%s\n", line);
    fflush(stderr);
}

void dump_pkt(uint8_t *buf, size_t len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
        if ((i % 16) < 15)
        {
            printf(", ");
        }
        else
        {
            printf("\n");
        }
    }
    if ((i % 16) != 15)
        printf("\n");
}

int main()
{
    SOCKET s;
    struct sockaddr_in server, from_sin;
    int slen, recv_len;
    char rbuf[BUFLEN], sbuf[BUFLEN], secret[32];
    WSADATA wsa;

    rusctp_enable_logging(log, NULL, RUSCTP_LOGLEVEL_TRACE);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("WSAStartup: %d\n", WSAGetLastError());
        exit(EXIT_FAILURE);
    }

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
    {
        printf("socket: %d\n", WSAGetLastError());
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(10009);

    if (bind(s, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
    {
        printf("bind: %d\n", WSAGetLastError());
        exit(EXIT_FAILURE);
    }

    memset(secret, 0, sizeof(secret));
    while (1)
    {
        size_t rbuf_len = sizeof(rbuf);
        size_t rbuf_off = 0;
        size_t sbuf_len = sizeof(sbuf);
        uint16_t src_port = 0, dst_port = 0;
        uint32_t vtag = 0;
        int rc = 0;
        rusctp_assoc *assoc = NULL;

        slen = sizeof(from_sin);
        if ((recv_len = recvfrom(s, rbuf, rbuf_len, 0, (struct sockaddr *)&from_sin, &slen)) == SOCKET_ERROR)
        {
            printf("recvfrom: %d\n", WSAGetLastError());
            continue;
        }

        printf("Received packet from %s:%d\n", inet_ntoa(from_sin.sin_addr), ntohs(from_sin.sin_port));
        dump_pkt(rbuf, recv_len);
        rc = rusctp_header_info(rbuf, recv_len, &src_port, &dst_port, &vtag);
        if (rc < 0)
        {
            continue;
        }

        rbuf_len = recv_len;
        assoc = rusctp_accept((struct sockaddr *)&from_sin, slen, rbuf, &rbuf_len, sbuf, &sbuf_len, secret, sizeof(secret));
        if (assoc == NULL)
        {
            rbuf_off += rbuf_len;
            if (sbuf_len > 0)
            {
                dump_pkt(sbuf, sbuf_len);
                if (sendto(s, sbuf, sbuf_len, 0, (struct sockaddr *)&from_sin, slen) == SOCKET_ERROR)
                {
                    printf("sendto() failed with error code: %d", WSAGetLastError());
                    exit(EXIT_FAILURE);
                }
            }
        }
        else
        {
            printf("Association established.\n");
            rusctp_assoc_free(assoc);
        }
    }

    closesocket(s);
    WSACleanup();

    return 0;
}