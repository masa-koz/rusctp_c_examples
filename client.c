#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <rusctp.h>

int main(int argc, char *argv[])
{
    printf("version: %s\n", rusctp_version());
}