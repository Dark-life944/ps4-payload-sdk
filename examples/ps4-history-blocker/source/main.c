#include "ps4.h"

#define debug(sock, format, ...)                    \
    do {                                            \
        char buffer[512];                           \
        int size = sprintf(buffer, format, ##__VA_ARGS__); \
        sceNetSend(sock, buffer, size, 0);          \
    } while(0)

int _main(void) {

    // Initialize
    initKernel();
    initLibc();
    initNetwork();

    char socketName[] = "debug";

    struct sockaddr_in server;
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = IP(192, 168, 0, 4);
    server.sin_port = sceNetHtons(9023);
    memset(server.sin_zero, 0, sizeof(server.sin_zero));

    int sock = sceNetSocket(socketName, AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return 0;

    if (sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        sceNetSocketClose(sock);
        return 0;
    }

    // Print PID
    debug(sock, "PID: %d\n", syscall(20));

    // ---- SCTP TEST ----
    int sctp = sceNetSocket("sctp_test", AF_INET, SOCK_STREAM, IPPROTO_SCTP);

    if (sctp < 0) {
        debug(sock, "SCTP not supported (error: %d)\n", sctp);
    } else {
        debug(sock, "SCTP supported\n");
        sceNetSocketClose(sctp);
    }
    // -------------------

    sceNetSocketClose(sock);

    return 0;
}