#include <ps4.h>

typedef void (*png_read_info_t)(void*, void*);
png_read_info_t orig_png_read_info;

void hook_png_read_info(void* png_ptr, void* info_ptr)
{
    printf("png_read_info called! png_ptr=%p info_ptr=%p\n", png_ptr, info_ptr);
    orig_png_read_info(png_ptr, info_ptr);
}

void _main(void)
{
    initKernel();
    initLibc();
    initNetwork();
    initPthread();

    // testcase 
    void *addr = (void*)resolve_sym("libScePngDec.sprx", "png_read_info");

    if(addr)
    {
        orig_png_read_info = (png_read_info_t)install_hook(addr, hook_png_read_info);
        printf("hook installed for png_read_info at %p\n", addr);
    }
    else
    {
        printf("png_read_info not found\n");
    }

    // keep payload alive
    while(1) sceKernelSleep(1);
}