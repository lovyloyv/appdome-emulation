#include <appdome.hpp>
#include <logcat.hpp>

#include <signal.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/sysconf.h>

uintptr_t exports::g_app_base = 0;
uintptr_t exports::g_appdome_base = 0;

// couldve done this better.
static const char* target_library_name{ nullptr };
static int dl_iter_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    const char* lib_name = info->dlpi_name;
    if (strstr(lib_name, target_library_name) != nullptr)
    {
        uintptr_t* base = reinterpret_cast<uintptr_t*>(data);
        *base = info->dlpi_addr;
        return 1;
    }
    return 0;
}

uintptr_t exports::get_app_base()
{
    uintptr_t base_address = 0;
    target_library_name = APP_LIB_NAME;
    dl_iterate_phdr(dl_iter_callback, &base_address);
    return base_address;
}

uintptr_t exports::get_appdome_base()
{
    uintptr_t base_address = 0;
    target_library_name = "libloader.so";
    dl_iterate_phdr(dl_iter_callback, &base_address);
    return base_address;
}

uintptr_t EXPORT_RESOLVER(uintptr_t RELATIVE_EXPORT_ADDR, uintptr_t SELF_ADDR, uintptr_t LR, uintptr_t);

exports::bss_info_t get_bss_info();
uintptr_t get_jni_onload_address();
void patch_all_objects(uintptr_t base);

void setup_object_manager_p2(uintptr_t app_base)
{
    auto bss_info = get_bss_info();

    auto trampoline_reloc_addr = bss_info.trampoline_reloc + app_base;
    auto bss_start = bss_info.start + app_base;
    auto bss_end = bss_info.end + app_base;
    log_D("bss start: 0x%lx", bss_start);
    log_D("bss end: 0x%lx", bss_end);
    log_D("trampoline reloc: 0x%lx", trampoline_reloc_addr);

    // debased bss start
    exports::handle_object_patch(bss_info.start, app_base, true); // no thumb bit
    log_D("did patches");

    *reinterpret_cast<uintptr_t*>(trampoline_reloc_addr) = (uintptr_t)EXPORT_RESOLVER;
    
    // we gotta mprotect the bss stuff to be rwx
    uintptr_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = bss_start & ~(page_size - 1);
    uintptr_t page_end = (bss_end + page_size - 1) & ~(page_size - 1);
    uintptr_t protect_len = page_end - page_start;
    if (mprotect(reinterpret_cast<void*>(page_start), protect_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        log_E("Failed to mprotect bss section");
    }

    log_D("ok export handler is up");
}

// we use a sigbus sigaction to listen for an exception with the appdome mark
// but on emulators this fucks up badly so we listen for everything
void signal_handler(int signum, siginfo_t* info, void* context)
{
    // log_D("ok we got a n exception");

    uintptr_t fault_address = reinterpret_cast<uintptr_t>(info->si_addr);
    log_D("fault address: 0x%lx", fault_address);
    
    // arm64 0x1137000001
    // arm32 0x6e000000
    // for arm64 we can just check the last byte and be chillling
    // but for arm32 we have to check that:
    // - first byte is not 00
    // - rest of the bytes are 00

#if defined(__aarch64__)
    auto last_bite = fault_address & 0xf;
    // log_D("last byte: 0x%lx", last_bite);
    if (last_bite != 0x1)
    {
        // log_D("unmarked exception, ignoring");
        return;
    }
#elif defined(__arm__)
    uint8_t first_byte = fault_address >> 24; // 0x6e000000 -> 0x6e
    uint32_t other_bytes = fault_address & 0xFFFFFF;
    if (first_byte == 0x00 || other_bytes != 0x000000)
    {
        // log_D("unmarked exception, ignoring");
        return;
    }
#elif defined(__x86_64__)
    if (fault_address != 0x0)
    {
        return;
    }
#endif

    log_D("fa: 0x%lx", fault_address);
    log_D("appdome exception, doing the thing");

    // we restore previous handlers so if something goes wrong we dont get into a loop of exceptions
    signal(SIGBUS, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGILL, SIG_DFL);

    // ok NOW we can do the thing

    uintptr_t jni_onload = get_jni_onload_address();
    log_D("got jni onload address: 0x%lx", jni_onload);

    auto app_base = exports::get_app_base();
    log_D("got app_base base address: 0x%lx", app_base);

    auto rebased_onload = jni_onload + app_base;
    log_D("rebased onload address: 0x%lx", rebased_onload);

    exports::g_app_base = app_base;

    exports::handle_object_patch(jni_onload, app_base, false, THUMB_BIT);
    setup_object_manager_p2(app_base);

    auto ucontext = reinterpret_cast<ucontext_t*>(context);

    // x1 = vm x2 = reserved
#if defined(__aarch64__)
    ucontext->uc_mcontext.pc = rebased_onload;

    // x0 = x1
    // x1 = x2
    ucontext->uc_mcontext.regs[0] = ucontext->uc_mcontext.regs[1];
    ucontext->uc_mcontext.regs[1] = ucontext->uc_mcontext.regs[2];
#elif defined(__arm__)
    ucontext->uc_mcontext.arm_pc = rebased_onload;

    // r0 = r1
    // r1 = r2
    ucontext->uc_mcontext.arm_r0 = ucontext->uc_mcontext.arm_r1;
    ucontext->uc_mcontext.arm_r1 = ucontext->uc_mcontext.arm_r2;
#elif defined(__x86_64__)
    // this was actually pretty tricky,
    // i like what they did here.
    const uintptr_t original_rsp = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);

    uintptr_t rsp_qword0 = 0;
    uintptr_t rsp_qword1 = 0;
    uintptr_t rsp_qword2 = 0;

    const auto* rsp_words = reinterpret_cast< const uintptr_t* >( original_rsp );
    rsp_qword0 = rsp_words[ 0 ]; // pushed rsi
    rsp_qword1 = rsp_words[ 1 ]; // pushed rdi
    rsp_qword2 = rsp_words[ 2 ]; // pushed rbx

    auto jni_vm = rsp_qword1;
    auto jni_reserved = rsp_qword0;
    auto restored_rbx = rsp_qword2;

    // pop rsi; pop rdi; pop rbx
    // we need JNI_OnLoad to start from the frame it was orig called with
    const uintptr_t restored_rsp = original_rsp + (3 * sizeof(uintptr_t));

    ucontext->uc_mcontext.gregs[REG_RIP] = rebased_onload;
    ucontext->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(restored_rsp);
    ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(restored_rbx);
    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(jni_vm);
    ucontext->uc_mcontext.gregs[REG_RSI] = static_cast<greg_t>(jni_reserved);
#endif

    log_D("ok redirecting");
}

void setup_sighandler( )
{
    struct sigaction sa;
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);

    log_I("ok sighandlers up");
}

void setup_object_manager( );
void exports::setup_handlers( )
{
    setup_sighandler( );
    setup_object_manager( );
}