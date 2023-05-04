//
//  AntiAntiDebug.m
//  AntiDebugAndAntiAntiDebug
//
//  Created by 亓鑫 on 2023/5/4.
//

#import "AntiAntiDebug.h"
#import "PtraceHeader.h"
#import "fishhook.h"


// -------------------------------------------------------------------
// ptrace 反反调试代码

/// 声明一个ptrace的函数指针
int (*ptrace_p)(int _request, pid_t _pid, caddr_t _addr, int _data);

/// 自定义的ptrace函数
int my_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data) {
    if (_request != PT_DENY_ATTACH) {
        return ptrace_p(_request, _pid, _addr, _data);
    }
    printf("[AntiAntiDebug]检测到ptrace\n");
    return 0;
}

/// fishhook 进行重绑定
void anti_ptrace(void) {
    struct rebinding rebindings[1] = {{"ptrace", my_ptrace, (void*)&ptrace_p}};
    rebind_symbols(rebindings, 1);
}
// -------------------------------------------------------------------




// -------------------------------------------------------------------
// dlopen & dlsym 方式
#import <dlfcn.h>
/// 声明一个函数指针
void * (*dlsym_p)(void * __handle, const char * __symbol);

/// 自定义
void * my_dlsym(void * __handle, const char * __symbol) {
    if (strcmp(__symbol, "ptrace") != 0) {
        return dlsym_p(__handle, __symbol);
    }
    printf("[AntiAntiDebug]检测到dlsym:ptrace\n");
    return my_ptrace;
}

void anti_dlsym(void) {
    struct rebinding rebindings[1] = {{"dlsym", my_dlsym, (void*)&dlsym_p}};
    rebind_symbols(rebindings, 1);
}
// -------------------------------------------------------------------






// -------------------------------------------------------------------
// sysctl 方式
#import <sys/sysctl.h>
// 原始地址
int (*sysctl_p)(int *, u_int, void *, size_t *, void *, size_t);

int my_sysctl(int *name, u_int nameSize, void *info, size_t *infoSize, void *newInfo, size_t newInfoSize) {
    int ret = sysctl_p(name, nameSize, info, infoSize, newInfo, newInfoSize);
    if (nameSize == 4 &&
        name[0] == CTL_KERN &&
        name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID &&
        info &&
        (int)*infoSize == sizeof(struct kinfo_proc)) {
        struct kinfo_proc *info_p = (struct kinfo_proc *)info;
        if (info_p && (info_p->kp_proc.p_flag & P_TRACED) != 0) {
            printf("[AntiAntiDebug]sysctl 查询 trace 状态\n");
            info_p->kp_proc.p_flag ^= P_TRACED;
            if ((info_p->kp_proc.p_flag & P_TRACED) == 0) {
                printf("[AntiAntiDebug]trace状态移除了\n");
            }
        }
    }
    return ret;
}

void anti_sysctl(void) {
    struct rebinding rebindings[1] = {{"sysctl", my_sysctl, (void *)&sysctl_p}};
    rebind_symbols(rebindings, 1);
}

// -------------------------------------------------------------------






// -------------------------------------------------------------------
// syscall方式
int (*syscall_p)(int, ...);

int my_syscall(int code, ...) {
    va_list args;
    va_start(args, code);
    if (code == 26) {
        int request = va_arg(args, int);
        if (request == PT_DENY_ATTACH) {
            printf("[AntiAntiDebug]syscall 在调用 ptrace\n");
            return 0;
        }
    }
    va_end(args);
    return (int)syscall_p(code, args);
}

void anti_syscall(void) {
    struct rebinding rebindings[1] = {{"syscall", my_syscall, (void *)&syscall_p}};
    rebind_symbols(rebindings, 1);
}

// -------------------------------------------------------------------





// -------------------------------------------------------------------
// 一次查所有
void anti_all(void) {
    struct rebinding rebindings[4] = {
        {"ptrace", my_ptrace, (void*)&ptrace_p},
        {"dlsym", my_dlsym, (void*)&dlsym_p},
        {"sysctl", my_sysctl, (void *)&sysctl_p},
        {"syscall", my_syscall, (void *)&syscall_p}
    };
    rebind_symbols(rebindings, 4);
}

// -------------------------------------------------------------------




/// 写一个构造函数,在main之前执行完fishhook交换
__attribute__ ((constructor)) static void entry() {
    
    printf("[AntiAntiDebug]反反调试注册\n");
    /*
    // ptrace
    anti_ptrace();
    
    // dlsym
    anti_dlsym();
    
    // sysctl
    anti_sysctl();
    
    // syscall
    anti_syscall();
    */
    
    // all
    anti_all();
}
