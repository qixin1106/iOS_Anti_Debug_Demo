//
//  main.m
//  AntiDebugAndAntiAntiDebug
//
//  Created by 亓鑫 on 2023/5/4.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

/**
 * 从macOS平台导出的头文件
 * ptrace第一个参数的宏定义在里面
 */
#import "PtraceHeader.h"



//MARK: 直接ptrace方式
void test_ptrace(void) {
    // 反反调试参考: AntiAntiDebug.m/anti_ptrace()
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
}



//MARK: dlopen + dlsym方式
#import <dlfcn.h>
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
void test_dlsym(void) {
    /**
     使用 dlopen 函数来打开一个动态链接库。dlopen 函数的第一个参数是库的路径，如果传入 0，则表示打开主程序。第二个参数是打开库时的标志位，RTLD_GLOBAL 表示将库中的符号定义为全局可见，RTLD_NOW 表示立即解析库中的所有符号。这段代码的作用是打开主程序并立即解析其中的所有符号，使它们全局可见。
     */
    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    
    /**
     上面定义一个函数指针类型 ptrace_ptr_t，它指向一个与 ptrace 函数签名相同的函数。然后使用 dlsym 函数在之前打开的动态链接库中查找名为 "ptrace" 的符号，并将其地址赋值给 ptrace_ptr。这样，ptrace_ptr 就可以像调用 ptrace 函数一样使用了。
     */
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    
    /**
     相当于还是使用ptrace
     */
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}




//MARK: sysctl方式
#import <sys/sysctl.h>
BOOL test_sysctl(void) {
    int name[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    info.kp_proc.p_flag = 0;
    
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        NSLog(@"sysctl error ...");
        return NO;
    }
    
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}




//MARK: syscall方式
void test_syscall(void) {
    syscall(26, PT_DENY_ATTACH, 0, 0, 0);
}





int main(int argc, char * argv[]) {
    printf("main函数!!\n");
    
    test_ptrace();
    
    test_dlsym();
    
    // 单次查询
    if (test_sysctl()) exit(0);
    
    // 也可以做一个timer轮询查询
    /**
     // 伪代码
     timer(2.0) {
         if (test_sysctl()) exit(0);
     }
     */
    
    test_syscall();
    
    
    
    
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
