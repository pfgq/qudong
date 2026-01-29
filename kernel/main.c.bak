#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <trace/events/syscalls.h> // 关键头文件

// 你自己的数据结构和头文件
#include "comm.h"
#include "memory.h"
#include "process.h"

// 命令范围
#define MIN_CMD OP_INIT_KEY
#define MAX_CMD OP_MODULE_BASE

#if defined(__NR_ioctl)
#define NR_IOCTL __NR_ioctl
#else
#error "No __NR_ioctl defined"
#endif

// 你自己的ioctl逻辑
static void handle_my_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    long ret = 0;

    switch (cmd) {
    case OP_READ_MEM:
        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
            ret = -1;
            break;
        }
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) {
            ret = -1;
        }
        break;
    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
            ret = -1;
            break;
        }
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) {
            ret = -1;
        }
        break;
    case OP_MODULE_BASE:
        if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 ||
            copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
            ret = -1;
            break;
        }
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
            ret = -1;
        }
        break;
    default:
        break;
    }
    printk(KERN_INFO "[Thook] ioctl intercepted: fd=%u, cmd=0x%x, arg=0x%lx, ret=%ld\n", fd, cmd, arg, ret);
}

// tracepoint回调，函数原型必须和trace/events/syscalls.h一致
static void my_sys_enter(void *ignore, struct pt_regs *regs, long id)
{
    if (id == NR_IOCTL) {
#if defined(CONFIG_ARM64)
        unsigned int fd = (unsigned int)regs->regs[0];
        unsigned int cmd = (unsigned int)regs->regs[1];
        unsigned long arg = (unsigned long)regs->regs[2];
#else // x86_64
        unsigned int fd = (unsigned int)regs->di;
        unsigned int cmd = (unsigned int)regs->si;
        unsigned long arg = (unsigned long)regs->dx;
#endif
        if (fd == (unsigned int)-1 && cmd >= MIN_CMD && cmd <= MAX_CMD) {
            handle_my_ioctl(fd, cmd, arg);
        }
    }
}

static int __init my_module_init(void)
{
    int ret = register_trace_sys_enter(my_sys_enter, NULL);
    if (ret) {
        printk(KERN_ERR "[Thook] register_trace_sys_enter failed: %d\n", ret);
    } else {
        printk(KERN_INFO "[Thook] sys_enter trace registered\n");
    }
    return ret;
}

static void __exit my_module_exit(void)
{
    unregister_trace_sys_enter(my_sys_enter, NULL);
    printk(KERN_INFO "[Thook] sys_enter trace unregistered\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("万载");
MODULE_DESCRIPTION("IOCTL tracepoint sample");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
