#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/fs.h>

// 你的自定义头文件
#include "comm.h"
#include "memory.h"
#include "process.h"

#define MIN_CMD OP_INIT_KEY
#define MAX_CMD OP_MODULE_BASE

#if defined(__NR_ioctl)
#define NR_IOCTL __NR_ioctl
#else
#error "No __NR_ioctl defined"
#endif

// 你的逻辑
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
        if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
            ret = -1;
        }
        break;
    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
            ret = -1;
            break;
        }
        if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
            ret = -1;
        }
        break;
    case OP_MODULE_BASE:
        if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0
            || copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
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
    printk(KERN_INFO "[tracepoint] ioctl intercepted: fd=%u, cmd=0x%x, arg=0x%lx, ret=%ld\n", fd, cmd, arg, ret);
}

// tracepoint 回调
static void sys_enter_callback(void *ignore, struct pt_regs *regs, long id)
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

// tracepoint 查找
static struct tracepoint *tp_sys_enter = NULL;
static void lookup_tracepoints(void)
{
    struct tracepoint *tp;
    extern struct tracepoint __start___tracepoints[];
    extern struct tracepoint __stop___tracepoints[];
    for (tp = __start___tracepoints; tp < __stop___tracepoints; tp++) {
        if (strcmp(tp->name, "sys_enter") == 0) {
            tp_sys_enter = tp;
            break;
        }
    }
}

static int __init my_module_init(void)
{
    lookup_tracepoints();
    if (tp_sys_enter) {
        tracepoint_probe_register(tp_sys_enter, (void *)sys_enter_callback, NULL);
        printk(KERN_INFO "[tracepoint] sys_enter registered\n");
    } else {
        printk(KERN_ERR "[tracepoint] sys_enter not found\n");
    }
    return 0;
}

static void __exit my_module_exit(void)
{
    if (tp_sys_enter) {
        tracepoint_probe_unregister(tp_sys_enter, (void *)sys_enter_callback, NULL);
        printk(KERN_INFO "[tracepoint] sys_enter unregistered\n");
    }
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("万载");
MODULE_DESCRIPTION("IOCTL tracepoint sample");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
