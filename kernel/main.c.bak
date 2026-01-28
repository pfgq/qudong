#include <linux/module.h>
#include <linux/tty.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

/* ============================================================
 * 你原有的业务逻辑：完全不动
 * ============================================================ */

long handle_ioctl(unsigned int fd, unsigned int const cmd, unsigned long const arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};

    switch (cmd) {
    case OP_READ_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -1;
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -1;
        break;

    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -1;
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -1;
        break;

    case OP_MODULE_BASE:
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) ||
            copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1))
            return -1;

        mb.base = get_module_base(mb.pid, name);

        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -1;
        break;

    default:
        break;
    }
    return 0;
}

/* ============================================================
 * kprobe hook 部分（替代 kallsyms + sys_call_table）
 * ============================================================ */

static struct kprobe kp;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
/* x86_64 新 ABI */
static int ioctl_kprobe_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd  = (unsigned int)regs->di;
    unsigned int cmd = (unsigned int)regs->si;
    unsigned long arg = regs->dx;

    if (fd == -1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE) {
        long ret = handle_ioctl(fd, cmd, arg);
        regs->ax = ret;   // 注入返回值
        return 1;         // 跳过原 sys_ioctl
    }
    return 0;
}
#else
/* 老 ABI */
static int ioctl_kprobe_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd  = regs->bx;
    unsigned int cmd = regs->cx;
    unsigned long arg = regs->dx;

    if (fd == -1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE) {
        long ret = handle_ioctl(fd, cmd, arg);
        regs->ax = ret;
        return 1;
    }
    return 0;
}
#endif

/* ============================================================
 * module init / exit
 * ============================================================ */

static int __init my_module_init(void)
{
    int ret;

    printk("[Thook] ==========================================\n");
    printk("[Thook] 驱动开始加载（kprobes 版本）...\n");

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "sys_ioctl";
    kp.pre_handler = ioctl_kprobe_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[Thook] register_kprobe failed: %d\n", ret);
        return ret;
    }

    printk("[Thook] [成功] kprobe 已拦截 sys_ioctl\n");
    printk("[Thook] 驱动加载完成，一切就绪！\n");
    printk("[Thook] ==========================================\n");

    return 0;
}

static void __exit my_module_exit(void)
{
    unregister_kprobe(&kp);
    printk("[Thook] exit\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom syscall module using kprobes");
MODULE_AUTHOR("万载");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
