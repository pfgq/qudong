#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

// ======================= 你的业务逻辑，不动 =======================
long handle_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
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
// ================================================================

// kprobe结构体
static struct kprobe kp;

// ARM64专用pre_handler，适用于安卓等所有arm64内核
static int ioctl_kprobe_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd  = (unsigned int)regs->regs[0];  // x0
    unsigned int cmd = (unsigned int)regs->regs[1];  // x1
    unsigned long arg = regs->regs[2];               // x2

    if (fd == -1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE) {
        long ret = handle_ioctl(fd, cmd, arg);
        regs->regs[0] = ret; // ARM64返回值
        return 1;            // 跳过原始sys_ioctl
    }
    return 0;
}

// 模块加载与卸载
static int __init my_module_init(void)
{
    int ret;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "sys_ioctl";
    kp.pre_handler = ioctl_kprobe_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[Thook] register_kprobe failed: %d\n", ret);
        return ret;
    }
    printk("[Thook] kprobe registered (sys_ioctl, arm64)\n");
    return 0;
}

static void __exit my_module_exit(void)
{
    unregister_kprobe(&kp);
    printk("[Thook] kprobe unregistered\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom syscall module using kprobes (ARM64 Android)");
MODULE_AUTHOR("万载");
