#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/version.h>

// 你自己的数据结构与命令定义（补充你的头文件）
#include "comm.h"
#include "memory.h"
#include "process.h"

// 命令范围定义
#define MIN_CMD OP_INIT_KEY
#define MAX_CMD OP_MODULE_BASE

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
            copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) != 0) {
            ret = -1;
            break;
        }
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) != 0) {
            ret = -1;
        }
        break;
    default:
        break;
    }
    printk(KERN_INFO "[Thook][kprobe] ioctl intercepted: fd=%u, cmd=0x%x, arg=0x%lx, ret=%ld\n", fd, cmd, arg, ret);
}

// kprobe预处理回调（ARM64专用，x86请改寄存器名）
static int pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    unsigned int cmd = (unsigned int)regs->regs[1];
    unsigned long arg = (unsigned long)regs->regs[2];
    if (fd == (unsigned int)-1 && cmd >= MIN_CMD && cmd <= MAX_CMD) {
        handle_my_ioctl(fd, cmd, arg);
    }
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "ksys_ioctl",
    .pre_handler = pre_handler,
};

static int __init my_module_init(void)
{
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[Thook][kprobe] register_kprobe failed, %d\n", ret);
    } else {
        printk(KERN_INFO "[Thook][kprobe] registered on ksys_ioctl\n");
    }
    return ret;
}

static void __exit my_module_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[Thook][kprobe] unregistered\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("万载");
MODULE_DESCRIPTION("IOCTL kprobe sample (ARM64)");
