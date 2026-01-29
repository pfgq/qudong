#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <asm/pgtable-prot.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

#define THOOK_LOG(fmt, ...) printk(KERN_INFO "[Thook] " fmt, ##__VA_ARGS__)

// --------- kallsyms 查找 ---------
static uintptr_t read_kallsyms(const char *symbol) {
    struct file *file;
    loff_t pos = 0;
    char *buf, *p, *line;
    uintptr_t addr = 0;
    ssize_t nread;

    file = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        THOOK_LOG("Failed to open /proc/kallsyms\n");
        return 0;
    }

    buf = kzalloc(512, GFP_KERNEL);
    if (!buf) {
        filp_close(file, NULL);
        THOOK_LOG("Failed to alloc buffer\n");
        return 0;
    }

    while ((nread = kernel_read(file, buf, 511, &pos)) > 0) {
        buf[nread] = 0;
        p = buf;
        while ((line = strsep(&p, "\n")) != NULL) {
            char sym[256], typ;
            uintptr_t val = 0;
            if (sscanf(line, "%lx %c %255s", &val, &typ, sym) == 3) {
                if (strcmp(sym, symbol) == 0) {
                    addr = val;
                    goto out;
                }
            }
        }
    }
out:
    kfree(buf);
    filp_close(file, NULL);
    if (addr)
        THOOK_LOG("Resolved %s = 0x%lx\n", symbol, addr);
    else
        THOOK_LOG("Failed to resolve %s\n", symbol);
    return addr;
}

// --------- ARM64 页表权限处理 ---------
/**
 * 你必须保证 PTE_DBM / PTE_RDONLY 宏定义正确。
 * 部分定制安卓内核宏定义不同，如遇编译错误，参考
 * arch/arm64/include/asm/pgtable-prot.h
 * 或 /proc/kallsyms 查找内核源码对应位
 */

#ifndef PTE_DBM
#define PTE_DBM   (1UL << 51)
#endif
#ifndef PTE_RDONLY
#define PTE_RDONLY (1UL << 7)
#endif

// 你的页表遍历函数（假设你有 pgtable_entry_kernel）
extern uint64_t *pgtable_entry_kernel(uint64_t va); // 需要你在memory.h实现

static int set_table_rw(uint64_t addr)
{
    uint64_t *pte = pgtable_entry_kernel(addr);
    if (!pte) {
        THOOK_LOG("set_table_rw: failed to get pte!\n");
        return -1;
    }
    *pte = (*pte | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_all();
    THOOK_LOG("set_table_rw: addr=%llx, pte=%llx\n", addr, *pte);
    return 0;
}

static int set_table_ro(uint64_t addr)
{
    uint64_t *pte = pgtable_entry_kernel(addr);
    if (!pte) {
        THOOK_LOG("set_table_ro: failed to get pte!\n");
        return -1;
    }
    *pte = (*pte & ~PTE_DBM) | PTE_RDONLY;
    flush_tlb_all();
    THOOK_LOG("set_table_ro: addr=%llx, pte=%llx\n", addr, *pte);
    return 0;
}

// --------- IOCTL处理逻辑 ---------
typedef long (*sys_ioctl_t)(const struct pt_regs *);
static unsigned long *__sys_call_table = NULL;
static sys_ioctl_t original_ioctl = NULL;

long handle_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    long ret = 0;

    switch (cmd) {
    case OP_READ_MEM:
        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
            THOOK_LOG("copy_from_user OP_READ_MEM failed\n");
            ret = -1; break;
        }
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) {
            THOOK_LOG("read_process_memory failed\n");
            ret = -1;
        }
        break;
    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
            THOOK_LOG("copy_from_user OP_WRITE_MEM failed\n");
            ret = -1; break;
        }
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) {
            THOOK_LOG("write_process_memory failed\n");
            ret = -1;
        }
        break;
    case OP_MODULE_BASE:
        if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 ||
            copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) != 0) {
            THOOK_LOG("copy_from_user OP_MODULE_BASE failed\n");
            ret = -1; break;
        }
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) != 0) {
            THOOK_LOG("copy_to_user OP_MODULE_BASE failed\n");
            ret = -1;
        }
        break;
    default:
        THOOK_LOG("Unknown ioctl cmd: 0x%x\n", cmd);
        break;
    }
    THOOK_LOG("ioctl: fd=%u cmd=0x%x arg=0x%lx ret=%ld\n", fd, cmd, arg, ret);
    return ret;
}

long new_hook_ioctl(const struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    unsigned int cmd = (unsigned int)regs->regs[1];
    unsigned long arg = (unsigned long)regs->regs[2];
    if (fd == (unsigned int)-1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE) {
        THOOK_LOG("new_hook_ioctl intercepted: fd=%u cmd=0x%x arg=0x%lx\n", fd, cmd, arg);
        return handle_ioctl(fd, cmd, arg);
    }
    return original_ioctl(regs);
}

// --------- 模块加载/卸载 ---------
static int __init my_module_init(void)
{
    unsigned long syscall_table_addr = read_kallsyms("sys_call_table");
    if (!syscall_table_addr) {
        THOOK_LOG("sys_call_table not found, abort\n");
        return -1;
    }
    __sys_call_table = (unsigned long *)syscall_table_addr;
    original_ioctl = (sys_ioctl_t)__sys_call_table[__NR_ioctl];

    THOOK_LOG("sys_call_table at %px\n", __sys_call_table);
    THOOK_LOG("original_ioctl: %px\n", original_ioctl);

    set_table_rw((uint64_t)__sys_call_table);
    __sys_call_table[__NR_ioctl] = (unsigned long)new_hook_ioctl;
    set_table_ro((uint64_t)__sys_call_table);

    THOOK_LOG("Hooked ioctl\n");
    return 0;
}

static void __exit my_module_exit(void)
{
    if (__sys_call_table && original_ioctl) {
        set_table_rw((uint64_t)__sys_call_table);
        __sys_call_table[__NR_ioctl] = (unsigned long)original_ioctl;
        set_table_ro((uint64_t)__sys_call_table);
        THOOK_LOG("Restored ioctl\n");
    }
    THOOK_LOG("exit\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("万载");
MODULE_DESCRIPTION("ARM64 syscall table hook with [Thook] dmesg log (no hide)");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
