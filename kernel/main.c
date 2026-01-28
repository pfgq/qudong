#include <linux/module.h>
#include <linux/tty.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h> // 必须保留
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <asm/tlbflush.h>
#include <linux/version.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))

typedef asmlinkage long (*syscall_ioctl_t)(unsigned int fd, unsigned int cmd, unsigned long arg);
typedef long (*new_syscall_ioctl_t)(const struct pt_regs *);

unsigned long *__sys_call_table;
syscall_ioctl_t original_ioctl;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 186)
new_syscall_ioctl_t new_original_ioctl;
#endif

/* * 使用 Kprobes 获取内核符号地址 
 */
static unsigned long get_symbol(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long addr;

    if (register_kprobe(&kp) < 0) {
        printk(KERN_ERR "[Thook] Failed to find symbol: %s\n", name);
        return 0;
    }
    
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

// 保持原有的页表操作逻辑不变
static uint64_t page_size_t = 0;
static uint64_t page_level_c = 0;
static uint64_t page_shift_t = 0;
static uint64_t pgd_k_pa = 0;
static uint64_t pgd_k = 0;

__attribute__((no_sanitize("cfi"))) void init_page_util(void)
{
    uint64_t tcr_el1, ttbr1_el1, va_bits, t1sz, tg1, baddr, page_size_mask;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    t1sz = bits(tcr_el1, 21, 16);
    tg1 = bits(tcr_el1, 31, 30);
    va_bits = 64 - t1sz;

    page_shift_t = 12;
    if (tg1 == 1) page_shift_t = 14;
    else if (tg1 == 3) page_shift_t = 16;
    
    page_size_t = 1 << page_shift_t;
    page_level_c = (va_bits - 4) / (page_shift_t - 3);

    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    page_size_mask = ~(page_size_t - 1);
    pgd_k_pa = baddr & page_size_mask;
    pgd_k = (uint64_t)phys_to_virt(pgd_k_pa);
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift_t - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa, pxd_entry_va = 0;
    uint64_t block_lv = 0;
    int64_t lv = 0;

    if (page_shift_t == 0 || page_level_c == 0) return NULL;

    for (lv = 4 - page_level_c; lv < 4; lv++) {
        uint64_t pxd_shift, pxd_index, pxd_desc;

        pxd_shift = (page_shift_t - 3) * (4 - lv) + 3;
        pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va) return NULL;

        pxd_desc = *((uint64_t *)pxd_entry_va);

        if ((pxd_desc & 0b11) == 0b11) { 
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift_t)) - 1) << page_shift_t);
        } else if ((pxd_desc & 0b11) == 0b01) { 
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift_t;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else {
            return NULL;
        }
        pxd_va = (uint64_t)phys_to_virt((phys_addr_t)pxd_pa);
        if (block_lv) break;
    }
    return (uint64_t *)pxd_entry_va;
}

inline uint64_t *pgtable_entry_kernel(uint64_t va) { return pgtable_entry(pgd_k, va); }

// IOCTL 处理逻辑 (保持不变)
long handle_ioctl(unsigned int fd, unsigned int const cmd, unsigned long const arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};

    switch (cmd) {
    case OP_READ_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -1;
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) return -1;
        break;
    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -1;
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) return -1;
        break;
    case OP_MODULE_BASE:
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) ||
            copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1)) return -1;
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb))) return -1;
        break;
    }
    return 0;
}

long new_hook_ioctl(const struct pt_regs *kregs)
{
    unsigned int fd = (unsigned int)kregs->regs[0];
    unsigned int cmd = (unsigned int)kregs->regs[1];
    unsigned long arg = (unsigned long)kregs->regs[2];

    if (fd == -1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE)
        return handle_ioctl(fd, cmd, arg);
    return new_original_ioctl(kregs);
}

asmlinkage long hook_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    if (fd == -1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE)
        return handle_ioctl(fd, cmd, arg);
    return original_ioctl(fd, cmd, arg);
}

static int hook_func(unsigned long hook_function, int nr, unsigned long *sys_table)
{
    uint64_t orginal_pte, *pte;

    if (nr < 0) return 3004;
    pte = pgtable_entry_kernel((uint64_t)&sys_table[nr]);
    if (!pte) return 3007;

    orginal_pte = *pte;
    *pte = (orginal_pte | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_all();

    // 存下原函数地址
    if (original_ioctl == NULL && new_original_ioctl == NULL) {
        #if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
            original_ioctl = (syscall_ioctl_t)sys_table[nr];
        #else
            new_original_ioctl = (new_syscall_ioctl_t)sys_table[nr];
        #endif
    }

    sys_table[nr] = hook_function;
    *pte = orginal_pte;
    flush_tlb_all();
    return 0;
}

static int __init my_module_init(void)
{
    printk("[Thook] ==========================================\n");
    
    // 1. 使用 kprobes 获取 sys_call_table
    __sys_call_table = (unsigned long *)get_symbol("sys_call_table");
    
    if (!__sys_call_table) {
        printk("[Thook] [错误] 无法定位 sys_call_table\n");
        return -EINVAL; 
    }
    printk("[Thook] [成功] sys_call_table: %px\n", __sys_call_table);

    init_page_util();

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
    hook_func((unsigned long)hook_ioctl, __NR_ioctl, __sys_call_table);
#else
    hook_func((unsigned long)new_hook_ioctl, __NR_ioctl, __sys_call_table);
#endif

    printk("[Thook] 驱动加载完成\n");
    return 0;
}

static void __exit my_module_exit(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
    hook_func((unsigned long)original_ioctl, __NR_ioctl, __sys_call_table);
#else
    hook_func((unsigned long)new_original_ioctl, __NR_ioctl, __sys_call_table);
#endif
    printk("[Thook] exit\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
MODULE_LICENSE("GPL");