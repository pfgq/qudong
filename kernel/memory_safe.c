// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 安全内存操作模块
 * 
 * 使用内核安全拷贝函数 (copy_from_kernel_nofault)
 * 提供更可靠的内存访问，具有完整的故障处理
 * 
 * 安全特性：
 * - VMA权限检查（防止读取陷阱地址）
 * - 缺页检测（跳过未映射页面）
 * - PTE安全验证（检测PROT_NONE陷阱）
 * - 物理地址验证
 */

#include "teargame.h"
#include "teargame_security.h"
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <asm/pgtable.h>

/*
 * ============================================================================
 * 安全的页表遍历
 * ============================================================================
 */

/*
 * 将虚拟地址安全地转换为物理地址
 * 使用RCU保护页表访问，并执行所有安全检查
 */
phys_addr_t vaddr_to_phys_safe(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t phys = 0;
    pte_t pte_val;
    pmd_t pmd_val;
    pud_t pud_val;
    
    if (!mm || !mm->pgd)
        return 0;
    
    rcu_read_lock();
    
    /* 第0级: PGD */
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
        goto out;
    
    /* 第1级: P4D */
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
        goto out;
    
    /* 第2级: PUD */
    pud = pud_offset(p4d, vaddr);
    pud_val = READ_ONCE(*pud);
    if (pud_none(pud_val))
        goto out;
    
    /* 检查1GB大页 */
    if (tear_pud_huge(pud_val)) {
        phys = (pud_pfn(pud_val) << PAGE_SHIFT) | (vaddr & ~PUD_MASK);
        /* 验证物理地址安全性 */
        if (!tear_is_phys_safe(phys))
            phys = 0;
        goto out;
    }
    
    if (unlikely(pud_bad(pud_val)))
        goto out;
    
    /* 第3级: PMD */
    pmd = pmd_offset(pud, vaddr);
    pmd_val = READ_ONCE(*pmd);
    if (pmd_none(pmd_val))
        goto out;
    
    /* 检查2MB大页 */
    if (tear_pmd_huge(pmd_val)) {
        phys = (pmd_pfn(pmd_val) << PAGE_SHIFT) | (vaddr & ~PMD_MASK);
        if (!tear_is_phys_safe(phys))
            phys = 0;
        goto out;
    }
    
    if (unlikely(pmd_bad(pmd_val)))
        goto out;
    
    /* 第4级: PTE */
    pte = tear_pte_offset_map(pmd, vaddr);
    if (!pte)
        goto out;
    
    pte_val = READ_ONCE(*pte);
    tear_pte_unmap(pte);
    
    /* PTE安全检查 */
    if (!tear_is_pte_safe(pte_val)) {
        tear_debug("安全页表遍历: PTE不安全 vaddr=0x%lx\n", vaddr);
        goto out;
    }
    
    phys = (pte_pfn(pte_val) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
    
    /* 物理地址安全检查 */
    if (!tear_is_phys_safe(phys)) {
        tear_debug("安全页表遍历: 物理地址不安全 phys=0x%llx\n", 
                   (unsigned long long)phys);
        phys = 0;
    }
    
out:
    rcu_read_unlock();
    return phys;
}

/*
 * ============================================================================
 * 安全内存读取
 * ============================================================================
 */

/*
 * 使用安全内核拷贝函数读取内存
 * 具有完整的安全检查链：VMA -> PTE -> 物理地址
 */
bool read_safe(pid_t pid, unsigned long addr,
               void __user *buffer, size_t size)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kernel_buf = NULL;
    size_t copied = 0;
    bool success = false;
    
    /* 参数验证 */
    if (!buffer || size == 0 || size > TEAR_MAX_SAFE_RW_SIZE) {
        tear_debug("安全读取: 参数无效\n");
        return false;
    }
    
    if (addr < TEAR_MIN_VALID_ADDR) {
        tear_debug("安全读取: 地址过低 addr=0x%lx\n", addr);
        return false;
    }
    
    /* 获取目标进程 */
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        tear_debug("安全读取: 找不到PID %d\n", pid);
        return false;
    }
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task) {
        tear_debug("安全读取: 找不到任务结构\n");
        return false;
    }
    
    mm = get_task_mm(task);
    put_task_struct(task);
    
    if (!mm) {
        tear_debug("安全读取: 找不到内存描述符\n");
        return false;
    }
    
    /* 分配内核缓冲区 */
    kernel_buf = tear_alloc_buffer(size);
    if (!kernel_buf) {
        tear_debug("安全读取: 分配缓冲区失败\n");
        mmput(mm);
        return false;
    }
    
    /* 使用安全拷贝读取 */
    while (copied < size) {
        phys_addr_t phys;
        unsigned long pfn;
        size_t offset;
        size_t chunk;
        void *kaddr;
        long ret;
        
#if TEAR_SECURITY_CHECK_VMA
        /* 安全检查1: VMA权限验证 */
        {
            struct vm_area_struct *vma;
            
            tear_mmap_read_lock(mm);
            vma = tear_find_safe_vma(mm, addr, false);
            tear_mmap_read_unlock(mm);
            
            if (!vma) {
                tear_debug("安全读取: VMA检查失败(可能是陷阱地址) addr=0x%lx\n", addr);
                break;
            }
        }
#endif

#if TEAR_SECURITY_CHECK_PRESENT
        /* 安全检查2: 缺页检测 */
        if (tear_would_fault(mm, addr)) {
            tear_debug("安全读取: 检测到缺页(跳过) addr=0x%lx\n", addr);
            break;
        }
#endif
        
        /* 获取物理地址（已包含安全检查） */
        phys = vaddr_to_phys_safe(mm, addr);
        if (phys == 0) {
            tear_debug("安全读取: 地址转换失败 addr=0x%lx\n", addr);
            break;
        }
        
        /* 验证PFN */
        pfn = phys >> PAGE_SHIFT;
        if (!tear_pfn_valid(pfn)) {
            tear_debug("安全读取: PFN无效 pfn=%lu\n", pfn);
            break;
        }
        
        /* 计算块大小 */
        offset = phys & ~PAGE_MASK;
        chunk = min(size - copied, PAGE_SIZE - offset);
        
        /* 获取内核虚拟地址 */
        kaddr = phys_to_virt(phys);
        if (!virt_addr_valid(kaddr)) {
            tear_debug("安全读取: 内核虚拟地址无效\n");
            break;
        }
        
        /* 使用安全拷贝 - 不会在故障时崩溃 */
        ret = tear_copy_from_kernel_nofault(
            (char *)kernel_buf + copied,
            kaddr,
            chunk
        );
        
        if (ret != 0) {
            tear_debug("安全读取: nofault拷贝失败 ret=%ld\n", ret);
            break;
        }
        
        copied += chunk;
        addr += chunk;
    }
    
    mmput(mm);
    
    /* 复制到用户空间 */
    if (copied == size) {
        if (copy_to_user(buffer, kernel_buf, size) == 0)
            success = true;
        else
            tear_debug("安全读取: 复制到用户空间失败\n");
    }
#if TEAR_SECURITY_SILENT_FAIL
    else if (copied > 0) {
        /* 静默失败模式: 返回已读取的部分，用零填充剩余 */
        memset((char *)kernel_buf + copied, 0, size - copied);
        if (copy_to_user(buffer, kernel_buf, size) == 0)
            success = true;
    }
#endif
    
    tear_free_buffer(kernel_buf, size);
    return success;
}

/*
 * ============================================================================
 * 安全内存写入
 * ============================================================================
 */

/*
 * 使用安全内核拷贝函数写入内存
 */
bool write_safe(pid_t pid, unsigned long addr,
                void __user *buffer, size_t size)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kernel_buf = NULL;
    size_t written = 0;
    bool success = false;
    
    /* 参数验证 */
    if (!buffer || size == 0 || size > TEAR_MAX_SAFE_RW_SIZE) {
        tear_debug("安全写入: 参数无效\n");
        return false;
    }
    
    if (addr < TEAR_MIN_VALID_ADDR) {
        tear_debug("安全写入: 地址过低 addr=0x%lx\n", addr);
        return false;
    }
    
    /* 获取目标进程 */
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task)
        return false;
    
    mm = get_task_mm(task);
    put_task_struct(task);
    
    if (!mm)
        return false;
    
    /* 分配内核缓冲区 */
    kernel_buf = tear_alloc_buffer(size);
    if (!kernel_buf) {
        mmput(mm);
        return false;
    }
    
    /* 从用户空间复制数据 */
    if (copy_from_user(kernel_buf, buffer, size)) {
        tear_debug("安全写入: 从用户空间复制失败\n");
        tear_free_buffer(kernel_buf, size);
        mmput(mm);
        return false;
    }
    
    /* 使用安全拷贝写入 */
    while (written < size) {
        phys_addr_t phys;
        unsigned long pfn;
        size_t offset;
        size_t chunk;
        void *kaddr;
        long ret;
        
#if TEAR_SECURITY_CHECK_VMA
        /* 安全检查1: VMA权限验证（写操作） */
        {
            struct vm_area_struct *vma;
            
            tear_mmap_read_lock(mm);
            vma = tear_find_safe_vma(mm, addr, true);
            tear_mmap_read_unlock(mm);
            
            if (!vma) {
                tear_debug("安全写入: VMA检查失败 addr=0x%lx\n", addr);
                break;
            }
        }
#endif

#if TEAR_SECURITY_CHECK_PRESENT
        /* 安全检查2: 缺页检测 */
        if (tear_would_fault(mm, addr)) {
            tear_debug("安全写入: 检测到缺页 addr=0x%lx\n", addr);
            break;
        }
#endif
        
        /* 获取物理地址 */
        phys = vaddr_to_phys_safe(mm, addr);
        if (phys == 0)
            break;
        
        /* 验证PFN */
        pfn = phys >> PAGE_SHIFT;
        if (!tear_pfn_valid(pfn))
            break;
        
        /* 计算块大小 */
        offset = phys & ~PAGE_MASK;
        chunk = min(size - written, PAGE_SIZE - offset);
        
        /* 获取内核虚拟地址 */
        kaddr = phys_to_virt(phys);
        if (!virt_addr_valid(kaddr))
            break;
        
        /* 使用安全拷贝写入 */
        ret = tear_copy_to_kernel_nofault(
            kaddr,
            (char *)kernel_buf + written,
            chunk
        );
        
        if (ret != 0) {
            tear_debug("安全写入: nofault拷贝失败 ret=%ld\n", ret);
            break;
        }
        
        written += chunk;
        addr += chunk;
    }
    
    mmput(mm);
    tear_free_buffer(kernel_buf, size);
    
    success = (written == size);
    return success;
}

/*
 * ============================================================================
 * 模块初始化/清理
 * ============================================================================
 */

int teargame_memory_safe_init(void)
{
    tear_info("安全内存子系统已初始化\n");
    tear_info("  严格模式: %s\n", TEAR_SECURITY_STRICT_MODE ? "启用" : "禁用");
    tear_info("  静默失败: %s\n", TEAR_SECURITY_SILENT_FAIL ? "启用" : "禁用");
    return 0;
}

void teargame_memory_safe_exit(void)
{
    tear_debug("安全内存子系统已清理\n");
}
