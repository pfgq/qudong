/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame 安全检查模块 v2.0
 * 
 * 提供以下安全检查功能：
 * - VMA权限检查（防止读取陷阱地址）
 * - 多层缺页检测（跳过未映射/换出/PROT_NONE页面）
 * - 陷阱地址综合检测（检测反作弊蜜罐）
 * - 页表安全验证
 * - 物理地址验证
 * - 软缺页处理（可选）
 */

#ifndef _TEARGAME_SECURITY_H
#define _TEARGAME_SECURITY_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>

#include "teargame_config.h"
#include "teargame_compat.h"

/*
 * ============================================================================
 * 页面状态定义
 * ============================================================================
 */

/* 页面状态码 */
#define PAGE_STATUS_OK              0   /* 页面安全可访问 */
#define PAGE_STATUS_NO_PTE          1   /* 无PTE（未映射） */
#define PAGE_STATUS_NOT_PRESENT     2   /* 不在物理内存中 */
#define PAGE_STATUS_SWAPPED         3   /* 已换出到swap */
#define PAGE_STATUS_PROT_NONE       4   /* PROT_NONE（无权限陷阱） */
#define PAGE_STATUS_SPECIAL         5   /* 特殊页（如零页） */
#define PAGE_STATUS_DEVICE          6   /* 设备映射 */
#define PAGE_STATUS_RESERVED        7   /* 保留页 */
#define PAGE_STATUS_GUARD           8   /* 保护页/Guard page */

/* 陷阱类型码 */
#define TRAP_NONE                   0   /* 非陷阱 */
#define TRAP_NO_VMA                 1   /* 无VMA（空洞） */
#define TRAP_NO_PERMISSION          2   /* 无读/写权限 */
#define TRAP_SUSPICIOUS             3   /* 可疑权限组合 */
#define TRAP_DEVICE                 4   /* 设备映射区域 */
#define TRAP_ANONYMOUS_RO           5   /* 可疑的匿名只读映射 */
#define TRAP_GUARD_PAGE             6   /* 保护页 */
#define TRAP_TINY_VMA               7   /* 极小VMA（可疑） */
#define TRAP_PERMISSION_REVOKED     8   /* 权限被撤销 */

/*
 * ============================================================================
 * VMA 安全检查
 * ============================================================================
 * 检测反作弊系统设置的陷阱VMA区域
 */

/*
 * 检查VMA是否安全可访问
 * 
 * 陷阱VMA特征：
 * - 无VM_READ权限
 * - VM_IO/VM_PFNMAP（设备映射）
 * - 权限异常组合
 * - 极小的匿名只读映射
 * 
 * @vma: 目标VMA
 * @write: 是否为写操作
 * @return: true=安全, false=危险/陷阱
 */
static inline bool tear_is_vma_safe(struct vm_area_struct *vma, bool write)
{
    unsigned long flags;
    unsigned long size;
    
    if (!vma)
        return false;
    
    flags = vma->vm_flags;
    size = vma->vm_end - vma->vm_start;
    
    /* 检查1: 必须有读权限 */
    if (!(flags & VM_READ)) {
        tear_security_debug("VMA无读权限 flags=0x%lx\n", flags);
        return false;
    }
    
    /* 检查2: 写操作必须有写权限 */
    if (write && !(flags & VM_WRITE)) {
        tear_security_debug("VMA无写权限 flags=0x%lx\n", flags);
        return false;
    }
    
#if TEAR_SECURITY_SKIP_DEVICE
    /* 检查3: 跳过设备映射（VM_IO = MMIO区域） */
    if (flags & VM_IO) {
        tear_security_debug("VMA是设备IO映射\n");
        return false;
    }
    
    /* 检查4: 跳过直接PFN映射 */
    if (flags & VM_PFNMAP) {
        tear_security_debug("VMA是PFN映射\n");
        return false;
    }
#endif

#if TEAR_SECURITY_STRICT_MODE
    /* 检查5: 可疑权限组合 - 权限被故意移除 */
    if ((flags & VM_MAYREAD) && !(flags & VM_READ)) {
        tear_security_debug("VMA权限被撤销\n");
        return false;
    }
    
    /* 检查6: 检测保护页标志 */
#ifdef VM_DONTEXPAND
    if (flags & VM_DONTEXPAND) {
        /* 不可扩展的VMA，可能是保护区域 */
        if (!(flags & VM_EXEC) && !(flags & VM_WRITE)) {
            tear_security_debug("VMA可能是保护页\n");
            return false;
        }
    }
#endif
    
    /* 检查7: 极小的匿名只读映射（高度可疑） */
    if (!vma->vm_file && !(flags & VM_WRITE) && !(flags & VM_EXEC)) {
        if (!(flags & VM_SHARED)) {
            /* 匿名只读私有映射 */
            if (size < PAGE_SIZE * 4) {
                tear_security_debug("VMA是极小匿名只读映射 size=%lu\n", size);
                return false;
            }
        }
    }
    
    /* 检查8: VM_DONTCOPY + 非共享（可疑） */
#ifdef VM_DONTCOPY
    if ((flags & VM_DONTCOPY) && !(flags & VM_SHARED)) {
        tear_security_debug("VMA有VM_DONTCOPY标志\n");
        return false;
    }
#endif

#endif /* TEAR_SECURITY_STRICT_MODE */
    
    return true;
}

/*
 * 查找并验证VMA
 */
static inline struct vm_area_struct *tear_find_safe_vma(struct mm_struct *mm,
                                                        unsigned long addr,
                                                        bool write)
{
    struct vm_area_struct *vma;
    
    if (!mm)
        return NULL;
    
    vma = find_vma(mm, addr);
    
    /* 检查地址是否在VMA范围内 */
    if (!vma || addr < vma->vm_start) {
        tear_security_debug("地址0x%lx不在任何VMA中\n", addr);
        return NULL;
    }
    
    /* 检查VMA是否安全 */
    if (!tear_is_vma_safe(vma, write)) {
        tear_security_debug("VMA不安全 addr=0x%lx\n", addr);
        return NULL;
    }
    
    return vma;
}

/*
 * ============================================================================
 * 多层页面状态检测
 * ============================================================================
 * 检测各种会触发缺页或反作弊检测的页面状态
 */

/*
 * 获取页面详细状态
 * 
 * 检测的缺页场景:
 * 1. PTE不存在 (pte_none)
 * 2. 页面已换出 (swap entry)
 * 3. PROT_NONE页 (无权限陷阱)
 * 4. 文件映射但未加载 (demand paging)
 * 5. 特殊页 (zero page等)
 * 
 * @mm: 目标进程内存描述符
 * @addr: 要检查的地址
 * @return: 页面状态码
 */
static inline int tear_page_status(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t pte_val;
    int status = PAGE_STATUS_NO_PTE;
    
    if (!mm || !mm->pgd)
        return PAGE_STATUS_NO_PTE;
    
    rcu_read_lock();
    
    /* 第1级: PGD */
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto out;
    
    /* 第2级: P4D */
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto out;
    
    /* 第3级: PUD */
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud))
        goto out;
    
    /* 检查PUD大页 */
    if (tear_pud_huge(*pud)) {
        status = PAGE_STATUS_OK;
        goto out;
    }
    
    if (pud_bad(*pud))
        goto out;
    
    /* 第4级: PMD */
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd))
        goto out;
    
    /* 检查PMD大页 */
    if (tear_pmd_huge(*pmd)) {
        status = PAGE_STATUS_OK;
        goto out;
    }
    
    if (pmd_bad(*pmd))
        goto out;
    
    /* 第5级: PTE */
    pte = tear_pte_offset_map(pmd, addr);
    if (!pte)
        goto out;
    
    pte_val = READ_ONCE(*pte);
    tear_pte_unmap(pte);
    
    /* 分析PTE状态 */
    if (pte_none(pte_val)) {
        status = PAGE_STATUS_NO_PTE;
    } else if (!pte_present(pte_val)) {
        /* 页面不在物理内存中 */
#ifdef __HAVE_ARCH_PTE_SWP_EXCLUSIVE
        if (is_swap_pte(pte_val)) {
            status = PAGE_STATUS_SWAPPED;
        } else
#endif
        {
            status = PAGE_STATUS_NOT_PRESENT;
        }
    } else {
        /* 页面在物理内存中，检查其他属性 */
#ifdef pte_protnone
        if (pte_protnone(pte_val)) {
            status = PAGE_STATUS_PROT_NONE;
            goto out;
        }
#endif
        
#ifdef pte_special
        if (pte_special(pte_val)) {
            status = PAGE_STATUS_SPECIAL;
            goto out;
        }
#endif
        
        status = PAGE_STATUS_OK;
    }
    
out:
    rcu_read_unlock();
    return status;
}

/*
 * 检查页面是否可安全读取
 */
static inline bool tear_is_page_readable(struct mm_struct *mm, unsigned long addr)
{
    int status = tear_page_status(mm, addr);
    return status == PAGE_STATUS_OK;
}

/*
 * 获取页面状态描述字符串（调试用）
 */
static inline const char *tear_page_status_str(int status)
{
    switch (status) {
    case PAGE_STATUS_OK:          return "OK";
    case PAGE_STATUS_NO_PTE:      return "NO_PTE";
    case PAGE_STATUS_NOT_PRESENT: return "NOT_PRESENT";
    case PAGE_STATUS_SWAPPED:     return "SWAPPED";
    case PAGE_STATUS_PROT_NONE:   return "PROT_NONE";
    case PAGE_STATUS_SPECIAL:     return "SPECIAL";
    case PAGE_STATUS_DEVICE:      return "DEVICE";
    case PAGE_STATUS_RESERVED:    return "RESERVED";
    case PAGE_STATUS_GUARD:       return "GUARD";
    default:                      return "UNKNOWN";
    }
}

/*
 * ============================================================================
 * 陷阱地址综合检测
 * ============================================================================
 * 检测反作弊系统设置的各种蜜罐内存区域
 */

/*
 * 检测陷阱地址
 * 
 * 常见陷阱特征:
 * 1. 匿名只读私有映射 (无文件、无写权限)
 * 2. 权限被移除的VMA (有MAYREAD但无READ)
 * 3. 保护页 (VM_DONTEXPAND + 只读)
 * 4. 设备映射 (VM_IO/VM_PFNMAP)
 * 5. 异常大小的VMA (极小)
 * 6. 空隙区域 (VMA之间的间隙)
 * 7. 奇异权限组合
 * 
 * @mm: 目标进程内存描述符
 * @addr: 要检查的地址
 * @write: 是否为写操作
 * @return: 陷阱类型码 (TRAP_NONE = 非陷阱)
 */
static inline int tear_detect_trap(struct mm_struct *mm, 
                                   unsigned long addr,
                                   bool write)
{
    struct vm_area_struct *vma;
    unsigned long flags;
    unsigned long size;
    
    if (!mm)
        return TRAP_NO_VMA;
    
    tear_mmap_read_lock(mm);
    
    vma = find_vma(mm, addr);
    if (!vma || addr < vma->vm_start) {
        tear_mmap_read_unlock(mm);
        return TRAP_NO_VMA;
    }
    
    flags = vma->vm_flags;
    size = vma->vm_end - vma->vm_start;
    
    /* 检测1: 基本权限 */
    if (!(flags & VM_READ)) {
        tear_mmap_read_unlock(mm);
        return TRAP_NO_PERMISSION;
    }
    
    if (write && !(flags & VM_WRITE)) {
        tear_mmap_read_unlock(mm);
        return TRAP_NO_PERMISSION;
    }
    
    /* 检测2: 设备映射 */
    if (flags & (VM_IO | VM_PFNMAP)) {
        tear_mmap_read_unlock(mm);
        return TRAP_DEVICE;
    }
    
    /* 检测3: 权限被撤销 */
    if ((flags & VM_MAYREAD) && !(flags & VM_READ)) {
        tear_mmap_read_unlock(mm);
        return TRAP_PERMISSION_REVOKED;
    }
    
    /* 检测4: 可疑的匿名只读映射 */
    if (!vma->vm_file && !(flags & VM_WRITE) && !(flags & VM_EXEC)) {
        if (!(flags & VM_SHARED)) {
            /* 检测4a: 极小区域更可疑 */
            if (size < PAGE_SIZE * 4) {
                tear_mmap_read_unlock(mm);
                return TRAP_TINY_VMA;
            }
            
            /* 检测4b: 匿名只读私有映射 */
#if TEAR_SECURITY_STRICT_MODE
            tear_mmap_read_unlock(mm);
            return TRAP_ANONYMOUS_RO;
#endif
        }
    }
    
    /* 检测5: 保护页 */
#ifdef VM_DONTEXPAND
    if ((flags & VM_DONTEXPAND) && !(flags & VM_EXEC) && !(flags & VM_WRITE)) {
        tear_mmap_read_unlock(mm);
        return TRAP_GUARD_PAGE;
    }
#endif
    
    /* 检测6: VM_DONTCOPY + 非共享 */
#ifdef VM_DONTCOPY
    if ((flags & VM_DONTCOPY) && !(flags & VM_SHARED)) {
        tear_mmap_read_unlock(mm);
        return TRAP_SUSPICIOUS;
    }
#endif
    
    tear_mmap_read_unlock(mm);
    return TRAP_NONE;
}

/*
 * 获取陷阱类型描述字符串（调试用）
 */
static inline const char *tear_trap_type_str(int trap)
{
    switch (trap) {
    case TRAP_NONE:               return "NONE";
    case TRAP_NO_VMA:             return "NO_VMA";
    case TRAP_NO_PERMISSION:      return "NO_PERMISSION";
    case TRAP_SUSPICIOUS:         return "SUSPICIOUS";
    case TRAP_DEVICE:             return "DEVICE";
    case TRAP_ANONYMOUS_RO:       return "ANONYMOUS_RO";
    case TRAP_GUARD_PAGE:         return "GUARD_PAGE";
    case TRAP_TINY_VMA:           return "TINY_VMA";
    case TRAP_PERMISSION_REVOKED: return "PERMISSION_REVOKED";
    default:                      return "UNKNOWN";
    }
}

/*
 * ============================================================================
 * PTE 安全检查
 * ============================================================================
 */

/*
 * 检查PTE是否安全可访问
 */
static inline bool tear_is_pte_safe(pte_t pte)
{
    /* 检查1: PTE必须存在 */
    if (pte_none(pte)) {
        tear_security_debug("PTE不存在\n");
        return false;
    }
    
#if TEAR_SECURITY_CHECK_PRESENT
    /* 检查2: 页面必须在物理内存中 */
    if (!pte_present(pte)) {
        tear_security_debug("页面不在内存中\n");
        return false;
    }
#endif

#if TEAR_SECURITY_CHECK_PROTNONE
    /* 检查3: 检测PROT_NONE页 */
#ifdef pte_protnone
    if (pte_protnone(pte)) {
        tear_security_debug("PROT_NONE页(陷阱)\n");
        return false;
    }
#endif
#endif

#ifdef CONFIG_ARM64
    /* ARM64特定检查: 用户态访问权限 */
#ifdef PTE_USER
    if (!(pte_val(pte) & PTE_USER)) {
        tear_security_debug("非用户态可访问\n");
        return false;
    }
#endif
#endif
    
    return true;
}

/*
 * 检测地址是否会触发缺页异常
 */
static inline bool tear_would_fault(struct mm_struct *mm, unsigned long addr)
{
    int status = tear_page_status(mm, addr);
    return status != PAGE_STATUS_OK;
}

/*
 * ============================================================================
 * 物理地址安全检查
 * ============================================================================
 */

/*
 * 检查物理地址是否指向安全的RAM
 */
static inline bool tear_is_phys_safe(phys_addr_t phys)
{
    unsigned long pfn = phys >> PAGE_SHIFT;
    struct page *page;
    
    /* 检查1: PFN必须有效 */
    if (!tear_pfn_valid(pfn)) {
        tear_security_debug("PFN无效 pfn=%lu\n", pfn);
        return false;
    }
    
    page = pfn_to_page(pfn);
    if (!page) {
        tear_security_debug("页面结构为空\n");
        return false;
    }
    
#if TEAR_SECURITY_SKIP_RESERVED
    /* 检查2: 跳过保留页 */
    if (PageReserved(page)) {
        tear_security_debug("保留页\n");
        return false;
    }
#endif
    
    /* 检查3: 确保是普通内存 */
#ifdef page_is_ram
    if (!page_is_ram(pfn)) {
        tear_security_debug("非RAM地址\n");
        return false;
    }
#endif
    
    return true;
}

/*
 * ============================================================================
 * 综合安全检查
 * ============================================================================
 */

/*
 * 完整的地址安全检查
 * 
 * 执行所有安全检查：
 * 1. 地址范围检查
 * 2. VMA检查
 * 3. 陷阱检测
 * 4. 缺页检查
 */
static inline bool tear_is_addr_safe(struct mm_struct *mm, 
                                     unsigned long addr,
                                     size_t size,
                                     bool write)
{
    unsigned long end_addr;
    int trap;
    
    if (!mm)
        return false;
    
    /* 检查地址范围 */
    if (addr < TEAR_MIN_VALID_ADDR) {
        tear_security_debug("地址过低 addr=0x%lx\n", addr);
        return false;
    }
    
    end_addr = addr + size;
    if (end_addr < addr) {
        tear_security_debug("地址溢出\n");
        return false;
    }
    
#if TEAR_SECURITY_CHECK_VMA
    /* 陷阱检测 */
    trap = tear_detect_trap(mm, addr, write);
    if (trap != TRAP_NONE) {
        tear_security_debug("检测到陷阱 type=%s addr=0x%lx\n", 
                           tear_trap_type_str(trap), addr);
        return false;
    }
#endif

#if TEAR_SECURITY_CHECK_PRESENT
    /* 缺页检查 */
    if (tear_would_fault(mm, addr)) {
        tear_security_debug("会触发缺页 addr=0x%lx status=%s\n", 
                           addr, tear_page_status_str(tear_page_status(mm, addr)));
        return false;
    }
#endif
    
    return true;
}

/*
 * 检查地址范围是否全部安全（逐页检查）
 */
static inline bool tear_is_range_safe(struct mm_struct *mm,
                                      unsigned long addr,
                                      size_t size,
                                      bool write)
{
    unsigned long end = addr + size;
    unsigned long check_addr;
    
    /* 逐页检查 */
    for (check_addr = addr & PAGE_MASK; 
         check_addr < end; 
         check_addr += PAGE_SIZE) {
        
        if (!tear_is_addr_safe(mm, check_addr, 1, write))
            return false;
    }
    
    return true;
}

/*
 * ============================================================================
 * 安全的页表遍历
 * ============================================================================
 */

/*
 * 安全地将虚拟地址转换为物理地址
 */
static inline phys_addr_t tear_vaddr_to_phys_secure(struct mm_struct *mm,
                                                    unsigned long vaddr,
                                                    unsigned long *page_size,
                                                    bool write)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t pte_val;
    pud_t pud_val;
    pmd_t pmd_val;
    phys_addr_t phys = 0;
    
    if (!mm || !mm->pgd)
        return 0;
    
    /* 默认4KB页 */
    if (page_size)
        *page_size = PAGE_SIZE;
    
#if TEAR_SECURITY_CHECK_VMA
    /* VMA安全检查 */
    {
        struct vm_area_struct *vma;
        
        tear_mmap_read_lock(mm);
        vma = tear_find_safe_vma(mm, vaddr, write);
        tear_mmap_read_unlock(mm);
        
        if (!vma) {
            tear_security_debug("VMA检查失败 vaddr=0x%lx\n", vaddr);
            return 0;
        }
    }
#endif
    
    rcu_read_lock();
    
    /* PGD */
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto out;
    
    /* P4D */
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto out;
    
    /* PUD */
    pud = pud_offset(p4d, vaddr);
    pud_val = READ_ONCE(*pud);
    
    if (pud_none(pud_val))
        goto out;
    
    /* 检查1GB大页 */
    if (tear_pud_huge(pud_val)) {
        phys = (pud_pfn(pud_val) << PAGE_SHIFT) | (vaddr & ~PUD_MASK);
        if (page_size)
            *page_size = PUD_SIZE;
        
        if (!tear_is_phys_safe(phys)) {
            phys = 0;
            goto out;
        }
        goto out;
    }
    
    if (pud_bad(pud_val))
        goto out;
    
    /* PMD */
    pmd = pmd_offset(pud, vaddr);
    pmd_val = READ_ONCE(*pmd);
    
    if (pmd_none(pmd_val))
        goto out;
    
    /* 检查2MB大页 */
    if (tear_pmd_huge(pmd_val)) {
        phys = (pmd_pfn(pmd_val) << PAGE_SHIFT) | (vaddr & ~PMD_MASK);
        if (page_size)
            *page_size = PMD_SIZE;
        
        if (!tear_is_phys_safe(phys)) {
            phys = 0;
            goto out;
        }
        goto out;
    }
    
    if (pmd_bad(pmd_val))
        goto out;
    
    /* PTE */
    pte = tear_pte_offset_map(pmd, vaddr);
    if (!pte)
        goto out;
    
    pte_val = READ_ONCE(*pte);
    tear_pte_unmap(pte);
    
    /* PTE安全检查 */
    if (!tear_is_pte_safe(pte_val)) {
        tear_security_debug("PTE不安全 vaddr=0x%lx\n", vaddr);
        goto out;
    }
    
    phys = (pte_pfn(pte_val) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
    
    /* 物理地址安全检查 */
    if (!tear_is_phys_safe(phys)) {
        phys = 0;
        goto out;
    }
    
out:
    rcu_read_unlock();
    return phys;
}

/*
 * ============================================================================
 * 软缺页处理（可选高级功能）
 * ============================================================================
 * 通过 get_user_pages 主动请求页面，不触发异常记录
 */

#if defined(TEAR_ENABLE_SOFT_FAULT) && TEAR_ENABLE_SOFT_FAULT

/*
 * 软缺页 - 通过get_user_pages请求页面
 * 不会触发游戏的缺页异常监控
 */
static inline int tear_soft_fault(struct mm_struct *mm, unsigned long addr)
{
    struct page *page = NULL;
    int ret;
    
    tear_mmap_read_lock(mm);
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    ret = get_user_pages_remote(mm, addr, 1, 
                                FOLL_FORCE | FOLL_REMOTE,
                                &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    ret = get_user_pages_remote(mm, addr, 1,
                                FOLL_FORCE, &page, NULL, NULL);
#else
    ret = get_user_pages_remote(current, mm, addr, 1,
                                FOLL_FORCE, &page, NULL, NULL);
#endif
    
    tear_mmap_read_unlock(mm);
    
    if (ret > 0 && page) {
        put_page(page);
        return 0;
    }
    
    return -EFAULT;
}

/*
 * 预热页面 - 确保可安全读取
 */
static inline bool tear_warmup_page(struct mm_struct *mm, unsigned long addr)
{
    int status = tear_page_status(mm, addr);
    
    if (status == PAGE_STATUS_OK)
        return true;
    
    if (status == PAGE_STATUS_NOT_PRESENT || 
        status == PAGE_STATUS_SWAPPED) {
        /* 尝试软缺页 */
        if (tear_soft_fault(mm, addr) == 0)
            return true;
    }
    
    return false;
}

#endif /* TEAR_ENABLE_SOFT_FAULT */

#endif /* _TEARGAME_SECURITY_H */
