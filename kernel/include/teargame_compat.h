/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame 内核多版本兼容层
 * 支持 Linux 4.19, 5.x, 6.x+（自动分支）
 */

#ifndef _TEARGAME_COMPAT_H
#define _TEARGAME_COMPAT_H

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/io.h>

/*
 * mmap锁兼容
 * 5.8+ 有 mmap_lock，4.19~5.7 只有 mmap_sem
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
#  define tear_mmap_read_lock(mm)       mmap_read_lock(mm)
#  define tear_mmap_read_unlock(mm)     mmap_read_unlock(mm)
#  define tear_mmap_read_trylock(mm)    mmap_read_trylock(mm)
#  define tear_mmap_write_lock(mm)      mmap_write_lock(mm)
#  define tear_mmap_write_unlock(mm)    mmap_write_unlock(mm)
#else
#  define tear_mmap_read_lock(mm)       down_read(&(mm)->mmap_sem)
#  define tear_mmap_read_unlock(mm)     up_read(&(mm)->mmap_sem)
#  define tear_mmap_read_trylock(mm)    down_read_trylock(&(mm)->mmap_sem)
#  define tear_mmap_write_lock(mm)      down_write(&(mm)->mmap_sem)
#  define tear_mmap_write_unlock(mm)    up_write(&(mm)->mmap_sem)
#endif

/*
 * VMA 遍历兼容（6.1 之前用链表）
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
#  define TEAR_USE_MAPLE_TREE 1
#  include <linux/maple_tree.h>
#  define tear_vma_iter_init(vmi, mm, addr) vma_iter_init(vmi, mm, addr)
#  define tear_for_each_vma(vmi, vma) for_each_vma(vmi, vma)
#else
#  define TEAR_USE_MAPLE_TREE 0
#  define tear_for_each_vma_legacy(mm, vma) \
       for ((vma) = (mm)->mmap; (vma); (vma) = (vma)->vm_next)
#endif

/*
 * VMA 遍历声明宏
 */
#if TEAR_USE_MAPLE_TREE
#  define TEAR_VMA_ITERATOR_DECL(name, mm, addr) VMA_ITERATOR(name, mm, addr)
#else
#  define TEAR_VMA_ITERATOR_DECL(name, mm, addr) \
      struct vm_area_struct *name##_vma = NULL; (void)(addr)
#endif

/*
 * PTE 兼容（5.11+ pte_offset_map 可为NULL，4.19用 pte_offset_kernel）
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
#  define tear_pte_offset_map(pmd, addr) pte_offset_map(pmd, addr)
#  define tear_pte_unmap(pte)            pte_unmap(pte)
#else
#  define tear_pte_offset_map(pmd, addr) pte_offset_kernel(pmd, addr)
#  define tear_pte_unmap(pte)            do { } while(0)
#endif

/*
 * copy_from/to 用户空间兼容（5.8+用copy_from_kernel_nofault，4.19用probe_kernel_read）
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
#  define tear_copy_from_kernel_nofault(dst, src, size) copy_from_kernel_nofault(dst, src, size)
#  define tear_copy_to_kernel_nofault(dst, src, size)   copy_to_kernel_nofault(dst, src, size)
#else
#  define tear_copy_from_kernel_nofault(dst, src, size) probe_kernel_read(dst, src, size)
#  define tear_copy_to_kernel_nofault(dst, src, size)   probe_kernel_write(dst, src, size)
#endif

/*
 * access_ok 兼容（5.0前必须加 VERIFY_READ/WRITE）
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#  define tear_access_ok(addr, size) access_ok((addr), (size))
#else
#  define tear_access_ok(addr, size) access_ok(VERIFY_READ, (addr), (size))
#endif

/*
 * get_task_exe_file 兼容（5.14+自带，4.19用 mm->exe_file）
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
#  define tear_get_task_exe_file(task) get_task_exe_file(task)
#else
static inline struct file *tear_get_task_exe_file(struct task_struct *task)
{
    struct file *exe_file = NULL;
    struct mm_struct *mm = get_task_mm(task);
    if (mm) {
        exe_file = mm->exe_file;
        if (exe_file)
            get_file(exe_file);
        mmput(mm);
    }
    return exe_file;
}
#endif

/*
 * input_mt_init_slots flags 兼容
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
#  define TEAR_MT_FLAGS (INPUT_MT_DIRECT | INPUT_MT_DROP_UNUSED)
#else
#  define TEAR_MT_FLAGS INPUT_MT_DIRECT
#endif

/*
 * refcount/atomic_t 兼容
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#  include <linux/refcount.h>
#  define tear_refcount_read(r) refcount_read(r)
#else
#  define tear_refcount_read(r) atomic_read(r)
#endif

/*
 * pfn_valid 兼容（ARM64/常规都直接用pfn_valid，极老内核才特殊）
 */
static inline bool tear_pfn_valid(unsigned long pfn)
{
#if defined(CONFIG_ARM64) || defined(CONFIG_HAVE_ARCH_PFN_VALID)
    return pfn_valid(pfn);
#else
    extern unsigned long max_pfn;
    return pfn < max_pfn;
#endif
}

/*
 * 工具日志宏
 */
#ifdef DEBUG
#  define tear_debug(fmt, ...) pr_debug("[TearGame] " fmt, ##__VA_ARGS__)
#else
#  define tear_debug(fmt, ...) do { } while(0)
#endif

#define tear_info(fmt, ...)  pr_info("[TearGame] " fmt, ##__VA_ARGS__)
#define tear_warn(fmt, ...)  pr_warn("[TearGame] 警告: " fmt, ##__VA_ARGS__)
#define tear_err(fmt, ...)   pr_err("[TearGame] 错误: " fmt, ##__VA_ARGS__)

/*
 * 只需确保内核 >= 4.19 即可
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0)
#  error "TearGame requires Linux kernel 4.19 or later"
#endif

#endif /* _TEARGAME_COMPAT_H */
