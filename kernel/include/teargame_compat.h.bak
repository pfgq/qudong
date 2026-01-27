/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame Kernel Version Compatibility Layer
 * Supports Linux 5.10, 5.15, 6.1, 6.6+
 */

#ifndef _TEARGAME_COMPAT_H
#define _TEARGAME_COMPAT_H

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/io.h>

/*
 * ============================================================================
 * Memory Management Lock Compatibility
 * ============================================================================
 * Linux 5.8+: mmap_lock replaces mmap_sem
 * But some 5.10 variants may still use mmap_sem
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
  #define tear_mmap_read_lock(mm)       mmap_read_lock(mm)
  #define tear_mmap_read_unlock(mm)     mmap_read_unlock(mm)
  #define tear_mmap_read_trylock(mm)    mmap_read_trylock(mm)
  #define tear_mmap_write_lock(mm)      mmap_write_lock(mm)
  #define tear_mmap_write_unlock(mm)    mmap_write_unlock(mm)
#else
  #define tear_mmap_read_lock(mm)       down_read(&(mm)->mmap_sem)
  #define tear_mmap_read_unlock(mm)     up_read(&(mm)->mmap_sem)
  #define tear_mmap_read_trylock(mm)    down_read_trylock(&(mm)->mmap_sem)
  #define tear_mmap_write_lock(mm)      down_write(&(mm)->mmap_sem)
  #define tear_mmap_write_unlock(mm)    up_write(&(mm)->mmap_sem)
#endif

/*
 * ============================================================================
 * VMA Iteration Compatibility
 * ============================================================================
 * Linux 6.1+: Uses maple tree instead of linked list
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
  #define TEAR_USE_MAPLE_TREE 1
  #include <linux/maple_tree.h>
  
  #define tear_vma_iter_init(vmi, mm, addr) \
      vma_iter_init(vmi, mm, addr)
  
  #define tear_for_each_vma(vmi, vma) \
      for_each_vma(vmi, vma)
      
#else
  #define TEAR_USE_MAPLE_TREE 0
  
  /* Use traditional linked list VMA traversal */
  #define tear_for_each_vma_legacy(mm, vma) \
      for ((vma) = (mm)->mmap; (vma); (vma) = (vma)->vm_next)
#endif

/*
 * VMA traversal wrapper - works on all versions
 */
#if TEAR_USE_MAPLE_TREE
  #define TEAR_VMA_ITERATOR_DECL(name, mm, addr) \
      VMA_ITERATOR(name, mm, addr)
#else
  /* Legacy: just declare the vma pointer */
  #define TEAR_VMA_ITERATOR_DECL(name, mm, addr) \
      struct vm_area_struct *name##_vma = NULL; \
      (void)(addr)
#endif

/*
 * ============================================================================
 * PTE Mapping Compatibility  
 * ============================================================================
 * Linux 5.11+: pte_offset_map may return NULL
 * Linux 6.5+: pte_offset_map_lock changes
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
  #define tear_pte_offset_map(pmd, addr) pte_offset_map(pmd, addr)
  #define tear_pte_unmap(pte)            pte_unmap(pte)
#else
  #define tear_pte_offset_map(pmd, addr) pte_offset_kernel(pmd, addr)
  #define tear_pte_unmap(pte)            do { } while(0)
#endif

/*
 * ============================================================================
 * Copy from/to User Compatibility
 * ============================================================================
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
  #define tear_access_ok(addr, size) access_ok((addr), (size))
#else
  #define tear_access_ok(addr, size) access_ok(VERIFY_READ, (addr), (size))
#endif

/*
 * ============================================================================
 * Kernel Fault Handling Compatibility
 * ============================================================================
 * Linux 5.8+: probe_kernel_read renamed to copy_from_kernel_nofault
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
  #define tear_copy_from_kernel_nofault(dst, src, size) \
      copy_from_kernel_nofault(dst, src, size)
  #define tear_copy_to_kernel_nofault(dst, src, size) \
      copy_to_kernel_nofault(dst, src, size)
#else
  #define tear_copy_from_kernel_nofault(dst, src, size) \
      probe_kernel_read(dst, src, size)
  #define tear_copy_to_kernel_nofault(dst, src, size) \
      probe_kernel_write(dst, src, size)
#endif

/*
 * ============================================================================
 * Memory Remap Compatibility
 * ============================================================================
 */
#ifndef MEMREMAP_WB
  #define MEMREMAP_WB 1
#endif

#ifndef MEMREMAP_WT
  #define MEMREMAP_WT 2
#endif

/*
 * ============================================================================
 * Task/Process Compatibility
 * ============================================================================
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
  /* get_task_exe_file available */
  #define tear_get_task_exe_file(task) get_task_exe_file(task)
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
 * ============================================================================
 * KProbe Compatibility
 * ============================================================================
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
  /* kretprobe_instance has 'data' field accessible via ri->data */
  #define tear_kretprobe_data(ri) ((void *)((ri)->data))
#else
  #define tear_kretprobe_data(ri) ((void *)((ri)->data))
#endif

/*
 * ============================================================================
 * Input Subsystem Compatibility
 * ============================================================================
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
  /* input_mt_init_slots flags changed */
  #define TEAR_MT_FLAGS (INPUT_MT_DIRECT | INPUT_MT_DROP_UNUSED)
#else
  #define TEAR_MT_FLAGS INPUT_MT_DIRECT
#endif

/*
 * ============================================================================
 * Reference Count Compatibility
 * ============================================================================
 * Linux 5.x uses refcount_t, older uses atomic_t
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
  #include <linux/refcount.h>
  #define tear_refcount_read(r) refcount_read(r)
#else
  #define tear_refcount_read(r) atomic_read(r)
#endif

/*
 * ============================================================================
 * PFN Valid Check Compatibility
 * ============================================================================
 * ARM64 always has pfn_valid() available
 * For other architectures, fallback to max_pfn check
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
 * ============================================================================
 * Page Table Helpers
 * ============================================================================
 */

/* Check if PUD is a huge page (1GB) */
static inline bool tear_pud_huge(pud_t pud)
{
#ifdef CONFIG_HUGETLB_PAGE
  #if defined(pud_huge)
    return pud_huge(pud);
  #elif defined(pud_large)
    return pud_large(pud);
  #else
    return (pud_val(pud) & 0x3) == 0x1;  /* ARM64 block descriptor */
  #endif
#else
    return false;
#endif
}

/* Check if PMD is a huge page (2MB) */
static inline bool tear_pmd_huge(pmd_t pmd)
{
#ifdef CONFIG_HUGETLB_PAGE
  #if defined(pmd_huge)
    return pmd_huge(pmd);
  #elif defined(pmd_large)
    return pmd_large(pmd);
  #else
    return (pmd_val(pmd) & 0x3) == 0x1;  /* ARM64 block descriptor */
  #endif
#else
    return false;
#endif
}

/*
 * ============================================================================
 * ARM64 Specific Definitions
 * ============================================================================
 */
#ifdef CONFIG_ARM64

/* ARM64 page table masks */
#ifndef PUD_MASK
  #define PUD_MASK  (~(PUD_SIZE - 1))
#endif

#ifndef PMD_MASK
  #define PMD_MASK  (~(PMD_SIZE - 1))
#endif

/* ARM64 descriptor types */
#define ARM64_DESC_INVALID  0x0
#define ARM64_DESC_BLOCK    0x1
#define ARM64_DESC_TABLE    0x3
#define ARM64_DESC_PAGE     0x3

#endif /* CONFIG_ARM64 */

/*
 * ============================================================================
 * 工具宏定义
 * ============================================================================
 */

/* 内核版本检查宏 */
#define TEAR_KERNEL_VERSION_GE(major, minor, patch) \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(major, minor, patch))

/* 调试输出宏 */
#ifdef DEBUG
  #define tear_debug(fmt, ...) \
      pr_debug("[TearGame] " fmt, ##__VA_ARGS__)
#else
  #define tear_debug(fmt, ...) do { } while(0)
#endif

/* 日志输出宏（中文前缀） */
#define tear_info(fmt, ...)  pr_info("[TearGame] " fmt, ##__VA_ARGS__)
#define tear_warn(fmt, ...)  pr_warn("[TearGame] 警告: " fmt, ##__VA_ARGS__)
#define tear_err(fmt, ...)   pr_err("[TearGame] 错误: " fmt, ##__VA_ARGS__)

/* 安全检查专用日志 */
#define tear_security_warn(fmt, ...) \
    pr_warn("[TearGame] 安全: " fmt, ##__VA_ARGS__)
#define tear_security_debug(fmt, ...) \
    tear_debug("安全检查: " fmt, ##__VA_ARGS__)

/*
 * ============================================================================
 * Static Assertions for Compatibility
 * ============================================================================
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
  #error "TearGame requires Linux kernel 5.10 or later"
#endif

#ifndef CONFIG_ARM64
  #warning "TearGame is optimized for ARM64 architecture"
#endif

#endif /* _TEARGAME_COMPAT_H */
