// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 内存操作模块 v2.0
 * 
 * 基于物理页表的内存读写，包含：
 * - 大页支持 (2MB/1GB)
 * - VMA安全检查（防止读取陷阱地址）
 * - 多层缺页检测
 * - 物理地址验证
 * - 增强页表遍历缓存（LRU策略）
 * - ARM64 NEON加速内存拷贝
 * - 智能预取策略
 */

#include "teargame.h"
#include "teargame_security.h"
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/percpu.h>
#include <linux/prefetch.h>
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <asm/io.h>

#ifdef CONFIG_ARM64
#include <asm/neon.h>
#endif

/*
 * ============================================================================
 * 私有常量
 * ============================================================================
 */

/* 每次页表遍历的最大块大小 */
#define TEAR_CHUNK_SIZE         PAGE_SIZE

/* 内存映射标志 */
#define TEAR_REMAP_FLAGS        MEMREMAP_WB

/* 增强缓存配置 */
#define TEAR_PTW_CACHE_SIZE_V2  64          /* 增加到64条 */
#define TEAR_PTW_CACHE_EXPIRY_V2 (HZ / 5)   /* 200ms过期 */

/* 智能预取配置 */
#define TEAR_PREFETCH_CONFIDENCE_THRESHOLD  3
#define TEAR_PREFETCH_MAX_STRIDE           (PAGE_SIZE * 4)

/*
 * ============================================================================
 * NEON 加速内存拷贝 (ARM64)
 * ============================================================================
 */

#ifdef CONFIG_ARM64

/*
 * NEON 加速的内存拷贝
 * 使用 NEON 寄存器一次拷贝 64 字节
 */
static void tear_memcpy_neon(void *dst, const void *src, size_t n)
{
    /* 只在非中断上下文且数据足够大时使用 NEON */
    if (n >= 64 && !in_interrupt() && !irqs_disabled()) {
        kernel_neon_begin();
        
        /* 使用 NEON 寄存器批量拷贝 */
        while (n >= 64) {
            asm volatile(
                "ldp q0, q1, [%1]\n"
                "ldp q2, q3, [%1, #32]\n"
                "stp q0, q1, [%0]\n"
                "stp q2, q3, [%0, #32]\n"
                : 
                : "r"(dst), "r"(src)
                : "memory", "v0", "v1", "v2", "v3"
            );
            dst += 64;
            src += 64;
            n -= 64;
        }
        
        kernel_neon_end();
    }
    
    /* 剩余部分使用普通拷贝 */
    if (n > 0)
        memcpy(dst, src, n);
}

#define tear_fast_memcpy tear_memcpy_neon

#else /* !CONFIG_ARM64 */

#define tear_fast_memcpy memcpy

#endif /* CONFIG_ARM64 */

/*
 * ============================================================================
 * 增强页表缓存 (Page Table Walk Cache v2.0)
 * ============================================================================
 * 特性:
 * - 更大的缓存容量 (64条/CPU)
 * - LRU 替换策略
 * - 命中计数统计
 * - 更长的过期时间
 */

#if TEAR_ENABLE_PTW_CACHE

/* 增强缓存条目结构 */
struct tear_ptw_cache_entry_v2 {
    pid_t           pid;            /* 进程ID */
    unsigned long   vaddr_page;     /* 虚拟地址（页对齐） */
    phys_addr_t     phys_page;      /* 物理地址（页对齐） */
    unsigned long   page_size;      /* 页大小 */
    unsigned long   timestamp;      /* 缓存时间 (jiffies) */
    unsigned int    hit_count;      /* 命中计数（用于LRU） */
    bool            valid;          /* 是否有效 */
};

/* Per-CPU 增强缓存结构 */
struct tear_ptw_cache_v2 {
    struct tear_ptw_cache_entry_v2 entries[TEAR_PTW_CACHE_SIZE_V2];
    unsigned int    next_slot;      /* 下一个写入槽位 */
    unsigned long   total_hits;     /* 总命中数 */
    unsigned long   total_misses;   /* 总未命中数 */
};

/* 定义 per-CPU 缓存变量 */
static DEFINE_PER_CPU(struct tear_ptw_cache_v2, ptw_cache_v2);

/*
 * LRU 槽位选择
 * 找到最少使用的槽位
 */
static unsigned int ptw_cache_find_lru_slot(struct tear_ptw_cache_v2 *cache)
{
    unsigned int min_hits = UINT_MAX;
    unsigned int lru_slot = 0;
    unsigned long now = jiffies;
    int i;
    
    for (i = 0; i < TEAR_PTW_CACHE_SIZE_V2; i++) {
        struct tear_ptw_cache_entry_v2 *e = &cache->entries[i];
        
        /* 优先选择无效槽位 */
        if (!e->valid)
            return i;
        
        /* 选择过期的槽位 */
        if (time_after(now, e->timestamp + TEAR_PTW_CACHE_EXPIRY_V2))
            return i;
        
        /* 选择命中最少的槽位 */
        if (e->hit_count < min_hits) {
            min_hits = e->hit_count;
            lru_slot = i;
        }
    }
    
    return lru_slot;
}

/*
 * 查找缓存（增强版）
 */
static bool ptw_cache_lookup(pid_t pid, unsigned long vaddr,
                             phys_addr_t *phys_out, unsigned long *page_size_out)
{
    struct tear_ptw_cache_v2 *cache;
    unsigned long vaddr_page = vaddr & PAGE_MASK;
    unsigned long now = jiffies;
    int i;
    
    preempt_disable();
    cache = this_cpu_ptr(&ptw_cache_v2);
    
    for (i = 0; i < TEAR_PTW_CACHE_SIZE_V2; i++) {
        struct tear_ptw_cache_entry_v2 *e = &cache->entries[i];
        
        if (!e->valid)
            continue;
        
        /* 检查是否过期 */
        if (time_after(now, e->timestamp + TEAR_PTW_CACHE_EXPIRY_V2)) {
            e->valid = false;
            continue;
        }
        
        /* 检查匹配 */
        if (e->pid == pid && e->vaddr_page == vaddr_page) {
            unsigned long offset = vaddr & (e->page_size - 1);
            *phys_out = e->phys_page + offset;
            if (page_size_out)
                *page_size_out = e->page_size;
            
            /* 更新命中计数 */
            e->hit_count++;
            cache->total_hits++;
            
            preempt_enable();
            return true;
        }
    }
    
    cache->total_misses++;
    preempt_enable();
    return false;
}

/*
 * 更新缓存（LRU策略）
 */
static void ptw_cache_update(pid_t pid, unsigned long vaddr,
                             phys_addr_t phys, unsigned long page_size)
{
    struct tear_ptw_cache_v2 *cache;
    struct tear_ptw_cache_entry_v2 *e;
    unsigned int slot;
    
    preempt_disable();
    cache = this_cpu_ptr(&ptw_cache_v2);
    
    /* 使用LRU策略选择槽位 */
    slot = ptw_cache_find_lru_slot(cache);
    
    e = &cache->entries[slot];
    e->pid = pid;
    e->vaddr_page = vaddr & PAGE_MASK;
    e->phys_page = phys & PAGE_MASK;
    e->page_size = page_size;
    e->timestamp = jiffies;
    e->hit_count = 1;
    e->valid = true;
    
    preempt_enable();
}

/*
 * 使指定进程的缓存失效
 */
static void ptw_cache_invalidate_pid(pid_t pid)
{
    int cpu;
    
    for_each_possible_cpu(cpu) {
        struct tear_ptw_cache_v2 *cache = per_cpu_ptr(&ptw_cache_v2, cpu);
        int i;
        
        for (i = 0; i < TEAR_PTW_CACHE_SIZE_V2; i++) {
            if (cache->entries[i].pid == pid)
                cache->entries[i].valid = false;
        }
    }
}

/*
 * 清空所有缓存
 */
static void ptw_cache_flush_all(void)
{
    int cpu;
    
    for_each_possible_cpu(cpu) {
        struct tear_ptw_cache_v2 *cache = per_cpu_ptr(&ptw_cache_v2, cpu);
        memset(cache, 0, sizeof(*cache));
    }
}

/*
 * 获取缓存统计信息
 */
void tear_ptw_cache_stats(unsigned long *hits, unsigned long *misses)
{
    int cpu;
    unsigned long total_hits = 0, total_misses = 0;
    
    for_each_possible_cpu(cpu) {
        struct tear_ptw_cache_v2 *cache = per_cpu_ptr(&ptw_cache_v2, cpu);
        total_hits += cache->total_hits;
        total_misses += cache->total_misses;
    }
    
    if (hits)
        *hits = total_hits;
    if (misses)
        *misses = total_misses;
}

#endif /* TEAR_ENABLE_PTW_CACHE */

/*
 * ============================================================================
 * 智能预取系统
 * ============================================================================
 * 根据访问模式自动预取后续页面
 */

#if TEAR_ENABLE_PREFETCH

/* 预取状态结构 */
struct tear_prefetch_state {
    unsigned long last_addr;    /* 上次访问地址 */
    long stride;                /* 检测到的步长 */
    int confidence;             /* 置信度 */
    pid_t pid;                  /* 关联进程 */
};

/* Per-CPU 预取状态 */
static DEFINE_PER_CPU(struct tear_prefetch_state, prefetch_state);

/*
 * 智能预取
 * 检测访问模式并预取后续页面
 */
static void smart_prefetch(pid_t pid, struct mm_struct *mm, unsigned long addr)
{
    struct tear_prefetch_state *ps;
    long detected_stride;
    int i;
    
    preempt_disable();
    ps = this_cpu_ptr(&prefetch_state);
    
    /* 如果切换了进程，重置状态 */
    if (ps->pid != pid) {
        ps->pid = pid;
        ps->last_addr = addr;
        ps->stride = 0;
        ps->confidence = 0;
        preempt_enable();
        return;
    }
    
    /* 计算步长 */
    detected_stride = (long)(addr - ps->last_addr);
    
    /* 检测访问模式 */
    if (detected_stride == ps->stride && 
        detected_stride != 0 &&
        detected_stride > -(long)TEAR_PREFETCH_MAX_STRIDE &&
        detected_stride < (long)TEAR_PREFETCH_MAX_STRIDE) {
        ps->confidence++;
    } else {
        ps->stride = detected_stride;
        ps->confidence = 1;
    }
    
    ps->last_addr = addr;
    
    /* 置信度足够时执行预取 */
    if (ps->confidence >= TEAR_PREFETCH_CONFIDENCE_THRESHOLD && 
        ps->stride != 0) {
        phys_addr_t prefetch_phys;
        
        for (i = 1; i <= TEAR_PREFETCH_STRIDE; i++) {
            unsigned long pf_addr = addr + ps->stride * i;
            
            /* 预先进行地址转换以填充缓存 */
            if (!ptw_cache_lookup(pid, pf_addr, &prefetch_phys, NULL)) {
                prefetch_phys = tear_vaddr_to_phys_secure(mm, pf_addr, NULL, false);
                if (prefetch_phys)
                    ptw_cache_update(pid, pf_addr, prefetch_phys, PAGE_SIZE);
            }
        }
    }
    
    preempt_enable();
}

#endif /* TEAR_ENABLE_PREFETCH */

/*
 * ============================================================================
 * 页表遍历 - ARM64优化版
 * ============================================================================
 */

/*
 * 将虚拟地址转换为物理地址（带页大小检测）
 * 支持4KB普通页、2MB大页、1GB大页
 */
phys_addr_t tear_vaddr_to_phys(struct mm_struct *mm, unsigned long vaddr,
                               unsigned long *page_size)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t phys = 0;
    
    if (!mm || !mm->pgd)
        return 0;
    
    /* 默认4KB页 */
    if (page_size)
        *page_size = PAGE_SIZE;
    
    /* 第0级: PGD */
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    
    /* 第1级: P4D (ARM64通常折叠) */
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    
    /* 第2级: PUD */
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud))
        return 0;
    
    /* 检查1GB大页 */
    if (tear_pud_huge(*pud)) {
        if (page_size)
            *page_size = PUD_SIZE;
        phys = (pud_pfn(*pud) << PAGE_SHIFT) | (vaddr & ~PUD_MASK);
        return phys;
    }
    
    if (pud_bad(*pud))
        return 0;
    
    /* 第3级: PMD */
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd))
        return 0;
    
    /* 检查2MB大页 */
    if (tear_pmd_huge(*pmd)) {
        if (page_size)
            *page_size = PMD_SIZE;
        phys = (pmd_pfn(*pmd) << PAGE_SHIFT) | (vaddr & ~PMD_MASK);
        return phys;
    }
    
    if (pmd_bad(*pmd))
        return 0;
    
    /* 第4级: PTE */
    pte = tear_pte_offset_map(pmd, vaddr);
    if (!pte)
        return 0;
    
    if (pte_none(*pte) || !pte_present(*pte)) {
        tear_pte_unmap(pte);
        return 0;
    }
    
    phys = (pte_pfn(*pte) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
    tear_pte_unmap(pte);
    
    return phys;
}

/*
 * ============================================================================
 * 物理内存映射辅助函数
 * ============================================================================
 */

/*
 * 映射物理地址到内核空间
 */
static void *tear_map_phys(phys_addr_t phys, size_t size, bool *use_ioremap)
{
    void *mapped;
    
    *use_ioremap = false;
    
    /* 验证PFN有效性 */
    if (!tear_pfn_valid(phys >> PAGE_SHIFT)) {
        tear_debug("物理映射: PFN无效 phys=0x%llx\n", (unsigned long long)phys);
        return NULL;
    }
    
#if TEAR_SECURITY_SKIP_RESERVED
    /* 安全检查: 跳过保留页 */
    if (!tear_is_phys_safe(phys)) {
        tear_debug("物理映射: 安全检查失败 phys=0x%llx\n", (unsigned long long)phys);
        return NULL;
    }
#endif
    
    /* 优先使用memremap */
    mapped = memremap(phys & PAGE_MASK, PAGE_SIZE, TEAR_REMAP_FLAGS);
    if (mapped)
        return mapped + (phys & ~PAGE_MASK);
    
    /* 后备: 使用ioremap */
#ifdef CONFIG_ARM64
    mapped = ioremap_cache(phys & PAGE_MASK, PAGE_SIZE);
#else
    mapped = ioremap(phys & PAGE_MASK, PAGE_SIZE);
#endif
    
    if (mapped) {
        *use_ioremap = true;
        return mapped + (phys & ~PAGE_MASK);
    }
    
    return NULL;
}

/*
 * 解除物理地址映射
 */
static void tear_unmap_phys(void *mapped, bool use_ioremap)
{
    void *page_start = (void *)((unsigned long)mapped & PAGE_MASK);
    
    if (use_ioremap)
        iounmap(page_start);
    else
        memunmap(page_start);
}

/*
 * ============================================================================
 * 内存读取实现
 * ============================================================================
 */

/*
 * 带缓存的地址转换
 */
static phys_addr_t tear_vaddr_to_phys_cached(pid_t pid, struct mm_struct *mm,
                                             unsigned long addr,
                                             unsigned long *page_size)
{
    phys_addr_t phys;
    unsigned long ps = PAGE_SIZE;
    
#if TEAR_ENABLE_PTW_CACHE
    /* 先查缓存 */
    if (ptw_cache_lookup(pid, addr, &phys, &ps)) {
        if (page_size)
            *page_size = ps;
        return phys;
    }
#endif
    
    /* 缓存未命中，执行页表遍历 */
    phys = tear_vaddr_to_phys_secure(mm, addr, &ps, false);
    
#if TEAR_ENABLE_PTW_CACHE
    /* 更新缓存 */
    if (phys != 0)
        ptw_cache_update(pid, addr, phys, ps);
#endif
    
    if (page_size)
        *page_size = ps;
    
    return phys;
}

/*
 * 从目标进程读取内存（带安全检查和性能优化）
 */
bool read_process_memory(pid_t pid, unsigned long addr,
                         void __user *buffer, size_t size)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kernel_buf = NULL;
    size_t copied = 0;
    bool success = false;
    unsigned long current_addr = addr;
    
    /* 参数验证 */
    if (!buffer || size == 0 || size > TEAR_MAX_RW_SIZE) {
        tear_debug("内存读取: 参数无效\n");
        return false;
    }
    
    if (addr < TEAR_MIN_VALID_ADDR) {
        tear_debug("内存读取: 地址过低 addr=0x%lx\n", addr);
        return false;
    }
    
    /* 获取目标进程 */
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        tear_debug("内存读取: 找不到PID %d\n", pid);
        return false;
    }
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task) {
        tear_debug("内存读取: 找不到任务结构\n");
        return false;
    }
    
    /* 获取mm_struct */
    mm = get_task_mm(task);
    put_task_struct(task);
    
    if (!mm) {
        tear_debug("内存读取: 找不到内存描述符\n");
        return false;
    }
    
    /* 分配内核缓冲区 */
    kernel_buf = tear_alloc_buffer(size);
    if (!kernel_buf) {
        tear_debug("内存读取: 分配缓冲区失败\n");
        mmput(mm);
        return false;
    }
    
    /* 分块读取 */
    while (copied < size) {
        unsigned long page_size;
        phys_addr_t phys;
        size_t offset;
        size_t chunk;
        void *mapped;
        bool use_ioremap;
        
#if TEAR_SECURITY_CHECK_VMA
        /* 安全检查: VMA权限验证 + 陷阱检测 */
        if (!tear_is_addr_safe(mm, current_addr, 1, false)) {
            tear_debug("内存读取: 地址不安全(可能是陷阱) addr=0x%lx\n", current_addr);
            break;
        }
#endif

#if TEAR_SECURITY_CHECK_PRESENT
        /* 安全检查: 多层缺页检测 */
        if (tear_would_fault(mm, current_addr)) {
            int status = tear_page_status(mm, current_addr);
            tear_debug("内存读取: 页面异常 addr=0x%lx status=%s\n", 
                       current_addr, tear_page_status_str(status));
            break;
        }
#endif
        
        /* 获取物理地址（使用缓存） */
        phys = tear_vaddr_to_phys_cached(pid, mm, current_addr, &page_size);
        if (phys == 0) {
            tear_debug("内存读取: 地址转换失败 addr=0x%lx\n", current_addr);
            break;
        }
        
        /* 计算块大小（不跨页边界） */
        offset = current_addr & (page_size - 1);
        chunk = min(size - copied, page_size - offset);
        
#if TEAR_ENABLE_PREFETCH
        /* 智能预取 */
        smart_prefetch(pid, mm, current_addr);
#endif
        
        /* 映射物理内存 */
        mapped = tear_map_phys(phys, chunk, &use_ioremap);
        if (!mapped) {
            tear_debug("内存读取: 物理映射失败 phys=0x%llx\n", 
                       (unsigned long long)phys);
            break;
        }
        
        /* 使用NEON加速拷贝（如果可用） */
        tear_fast_memcpy((char *)kernel_buf + copied, mapped, chunk);
        
        /* 解除映射 */
        tear_unmap_phys(mapped - (phys & ~PAGE_MASK), use_ioremap);
        
        copied += chunk;
        current_addr += chunk;
    }
    
    mmput(mm);
    
    /* 复制到用户空间 */
    if (copied == size) {
        if (copy_to_user(buffer, kernel_buf, size) == 0)
            success = true;
        else
            tear_debug("内存读取: 复制到用户空间失败\n");
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
 * 内存写入实现
 * ============================================================================
 */

/*
 * 向目标进程写入内存（带安全检查）
 */
bool write_process_memory(pid_t pid, unsigned long addr,
                          void __user *buffer, size_t size)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kernel_buf = NULL;
    size_t written = 0;
    bool success = false;
    
    /* 参数验证 */
    if (!buffer || size == 0 || size > TEAR_MAX_RW_SIZE) {
        tear_debug("内存写入: 参数无效\n");
        return false;
    }
    
    if (addr < TEAR_MIN_VALID_ADDR) {
        tear_debug("内存写入: 地址过低 addr=0x%lx\n", addr);
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
        tear_debug("内存写入: 从用户空间复制失败\n");
        tear_free_buffer(kernel_buf, size);
        mmput(mm);
        return false;
    }
    
    /* 分块写入 */
    while (written < size) {
        unsigned long page_size;
        phys_addr_t phys;
        size_t offset;
        size_t chunk;
        void *mapped;
        bool use_ioremap;
        
#if TEAR_SECURITY_CHECK_VMA
        /* 安全检查: VMA权限验证（写操作） */
        if (!tear_is_addr_safe(mm, addr, 1, true)) {
            tear_debug("内存写入: 地址不安全 addr=0x%lx\n", addr);
            break;
        }
#endif

#if TEAR_SECURITY_CHECK_PRESENT
        /* 安全检查: 缺页检测 */
        if (tear_would_fault(mm, addr)) {
            tear_debug("内存写入: 页面不存在 addr=0x%lx\n", addr);
            break;
        }
#endif
        
        /* 获取物理地址（带安全检查） */
        phys = tear_vaddr_to_phys_secure(mm, addr, &page_size, true);
        if (phys == 0)
            break;
        
        /* 计算块大小 */
        offset = addr & (page_size - 1);
        chunk = min(size - written, page_size - offset);
        
        /* 映射物理内存 */
        mapped = tear_map_phys(phys, chunk, &use_ioremap);
        if (!mapped)
            break;
        
        /* 使用NEON加速拷贝（如果可用） */
        tear_fast_memcpy(mapped, (char *)kernel_buf + written, chunk);
        
        /* 解除映射 */
        tear_unmap_phys(mapped - (phys & ~PAGE_MASK), use_ioremap);
        
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

int teargame_memory_init(void)
{
#if TEAR_ENABLE_PTW_CACHE
    /* 初始化 per-CPU 页表缓存 */
    ptw_cache_flush_all();
    tear_info("内存子系统已初始化 (页表缓存: %d条/CPU, LRU策略)\n", 
              TEAR_PTW_CACHE_SIZE_V2);
#else
    tear_info("内存子系统已初始化\n");
#endif
    
    tear_info("  安全检查: VMA=%d, 缺页=%d, PROT_NONE=%d\n",
              TEAR_SECURITY_CHECK_VMA,
              TEAR_SECURITY_CHECK_PRESENT,
              TEAR_SECURITY_CHECK_PROTNONE);
    tear_info("  性能优化: 缓存=%d, 预取=%d, NEON=%d\n",
              TEAR_ENABLE_PTW_CACHE,
              TEAR_ENABLE_PREFETCH,
#ifdef CONFIG_ARM64
              1
#else
              0
#endif
              );
    return 0;
}

void teargame_memory_exit(void)
{
#if TEAR_ENABLE_PTW_CACHE
    unsigned long hits, misses;
    tear_ptw_cache_stats(&hits, &misses);
    tear_debug("页表缓存统计: 命中=%lu, 未命中=%lu, 命中率=%.1f%%\n",
               hits, misses, 
               (hits + misses) > 0 ? 
               (100.0 * hits / (hits + misses)) : 0.0);
    ptw_cache_flush_all();
#endif
    tear_debug("内存子系统已清理\n");
}

/* 导出函数供其他模块使用 */
void tear_memory_invalidate_pid(pid_t pid)
{
#if TEAR_ENABLE_PTW_CACHE
    ptw_cache_invalidate_pid(pid);
#endif
}
