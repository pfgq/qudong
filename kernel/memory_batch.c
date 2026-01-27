// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 批量内存操作模块
 * 
 * 提供高性能批量内存操作：
 * - 零拷贝读取（使用 kmap_local_page）
 * - 批量页表遍历（减少 mm_struct 获取开销）
 * - 散射/聚集读取（一次性读取多个不连续地址）
 */

#include "teargame.h"
#include "teargame_security.h"
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>

/*
 * ============================================================================
 * 批量页表遍历
 * ============================================================================
 * 一次获取 mm_struct，遍历多个地址
 */

/* 批量页表遍历条目 */
struct tear_ptw_batch_entry {
    unsigned long vaddr;        /* 输入: 虚拟地址 */
    phys_addr_t phys;           /* 输出: 物理地址 */
    unsigned long page_size;    /* 输出: 页大小 */
    int result;                 /* 输出: 0=成功, <0=错误码 */
};

/*
 * 批量页表遍历
 * 减少 mm_struct 获取和释放的开销
 * 
 * @pid: 目标进程ID
 * @entries: 遍历条目数组
 * @count: 条目数量
 * @return: 成功遍历的数量
 */
int tear_batch_ptw(pid_t pid, struct tear_ptw_batch_entry *entries, int count)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    int i, success = 0;
    
    if (!entries || count <= 0 || count > 256)
        return -EINVAL;
    
    /* 获取目标进程（只获取一次） */
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return -ESRCH;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task)
        return -ESRCH;
    
    mm = get_task_mm(task);
    put_task_struct(task);
    
    if (!mm)
        return -ESRCH;
    
    /* 获取 mmap 锁（只获取一次） */
    tear_mmap_read_lock(mm);
    
    /* 批量遍历 */
    for (i = 0; i < count; i++) {
        entries[i].page_size = PAGE_SIZE;
        entries[i].phys = tear_vaddr_to_phys_secure(
            mm, entries[i].vaddr, &entries[i].page_size, false);
        
        if (entries[i].phys) {
            entries[i].result = 0;
            success++;
        } else {
            entries[i].result = -EFAULT;
        }
    }
    
    tear_mmap_read_unlock(mm);
    mmput(mm);
    
    return success;
}

/*
 * ============================================================================
 * 零拷贝读取
 * ============================================================================
 * 使用 kmap_local_page 直接映射物理页面，减少拷贝开销
 */

/*
 * 零拷贝读取单个值
 * 适用于读取小型数据（8字节以内）
 * 
 * @pid: 目标进程ID
 * @addr: 目标地址
 * @out_val: 输出值指针
 * @size: 读取大小（1/2/4/8）
 * @return: true=成功, false=失败
 */
bool tear_read_zero_copy(pid_t pid, unsigned long addr, void *out_val, size_t size)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    phys_addr_t phys;
    unsigned long pfn;
    struct page *page;
    void *kaddr;
    unsigned long offset;
    bool success = false;
    
    if (!out_val || size == 0 || size > 8)
        return false;
    
    if (addr < TEAR_MIN_VALID_ADDR)
        return false;
    
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
    
    /* 安全检查 */
#if TEAR_SECURITY_CHECK_VMA
    if (!tear_is_addr_safe(mm, addr, size, false)) {
        mmput(mm);
        return false;
    }
#endif
    
    /* 获取物理地址 */
    phys = tear_vaddr_to_phys_secure(mm, addr, NULL, false);
    mmput(mm);
    
    if (!phys)
        return false;
    
    /* 验证 PFN */
    pfn = phys >> PAGE_SHIFT;
    if (!tear_pfn_valid(pfn))
        return false;
    
    /* 获取 page 结构 */
    page = pfn_to_page(pfn);
    if (!page)
        return false;
    
#if TEAR_SECURITY_SKIP_RESERVED
    if (PageReserved(page))
        return false;
#endif
    
    /* 零拷贝映射 */
    kaddr = kmap_local_page(page);
    if (!kaddr)
        return false;
    
    /* 计算页内偏移 */
    offset = phys & ~PAGE_MASK;
    
    /* 直接读取 */
    switch (size) {
    case 1:
        *(u8 *)out_val = *(u8 *)(kaddr + offset);
        success = true;
        break;
    case 2:
        *(u16 *)out_val = *(u16 *)(kaddr + offset);
        success = true;
        break;
    case 4:
        *(u32 *)out_val = *(u32 *)(kaddr + offset);
        success = true;
        break;
    case 8:
        *(u64 *)out_val = *(u64 *)(kaddr + offset);
        success = true;
        break;
    default:
        memcpy(out_val, kaddr + offset, size);
        success = true;
        break;
    }
    
    kunmap_local(kaddr);
    return success;
}

/*
 * ============================================================================
 * 散射读取 (Scatter Read)
 * ============================================================================
 * 一次性读取多个不连续的地址
 * 注意: struct tear_scatter_entry 已在 teargame_cmd.h 中定义
 */

/*
 * 散射读取
 * 
 * @pid: 目标进程ID
 * @entries: 散射读取条目数组
 * @count: 条目数量
 * @return: 成功读取的条目数
 */
int tear_scatter_read(pid_t pid, struct tear_scatter_entry *entries, int count)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    int i, success = 0;
    void *temp_buf = NULL;
    size_t max_size = 0;
    
    if (!entries || count <= 0 || count > 64)
        return -EINVAL;
    
    /* 找出最大读取大小 */
    for (i = 0; i < count; i++) {
        if (entries[i].size > max_size)
            max_size = entries[i].size;
        if (entries[i].size > TEAR_MAX_RW_SIZE)
            return -EINVAL;
    }
    
    /* 分配临时缓冲区 */
    temp_buf = tear_alloc_buffer(max_size);
    if (!temp_buf)
        return -ENOMEM;
    
    /* 获取目标进程 */
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        tear_free_buffer(temp_buf, max_size);
        return -ESRCH;
    }
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task) {
        tear_free_buffer(temp_buf, max_size);
        return -ESRCH;
    }
    
    mm = get_task_mm(task);
    put_task_struct(task);
    
    if (!mm) {
        tear_free_buffer(temp_buf, max_size);
        return -ESRCH;
    }
    
    /* 批量读取 */
    for (i = 0; i < count; i++) {
        struct tear_scatter_entry *e = &entries[i];
        phys_addr_t phys;
        unsigned long pfn;
        struct page *page;
        void *kaddr;
        size_t copied = 0;
        unsigned long current_addr = e->addr;
        
        e->result = -EFAULT;
        
        if (!e->buffer || e->size == 0 || e->addr < TEAR_MIN_VALID_ADDR)
            continue;
        
        /* 分块读取（可能跨页） */
        while (copied < e->size) {
            unsigned long offset;
            size_t chunk;
            
#if TEAR_SECURITY_CHECK_VMA
            if (!tear_is_addr_safe(mm, current_addr, 1, false))
                break;
#endif
            
            phys = tear_vaddr_to_phys_secure(mm, current_addr, NULL, false);
            if (!phys)
                break;
            
            pfn = phys >> PAGE_SHIFT;
            if (!tear_pfn_valid(pfn))
                break;
            
            page = pfn_to_page(pfn);
            if (!page)
                break;
            
            /* 计算块大小 */
            offset = phys & ~PAGE_MASK;
            chunk = min(e->size - copied, PAGE_SIZE - offset);
            
            /* 零拷贝读取 */
            kaddr = kmap_local_page(page);
            if (!kaddr)
                break;
            
            memcpy((char *)temp_buf + copied, kaddr + offset, chunk);
            kunmap_local(kaddr);
            
            copied += chunk;
            current_addr += chunk;
        }
        
        /* 复制到用户空间 */
        if (copied == e->size) {
            if (copy_to_user((void __user *)(unsigned long)e->buffer, temp_buf, e->size) == 0) {
                e->result = 0;
                success++;
            }
        }
    }
    
    mmput(mm);
    tear_free_buffer(temp_buf, max_size);
    
    return success;
}

/*
 * ============================================================================
 * 批量写入
 * ============================================================================
 */

/* 批量写入条目 */
struct tear_batch_write_entry {
    unsigned long addr;         /* 输入: 目标地址 */
    void __user *buffer;        /* 输入: 源缓冲区 */
    size_t size;                /* 输入: 写入大小 */
    int result;                 /* 输出: 0=成功, <0=错误码 */
};

/*
 * 批量写入
 * 
 * @pid: 目标进程ID
 * @entries: 批量写入条目数组
 * @count: 条目数量
 * @return: 成功写入的条目数
 */
int tear_batch_write(pid_t pid, struct tear_batch_write_entry *entries, int count)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    int i, success = 0;
    void *temp_buf = NULL;
    size_t max_size = 0;
    
    if (!entries || count <= 0 || count > 64)
        return -EINVAL;
    
    /* 找出最大写入大小 */
    for (i = 0; i < count; i++) {
        if (entries[i].size > max_size)
            max_size = entries[i].size;
        if (entries[i].size > TEAR_MAX_RW_SIZE)
            return -EINVAL;
    }
    
    /* 分配临时缓冲区 */
    temp_buf = tear_alloc_buffer(max_size);
    if (!temp_buf)
        return -ENOMEM;
    
    /* 获取目标进程 */
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        tear_free_buffer(temp_buf, max_size);
        return -ESRCH;
    }
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task) {
        tear_free_buffer(temp_buf, max_size);
        return -ESRCH;
    }
    
    mm = get_task_mm(task);
    put_task_struct(task);
    
    if (!mm) {
        tear_free_buffer(temp_buf, max_size);
        return -ESRCH;
    }
    
    /* 批量写入 */
    for (i = 0; i < count; i++) {
        struct tear_batch_write_entry *e = &entries[i];
        phys_addr_t phys;
        unsigned long pfn;
        struct page *page;
        void *kaddr;
        size_t written = 0;
        unsigned long current_addr = e->addr;
        
        e->result = -EFAULT;
        
        if (!e->buffer || e->size == 0 || e->addr < TEAR_MIN_VALID_ADDR)
            continue;
        
        /* 从用户空间复制数据 */
        if (copy_from_user(temp_buf, e->buffer, e->size))
            continue;
        
        /* 分块写入 */
        while (written < e->size) {
            unsigned long offset;
            size_t chunk;
            
#if TEAR_SECURITY_CHECK_VMA
            if (!tear_is_addr_safe(mm, current_addr, 1, true))
                break;
#endif
            
            phys = tear_vaddr_to_phys_secure(mm, current_addr, NULL, true);
            if (!phys)
                break;
            
            pfn = phys >> PAGE_SHIFT;
            if (!tear_pfn_valid(pfn))
                break;
            
            page = pfn_to_page(pfn);
            if (!page)
                break;
            
            /* 计算块大小 */
            offset = phys & ~PAGE_MASK;
            chunk = min(e->size - written, PAGE_SIZE - offset);
            
            /* 零拷贝写入 */
            kaddr = kmap_local_page(page);
            if (!kaddr)
                break;
            
            memcpy(kaddr + offset, (char *)temp_buf + written, chunk);
            kunmap_local(kaddr);
            
            written += chunk;
            current_addr += chunk;
        }
        
        if (written == e->size) {
            e->result = 0;
            success++;
        }
    }
    
    mmput(mm);
    tear_free_buffer(temp_buf, max_size);
    
    return success;
}

/*
 * ============================================================================
 * 模块初始化/清理
 * ============================================================================
 */

int teargame_memory_batch_init(void)
{
    tear_info("批量内存操作模块已初始化\n");
    tear_debug("  零拷贝读取: 启用\n");
    tear_debug("  批量页表遍历: 启用\n");
    tear_debug("  散射/聚集IO: 启用\n");
    return 0;
}

void teargame_memory_batch_exit(void)
{
    tear_debug("批量内存操作模块已清理\n");
}
