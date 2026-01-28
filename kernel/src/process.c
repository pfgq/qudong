// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 进程操作模块
 * 
 * 进程查找、模块基址获取和VMA遍历
 * 兼容内核版本 5.10-6.x
 */

#include "teargame.h"
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mm.h>

/* 缓存函数前向声明 */
extern pid_t tear_cache_find(const char *name);
extern void tear_cache_refresh_if_needed(void);

/*
 * ============================================================================
 * 辅助函数
 * ============================================================================
 */

/*
 * 安全地从dentry获取基本名称
 */
char *safe_get_basename(struct dentry *dentry)
{
    const unsigned char *name;
    
    if (!dentry)
        return NULL;
    
    name = READ_ONCE(dentry->d_name.name);
    if (!name || name[0] == '\0')
        return NULL;
    
    return (char *)name;
}

/*
 * 验证PID是否有效且可访问
 */
bool verify_pid(pid_t pid)
{
    struct pid *pid_struct;
    struct task_struct *task;
    bool valid = false;
    
    if (pid <= 0)
        return false;
    
    rcu_read_lock();
    
    pid_struct = find_vpid(pid);
    if (!pid_struct)
        goto out;
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        goto out;
    
    /* 检查任务是否正在退出或已死亡 */
    if (task->flags & (PF_EXITING | PF_KTHREAD))
        goto out;
    
    /* 检查任务是否有有效的mm */
    if (!task->mm)
        goto out;
    
    valid = true;
    
out:
    rcu_read_unlock();
    return valid;
}

/*
 * 获取进程的命令行
 */
int get_cmdline_by_pid_safe(pid_t pid, char *buf, size_t size)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long arg_start, arg_end;
    size_t len;
    int ret = 0;
    
    if (!buf || size == 0)
        return 0;
    
    memset(buf, 0, size);
    
    if (pid <= 0)
        return 0;
    
    rcu_read_lock();
    
    pid_struct = find_vpid(pid);
    if (!pid_struct) {
        rcu_read_unlock();
        return 0;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return 0;
    }
    
    get_task_struct(task);
    rcu_read_unlock();
    
    /* 检查是否为内核线程 */
    if (task->flags & PF_KTHREAD) {
        put_task_struct(task);
        return 0;
    }
    
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return 0;
    }
    
    /* 获取arg_start和arg_end */
    tear_mmap_read_lock(mm);
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    tear_mmap_read_unlock(mm);
    
    if (arg_start == 0 || arg_start >= arg_end) {
        mmput(mm);
        put_task_struct(task);
        return 0;
    }
    
    /* 计算长度 */
    len = arg_end - arg_start;
    if (len > size - 1)
        len = size - 1;
    
    /* 使用access_process_vm读取命令行 */
    ret = access_process_vm(task, arg_start, buf, len, 0);
    
    mmput(mm);
    put_task_struct(task);
    
    if (ret > 0) {
        buf[ret] = '\0';
        return strlen(buf);
    }
    
    return 0;
}

/*
 * ============================================================================
 * 进程查找函数
 * ============================================================================
 */

/*
 * 通过进程名查找PID（comm或cmdline匹配）
 */
pid_t find_pid_by_name(const char *name)
{
    struct task_struct *task;
    char cmdline[TEAR_CMDLINE_MAX_LEN];
    size_t name_len;
    pid_t found_pid = 0;
    pid_t fallback_pid = 0;
    int matches = 0;
    
    if (!name || name[0] == '\0')
        return 0;
    
    name_len = strlen(name);
    if (name_len == 0 || name_len > TEAR_MODULE_NAME_MAX)
        return 0;
    
    rcu_read_lock();
    
    for_each_process(task) {
        int pid_nr;
        
        /* 跳过内核线程和僵尸进程 */
        if (task->flags & (PF_KTHREAD | PF_EXITING))
            continue;
        
        /* 只检查线程组领导者 */
        if (task->pid != task->tgid)
            continue;
        
        if (!task->mm)
            continue;
        
        pid_nr = task->pid;
        
        /* 检查comm（任务名）- 最大15字符 */
        if (name_len <= TASK_COMM_LEN - 1) {
            if (strncmp(task->comm, name, name_len) == 0) {
                if (name_len == strlen(task->comm) ||
                    name_len == TASK_COMM_LEN - 1) {
                    rcu_read_unlock();
                    return pid_nr;
                }
            }
        }
        
        /* 对于更长的名称，需要检查cmdline */
        if (name_len >= TASK_COMM_LEN - 1) {
            if (strncmp(task->comm, name, TASK_COMM_LEN - 1) == 0) {
                fallback_pid = pid_nr;
                matches++;
            }
        }
    }
    
    rcu_read_unlock();
    
    /* 如果有潜在匹配，检查cmdline */
    if (matches > 0 || found_pid == 0) {
        /* 使用cmdline检查重新扫描 */
        rcu_read_lock();
        
        for_each_process(task) {
            int pid_nr;
            int cmdline_len;
            
            if (task->flags & (PF_KTHREAD | PF_EXITING))
                continue;
            
            if (task->pid != task->tgid)
                continue;
            
            if (!task->mm)
                continue;
            
            pid_nr = task->pid;
            
            rcu_read_unlock();
            
            /* 获取cmdline */
            cmdline_len = get_cmdline_by_pid_safe(pid_nr, cmdline, 
                                                   sizeof(cmdline));
            
            if (cmdline_len > 0) {
                /* 精确匹配 */
                if (strcmp(cmdline, name) == 0) {
                    return pid_nr;
                }
                
                /* 前缀匹配 */
                if (strncmp(cmdline, name, name_len) == 0) {
                    char next_char = cmdline[name_len];
                    if (next_char == '\0' || next_char == ' ' || 
                        next_char == '\t') {
                        return pid_nr;
                    }
                }
                
                /* 子字符串匹配 */
                if (strstr(cmdline, name) != NULL) {
                    found_pid = pid_nr;
                }
            }
            
            rcu_read_lock();
        }
        
        rcu_read_unlock();
    }
    
    /* 返回最佳匹配 */
    if (found_pid)
        return found_pid;
    
    if (matches == 1)
        return fallback_pid;
    
    return 0;
}

/*
 * 安全查找PID（带任务验证）
 */
pid_t find_pid_safe(const char *name)
{
    pid_t pid;
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    bool valid = false;
    
    if (!name || name[0] == '\0')
        return 0;
    
    pid = find_pid_by_name(name);
    if (pid <= 0)
        return 0;
    
    /* 验证PID仍然有效 */
    rcu_read_lock();
    
    pid_struct = find_vpid(pid);
    if (!pid_struct) {
        rcu_read_unlock();
        return 0;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return 0;
    }
    
    get_task_struct(task);
    rcu_read_unlock();
    
    /* 检查任务状态 */
    if (task->flags & (PF_EXITING | PF_KTHREAD))
        goto out;
    
    /* 验证mm存在 */
    mm = get_task_mm(task);
    if (!mm)
        goto out;
    
    mmput(mm);
    valid = true;
    
out:
    put_task_struct(task);
    return valid ? pid : 0;
}

/*
 * 使用缓存查找PID（隐蔽模式）
 */
pid_t find_pid_stealth(const char *name)
{
    pid_t pid;
    
    if (!name || name[0] == '\0')
        return 0;
    
    /* 如需要刷新缓存 */
    tear_cache_refresh_if_needed();
    
    /* 先尝试缓存 */
    pid = tear_cache_find(name);
    if (pid > 0 && verify_pid(pid))
        return pid;
    
    /* 缓存未命中或无效，进行新查找 */
    pid = find_pid_by_name(name);
    if (pid > 0 && verify_pid(pid))
        return pid;
    
    return 0;
}

/*
 * ============================================================================
 * 模块基址函数
 * ============================================================================
 */

/*
 * 通过名称获取模块基址
 * 遍历VMA列表查找匹配的映射文件
 */
unsigned long get_module_base(pid_t pid, const char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long base = 0;
    size_t name_len;
    
    if (!name || name[0] == '\0')
        return 0;
    
    if (pid <= 0)
        return 0;
    
    name_len = strlen(name);
    if (name_len == 0 || name_len > TEAR_MODULE_NAME_MAX)
        return 0;
    
    /* 获取任务 */
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task)
        return 0;
    
    /* 检查任务有效性 */
    if (task->exit_state || (task->flags & PF_EXITING)) {
        put_task_struct(task);
        return 0;
    }
    
    mm = get_task_mm(task);
    put_task_struct(task);
    
    if (!mm)
        return 0;
    
    /* 锁定mm用于VMA遍历 */
    if (tear_mmap_read_trylock(mm) == 0) {
        tear_mmap_read_lock(mm);
    }
    
    /* 遍历VMA */
#if TEAR_USE_MAPLE_TREE
    {
        VMA_ITERATOR(vmi, mm, 0);
        struct vm_area_struct *vma;
        
        for_each_vma(vmi, vma) {
            struct file *file;
            struct dentry *dentry;
            const char *basename;
            
            file = vma->vm_file;
            if (!file)
                continue;
            
            dentry = file->f_path.dentry;
            if (!dentry)
                continue;
            
            basename = safe_get_basename(dentry);
            if (!basename)
                continue;
            
            /* 比较名称 */
            if (strcmp(basename, name) == 0) {
                base = vma->vm_start;
                break;
            }
        }
    }
#else
    {
        struct vm_area_struct *vma;
        
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
            struct file *file;
            struct dentry *dentry;
            const char *basename;
            
            file = vma->vm_file;
            if (!file)
                continue;
            
            dentry = file->f_path.dentry;
            if (!dentry)
                continue;
            
            basename = safe_get_basename(dentry);
            if (!basename)
                continue;
            
            if (strcmp(basename, name) == 0) {
                base = vma->vm_start;
                break;
            }
        }
    }
#endif
    
    tear_mmap_read_unlock(mm);
    mmput(mm);
    
    return base;
}

/*
 * 获取模块BSS段地址
 * BSS通常是模块之后的第一个匿名映射
 */
unsigned long get_module_bss(pid_t pid, const char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long bss_base = 0;
    unsigned long module_base = 0;
    bool found_module = false;
    int anon_count = 0;
    size_t name_len;
    
    if (!name || name[0] == '\0')
        return 0;
    
    if (pid <= 0)
        return 0;
    
    name_len = strlen(name);
    if (name_len == 0 || name_len > TEAR_MODULE_NAME_MAX)
        return 0;
    
    /* 获取任务 */
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task)
        return 0;
    
    if (task->exit_state || (task->flags & PF_EXITING)) {
        put_task_struct(task);
        return 0;
    }
    
    mm = get_task_mm(task);
    put_task_struct(task);
    
    if (!mm)
        return 0;
    
    if (tear_mmap_read_trylock(mm) == 0) {
        tear_mmap_read_lock(mm);
    }
    
#if TEAR_USE_MAPLE_TREE
    {
        VMA_ITERATOR(vmi, mm, 0);
        struct vm_area_struct *vma;
        
        for_each_vma(vmi, vma) {
            if (!found_module) {
                struct file *file = vma->vm_file;
                struct dentry *dentry;
                const char *basename;
                
                if (!file)
                    continue;
                
                dentry = file->f_path.dentry;
                if (!dentry)
                    continue;
                
                basename = safe_get_basename(dentry);
                if (!basename)
                    continue;
                
                if (strcmp(basename, name) == 0) {
                    module_base = vma->vm_start;
                    found_module = true;
                    anon_count = 0;
                }
            } else {
                /* 查找匿名RW段（BSS） */
                if (!vma->vm_file) {
                    unsigned long flags = vma->vm_flags;
                    
                    if ((flags & (VM_READ | VM_WRITE)) == 
                        (VM_READ | VM_WRITE)) {
                        bss_base = vma->vm_start;
                        break;
                    }
                    
                    anon_count++;
                    if (anon_count >= 3)
                        break;
                } else {
                    /* 碰到另一个文件映射，停止 */
                    break;
                }
            }
        }
    }
#else
    {
        struct vm_area_struct *vma;
        
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
            if (!found_module) {
                struct file *file = vma->vm_file;
                struct dentry *dentry;
                const char *basename;
                
                if (!file)
                    continue;
                
                dentry = file->f_path.dentry;
                if (!dentry)
                    continue;
                
                basename = safe_get_basename(dentry);
                if (!basename)
                    continue;
                
                if (strcmp(basename, name) == 0) {
                    module_base = vma->vm_start;
                    found_module = true;
                    anon_count = 0;
                }
            } else {
                if (!vma->vm_file) {
                    unsigned long flags = vma->vm_flags;
                    
                    if ((flags & (VM_READ | VM_WRITE)) == 
                        (VM_READ | VM_WRITE)) {
                        bss_base = vma->vm_start;
                        break;
                    }
                    
                    anon_count++;
                    if (anon_count >= 3)
                        break;
                } else {
                    break;
                }
            }
        }
    }
#endif
    
    tear_mmap_read_unlock(mm);
    mmput(mm);
    
    return bss_base;
}
