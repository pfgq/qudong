// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 进程缓存
 * 
 * 基于哈希的进程缓存，使用RCU实现无锁读取
 * 和LRU自动缓存淘汰
 */

#include "teargame.h"
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

/*
 * ============================================================================
 * 缓存状态
 * ============================================================================
 */
static struct tear_process_cache cache = {
    .initialized = false,
    .last_scan = 0,
};

/*
 * ============================================================================
 * 私有辅助函数
 * ============================================================================
 */

/*
 * RCU回调释放缓存条目
 */
static void cache_entry_free_rcu(struct rcu_head *head)
{
    struct tear_process_entry *entry;
    
    entry = container_of(head, struct tear_process_entry, rcu);
    kfree(entry);
}

/*
 * 从缓存移除条目（必须持有锁）
 */
static void cache_remove_entry_locked(struct tear_process_entry *entry)
{
    if (!entry)
        return;
    
    hlist_del_rcu(&entry->node);
    call_rcu(&entry->rcu, cache_entry_free_rcu);
    atomic_dec(&cache.count);
}

/*
 * 添加条目到缓存（必须持有锁）
 */
static void cache_add_entry_locked(struct tear_process_entry *entry)
{
    unsigned int hash;
    
    if (!entry)
        return;
    
    hash = tear_hash_string(entry->cmdline);
    if (hash >= TEAR_CACHE_BUCKETS)
        hash = hash % TEAR_CACHE_BUCKETS;
    
    hlist_add_head_rcu(&entry->node, &cache.buckets[hash]);
    atomic_inc(&cache.count);
}

/*
 * 通过PID查找条目（必须持有锁或RCU）
 */
static struct tear_process_entry *cache_find_by_pid_locked(pid_t pid)
{
    struct tear_process_entry *entry;
    unsigned int i;
    
    for (i = 0; i < TEAR_CACHE_BUCKETS; i++) {
        hlist_for_each_entry_rcu(entry, &cache.buckets[i], node) {
            if (entry->pid == pid)
                return entry;
        }
    }
    
    return NULL;
}

/*
 * ============================================================================
 * 公共API
 * ============================================================================
 */

/*
 * 初始化进程缓存
 */
int tear_cache_init(void)
{
    unsigned int i;
    
    if (cache.initialized)
        return 0;
    
    /* 初始化哈希桶 */
    for (i = 0; i < TEAR_CACHE_BUCKETS; i++) {
        INIT_HLIST_HEAD(&cache.buckets[i]);
    }
    
    spin_lock_init(&cache.lock);
    atomic_set(&cache.count, 0);
    cache.last_scan = 0;
    cache.initialized = true;
    
    tear_debug("进程缓存已初始化，%d 个桶\n", TEAR_CACHE_BUCKETS);
    
    return 0;
}

/*
 * 清理进程缓存
 */
void tear_cache_cleanup(void)
{
    struct tear_process_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned int i;
    
    if (!cache.initialized)
        return;
    
    spin_lock_irqsave(&cache.lock, flags);
    
    for (i = 0; i < TEAR_CACHE_BUCKETS; i++) {
        hlist_for_each_entry_safe(entry, tmp, &cache.buckets[i], node) {
            hlist_del_rcu(&entry->node);
            call_rcu(&entry->rcu, cache_entry_free_rcu);
        }
    }
    
    atomic_set(&cache.count, 0);
    
    spin_unlock_irqrestore(&cache.lock, flags);
    
    /* 等待RCU回调完成 */
    synchronize_rcu();
    
    cache.initialized = false;
    
    tear_debug("进程缓存已清理\n");
}

/*
 * 如需要则刷新缓存
 */
void tear_cache_refresh_if_needed(void)
{
    struct task_struct *task;
    struct tear_process_entry *entry, *old_entry;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned long now = tear_jiffies();
    char cmdline[TEAR_CMDLINE_MAX_LEN];
    pid_t *pid_list = NULL;
    int pid_count = 0;
    int max_pids = 512;
    int i;
    
    if (!cache.initialized)
        return;
    
    /* 检查是否需要刷新 */
    if (time_before(now, cache.last_scan + TEAR_CACHE_REFRESH_JIFFIES))
        return;
    
    cache.last_scan = now;
    
    /* 分配临时PID列表 */
    pid_list = kmalloc(sizeof(pid_t) * max_pids, GFP_KERNEL);
    if (!pid_list)
        return;
    
    /* 在RCU下收集PID */
    rcu_read_lock();
    
    for_each_process(task) {
        if (pid_count >= max_pids)
            break;
        
        /* 跳过内核线程 */
        if (task->flags & PF_KTHREAD)
            continue;
        
        /* 只要线程组领导者 */
        if (task->pid != task->tgid)
            continue;
        
        /* 跳过正在退出的任务 */
        if (task->flags & PF_EXITING)
            continue;
        
        if (!task->mm)
            continue;
        
        pid_list[pid_count++] = task->pid;
    }
    
    rcu_read_unlock();
    
    /* 处理每个PID */
    for (i = 0; i < pid_count; i++) {
        pid_t pid = pid_list[i];
        int cmdline_len;
        unsigned int hash;
        
        /* 获取命令行 */
        cmdline_len = get_cmdline_by_pid_safe(pid, cmdline, sizeof(cmdline));
        if (cmdline_len <= 0 || cmdline[0] == '\0')
            continue;
        
        /* 分配新条目 */
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            continue;
        
        entry->pid = pid;
        strncpy(entry->cmdline, cmdline, sizeof(entry->cmdline) - 1);
        entry->cmdline[sizeof(entry->cmdline) - 1] = '\0';
        
        /* 获取任务comm */
        rcu_read_lock();
        task = find_task_by_vpid(pid);
        if (task) {
            strncpy(entry->name, task->comm, sizeof(entry->name) - 1);
            entry->name[sizeof(entry->name) - 1] = '\0';
        } else {
            entry->name[0] = '\0';
        }
        rcu_read_unlock();
        
        entry->cache_time = now;
        entry->last_access = now;
        
        /* 添加到缓存，如果存在则移除旧条目 */
        hash = tear_hash_string(entry->cmdline);
        if (hash >= TEAR_CACHE_BUCKETS)
            hash = hash % TEAR_CACHE_BUCKETS;
        
        spin_lock_irqsave(&cache.lock, flags);
        
        /* 检查是否存在相同PID的条目 */
        old_entry = cache_find_by_pid_locked(pid);
        if (old_entry)
            cache_remove_entry_locked(old_entry);
        
        /* 检查缓存大小限制 */
        if (atomic_read(&cache.count) >= TEAR_CACHE_MAX_ENTRIES) {
            /* 移除最旧的条目（简单LRU） */
            unsigned int j;
            unsigned long oldest_time = now;
            struct tear_process_entry *oldest = NULL;
            
            for (j = 0; j < TEAR_CACHE_BUCKETS; j++) {
                hlist_for_each_entry_safe(old_entry, tmp, 
                                          &cache.buckets[j], node) {
                    if (time_before(old_entry->last_access, oldest_time)) {
                        oldest_time = old_entry->last_access;
                        oldest = old_entry;
                    }
                }
            }
            
            if (oldest)
                cache_remove_entry_locked(oldest);
        }
        
        cache_add_entry_locked(entry);
        
        spin_unlock_irqrestore(&cache.lock, flags);
    }
    
    kfree(pid_list);
}

/*
 * 通过名称在缓存中查找PID
 */
pid_t tear_cache_find(const char *name)
{
    struct tear_process_entry *entry;
    unsigned int hash;
    size_t name_len;
    pid_t found_pid = 0;
    
    if (!name || name[0] == '\0' || !cache.initialized)
        return 0;
    
    name_len = strlen(name);
    
    /* 计算哈希用于直接查找 */
    hash = tear_hash_string(name);
    if (hash >= TEAR_CACHE_BUCKETS)
        hash = hash % TEAR_CACHE_BUCKETS;
    
    rcu_read_lock();
    
    /* 先在哈希桶中尝试精确匹配 */
    hlist_for_each_entry_rcu(entry, &cache.buckets[hash], node) {
        if (strcmp(entry->cmdline, name) == 0) {
            entry->last_access = tear_jiffies();
            found_pid = entry->pid;
            goto out;
        }
    }
    
    /* 尝试所有桶进行部分匹配 */
    for (hash = 0; hash < TEAR_CACHE_BUCKETS; hash++) {
        hlist_for_each_entry_rcu(entry, &cache.buckets[hash], node) {
            /* 检查前缀匹配 */
            if (strncmp(entry->cmdline, name, name_len) == 0) {
                char next = entry->cmdline[name_len];
                if (next == '\0' || next == ' ' || next == ':') {
                    entry->last_access = tear_jiffies();
                    found_pid = entry->pid;
                    goto out;
                }
            }
            
            /* 检查子字符串匹配 */
            if (strstr(entry->cmdline, name) != NULL) {
                entry->last_access = tear_jiffies();
                found_pid = entry->pid;
                goto out;
            }
            
            /* 检查comm匹配 */
            if (entry->name[0] != '\0' && 
                strcmp(entry->name, name) == 0) {
                entry->last_access = tear_jiffies();
                found_pid = entry->pid;
                goto out;
            }
        }
    }
    
out:
    rcu_read_unlock();
    return found_pid;
}

/*
 * 使特定PID的缓存条目失效
 */
void tear_cache_invalidate_pid(pid_t pid)
{
    struct tear_process_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned int i;
    
    if (!cache.initialized)
        return;
    
    spin_lock_irqsave(&cache.lock, flags);
    
    for (i = 0; i < TEAR_CACHE_BUCKETS; i++) {
        hlist_for_each_entry_safe(entry, tmp, &cache.buckets[i], node) {
            if (entry->pid == pid) {
                cache_remove_entry_locked(entry);
                break;
            }
        }
    }
    
    spin_unlock_irqrestore(&cache.lock, flags);
}
