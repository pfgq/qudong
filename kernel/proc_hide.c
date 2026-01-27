// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 进程隐藏模块
 * 
 * 实现方式:
 * 1. Hook /proc 目录遍历，过滤隐藏进程的PID目录
 * 2. 隐藏的进程仍正常运行，CPU调度、内存管理等不受影响
 * 
 * 特点:
 * - 支持按PID隐藏
 * - 支持按进程名隐藏（所有同名进程）
 * - 进程功能完全正常
 * - 从 ps、top、/proc 中不可见
 */

#include "teargame.h"
#include "teargame_stealth.h"
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/pid.h>

/*
 * ============================================================================
 * 配置常量
 * ============================================================================
 */

/* 最大隐藏进程数 */
#define MAX_HIDDEN_PROCS    32

/*
 * ============================================================================
 * 数据结构
 * ============================================================================
 */

/* linux_dirent64 结构体定义（内核中可能未完整导出） */
struct linux_dirent64 {
    u64             d_ino;
    s64             d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

/* 隐藏进程条目 */
struct hidden_proc_entry {
    pid_t pid;                      /* 进程ID（按PID隐藏时使用） */
    char comm[TASK_COMM_LEN];       /* 进程名（按名称隐藏时使用） */
    bool by_name;                   /* true=按名称匹配, false=按PID匹配 */
    bool active;                    /* 是否激活 */
};

/* 模块状态 */
static struct {
    struct hidden_proc_entry entries[MAX_HIDDEN_PROCS];
    spinlock_t lock;
    int count;                      /* 当前隐藏条目数 */
    bool initialized;
} proc_hide_state;

/* Kretprobe 钩子 - 用于 /proc 的 getdents */
static struct kretprobe proc_getdents_krp;
static bool proc_hook_installed = false;

/* 钩子数据 */
struct proc_getdents_data {
    void __user *dirent;
    unsigned int count;
    int fd;
    char path[64];                  /* 文件路径（用于检测是否是 /proc） */
    bool is_proc;
};

/*
 * ============================================================================
 * 辅助函数
 * ============================================================================
 */

/*
 * 检查 PID 是否应被隐藏
 */
static bool should_hide_pid(pid_t pid)
{
    int i;
    bool hide = false;
    unsigned long flags;
    struct task_struct *task;
    
    if (pid <= 0)
        return false;
    
    spin_lock_irqsave(&proc_hide_state.lock, flags);
    
    for (i = 0; i < MAX_HIDDEN_PROCS; i++) {
        struct hidden_proc_entry *entry = &proc_hide_state.entries[i];
        
        if (!entry->active)
            continue;
        
        if (!entry->by_name) {
            /* 按PID匹配 */
            if (entry->pid == pid) {
                hide = true;
                break;
            }
        } else {
            /* 按进程名匹配 */
            rcu_read_lock();
            task = find_task_by_vpid(pid);
            if (task) {
                get_task_struct(task);
                if (strncmp(task->comm, entry->comm, TASK_COMM_LEN) == 0) {
                    hide = true;
                }
                put_task_struct(task);
            }
            rcu_read_unlock();
            
            if (hide)
                break;
        }
    }
    
    spin_unlock_irqrestore(&proc_hide_state.lock, flags);
    return hide;
}

/*
 * 检查字符串是否全是数字（PID目录）
 */
static bool is_pid_string(const char *str, int len)
{
    int i;
    
    if (len <= 0 || len > 10)  /* PID不会超过10位 */
        return false;
    
    for (i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9')
            return false;
    }
    
    return true;
}

/*
 * 字符串转PID
 */
static pid_t str_to_pid(const char *str, int len)
{
    pid_t pid = 0;
    int i;
    
    for (i = 0; i < len; i++) {
        pid = pid * 10 + (str[i] - '0');
    }
    
    return pid;
}

/*
 * 检查文件描述符是否指向 /proc
 */
static bool fd_is_proc(int fd)
{
    struct fd f;
    struct path path;
    char buf[64];
    char *pathname;
    bool is_proc = false;
    
    f = fdget(fd);
    if (!f.file)
        return false;
    
    path = f.file->f_path;
    pathname = d_path(&path, buf, sizeof(buf));
    
    if (!IS_ERR(pathname)) {
        is_proc = (strncmp(pathname, "/proc", 5) == 0);
        /* 确保是 /proc 根目录或 /proc/xxx 但不是 /proc/xxx/yyy */
        if (is_proc) {
            char *p = pathname + 5;
            if (*p == '\0' || (*p == '/' && strchr(p + 1, '/') == NULL)) {
                is_proc = true;
            } else if (*p == '/' && is_pid_string(p + 1, strlen(p + 1))) {
                /* /proc/PID 目录 */
                is_proc = true;
            } else {
                is_proc = false;
            }
        }
    }
    
    fdput(f);
    return is_proc;
}

/*
 * ============================================================================
 * Kretprobe 处理程序
 * ============================================================================
 */

/*
 * 入口处理程序 - 保存参数并检查是否是 /proc
 */
static int proc_getdents_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct proc_getdents_data *data = (struct proc_getdents_data *)ri->data;
    int fd;
    
#ifdef CONFIG_ARM64
    fd = (int)regs->regs[0];
    data->dirent = (void __user *)regs->regs[1];
    data->count = (unsigned int)regs->regs[2];
#else
    fd = (int)regs->di;
    data->dirent = (void __user *)regs->si;
    data->count = (unsigned int)regs->dx;
#endif
    
    data->fd = fd;
    
    /* 检查是否是 /proc 目录 */
    data->is_proc = fd_is_proc(fd);
    
    return 0;
}

/*
 * 返回处理程序 - 过滤隐藏进程
 */
static int proc_getdents_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct proc_getdents_data *data = (struct proc_getdents_data *)ri->data;
    struct linux_dirent64 __user *dirent;
    char *kbuf = NULL;
    long ret;
    long new_ret;
    unsigned long offset = 0;
    
    /* 如果不是 /proc 目录，不处理 */
    if (!data->is_proc)
        return 0;
    
#ifdef CONFIG_ARM64
    ret = (long)regs->regs[0];
#else
    ret = (long)regs->ax;
#endif
    
    /* 如果返回值 <= 0，无需处理 */
    if (ret <= 0)
        return 0;
    
    /* 检查是否有隐藏条目 */
    if (proc_hide_state.count == 0)
        return 0;
    
    dirent = data->dirent;
    
    /* 分配内核缓冲区 */
    kbuf = kmalloc(ret, GFP_ATOMIC);
    if (!kbuf)
        return 0;
    
    /* 复制到内核空间 */
    if (copy_from_user(kbuf, dirent, ret)) {
        kfree(kbuf);
        return 0;
    }
    
    new_ret = ret;
    
    /* 遍历目录条目 */
    while (offset < ret) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + offset);
        int reclen = d->d_reclen;
        int namelen;
        pid_t pid;
        
        if (reclen <= 0 || offset + reclen > ret)
            break;
        
        namelen = strlen(d->d_name);
        
        /* 检查是否是 PID 目录 */
        if (is_pid_string(d->d_name, namelen)) {
            pid = str_to_pid(d->d_name, namelen);
            
            if (should_hide_pid(pid)) {
                /* 隐藏此条目：将后续条目前移 */
                int remaining = ret - offset - reclen;
                
                if (remaining > 0) {
                    memmove(kbuf + offset, kbuf + offset + reclen, remaining);
                }
                
                new_ret -= reclen;
                ret -= reclen;
                /* 不增加 offset，继续检查当前位置 */
                continue;
            }
        }
        
        offset += reclen;
    }
    
    /* 复制修改后的数据回用户空间 */
    if (new_ret > 0 && new_ret < ret + (ret - new_ret)) {
        if (copy_to_user(dirent, kbuf, new_ret) == 0) {
            /* 更新返回值 */
#ifdef CONFIG_ARM64
            regs->regs[0] = new_ret;
#else
            regs->ax = new_ret;
#endif
        }
    }
    
    kfree(kbuf);
    return 0;
}

/*
 * ============================================================================
 * 公共API
 * ============================================================================
 */

/*
 * 按 PID 隐藏进程
 */
int tear_proc_hide_pid(pid_t pid)
{
    int i, ret = -ENOSPC;
    unsigned long flags;
    
    if (pid <= 0)
        return -EINVAL;
    
    /* 验证 PID 存在 */
    rcu_read_lock();
    if (!find_task_by_vpid(pid)) {
        rcu_read_unlock();
        return -ESRCH;
    }
    rcu_read_unlock();
    
    spin_lock_irqsave(&proc_hide_state.lock, flags);
    
    /* 检查是否已隐藏 */
    for (i = 0; i < MAX_HIDDEN_PROCS; i++) {
        struct hidden_proc_entry *entry = &proc_hide_state.entries[i];
        if (entry->active && !entry->by_name && entry->pid == pid) {
            ret = 0;  /* 已经隐藏 */
            goto out;
        }
    }
    
    /* 查找空槽位 */
    for (i = 0; i < MAX_HIDDEN_PROCS; i++) {
        struct hidden_proc_entry *entry = &proc_hide_state.entries[i];
        
        if (!entry->active) {
            entry->pid = pid;
            entry->by_name = false;
            entry->active = true;
            proc_hide_state.count++;
            ret = 0;
            break;
        }
    }
    
out:
    spin_unlock_irqrestore(&proc_hide_state.lock, flags);
    
    if (ret == 0) {
        tear_debug("隐藏进程PID: %d\n", pid);
    }
    
    return ret;
}

/*
 * 按名称隐藏进程（所有同名进程都会被隐藏）
 */
int tear_proc_hide_name(const char *name)
{
    int i, ret = -ENOSPC;
    unsigned long flags;
    size_t name_len;
    
    if (!name)
        return -EINVAL;
    
    name_len = strlen(name);
    if (name_len == 0 || name_len >= TASK_COMM_LEN)
        return -EINVAL;
    
    spin_lock_irqsave(&proc_hide_state.lock, flags);
    
    /* 检查是否已隐藏 */
    for (i = 0; i < MAX_HIDDEN_PROCS; i++) {
        struct hidden_proc_entry *entry = &proc_hide_state.entries[i];
        if (entry->active && entry->by_name && 
            strncmp(entry->comm, name, TASK_COMM_LEN) == 0) {
            ret = 0;  /* 已经隐藏 */
            goto out;
        }
    }
    
    /* 查找空槽位 */
    for (i = 0; i < MAX_HIDDEN_PROCS; i++) {
        struct hidden_proc_entry *entry = &proc_hide_state.entries[i];
        
        if (!entry->active) {
            strncpy(entry->comm, name, TASK_COMM_LEN - 1);
            entry->comm[TASK_COMM_LEN - 1] = '\0';
            entry->by_name = true;
            entry->active = true;
            proc_hide_state.count++;
            ret = 0;
            break;
        }
    }
    
out:
    spin_unlock_irqrestore(&proc_hide_state.lock, flags);
    
    if (ret == 0) {
        tear_debug("隐藏进程名: %s\n", name);
    }
    
    return ret;
}

/*
 * 取消隐藏进程（按PID）
 */
int tear_proc_unhide_pid(pid_t pid)
{
    int i, ret = -ENOENT;
    unsigned long flags;
    
    if (pid <= 0)
        return -EINVAL;
    
    spin_lock_irqsave(&proc_hide_state.lock, flags);
    
    for (i = 0; i < MAX_HIDDEN_PROCS; i++) {
        struct hidden_proc_entry *entry = &proc_hide_state.entries[i];
        
        if (entry->active && !entry->by_name && entry->pid == pid) {
            entry->active = false;
            proc_hide_state.count--;
            ret = 0;
            break;
        }
    }
    
    spin_unlock_irqrestore(&proc_hide_state.lock, flags);
    
    tear_debug("取消隐藏进程PID: %d (结果=%d)\n", pid, ret);
    return ret;
}

/*
 * 取消隐藏进程（按名称）
 */
int tear_proc_unhide_name(const char *name)
{
    int i, ret = -ENOENT;
    unsigned long flags;
    
    if (!name)
        return -EINVAL;
    
    spin_lock_irqsave(&proc_hide_state.lock, flags);
    
    for (i = 0; i < MAX_HIDDEN_PROCS; i++) {
        struct hidden_proc_entry *entry = &proc_hide_state.entries[i];
        
        if (entry->active && entry->by_name &&
            strncmp(entry->comm, name, TASK_COMM_LEN) == 0) {
            entry->active = false;
            proc_hide_state.count--;
            ret = 0;
            break;
        }
    }
    
    spin_unlock_irqrestore(&proc_hide_state.lock, flags);
    
    tear_debug("取消隐藏进程名: %s (结果=%d)\n", name, ret);
    return ret;
}

/*
 * 清除所有隐藏条目
 */
void tear_proc_hide_clear(void)
{
    unsigned long flags;
    
    spin_lock_irqsave(&proc_hide_state.lock, flags);
    
    memset(proc_hide_state.entries, 0, sizeof(proc_hide_state.entries));
    proc_hide_state.count = 0;
    
    spin_unlock_irqrestore(&proc_hide_state.lock, flags);
    
    tear_debug("已清除所有进程隐藏条目\n");
}

/*
 * 获取隐藏条目数量
 */
int tear_proc_hide_count(void)
{
    return proc_hide_state.count;
}

/*
 * 检查进程是否被隐藏
 */
bool tear_proc_is_hidden(pid_t pid)
{
    return should_hide_pid(pid);
}

/*
 * ============================================================================
 * 模块初始化/清理
 * ============================================================================
 */

/*
 * 初始化进程隐藏模块
 */
int teargame_proc_hide_init(void)
{
    int ret;
    
    if (proc_hide_state.initialized)
        return 0;
    
    /* 初始化状态 */
    spin_lock_init(&proc_hide_state.lock);
    memset(proc_hide_state.entries, 0, sizeof(proc_hide_state.entries));
    proc_hide_state.count = 0;
    
    /* 安装 kretprobe hook */
    memset(&proc_getdents_krp, 0, sizeof(proc_getdents_krp));
    proc_getdents_krp.kp.symbol_name = "__arm64_sys_getdents64";
    proc_getdents_krp.handler = proc_getdents_ret;
    proc_getdents_krp.entry_handler = proc_getdents_entry;
    proc_getdents_krp.data_size = sizeof(struct proc_getdents_data);
    proc_getdents_krp.maxactive = TEAR_KRETPROBE_MAXACTIVE;
    
    ret = register_kretprobe(&proc_getdents_krp);
    if (ret < 0) {
        tear_warn("进程隐藏hook安装失败: %d\n", ret);
        return ret;
    }
    
    proc_hook_installed = true;
    proc_hide_state.initialized = true;
    
    tear_info("进程隐藏模块已初始化\n");
    return 0;
}

/*
 * 清理进程隐藏模块
 */
void teargame_proc_hide_exit(void)
{
    if (!proc_hide_state.initialized)
        return;
    
    /* 移除 hook */
    if (proc_hook_installed) {
        unregister_kretprobe(&proc_getdents_krp);
        proc_hook_installed = false;
    }
    
    /* 清除隐藏条目 */
    tear_proc_hide_clear();
    
    proc_hide_state.initialized = false;
    tear_debug("进程隐藏模块已清理\n");
}
