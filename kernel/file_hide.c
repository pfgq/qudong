// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 文件隐藏模块
 * 
 * 通过 hook getdents64 系统调用实现文件/文件夹隐藏
 * 隐藏的文件仍可正常访问，只是不出现在目录列表中
 * 
 * 特点:
 * - 支持精确匹配和通配符匹配
 * - 支持指定父目录的隐藏
 * - 文件功能不受影响（可正常打开、读写）
 */

#include "teargame.h"
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

/*
 * ============================================================================
 * 配置常量
 * ============================================================================
 */

/* 最大隐藏条目数 */
#define MAX_HIDDEN_FILES    64

/* 文件名最大长度 */
#define MAX_FILENAME_LEN    256

/* 路径最大长度 */
#define MAX_PATH_LEN        512

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

/* 隐藏条目 */
struct hidden_file_entry {
    char name[MAX_FILENAME_LEN];    /* 文件/目录名或模式 */
    char parent_path[MAX_PATH_LEN]; /* 父目录路径（可选，空=全局匹配） */
    bool is_pattern;                /* 是否是通配符模式 */
    bool active;                    /* 是否激活 */
};

/* 模块状态 */
static struct {
    struct hidden_file_entry entries[MAX_HIDDEN_FILES];
    spinlock_t lock;
    int count;                      /* 当前隐藏条目数 */
    bool initialized;
} file_hide_state;

/* Kretprobe 钩子 */
static struct kretprobe getdents_krp;
static struct kretprobe getdents64_krp;
static bool getdents_hook_installed = false;
static bool getdents64_hook_installed = false;

/* getdents 钩子的数据 */
struct getdents_hook_data {
    void __user *dirent;
    unsigned int count;
    int fd;
};

/*
 * ============================================================================
 * 辅助函数
 * ============================================================================
 */

/*
 * 检查文件名是否匹配模式
 * 支持 * 通配符（只在开头）
 */
static bool match_pattern(const char *pattern, const char *name)
{
    /* 通配符匹配: *xxx 匹配包含 xxx 的名称 */
    if (pattern[0] == '*') {
        return strstr(name, pattern + 1) != NULL;
    }
    
    /* 精确匹配 */
    return strcmp(pattern, name) == 0;
}

/*
 * 检查文件名是否应被隐藏
 */
static bool should_hide_file(const char *name, const char *dir_path)
{
    int i;
    bool hide = false;
    unsigned long flags;
    
    if (!name || name[0] == '\0')
        return false;
    
    /* 不隐藏 . 和 .. */
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return false;
    
    spin_lock_irqsave(&file_hide_state.lock, flags);
    
    for (i = 0; i < MAX_HIDDEN_FILES; i++) {
        struct hidden_file_entry *entry = &file_hide_state.entries[i];
        
        if (!entry->active)
            continue;
        
        /* 检查父目录（如果指定） */
        if (entry->parent_path[0] != '\0' && dir_path) {
            if (strcmp(entry->parent_path, dir_path) != 0)
                continue;
        }
        
        /* 检查名称匹配 */
        if (entry->is_pattern) {
            if (match_pattern(entry->name, name)) {
                hide = true;
                break;
            }
        } else {
            if (strcmp(entry->name, name) == 0) {
                hide = true;
                break;
            }
        }
    }
    
    spin_unlock_irqrestore(&file_hide_state.lock, flags);
    return hide;
}

/*
 * ============================================================================
 * Kretprobe 处理程序 - getdents64
 * ============================================================================
 */

/*
 * getdents64 入口处理 - 保存参数
 */
static int getdents64_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct getdents_hook_data *data = (struct getdents_hook_data *)ri->data;
    
#ifdef CONFIG_ARM64
    data->fd = (int)regs->regs[0];
    data->dirent = (void __user *)regs->regs[1];
    data->count = (unsigned int)regs->regs[2];
#else
    data->fd = (int)regs->di;
    data->dirent = (void __user *)regs->si;
    data->count = (unsigned int)regs->dx;
#endif
    
    return 0;
}

/*
 * getdents64 返回处理 - 过滤隐藏文件
 */
static int getdents64_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct getdents_hook_data *data = (struct getdents_hook_data *)ri->data;
    struct linux_dirent64 __user *dirent;
    char *kbuf = NULL;
    long ret;
    long new_ret;
    unsigned long offset = 0;
    char name_buf[MAX_FILENAME_LEN];
    
#ifdef CONFIG_ARM64
    ret = (long)regs->regs[0];
#else
    ret = (long)regs->ax;
#endif
    
    /* 如果返回值 <= 0，无需处理 */
    if (ret <= 0)
        return 0;
    
    /* 检查是否有隐藏条目 */
    if (file_hide_state.count == 0)
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
        
        if (reclen <= 0 || offset + reclen > ret)
            break;
        
        /* 获取文件名 */
        strncpy(name_buf, d->d_name, sizeof(name_buf) - 1);
        name_buf[sizeof(name_buf) - 1] = '\0';
        
        if (should_hide_file(name_buf, NULL)) {
            /* 隐藏此条目：将后续条目前移 */
            int remaining = ret - offset - reclen;
            
            if (remaining > 0) {
                memmove(kbuf + offset, kbuf + offset + reclen, remaining);
            }
            
            new_ret -= reclen;
            ret -= reclen;
            /* 不增加 offset，继续检查当前位置 */
        } else {
            offset += reclen;
        }
    }
    
    /* 复制修改后的数据回用户空间 */
    if (new_ret > 0 && new_ret != ret + (ret - new_ret)) {
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
 * 添加隐藏文件/文件夹
 * 
 * @name: 文件/文件夹名称或模式（*xxx 表示包含xxx）
 * @parent_path: 父目录路径（NULL或空表示全局匹配）
 */
int tear_file_hide_add(const char *name, const char *parent_path)
{
    int i, ret = -ENOSPC;
    unsigned long flags;
    size_t name_len;
    
    if (!name)
        return -EINVAL;
    
    name_len = strlen(name);
    if (name_len == 0 || name_len >= MAX_FILENAME_LEN)
        return -EINVAL;
    
    spin_lock_irqsave(&file_hide_state.lock, flags);
    
    /* 查找空槽位 */
    for (i = 0; i < MAX_HIDDEN_FILES; i++) {
        struct hidden_file_entry *entry = &file_hide_state.entries[i];
        
        if (!entry->active) {
            /* 填充条目 */
            strncpy(entry->name, name, MAX_FILENAME_LEN - 1);
            entry->name[MAX_FILENAME_LEN - 1] = '\0';
            
            /* 判断是否是通配符模式 */
            entry->is_pattern = (name[0] == '*');
            
            /* 设置父目录 */
            if (parent_path && parent_path[0] != '\0') {
                strncpy(entry->parent_path, parent_path, MAX_PATH_LEN - 1);
                entry->parent_path[MAX_PATH_LEN - 1] = '\0';
            } else {
                entry->parent_path[0] = '\0';
            }
            
            entry->active = true;
            file_hide_state.count++;
            ret = 0;
            break;
        }
    }
    
    spin_unlock_irqrestore(&file_hide_state.lock, flags);
    
    if (ret == 0) {
        tear_debug("隐藏文件: %s (结果=%d)\n", name, ret);
    }
    
    return ret;
}

/*
 * 取消隐藏文件/文件夹
 */
int tear_file_hide_remove(const char *name)
{
    int i, ret = -ENOENT;
    unsigned long flags;
    
    if (!name)
        return -EINVAL;
    
    spin_lock_irqsave(&file_hide_state.lock, flags);
    
    for (i = 0; i < MAX_HIDDEN_FILES; i++) {
        struct hidden_file_entry *entry = &file_hide_state.entries[i];
        
        if (entry->active && strcmp(entry->name, name) == 0) {
            entry->active = false;
            file_hide_state.count--;
            ret = 0;
            break;
        }
    }
    
    spin_unlock_irqrestore(&file_hide_state.lock, flags);
    
    tear_debug("取消隐藏文件: %s (结果=%d)\n", name, ret);
    return ret;
}

/*
 * 清除所有隐藏条目
 */
void tear_file_hide_clear(void)
{
    unsigned long flags;
    
    spin_lock_irqsave(&file_hide_state.lock, flags);
    
    memset(file_hide_state.entries, 0, sizeof(file_hide_state.entries));
    file_hide_state.count = 0;
    
    spin_unlock_irqrestore(&file_hide_state.lock, flags);
    
    tear_debug("已清除所有文件隐藏条目\n");
}

/*
 * 获取隐藏条目数量
 */
int tear_file_hide_count(void)
{
    return file_hide_state.count;
}

/*
 * 检查文件是否被隐藏
 */
bool tear_file_is_hidden(const char *name)
{
    return should_hide_file(name, NULL);
}

/*
 * ============================================================================
 * 模块初始化/清理
 * ============================================================================
 */

/*
 * 初始化文件隐藏模块
 */
int teargame_file_hide_init(void)
{
    int ret;
    
    if (file_hide_state.initialized)
        return 0;
    
    /* 初始化状态 */
    spin_lock_init(&file_hide_state.lock);
    memset(file_hide_state.entries, 0, sizeof(file_hide_state.entries));
    file_hide_state.count = 0;
    
    /* 安装 getdents64 hook */
    memset(&getdents64_krp, 0, sizeof(getdents64_krp));
    getdents64_krp.kp.symbol_name = "__arm64_sys_getdents64";
    getdents64_krp.handler = getdents64_ret;
    getdents64_krp.entry_handler = getdents64_entry;
    getdents64_krp.data_size = sizeof(struct getdents_hook_data);
    getdents64_krp.maxactive = TEAR_KRETPROBE_MAXACTIVE;
    
    ret = register_kretprobe(&getdents64_krp);
    if (ret < 0) {
        tear_warn("文件隐藏hook(getdents64)安装失败: %d\n", ret);
        /* 继续尝试其他 */
    } else {
        getdents64_hook_installed = true;
        tear_debug("getdents64 hook已安装\n");
    }
    
    /* 同时安装 getdents hook（32位兼容） */
    memset(&getdents_krp, 0, sizeof(getdents_krp));
    getdents_krp.kp.symbol_name = "__arm64_sys_getdents";
    getdents_krp.handler = getdents64_ret;  /* 使用相同处理器 */
    getdents_krp.entry_handler = getdents64_entry;
    getdents_krp.data_size = sizeof(struct getdents_hook_data);
    getdents_krp.maxactive = TEAR_KRETPROBE_MAXACTIVE;
    
    ret = register_kretprobe(&getdents_krp);
    if (ret < 0) {
        tear_debug("文件隐藏hook(getdents)安装失败: %d (非致命)\n", ret);
    } else {
        getdents_hook_installed = true;
        tear_debug("getdents hook已安装\n");
    }
    
    if (!getdents64_hook_installed && !getdents_hook_installed) {
        tear_err("文件隐藏模块初始化失败: 无法安装任何hook\n");
        return -ENOENT;
    }
    
    file_hide_state.initialized = true;
    tear_info("文件隐藏模块已初始化\n");
    
    return 0;
}

/*
 * 清理文件隐藏模块
 */
void teargame_file_hide_exit(void)
{
    if (!file_hide_state.initialized)
        return;
    
    /* 移除 hooks */
    if (getdents64_hook_installed) {
        unregister_kretprobe(&getdents64_krp);
        getdents64_hook_installed = false;
    }
    
    if (getdents_hook_installed) {
        unregister_kretprobe(&getdents_krp);
        getdents_hook_installed = false;
    }
    
    /* 清除隐藏条目 */
    tear_file_hide_clear();
    
    file_hide_state.initialized = false;
    tear_debug("文件隐藏模块已清理\n");
}
