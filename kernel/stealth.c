// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 隐藏模块 v2.0
 * 
 * 从以下位置隐藏模块:
 * - lsmod / /proc/modules
 * - /sys/module/
 * - kallsyms
 * 
 * 增强特性:
 * - 模块伪装（使用合法模块名而非清空）
 * - Kretprobe结构混淆
 * - 更全面的符号过滤
 */

#include "teargame.h"
#include "teargame_stealth.h"
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/vmalloc.h>

/*
 * ============================================================================
 * 伪装模块名列表
 * ============================================================================
 * 使用常见且不可疑的内核模块名
 */
static const char *decoy_module_names[] = {
    "crc32_ce",         /* ARM加密模块 */
    "sha256_arm64",     /* SHA256模块 */
    "aes_ce_blk",       /* AES加密模块 */
    "ghash_ce",         /* GHASH模块 */
    "dm_mod",           /* 设备映射 */
    "loop",             /* 回环设备 */
    "ip_tables",        /* 网络过滤 */
    "nf_nat",           /* NAT模块 */
};

#define NUM_DECOY_NAMES ARRAY_SIZE(decoy_module_names)

/*
 * ============================================================================
 * 隐藏状态
 * ============================================================================
 * struct tear_stealth_state 已在 teargame_types.h 中定义
 */
static struct tear_stealth_state stealth;

/* 用于隐藏 kallsyms 的 s_show 钩子 */
static struct kretprobe s_show_krp;
static bool s_show_hook_installed = false;

/*
 * ============================================================================
 * 需要过滤的符号模式
 * ============================================================================
 */
static const char *filter_patterns[] = {
    "teargame",
    "TearGame",
    "tear_",
    "TEAR_",
    "g_state",
    "stealth",
    "obfuscate",
    "_okrp",
    "prctl_krp",
    "hidden_",
    "decoy_",
};

#define NUM_FILTER_PATTERNS ARRAY_SIZE(filter_patterns)

/*
 * ============================================================================
 * Kallsyms 隐藏 (s_show 钩子)
 * ============================================================================
 */

/* s_show 钩子的数据 */
struct s_show_data {
    struct seq_file *seq;
    size_t prev_count;
};

/*
 * s_show 入口处理程序
 */
static int s_show_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct s_show_data *data = (struct s_show_data *)ri->data;
    
#ifdef CONFIG_ARM64
    data->seq = (struct seq_file *)regs->regs[0];
#else
    data->seq = (struct seq_file *)regs->regs[0];
#endif

    if (data->seq)
        data->prev_count = data->seq->count;
    else
        data->prev_count = 0;
    
    return 0;
}

/*
 * 检查缓冲区是否包含需要过滤的模式
 */
static bool should_filter_symbol(const char *buf, size_t len)
{
    int i;
    
    for (i = 0; i < NUM_FILTER_PATTERNS; i++) {
        if (strnstr(buf, filter_patterns[i], len))
            return true;
    }
    
    /* 也检查原始模块名 */
    if (stealth.orig_name[0] != '\0' &&
        strnstr(buf, stealth.orig_name, len)) {
        return true;
    }
    
    /* 检查伪装名（避免伪装名的符号被发现） */
    if (stealth.decoy_name[0] != '\0' &&
        strnstr(buf, stealth.decoy_name, len)) {
        /* 如果是真正的伪装模块的符号，不要过滤 */
        /* 但如果是我们的符号带伪装名前缀，需要过滤 */
        if (strnstr(buf, "tear_", len) || strnstr(buf, "TEAR_", len))
            return true;
    }
    
    return false;
}

/*
 * s_show 返回处理程序 - 过滤掉 teargame 符号
 */
static int s_show_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct s_show_data *data = (struct s_show_data *)ri->data;
    struct seq_file *seq;
    size_t prev_count;
    size_t curr_count;
    char *buf_start;
    size_t len;
    
    if (!stealth.hidden)
        return 0;
    
    seq = data->seq;
    if (!seq || !seq->buf)
        return 0;
    
    prev_count = data->prev_count;
    curr_count = seq->count;
    
    if (curr_count <= prev_count)
        return 0;
    
    buf_start = seq->buf + prev_count;
    len = curr_count - prev_count;
    
    /* 检查是否需要过滤 */
    if (should_filter_symbol(buf_start, len)) {
        /* 通过回滚 seq->count 来隐藏 */
        seq->count = prev_count;
        tear_debug("过滤符号: %.*s\n", (int)min(len, (size_t)64), buf_start);
    }
    
    return 0;
}

/*
 * 安装 kallsyms 隐藏钩子
 */
static int install_kallsym_hook(void)
{
    int ret;
    
    if (s_show_hook_installed)
        return 0;
    
    memset(&s_show_krp, 0, sizeof(s_show_krp));
    
    s_show_krp.kp.symbol_name = TEAR_HOOK_SSHOW_SYMBOL;
    s_show_krp.handler = s_show_ret;
    s_show_krp.entry_handler = s_show_entry;
    s_show_krp.data_size = sizeof(struct s_show_data);
    s_show_krp.maxactive = TEAR_KRETPROBE_MAXACTIVE;
    
    ret = register_kretprobe(&s_show_krp);
    if (ret < 0) {
        tear_warn("安装kallsyms钩子失败: %d\n", ret);
        return ret;
    }
    
    s_show_hook_installed = true;
    tear_debug("kallsyms钩子已安装\n");
    
    return 0;
}

/*
 * 移除 kallsyms 隐藏钩子
 */
static void remove_kallsym_hook(void)
{
    if (!s_show_hook_installed)
        return;
    
    if (s_show_krp.kp.addr)
        unregister_kretprobe(&s_show_krp);
    
    s_show_hook_installed = false;
    tear_debug("kallsyms钩子已移除\n");
}

/*
 * ============================================================================
 * 模块链表操作
 * ============================================================================
 */

/*
 * 从模块链表中移除（但保留模块功能）
 */
static int remove_from_module_list(struct module *mod)
{
    if (stealth.list_removed)
        return 0;
    
    /* 保存链表位置以便恢复 */
    stealth.prev_module = mod->list.prev;
    stealth.next_module = mod->list.next;
    
    /* 使用 RCU 安全移除 */
    list_del_rcu(&mod->list);
    synchronize_rcu();
    
    stealth.list_removed = true;
    tear_debug("已从模块链表移除\n");
    
    return 0;
}

/*
 * 恢复到模块链表
 */
static int restore_to_module_list(struct module *mod)
{
    if (!stealth.list_removed)
        return 0;
    
    if (!stealth.prev_module || !stealth.next_module)
        return -EINVAL;
    
    /* 重新加入链表 */
    list_add_rcu(&mod->list, stealth.prev_module);
    synchronize_rcu();
    
    stealth.list_removed = false;
    tear_debug("已恢复到模块链表\n");
    
    return 0;
}

/*
 * ============================================================================
 * 公共API
 * ============================================================================
 */

/*
 * 初始化隐藏模块
 */
int teargame_stealth_init(void)
{
    mutex_init(&stealth.lock);
    stealth.hidden = false;
    stealth.kallsym_hooked = false;
    stealth.orig_parent = NULL;
    stealth.list_removed = false;
    stealth.prev_module = NULL;
    stealth.next_module = NULL;
    memset(stealth.orig_name, 0, sizeof(stealth.orig_name));
    memset(stealth.decoy_name, 0, sizeof(stealth.decoy_name));
    
    tear_debug("隐藏模块已初始化\n");
    return 0;
}

/*
 * 清理隐藏模块
 */
void teargame_stealth_cleanup(void)
{
    /* 在清理之前确保可见 */
    teargame_stealth_show();
    
    tear_debug("隐藏模块已清理\n");
}

/*
 * 选择伪装名
 */
static const char *select_decoy_name(void)
{
    unsigned int idx;
    
    /* 使用随机索引选择伪装名 */
    idx = prandom_u32() % NUM_DECOY_NAMES;
    
    return decoy_module_names[idx];
}

/*
 * 隐藏模块
 */
int teargame_stealth_hide(void)
{
    struct module *mod = THIS_MODULE;
    const char *decoy;
    
    mutex_lock(&stealth.lock);
    
    if (stealth.hidden) {
        tear_debug("模块已经隐藏\n");
        mutex_unlock(&stealth.lock);
        return 0;
    }
    
    tear_debug("正在隐藏模块...\n");
    
    /* 保持模块引用，防止意外卸载 */
    if (!try_module_get(mod)) {
        tear_warn("获取模块引用失败\n");
        mutex_unlock(&stealth.lock);
        return -ENOENT;
    }
    
    /* 保存原始名称 */
    strncpy(stealth.orig_name, mod->name, sizeof(stealth.orig_name) - 1);
    
    /* 选择伪装名 */
    decoy = select_decoy_name();
    strncpy(stealth.decoy_name, decoy, sizeof(stealth.decoy_name) - 1);
    
    /* 安装 kallsyms 钩子（在修改名称之前） */
    if (!stealth.kallsym_hooked) {
        if (install_kallsym_hook() == 0)
            stealth.kallsym_hooked = true;
    }
    
    /* 通过移除 kobject 从 /sys/module 隐藏 */
    if (mod->mkobj.kobj.parent) {
        stealth.orig_parent = mod->mkobj.kobj.parent;
        kobject_del(&mod->mkobj.kobj);
        tear_debug("已从sysfs移除\n");
    }
    
    /* 从模块链表移除 */
    remove_from_module_list(mod);
    
    /* 使用伪装名而非清空（更隐蔽） */
    strncpy((char *)mod->name, decoy, MODULE_NAME_LEN - 1);
    ((char *)mod->name)[MODULE_NAME_LEN - 1] = '\0';
    
    stealth.hidden = true;
    
    mutex_unlock(&stealth.lock);
    
    tear_debug("模块隐藏成功 (伪装为: %s)\n", decoy);
    return 0;
}

/*
 * 显示模块（取消隐藏）
 */
int teargame_stealth_show(void)
{
    struct module *mod = THIS_MODULE;
    int ret;
    
    mutex_lock(&stealth.lock);
    
    if (!stealth.hidden) {
        tear_debug("模块未隐藏\n");
        mutex_unlock(&stealth.lock);
        return 0;
    }
    
    tear_debug("正在显示模块...\n");
    
    /* 恢复模块名 */
    if (stealth.orig_name[0] != '\0') {
        strncpy((char *)mod->name, stealth.orig_name, MODULE_NAME_LEN - 1);
        ((char *)mod->name)[MODULE_NAME_LEN - 1] = '\0';
    }
    
    /* 恢复到模块链表 */
    restore_to_module_list(mod);
    
    /* 恢复 kobject 到 sysfs */
    if (stealth.orig_parent) {
        ret = kobject_add(&mod->mkobj.kobj, stealth.orig_parent,
                          "%s", stealth.orig_name);
        if (ret == 0) {
            stealth.orig_parent = NULL;
            tear_debug("已恢复到sysfs\n");
        } else {
            tear_warn("恢复kobject失败: %d\n", ret);
        }
    }
    
    /* 移除 kallsyms 钩子 */
    if (stealth.kallsym_hooked) {
        remove_kallsym_hook();
        stealth.kallsym_hooked = false;
    }
    
    /* 释放模块引用 */
    module_put(mod);
    
    stealth.hidden = false;
    memset(stealth.decoy_name, 0, sizeof(stealth.decoy_name));
    
    mutex_unlock(&stealth.lock);
    
    tear_debug("模块已可见\n");
    return 0;
}

/*
 * 检查模块是否隐藏
 */
bool teargame_stealth_is_hidden(void)
{
    return stealth.hidden;
}

/*
 * 获取当前伪装名
 */
const char *teargame_stealth_get_decoy_name(void)
{
    if (!stealth.hidden)
        return NULL;
    
    return stealth.decoy_name;
}

/*
 * 添加自定义过滤模式
 */
int teargame_stealth_add_filter(const char *pattern)
{
    /* 预留接口，当前使用静态列表 */
    (void)pattern;
    return -ENOSYS;
}
