// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 钩子系统 v2.0
 * 
 * 使用 kretprobe 钩住 __arm64_sys_prctl
 * 拦截通过 prctl 系统调用传递的 TearGame 命令
 * 
 * 无痕优化特性:
 * - 动态魔数验证（每10秒变化）
 * - 快速路径筛选（最小化非TearGame调用开销）
 * - 时序抖动（模糊操作时序特征）
 * - 常量时间比较（防止时序侧信道）
 */

#include "teargame.h"
#include "teargame_stealth.h"
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>

/*
 * ============================================================================
 * 钩子数据结构
 * ============================================================================
 */

/* 在入口和返回处理程序之间传递的数据 */
struct tear_prctl_hook_data {
    int is_tear_call;
    unsigned long cmd;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    u64 entry_time;         /* 入口时间戳（用于调试） */
};

/*
 * ============================================================================
 * Prctl 钩子
 * ============================================================================
 */

static struct kretprobe prctl_krp;
static bool prctl_hook_installed = false;

/* 统计信息（调试用） */
#if TEAR_DEBUG_ENABLED
static atomic64_t hook_total_calls = ATOMIC64_INIT(0);
static atomic64_t hook_tear_calls = ATOMIC64_INIT(0);
static atomic64_t hook_fast_reject = ATOMIC64_INIT(0);
#endif

/*
 * 入口处理程序 - 在进入 prctl 时调用
 * 
 * 优化策略:
 * 1. 快速路径：检查魔数高位特征，不匹配直接返回（最小开销）
 * 2. 完整验证：高位匹配后进行动态魔数验证
 * 3. 时序抖动：验证通过后添加随机延迟
 */
static int prctl_entry_handler(struct kretprobe_instance *ri, 
                               struct pt_regs *regs)
{
    struct tear_prctl_hook_data *data;
    u32 option;
    
    data = (struct tear_prctl_hook_data *)ri->data;
    
    /* 初始化为非 TearGame 调用 */
    data->is_tear_call = 0;
    
#if TEAR_DEBUG_ENABLED
    atomic64_inc(&hook_total_calls);
#endif
    
#ifdef CONFIG_ARM64
    /* ARM64: 参数在 x0-x4 */
    option = (u32)regs->regs[0];
#else
    option = (u32)regs->regs[0];
#endif

    /*
     * 快速路径：检查魔数高4位特征
     * 这是最常见的情况（非TearGame调用），需要最小开销
     * 使用 likely() 提示编译器优化分支预测
     */
    if (likely(!tear_quick_check(option))) {
#if TEAR_DEBUG_ENABLED
        atomic64_inc(&hook_fast_reject);
#endif
        return 0;  /* 极小开销退出 */
    }
    
    /*
     * 高位匹配，进行完整的动态魔数验证
     * 使用常量时间比较防止时序侧信道
     */
    if (!tear_verify_magic(option)) {
        /* 高位匹配但魔数不对，可能是误判或探测 */
        TEAR_JITTER();  /* 添加抖动混淆时序 */
        return 0;
    }
    
    /* 
     * TearGame 调用确认
     * 添加时序抖动防止时序分析
     */
    TEAR_JITTER();
    
    data->is_tear_call = 1;
    
#if TEAR_DEBUG_ENABLED
    atomic64_inc(&hook_tear_calls);
    data->entry_time = ktime_get_ns();
#endif
    
#ifdef CONFIG_ARM64
    data->cmd = regs->regs[1];   /* x1 = 命令 */
    data->arg1 = regs->regs[2];  /* x2 = 参数1 */
    data->arg2 = regs->regs[3];  /* x3 = 参数2 */
    data->arg3 = regs->regs[4];  /* x4 = 参数3 */
#else
    data->cmd = regs->regs[1];
    data->arg1 = regs->regs[2];
    data->arg2 = regs->regs[3];
    data->arg3 = regs->regs[4];
#endif

    tear_debug("检测到TearGame调用: cmd=0x%lx\n", data->cmd);
    
    return 0;
}

/*
 * 返回处理程序 - 在 prctl 返回时调用
 * 如果这是 TearGame 调用，执行命令并修改返回值
 */
static int prctl_ret_handler(struct kretprobe_instance *ri,
                            struct pt_regs *regs)
{
    struct tear_prctl_hook_data *data;
    long result;
    
    data = (struct tear_prctl_hook_data *)ri->data;
    
    if (!data->is_tear_call)
        return 0;
    
    /* 添加入口抖动 */
    TEAR_JITTER();
    
    /* 执行 TearGame 命令 */
    result = teargame_handle_command(data->cmd, data->arg1, 
                                     data->arg2, data->arg3);
    
    /* 修改返回值 */
#ifdef CONFIG_ARM64
    regs->regs[0] = result;
#else
    regs->regs[0] = result;
#endif

    /* 添加出口抖动 */
    TEAR_JITTER();

#if TEAR_DEBUG_ENABLED
    {
        u64 duration = ktime_get_ns() - data->entry_time;
        tear_debug("TearGame命令结果: %ld (耗时: %llu ns)\n", 
                   result, duration);
    }
#else
    tear_debug("TearGame命令结果: %ld\n", result);
#endif
    
    return 0;
}

/*
 * ============================================================================
 * 公共API
 * ============================================================================
 */

/*
 * 初始化钩子系统
 */
int teargame_hook_init(void)
{
    int ret;
    
    if (prctl_hook_installed) {
        tear_info("钩子已安装\n");
        return 0;
    }
    
    /* 初始化混淆密钥 */
    tear_obf_init();
    
    memset(&prctl_krp, 0, sizeof(prctl_krp));
    
    /* 配置 kretprobe */
    prctl_krp.kp.symbol_name = TEAR_HOOK_PRCTL_SYMBOL;
    prctl_krp.handler = prctl_ret_handler;
    prctl_krp.entry_handler = prctl_entry_handler;
    prctl_krp.data_size = sizeof(struct tear_prctl_hook_data);
    prctl_krp.maxactive = TEAR_KRETPROBE_MAXACTIVE;
    
    /* 注册探针 */
    ret = register_kretprobe(&prctl_krp);
    if (ret < 0) {
        tear_err("注册kretprobe失败: %d\n", ret);
        return ret;
    }
    
    prctl_hook_installed = true;
    
    tear_info("钩子已安装 (动态魔数已启用)\n");
    tear_debug("  符号: %s\n", TEAR_HOOK_PRCTL_SYMBOL);
    tear_debug("  地址: %pS\n", prctl_krp.kp.addr);
    tear_debug("  魔数高位: 0x%08x\n", tear_magic_high_nibble());
    
    return 0;
}

/*
 * 清理钩子系统
 */
void teargame_hook_exit(void)
{
    if (!prctl_hook_installed)
        return;
    
    unregister_kretprobe(&prctl_krp);
    prctl_hook_installed = false;
    
#if TEAR_DEBUG_ENABLED
    tear_info("钩子已移除 (丢失: %u)\n", prctl_krp.nmissed);
    tear_info("  总调用: %lld\n", atomic64_read(&hook_total_calls));
    tear_info("  TearGame调用: %lld\n", atomic64_read(&hook_tear_calls));
    tear_info("  快速拒绝: %lld\n", atomic64_read(&hook_fast_reject));
#else
    tear_info("钩子已移除 (丢失: %u)\n", prctl_krp.nmissed);
#endif
}

/*
 * 获取当前动态魔数（供用户空间使用）
 */
u32 teargame_get_current_magic(void)
{
    return tear_dynamic_magic(0);
}

/*
 * 检查钩子状态
 */
bool teargame_hook_is_installed(void)
{
    return prctl_hook_installed;
}
