// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 内核模块 - 主入口
 * 
 * 本模块提供:
 * - 跨进程内存读写
 * - 进程查找和模块基址获取
 * - 虚拟触控输入设备
 * - 模块隐藏功能
 */

#include "teargame.h"

/*
 * ============================================================================
 * 全局状态
 * ============================================================================
 */
struct tear_global_state g_state = {
    .memory_init = false,
    .touch_init = false,
    .hook_init = false,
    .stealth_init = false,
    .cache_init = false,
};

/*
 * ============================================================================
 * 模块初始化
 * ============================================================================
 */
static int __init teargame_init(void)
{
    int ret;

    tear_info("========================================\n");
    tear_info("  TearGame 内核模块 v%s\n", TEARGAME_VERSION);
    tear_info("========================================\n");
    tear_info("作者: %s\n", TEARGAME_AUTHOR);
    tear_info("目标: ARM64, Linux 5.10+\n");
    tear_info("========================================\n");

    /* 初始化认证系统 */
    tear_auth_init();
    tear_info("认证系统已初始化\n");

    /* 初始化内存子系统 */
    ret = teargame_memory_init();
    if (ret < 0) {
        tear_err("初始化内存子系统失败: %d\n", ret);
        goto err_memory;
    }
    g_state.memory_init = true;

    /* 初始化安全内存子系统 */
    ret = teargame_memory_safe_init();
    if (ret < 0) {
        tear_err("初始化安全内存子系统失败: %d\n", ret);
        goto err_memory_safe;
    }

    /* 初始化批量内存操作 */
    ret = teargame_memory_batch_init();
    if (ret < 0) {
        tear_err("初始化批量内存子系统失败: %d\n", ret);
        goto err_memory_batch;
    }

    /* 初始化反调试模块 */
    ret = teargame_antidbg_init();
    if (ret < 0) {
        tear_err("初始化反调试模块失败: %d\n", ret);
        goto err_antidbg;
    }

    /* 初始化文件隐藏模块 */
    ret = teargame_file_hide_init();
    if (ret < 0) {
        tear_err("初始化文件隐藏模块失败: %d\n", ret);
        goto err_file_hide;
    }

    /* 初始化进程隐藏模块 */
    ret = teargame_proc_hide_init();
    if (ret < 0) {
        tear_err("初始化进程隐藏模块失败: %d\n", ret);
        goto err_proc_hide;
    }

    /* 初始化进程缓存 */
    ret = tear_cache_init();
    if (ret < 0) {
        tear_err("初始化进程缓存失败: %d\n", ret);
        goto err_cache;
    }
    g_state.cache_init = true;
    tear_info("进程缓存已初始化\n");

    /* 初始化触控设备 */
    ret = teargame_touch_module_init();
    if (ret < 0) {
        tear_err("初始化触控模块失败: %d\n", ret);
        goto err_touch;
    }
    g_state.touch_init = true;
    tear_info("触控模块已初始化\n");

    /* 初始化隐藏模块 */
    ret = teargame_stealth_init();
    if (ret < 0) {
        tear_err("初始化隐藏模块失败: %d\n", ret);
        goto err_stealth;
    }
    g_state.stealth_init = true;
    tear_info("隐藏模块已初始化\n");

    /* 初始化钩子 (prctl) */
    ret = teargame_hook_init();
    if (ret < 0) {
        tear_err("初始化钩子失败: %d\n", ret);
        goto err_hook;
    }
    g_state.hook_init = true;
    tear_info("钩子安装成功\n");

    /* 自动隐藏模块 */
#if TEAR_FEATURE_STEALTH
    teargame_stealth_hide();
    tear_info("模块已隐藏\n");
#endif

    tear_info("========================================\n");
    tear_info("  TearGame 初始化完成!\n");
    tear_info("========================================\n");

    return 0;

err_hook:
    teargame_stealth_cleanup();
err_stealth:
    teargame_touch_module_exit();
err_touch:
    tear_cache_cleanup();
err_cache:
    teargame_proc_hide_exit();
err_proc_hide:
    teargame_file_hide_exit();
err_file_hide:
    teargame_antidbg_exit();
err_antidbg:
    teargame_memory_batch_exit();
err_memory_batch:
    teargame_memory_safe_exit();
err_memory_safe:
    teargame_memory_exit();
err_memory:
    tear_auth_cleanup();
    
    tear_err("模块初始化失败!\n");
    return ret;
}

/*
 * ============================================================================
 * 模块清理
 * ============================================================================
 */
static void __exit teargame_exit(void)
{
    tear_info("TearGame 模块正在卸载...\n");

    /* 如果隐藏了先显示 */
    if (g_state.stealth_init) {
        teargame_stealth_show();
    }

    /* 清理认证 */
    tear_auth_cleanup();
    tear_info("认证系统已清理\n");

    /* 注销钩子 */
    if (g_state.hook_init) {
        teargame_hook_exit();
        tear_info("钩子已移除\n");
    }

    /* 清理触控设备 */
    if (g_state.touch_init) {
        teargame_touch_module_exit();
        tear_info("触控模块已清理\n");
    }

    /* 清理进程缓存 */
    if (g_state.cache_init) {
        tear_cache_cleanup();
        tear_info("进程缓存已清理\n");
    }

    /* 清理隐藏模块 */
    if (g_state.stealth_init) {
        teargame_stealth_cleanup();
        tear_info("隐藏模块已清理\n");
    }

    /* 清理进程隐藏 */
    teargame_proc_hide_exit();
    tear_info("进程隐藏模块已清理\n");

    /* 清理文件隐藏 */
    teargame_file_hide_exit();
    tear_info("文件隐藏模块已清理\n");

    /* 清理反调试 */
    teargame_antidbg_exit();
    tear_info("反调试模块已清理\n");

    /* 清理批量内存操作 */
    teargame_memory_batch_exit();
    tear_info("批量内存操作模块已清理\n");

    /* 清理内存子系统 */
    teargame_memory_safe_exit();
    if (g_state.memory_init) {
        teargame_memory_exit();
    }
    tear_info("内存子系统已清理\n");

    tear_info("TearGame 模块卸载成功\n");
}

module_init(teargame_init);
module_exit(teargame_exit);

MODULE_LICENSE(TEARGAME_LICENSE);
MODULE_AUTHOR(TEARGAME_AUTHOR);
MODULE_DESCRIPTION(TEARGAME_DESC);
MODULE_VERSION(TEARGAME_VERSION);

#ifdef CONFIG_ARM64
MODULE_INFO(arch, "arm64");
#endif
