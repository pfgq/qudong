/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame Configuration Parameters
 */

#ifndef _TEARGAME_CONFIG_H
#define _TEARGAME_CONFIG_H

/*
 * ============================================================================
 * Module Information
 * ============================================================================
 */
#define TEARGAME_VERSION        "2.0.0"
#define TEARGAME_AUTHOR         "TearGame Team"
#define TEARGAME_DESC           "TearGame Memory Access Module"
#define TEARGAME_LICENSE        "GPL"

/*
 * ============================================================================
 * Memory Operation Limits
 * ============================================================================
 */
/* Maximum size for single read/write operation (1MB) */
#define TEAR_MAX_RW_SIZE        (1 << 20)

/* Maximum size for safe read/write (256KB) */
#define TEAR_MAX_SAFE_RW_SIZE   (256 * 1024)

/* Minimum valid address (skip NULL page) */
#define TEAR_MIN_VALID_ADDR     0x1000UL

/* Maximum scatter/gather entries per request */
#define TEAR_MAX_SCATTER_ENTRIES 64

/*
 * ============================================================================
 * Process Cache Configuration
 * ============================================================================
 */
/* Number of hash buckets for process cache */
#ifdef CONFIG_TEARGAME_CACHE_BUCKETS
  #define TEAR_CACHE_BUCKETS    CONFIG_TEARGAME_CACHE_BUCKETS
#else
  #define TEAR_CACHE_BUCKETS    256
#endif

/* Maximum cached process entries */
#define TEAR_CACHE_MAX_ENTRIES  2048

/* Cache refresh interval in jiffies (500ms) */
#define TEAR_CACHE_REFRESH_JIFFIES  (HZ / 2)

/* LRU expiry time in jiffies (30 seconds) */
#define TEAR_CACHE_LRU_EXPIRY   (30 * HZ)

/* Maximum command line length to cache */
#define TEAR_CMDLINE_MAX_LEN    256

/* Maximum module name length */
#define TEAR_MODULE_NAME_MAX    256

/*
 * ============================================================================
 * Touch Device Configuration
 * ============================================================================
 */
/* Number of multi-touch slots */
#ifdef CONFIG_TEARGAME_TOUCH_SLOTS
  #define TEAR_TOUCH_MAX_SLOTS  CONFIG_TEARGAME_TOUCH_SLOTS
#else
  #define TEAR_TOUCH_MAX_SLOTS  10
#endif

/* Default touch screen dimensions */
#define TEAR_TOUCH_DEFAULT_WIDTH    1080
#define TEAR_TOUCH_DEFAULT_HEIGHT   2400

/* Touch pressure range */
#define TEAR_TOUCH_MIN_PRESSURE     0
#define TEAR_TOUCH_MAX_PRESSURE     255
#define TEAR_TOUCH_DEFAULT_PRESSURE 128

/* Touch major/minor axis */
#define TEAR_TOUCH_MIN_MAJOR        0
#define TEAR_TOUCH_MAX_MAJOR        255
#define TEAR_TOUCH_DEFAULT_MAJOR    10

/* Touch device name */
#define TEAR_TOUCH_DEVICE_NAME      "teargame_virtual_touch"

/*
 * ============================================================================
 * Authentication Configuration
 * ============================================================================
 */
/* Magic number for identification */
#define TEAR_MAGIC              0x54454152  /* "TEAR" in ASCII */

/* Authentication time window (seconds) */
#define TEAR_AUTH_TIME_WINDOW   60

/* Maximum authentication attempts before lockout */
#define TEAR_AUTH_MAX_ATTEMPTS  5

/* Lockout duration (seconds) */
#define TEAR_AUTH_LOCKOUT_SEC   300

/* Hash seed for key generation */
#define TEAR_AUTH_HASH_SEED     0x4A319941

/* Key length (characters) */
#define TEAR_AUTH_KEY_LEN       16

/*
 * ============================================================================
 * Hook Configuration
 * ============================================================================
 */
/* Maximum active kretprobe instances */
#define TEAR_KRETPROBE_MAXACTIVE    64

/* Hooked syscall symbol name */
#define TEAR_HOOK_PRCTL_SYMBOL      "__arm64_sys_prctl"

/* Hooked kallsyms symbol name */
#define TEAR_HOOK_SSHOW_SYMBOL      "s_show"

/*
 * ============================================================================
 * Performance Tuning
 * ============================================================================
 */
/* Enable page prefetching */
#define TEAR_ENABLE_PREFETCH        1

/* Prefetch stride (pages) */
#define TEAR_PREFETCH_STRIDE        4

/* Enable batch page table walks */
#define TEAR_ENABLE_BATCH_PTW       1

/* Batch size for page table walks */
#define TEAR_BATCH_PTW_SIZE         16

/* Use percpu cache for allocations */
#define TEAR_USE_PERCPU_CACHE       1

/*
 * ============================================================================
 * Page Table Cache Configuration (页表缓存配置)
 * ============================================================================
 */
/* 启用页表遍历缓存 */
#define TEAR_ENABLE_PTW_CACHE       1

/* 页表缓存条目数（per-CPU） */
#define TEAR_PTW_CACHE_SIZE         32

/* 缓存过期时间 (jiffies) - 约100ms */
#define TEAR_PTW_CACHE_EXPIRY       (HZ / 10)

/* 缓存命中统计 (用于调试) */
#define TEAR_PTW_CACHE_STATS        0

/*
 * ============================================================================
 * Debug Configuration
 * ============================================================================
 */
#ifdef CONFIG_TEARGAME_DEBUG
  #define TEAR_DEBUG_ENABLED        1
#else
  #define TEAR_DEBUG_ENABLED        0
#endif

/* Touch debug (separate from main debug) */
#define TEAR_TOUCH_DEBUG_DEFAULT    0

/* Verbose memory operation logging */
#define TEAR_MEMORY_DEBUG           0

/* Log all command invocations */
#define TEAR_COMMAND_DEBUG          0

/*
 * ============================================================================
 * Error Codes (negative values)
 * ============================================================================
 */
#define TEAR_SUCCESS                0
#define TEAR_ERR_INVALID_ARG        (-EINVAL)
#define TEAR_ERR_NOT_AUTHORIZED     (-EPERM)
#define TEAR_ERR_NO_MEMORY          (-ENOMEM)
#define TEAR_ERR_FAULT              (-EFAULT)
#define TEAR_ERR_NOT_FOUND          (-ESRCH)
#define TEAR_ERR_IO                 (-EIO)
#define TEAR_ERR_BUSY               (-EBUSY)
#define TEAR_ERR_INVALID_CMD        (-ENOTTY)

/*
 * ============================================================================
 * Feature Flags
 * ============================================================================
 */
/* Enable stealth features */
#define TEAR_FEATURE_STEALTH        1

/* Enable virtual touch */
#define TEAR_FEATURE_TOUCH          1

/* Enable process cache */
#define TEAR_FEATURE_CACHE          1

/* Enable safe memory operations */
#define TEAR_FEATURE_SAFE_MEM       1

/* Enable huge page support */
#define TEAR_FEATURE_HUGEPAGE       1

/*
 * ============================================================================
 * 安全检查配置 (Security Configuration)
 * ============================================================================
 * 用于防止读取反作弊系统设置的陷阱地址
 */

/* 启用VMA权限检查 - 检测无读权限的陷阱区域 */
#define TEAR_SECURITY_CHECK_VMA         1

/* 启用缺页检测 - 跳过未映射/已换出的页面 */
#define TEAR_SECURITY_CHECK_PRESENT     1

/* 启用PROT_NONE检测 - 检测无权限陷阱页 */
#define TEAR_SECURITY_CHECK_PROTNONE    1

/* 跳过保护页 - Guard Page检测 */
#define TEAR_SECURITY_SKIP_GUARD        1

/* 跳过无读权限的VMA */
#define TEAR_SECURITY_SKIP_NOREAD       1

/* 跳过设备映射区域 (VM_IO/VM_PFNMAP) */
#define TEAR_SECURITY_SKIP_DEVICE       1

/* 跳过保留页 (PageReserved) */
#define TEAR_SECURITY_SKIP_RESERVED     1

/* 严格模式：任何可疑情况都跳过 */
#define TEAR_SECURITY_STRICT_MODE       1

/* 安全检查失败时返回零而非错误 */
#define TEAR_SECURITY_SILENT_FAIL       1

/*
 * ============================================================================
 * 安全错误码
 * ============================================================================
 */
#define TEAR_ERR_VMA_UNSAFE         (-1001)  /* VMA不安全 */
#define TEAR_ERR_PAGE_FAULT         (-1002)  /* 会触发缺页 */
#define TEAR_ERR_TRAP_ADDR          (-1003)  /* 陷阱地址 */
#define TEAR_ERR_PROT_NONE          (-1004)  /* PROT_NONE页 */
#define TEAR_ERR_NOT_PRESENT        (-1005)  /* 页面不存在 */
#define TEAR_ERR_RESERVED_PAGE      (-1006)  /* 保留页 */

#endif /* _TEARGAME_CONFIG_H */
