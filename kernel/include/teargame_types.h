/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame Type Definitions
 */

#ifndef _TEARGAME_TYPES_H
#define _TEARGAME_TYPES_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/input.h>
#include <linux/sched.h>

#include "teargame_config.h"

/*
 * ============================================================================
 * Process Cache Types
 * ============================================================================
 */

/* Cached process entry */
struct tear_process_entry {
    struct hlist_node   node;           /* Hash list node */
    struct rcu_head     rcu;            /* RCU callback head */
    pid_t               pid;            /* Process ID */
    char                name[TASK_COMM_LEN];    /* Process name (comm) */
    char                cmdline[TEAR_CMDLINE_MAX_LEN]; /* Command line */
    unsigned long       last_access;    /* Last access jiffies (for LRU) */
    unsigned long       cache_time;     /* When entry was cached */
};

/* Process cache hash table */
struct tear_process_cache {
    struct hlist_head   buckets[TEAR_CACHE_BUCKETS];
    spinlock_t          lock;
    atomic_t            count;
    unsigned long       last_scan;
    bool                initialized;
};

/*
 * ============================================================================
 * Memory Operation Types
 * ============================================================================
 */

/* Page table walk result */
struct tear_ptw_result {
    phys_addr_t         phys_addr;      /* Physical address */
    unsigned long       page_size;      /* Page size (4K/2M/1G) */
    bool                valid;          /* Is mapping valid */
    bool                writable;       /* Is mapping writable */
};

/* Memory operation context */
struct tear_mem_context {
    struct task_struct  *task;
    struct mm_struct    *mm;
    void                *kernel_buf;
    size_t              buf_size;
    bool                need_free;
};

/* Batch read request (internal) */
struct tear_batch_entry {
    unsigned long       vaddr;
    size_t              size;
    void                *dest;
    ssize_t             result;
};

/*
 * ============================================================================
 * Touch Device Types
 * ============================================================================
 */

/* Touch slot state */
struct tear_touch_slot {
    bool                down;           /* Is finger down */
    int                 x;              /* Last X position */
    int                 y;              /* Last Y position */
    int                 pressure;       /* Pressure value */
    unsigned long       down_time;      /* When finger went down */
};

/* Touch device context */
struct tear_touch_device {
    struct input_dev    *input;         /* Input device */
    struct mutex        lock;           /* Device lock */
    rwlock_t            rwlock;         /* Read-write lock for hot path */
    bool                initialized;    /* Is device ready */
    int                 width;          /* Screen width */
    int                 height;         /* Screen height */
    struct tear_touch_slot slots[TEAR_TOUCH_MAX_SLOTS];
    atomic_t            down_count;     /* Active touch count */
    atomic_t            total_down;     /* Total down events */
    atomic_t            total_up;       /* Total up events */
    bool                debug;          /* Debug mode */
};

/*
 * ============================================================================
 * Hook Types
 * ============================================================================
 */

/* Data passed between entry and return handlers */
struct tear_prctl_data {
    bool                is_tear_call;   /* Is this a TearGame call */
    unsigned long       cmd;            /* Command code */
    unsigned long       arg1;           /* Argument 1 */
    unsigned long       arg2;           /* Argument 2 */
    unsigned long       arg3;           /* Argument 3 */
    long                result;         /* Command result */
};

/* S_show hook data (for kallsyms hiding) */
struct tear_sshow_data {
    struct seq_file     *seq;
    size_t              prev_count;
};

/*
 * ============================================================================
 * Stealth Types
 * ============================================================================
 */

/* Stealth state */
struct tear_stealth_state {
    bool                hidden;
    bool                kallsym_hooked;
    struct kobject      *orig_parent;
    char                orig_name[MODULE_NAME_LEN];
    char                decoy_name[MODULE_NAME_LEN];
    struct mutex        lock;
    
    /* 模块链表相关 */
    struct list_head    *prev_module;
    struct list_head    *next_module;
    bool                list_removed;
};

/*
 * ============================================================================
 * Authentication Types
 * ============================================================================
 */

/* Authentication state */
struct tear_auth_state {
    atomic_t            verified;       /* Is authenticated */
    atomic_t            attempts;       /* Failed attempt count */
    unsigned long       lockout_until;  /* Lockout expiry jiffies */
    spinlock_t          lock;
};

/*
 * ============================================================================
 * Anti-Debug Types
 * ============================================================================
 */

/* Debug detection status */
struct tear_debug_status {
    bool                kgdb_connected;     /* 内核调试器连接 */
    bool                debugger_present;   /* 调试器进程存在 */
    bool                analyzer_present;   /* 分析工具存在 */
    bool                injector_present;   /* 注入工具存在 */
    bool                current_traced;     /* 当前进程被追踪 */
};

/*
 * ============================================================================
 * Global State Type
 * ============================================================================
 */

/* Module global state */
struct tear_global_state {
    struct tear_auth_state      auth;
    struct tear_touch_device    touch;
    struct tear_process_cache   cache;
    struct tear_stealth_state   stealth;
    
    /* kretprobe for prctl */
    struct kretprobe            prctl_probe;
    
    /* Module initialization flags */
    bool                        memory_init;
    bool                        touch_init;
    bool                        hook_init;
    bool                        stealth_init;
    bool                        cache_init;
};

/*
 * ============================================================================
 * Function Pointer Types
 * ============================================================================
 */

/* Command handler function type */
typedef long (*tear_cmd_handler_t)(unsigned long cmd, 
                                   unsigned long arg1,
                                   unsigned long arg2,
                                   unsigned long arg3);

/* Memory operation function type */
typedef bool (*tear_mem_op_t)(pid_t pid, 
                              unsigned long addr,
                              void __user *buffer,
                              size_t size);

/*
 * ============================================================================
 * Inline Helper Functions
 * ============================================================================
 */

/* Check if PID is valid */
static inline bool tear_pid_valid(pid_t pid)
{
    return pid > 0 && pid <= PID_MAX_LIMIT;
}

/* Check if size is valid for memory operations */
static inline bool tear_size_valid(size_t size)
{
    return size > 0 && size <= TEAR_MAX_RW_SIZE;
}

/* Check if address is valid */
static inline bool tear_addr_valid(unsigned long addr)
{
    return addr >= TEAR_MIN_VALID_ADDR;
}

/* Get current jiffies safely */
static inline unsigned long tear_jiffies(void)
{
    return jiffies;
}

/* Check if time has elapsed */
static inline bool tear_time_after(unsigned long a, unsigned long b)
{
    return time_after(a, b);
}

/*
 * ============================================================================
 * Hash Functions
 * ============================================================================
 */

/* Simple string hash for process cache */
static inline unsigned int tear_hash_string(const char *str)
{
    unsigned int hash = 0;
    
    while (*str) {
        hash = hash * 31 + (unsigned char)*str;
        str++;
    }
    
    /* Use golden ratio for final mixing */
    return (hash * 0x61C88647) >> (32 - 8); /* 8 bits = 256 buckets */
}

/* PID hash */
static inline unsigned int tear_hash_pid(pid_t pid)
{
    return ((unsigned int)pid * 0x61C88647) >> (32 - 8);
}

#endif /* _TEARGAME_TYPES_H */
