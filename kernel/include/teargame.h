/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame Main Header
 * Kernel module for cross-process memory access and virtual input
 */

#ifndef _TEARGAME_H
#define _TEARGAME_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/kprobes.h>
#include <linux/rcupdate.h>

/* TearGame headers */
#include "teargame_compat.h"
#include "teargame_config.h"
#include "teargame_cmd.h"
#include "teargame_types.h"
#include "teargame_security.h"

/*
 * ============================================================================
 * Module Information
 * ============================================================================
 */
#define TEARGAME_MODULE_NAME    "teargame"

/*
 * ============================================================================
 * Global State (defined in main.c)
 * ============================================================================
 */
extern struct tear_global_state g_state;

/*
 * ============================================================================
 * Authentication Functions (auth.c)
 * ============================================================================
 */
void tear_auth_init(void);
void tear_auth_cleanup(void);
int tear_auth_verify_key(void __user *key_ptr);
bool tear_auth_is_verified(void);
int tear_auth_check(void);

/*
 * ============================================================================
 * Memory Functions (memory.c)
 * ============================================================================
 */
int teargame_memory_init(void);
void teargame_memory_exit(void);
bool read_process_memory(pid_t pid, unsigned long addr, 
                         void __user *buffer, size_t size);
bool write_process_memory(pid_t pid, unsigned long addr,
                          void __user *buffer, size_t size);

/* Page table helpers */
phys_addr_t tear_vaddr_to_phys(struct mm_struct *mm, unsigned long vaddr,
                               unsigned long *page_size);

/*
 * ============================================================================
 * Safe Memory Functions (memory_safe.c)
 * ============================================================================
 */
int teargame_memory_safe_init(void);
void teargame_memory_safe_exit(void);
bool read_safe(pid_t pid, unsigned long addr, 
               void __user *buffer, size_t size);
bool write_safe(pid_t pid, unsigned long addr,
                void __user *buffer, size_t size);

/* Physical address helpers */
phys_addr_t vaddr_to_phys_safe(struct mm_struct *mm, unsigned long vaddr);

/*
 * ============================================================================
 * Process Functions (process.c)
 * ============================================================================
 */
pid_t find_pid_by_name(const char *name);
pid_t find_pid_safe(const char *name);
pid_t find_pid_stealth(const char *name);
unsigned long get_module_base(pid_t pid, const char *name);
unsigned long get_module_bss(pid_t pid, const char *name);

/* Helper functions */
int get_cmdline_by_pid_safe(pid_t pid, char *buf, size_t size);
char *safe_get_basename(struct dentry *dentry);
bool verify_pid(pid_t pid);

/*
 * ============================================================================
 * Process Cache Functions (process_cache.c)
 * ============================================================================
 */
int tear_cache_init(void);
void tear_cache_cleanup(void);
void tear_cache_refresh_if_needed(void);
pid_t tear_cache_find(const char *name);
void tear_cache_invalidate_pid(pid_t pid);

/*
 * ============================================================================
 * Touch Functions (touch.c)
 * ============================================================================
 */
int teargame_touch_module_init(void);
void teargame_touch_module_exit(void);
int teargame_touch_init_device(int width, int height);
int teargame_touch_down(int slot, int x, int y);
int teargame_touch_move(int slot, int x, int y);
int teargame_touch_up(int slot);
void teargame_touch_set_debug(int enable);

/*
 * ============================================================================
 * Hook Functions (hook.c)
 * ============================================================================
 */
int teargame_hook_init(void);
void teargame_hook_exit(void);

/*
 * ============================================================================
 * Stealth Functions (stealth.c)
 * ============================================================================
 */
int teargame_stealth_init(void);
void teargame_stealth_cleanup(void);
int teargame_stealth_hide(void);
int teargame_stealth_show(void);
bool teargame_stealth_is_hidden(void);

/*
 * ============================================================================
 * Memory Batch Functions (memory_batch.c)
 * ============================================================================
 */
int teargame_memory_batch_init(void);
void teargame_memory_batch_exit(void);

/*
 * ============================================================================
 * Anti-Debug Functions (antidbg.c)
 * ============================================================================
 */
int teargame_antidbg_init(void);
void teargame_antidbg_exit(void);
bool tear_is_being_debugged(void);
bool tear_detect_kgdb(void);
bool tear_detect_debugger_process(void);

/*
 * ============================================================================
 * File Hide Functions (file_hide.c)
 * ============================================================================
 */
int teargame_file_hide_init(void);
void teargame_file_hide_exit(void);
int tear_file_hide_add(const char *name, const char *parent_path);
int tear_file_hide_remove(const char *name);
void tear_file_hide_clear(void);
int tear_file_hide_count(void);
bool tear_file_is_hidden(const char *name);

/*
 * ============================================================================
 * Process Hide Functions (proc_hide.c)
 * ============================================================================
 */
int teargame_proc_hide_init(void);
void teargame_proc_hide_exit(void);
int tear_proc_hide_pid(pid_t pid);
int tear_proc_hide_name(const char *name);
int tear_proc_unhide_pid(pid_t pid);
int tear_proc_unhide_name(const char *name);
void tear_proc_hide_clear(void);
int tear_proc_hide_count(void);
bool tear_proc_is_hidden(pid_t pid);

/*
 * ============================================================================
 * Command Handler (command.c)
 * ============================================================================
 */
long teargame_handle_command(unsigned long cmd, unsigned long arg1,
                             unsigned long arg2, unsigned long arg3);

/*
 * ============================================================================
 * Utility Macros
 * ============================================================================
 */

/* Safe task reference counting */
#define tear_get_task_struct(task) get_task_struct(task)
#define tear_put_task_struct(task) put_task_struct(task)

/* Safe mm reference counting */
static inline struct mm_struct *tear_get_task_mm_safe(struct task_struct *task)
{
    struct mm_struct *mm = get_task_mm(task);
    return mm;
}

static inline void tear_put_mm(struct mm_struct *mm)
{
    if (mm)
        mmput(mm);
}

/* Validate userspace pointer */
static inline bool tear_validate_user_ptr(const void __user *ptr, size_t size)
{
    if (!ptr)
        return false;
    return tear_access_ok(ptr, size);
}

/* Safe copy from user with validation */
static inline long tear_copy_from_user_safe(void *to, 
                                            const void __user *from,
                                            size_t size)
{
    if (!tear_validate_user_ptr(from, size))
        return -EFAULT;
    
    if (copy_from_user(to, from, size))
        return -EFAULT;
    
    return 0;
}

/* Safe copy to user with validation */
static inline long tear_copy_to_user_safe(void __user *to,
                                          const void *from,
                                          size_t size)
{
    if (!tear_validate_user_ptr(to, size))
        return -EFAULT;
    
    if (copy_to_user(to, from, size))
        return -EFAULT;
    
    return 0;
}

/*
 * ============================================================================
 * Memory Allocation Helpers
 * ============================================================================
 */

/* Allocate kernel buffer for memory operations */
static inline void *tear_alloc_buffer(size_t size)
{
    if (size > PAGE_SIZE)
        return kvmalloc(size, GFP_KERNEL);
    else
        return kmalloc(size, GFP_KERNEL);
}

/* Free kernel buffer */
static inline void tear_free_buffer(void *buf, size_t size)
{
    if (!buf)
        return;
    
    if (size > PAGE_SIZE)
        kvfree(buf);
    else
        kfree(buf);
}

/*
 * ============================================================================
 * Validation Macros with Error Returns
 * ============================================================================
 */

#define TEAR_VALIDATE_PID(pid) \
    do { \
        if (!tear_pid_valid(pid)) { \
            tear_debug("Invalid PID: %d\n", pid); \
            return -EINVAL; \
        } \
    } while (0)

#define TEAR_VALIDATE_SIZE(size) \
    do { \
        if (!tear_size_valid(size)) { \
            tear_debug("Invalid size: %zu\n", size); \
            return -EINVAL; \
        } \
    } while (0)

#define TEAR_VALIDATE_ADDR(addr) \
    do { \
        if (!tear_addr_valid(addr)) { \
            tear_debug("Invalid address: 0x%lx\n", addr); \
            return -EFAULT; \
        } \
    } while (0)

#define TEAR_VALIDATE_PTR(ptr) \
    do { \
        if (!(ptr)) { \
            tear_debug("NULL pointer\n"); \
            return -EINVAL; \
        } \
    } while (0)

#define TEAR_CHECK_AUTH() \
    do { \
        if (!tear_auth_is_verified()) { \
            tear_debug("Not authenticated\n"); \
            return -EPERM; \
        } \
    } while (0)

#endif /* _TEARGAME_H */
