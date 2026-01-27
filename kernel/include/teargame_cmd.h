/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame Command Definitions
 * Command codes for prctl hook interface
 */

#ifndef _TEARGAME_CMD_H
#define _TEARGAME_CMD_H

#include <linux/types.h>

/*
 * ============================================================================
 * Command Codes
 * ============================================================================
 * These are passed as the first argument after the magic identifier
 */

/* System Commands */
#define TEAR_CMD_MAGIC              0x19E5  /* Return magic number */
#define TEAR_CMD_AUTH               0x1A2B  /* Authenticate with key */

/* Memory Read Commands */
#define TEAR_CMD_READ_MEMORY        0x2E91  /* Physical page table read */
#define TEAR_CMD_READ_SAFE          0x3A82  /* Safe kernel copy read */

/* Memory Write Commands */
#define TEAR_CMD_WRITE_SAFE         0x4B93  /* Safe kernel copy write */
#define TEAR_CMD_WRITE_MEMORY       0x5C4D  /* Physical page table write */

/* Batch Read Commands - 批量读取（高性能） */
#define TEAR_CMD_READ_BATCH         0x2EA0  /* 批量读取：多地址到连续缓冲区 */
#define TEAR_CMD_READ_SCATTER       0x2EB1  /* 分散-聚集读取：多地址到多缓冲区 */
#define TEAR_CMD_WRITE_BATCH        0x5CA0  /* 批量写入 */

/* Touch Commands */
#define TEAR_CMD_TOUCH_INIT         0x4D8A  /* Initialize touch device */
#define TEAR_CMD_TOUCH_DOWN         0x6F3B  /* Touch down event */
#define TEAR_CMD_TOUCH_MOVE         0x7E2C  /* Touch move event */
#define TEAR_CMD_TOUCH_UP           0x8D1F  /* Touch up event */

/* Process Commands */
#define TEAR_CMD_GET_MODULE_BASE    0x8B17  /* Get module base address */
#define TEAR_CMD_GET_MODULE_BSS     0x3F72  /* Get module BSS address */
#define TEAR_CMD_FIND_PID           0xB5E9  /* Find PID (standard) */
#define TEAR_CMD_FIND_PID_STEALTH   0xC7D3  /* Find PID (cached/stealth) */
#define TEAR_CMD_FIND_PID_BYNAME    0xF2C8  /* Find PID by exact name */

/* Hide Commands - 隐藏功能 */
#define TEAR_CMD_HIDE_FILE          0xA001  /* 隐藏文件/文件夹 */
#define TEAR_CMD_UNHIDE_FILE        0xA002  /* 取消隐藏文件 */
#define TEAR_CMD_HIDE_PROCESS       0xA003  /* 按PID隐藏进程 */
#define TEAR_CMD_HIDE_PROCESS_NAME  0xA004  /* 按名称隐藏进程 */
#define TEAR_CMD_UNHIDE_PROCESS     0xA005  /* 取消隐藏进程 */

/*
 * ============================================================================
 * Command Argument Structures
 * ============================================================================
 * These structures are passed from userspace via copy_from_user
 */

/* Memory copy operation */
struct tear_copy_memory {
    __s32 pid;              /* Target process ID */
    __s32 reserved;         /* Alignment padding */
    __u64 addr;             /* Remote address */
    __u64 buffer;           /* Local buffer (userspace pointer) */
    __u64 size;             /* Number of bytes */
} __attribute__((packed));

#define TEAR_COPY_MEMORY_SIZE   sizeof(struct tear_copy_memory)

/* Module base lookup */
struct tear_module_base {
    __s32 pid;              /* Target process ID */
    __s32 reserved;         /* Alignment padding */
    __u64 name_ptr;         /* Module name (userspace pointer) */
    __u64 result;           /* Output: base address */
} __attribute__((packed));

#define TEAR_MODULE_BASE_SIZE   sizeof(struct tear_module_base)

/* Process ID lookup */
struct tear_get_pid {
    __u64 name_ptr;         /* Process name (userspace pointer) */
    __s32 result;           /* Output: PID */
    __s32 reserved;         /* Alignment padding */
} __attribute__((packed));

#define TEAR_GET_PID_SIZE       sizeof(struct tear_get_pid)

/* Touch device initialization */
struct tear_touch_init {
    __s32 width;            /* Screen width */
    __s32 height;           /* Screen height */
} __attribute__((packed));

#define TEAR_TOUCH_INIT_SIZE    sizeof(struct tear_touch_init)

/* Touch event */
struct tear_touch_event {
    __s32 slot;             /* Touch slot (0-9) */
    __s32 x;                /* X coordinate */
    __s32 y;                /* Y coordinate */
} __attribute__((packed));

#define TEAR_TOUCH_EVENT_SIZE   sizeof(struct tear_touch_event)

/* Authentication */
struct tear_auth_key {
    __u64 key_ptr;          /* Key string (userspace pointer) */
    __u64 key_len;          /* Key length */
} __attribute__((packed));

#define TEAR_AUTH_KEY_SIZE      sizeof(struct tear_auth_key)

/*
 * ============================================================================
 * Batch Read/Write (高性能批量操作)
 * ============================================================================
 */

/* 批量读取请求条目 */
struct tear_batch_item {
    __u64 addr;             /* 目标进程中的地址 */
    __u32 size;             /* 读取/写入大小 */
    __s32 result;           /* 输出：实际读取字节数或错误码 */
} __attribute__((packed));

#define TEAR_BATCH_ITEM_SIZE    sizeof(struct tear_batch_item)

/* 批量读取：多地址读到连续缓冲区 */
struct tear_batch_read {
    __s32 pid;              /* 目标进程ID */
    __u32 count;            /* 条目数量 */
    __u64 items;            /* tear_batch_item 数组指针 */
    __u64 buffer;           /* 输出缓冲区（连续内存） */
    __u64 buffer_size;      /* 缓冲区总大小 */
} __attribute__((packed));

#define TEAR_BATCH_READ_SIZE    sizeof(struct tear_batch_read)
#define TEAR_BATCH_MAX_COUNT    64  /* 单次最大批量数 */

/* 分散-聚集读取：多地址到多缓冲区 */
struct tear_scatter_entry {
    __u64 addr;             /* 目标地址 */
    __u64 buffer;           /* 本地缓冲区指针 */
    __u32 size;             /* 字节数 */
    __s32 result;           /* 输出：读取字节数或错误码 */
} __attribute__((packed));

#define TEAR_SCATTER_ENTRY_SIZE sizeof(struct tear_scatter_entry)

struct tear_scatter_read {
    __s32 pid;              /* 目标进程ID */
    __u32 count;            /* 条目数量 */
    __u64 entries;          /* tear_scatter_entry 数组指针 */
} __attribute__((packed));

#define TEAR_SCATTER_READ_SIZE  sizeof(struct tear_scatter_read)

/* 批量写入 */
struct tear_batch_write {
    __s32 pid;              /* 目标进程ID */
    __u32 count;            /* 条目数量 */
    __u64 items;            /* tear_batch_item 数组指针 */
    __u64 buffer;           /* 输入数据缓冲区（连续内存） */
    __u64 buffer_size;      /* 缓冲区总大小 */
} __attribute__((packed));

#define TEAR_BATCH_WRITE_SIZE   sizeof(struct tear_batch_write)

/*
 * ============================================================================
 * Hide Commands (隐藏功能)
 * ============================================================================
 */

/* 隐藏文件参数 */
struct tear_hide_file {
    __u64 name_ptr;             /* 文件名指针 */
    __u64 parent_path_ptr;      /* 父目录路径指针（可选） */
} __attribute__((packed));

#define TEAR_HIDE_FILE_SIZE     sizeof(struct tear_hide_file)

/* 隐藏进程参数 */
struct tear_hide_proc {
    __s32 pid;                  /* 进程ID */
    __u32 reserved;
    __u64 name_ptr;             /* 进程名指针 */
} __attribute__((packed));

#define TEAR_HIDE_PROC_SIZE     sizeof(struct tear_hide_proc)

/*
 * ============================================================================
 * Command Result Codes
 * ============================================================================
 */
#define TEAR_RESULT_SUCCESS         0
#define TEAR_RESULT_ERR_AUTH        (-EPERM)    /* -1: Not authenticated */
#define TEAR_RESULT_ERR_COPY        (-EFAULT)   /* -14: Copy failed */
#define TEAR_RESULT_ERR_PID         (-ESRCH)    /* -3: Process not found */
#define TEAR_RESULT_ERR_IO          (-EIO)      /* -5: I/O error */
#define TEAR_RESULT_ERR_NOMEM       (-ENOMEM)   /* -12: Out of memory */
#define TEAR_RESULT_ERR_INVAL       (-EINVAL)   /* -22: Invalid argument */

/*
 * ============================================================================
 * Validation Macros
 * ============================================================================
 */
#define TEAR_CMD_IS_VALID(cmd) \
    ((cmd) == TEAR_CMD_MAGIC || \
     (cmd) == TEAR_CMD_AUTH || \
     (cmd) == TEAR_CMD_READ_MEMORY || \
     (cmd) == TEAR_CMD_READ_SAFE || \
     (cmd) == TEAR_CMD_READ_BATCH || \
     (cmd) == TEAR_CMD_READ_SCATTER || \
     (cmd) == TEAR_CMD_WRITE_SAFE || \
     (cmd) == TEAR_CMD_WRITE_MEMORY || \
     (cmd) == TEAR_CMD_WRITE_BATCH || \
     (cmd) == TEAR_CMD_TOUCH_INIT || \
     (cmd) == TEAR_CMD_TOUCH_DOWN || \
     (cmd) == TEAR_CMD_TOUCH_MOVE || \
     (cmd) == TEAR_CMD_TOUCH_UP || \
     (cmd) == TEAR_CMD_GET_MODULE_BASE || \
     (cmd) == TEAR_CMD_GET_MODULE_BSS || \
     (cmd) == TEAR_CMD_FIND_PID || \
     (cmd) == TEAR_CMD_FIND_PID_STEALTH || \
     (cmd) == TEAR_CMD_FIND_PID_BYNAME || \
     (cmd) == TEAR_CMD_HIDE_FILE || \
     (cmd) == TEAR_CMD_UNHIDE_FILE || \
     (cmd) == TEAR_CMD_HIDE_PROCESS || \
     (cmd) == TEAR_CMD_HIDE_PROCESS_NAME || \
     (cmd) == TEAR_CMD_UNHIDE_PROCESS)

#define TEAR_CMD_REQUIRES_AUTH(cmd) \
    ((cmd) != TEAR_CMD_MAGIC && (cmd) != TEAR_CMD_AUTH)

#define TEAR_CMD_IS_MEMORY_OP(cmd) \
    ((cmd) == TEAR_CMD_READ_MEMORY || \
     (cmd) == TEAR_CMD_READ_SAFE || \
     (cmd) == TEAR_CMD_READ_BATCH || \
     (cmd) == TEAR_CMD_READ_SCATTER || \
     (cmd) == TEAR_CMD_WRITE_SAFE || \
     (cmd) == TEAR_CMD_WRITE_MEMORY || \
     (cmd) == TEAR_CMD_WRITE_BATCH)

#define TEAR_CMD_IS_TOUCH_OP(cmd) \
    ((cmd) == TEAR_CMD_TOUCH_INIT || \
     (cmd) == TEAR_CMD_TOUCH_DOWN || \
     (cmd) == TEAR_CMD_TOUCH_MOVE || \
     (cmd) == TEAR_CMD_TOUCH_UP)

#define TEAR_CMD_IS_PROCESS_OP(cmd) \
    ((cmd) == TEAR_CMD_GET_MODULE_BASE || \
     (cmd) == TEAR_CMD_GET_MODULE_BSS || \
     (cmd) == TEAR_CMD_FIND_PID || \
     (cmd) == TEAR_CMD_FIND_PID_STEALTH || \
     (cmd) == TEAR_CMD_FIND_PID_BYNAME)

#define TEAR_CMD_IS_HIDE_OP(cmd) \
    ((cmd) == TEAR_CMD_HIDE_FILE || \
     (cmd) == TEAR_CMD_UNHIDE_FILE || \
     (cmd) == TEAR_CMD_HIDE_PROCESS || \
     (cmd) == TEAR_CMD_HIDE_PROCESS_NAME || \
     (cmd) == TEAR_CMD_UNHIDE_PROCESS)

#endif /* _TEARGAME_CMD_H */
