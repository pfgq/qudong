/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame User Space Header
 * Include this in your user-space application
 */

#ifndef _TEARGAME_USER_H
#define _TEARGAME_USER_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

/*
 * ============================================================================
 * Constants
 * ============================================================================
 */
#define TEAR_MAGIC              0x54454152

/* Command codes */
#define TEAR_CMD_MAGIC          0x19E5
#define TEAR_CMD_AUTH           0x1A2B
#define TEAR_CMD_READ_MEMORY    0x2E91
#define TEAR_CMD_READ_SAFE      0x3A82
#define TEAR_CMD_READ_BATCH     0x2EA0  /* 批量读取 */
#define TEAR_CMD_READ_SCATTER   0x2EB1  /* 分散-聚集读取 */
#define TEAR_CMD_WRITE_SAFE     0x4B93
#define TEAR_CMD_WRITE_MEMORY   0x5C4D
#define TEAR_CMD_WRITE_BATCH    0x5CA0  /* 批量写入 */
#define TEAR_CMD_TOUCH_INIT     0x4D8A
#define TEAR_CMD_TOUCH_DOWN     0x6F3B
#define TEAR_CMD_TOUCH_MOVE     0x7E2C
#define TEAR_CMD_TOUCH_UP       0x8D1F
#define TEAR_CMD_GET_MODULE_BASE 0x8B17
#define TEAR_CMD_GET_MODULE_BSS 0x3F72
#define TEAR_CMD_FIND_PID       0xB5E9
#define TEAR_CMD_FIND_PID_STEALTH 0xC7D3
#define TEAR_CMD_FIND_PID_BYNAME 0xF2C8

/* Batch operation limits */
#define TEAR_BATCH_MAX_COUNT    64

/* Auth constants */
#define TEAR_AUTH_KEY_LEN       16
#define TEAR_AUTH_HASH_SEED     0x4A319941

/*
 * ============================================================================
 * Structures
 * ============================================================================
 */

struct tear_copy_memory {
    int32_t pid;
    int32_t reserved;
    uint64_t addr;
    uint64_t buffer;
    uint64_t size;
} __attribute__((packed));

struct tear_module_base {
    int32_t pid;
    int32_t reserved;
    uint64_t name_ptr;
    uint64_t result;
} __attribute__((packed));

struct tear_get_pid {
    uint64_t name_ptr;
    int32_t result;
    int32_t reserved;
} __attribute__((packed));

struct tear_touch_init {
    int32_t width;
    int32_t height;
} __attribute__((packed));

struct tear_touch_event {
    int32_t slot;
    int32_t x;
    int32_t y;
} __attribute__((packed));

struct tear_auth_key {
    uint64_t key_ptr;
    uint64_t key_len;
} __attribute__((packed));

/*
 * ============================================================================
 * 批量读取结构体 (Batch Read Structures)
 * ============================================================================
 */

/* 批量读取条目 */
struct tear_batch_item {
    uint64_t addr;          /* 目标地址 */
    uint32_t size;          /* 读取大小 */
    int32_t result;         /* 输出：实际读取字节数或错误码 */
} __attribute__((packed));

/* 批量读取请求 - 多地址读到连续缓冲区 */
struct tear_batch_read {
    int32_t pid;            /* 目标进程ID */
    uint32_t count;         /* 条目数量 */
    uint64_t items;         /* tear_batch_item 数组指针 */
    uint64_t buffer;        /* 输出缓冲区（连续内存） */
    uint64_t buffer_size;   /* 缓冲区总大小 */
} __attribute__((packed));

/* 分散读取条目 - 每个条目有独立缓冲区 */
struct tear_scatter_entry {
    uint64_t addr;          /* 目标地址 */
    uint64_t buffer;        /* 本地缓冲区指针 */
    uint32_t size;          /* 字节数 */
    int32_t result;         /* 输出：读取字节数或错误码 */
} __attribute__((packed));

/* 分散读取请求 */
struct tear_scatter_read {
    int32_t pid;            /* 目标进程ID */
    uint32_t count;         /* 条目数量 */
    uint64_t entries;       /* tear_scatter_entry 数组指针 */
} __attribute__((packed));

/* 批量写入请求 */
struct tear_batch_write {
    int32_t pid;            /* 目标进程ID */
    uint32_t count;         /* 条目数量 */
    uint64_t items;         /* tear_batch_item 数组指针 */
    uint64_t buffer;        /* 输入数据缓冲区（连续内存） */
    uint64_t buffer_size;   /* 缓冲区总大小 */
} __attribute__((packed));

/*
 * ============================================================================
 * API Functions
 * ============================================================================
 */

/* Generate authentication key */
static inline void tear_generate_key(const char *magic, long timestamp,
                                     char *out_key, size_t key_len)
{
    int hash;
    int i;
    size_t magic_len;
    
    hash = (int)(timestamp * TEAR_AUTH_HASH_SEED) - 0x7ACE8F1A;
    
    magic_len = strlen(magic);
    if (magic_len > 128) magic_len = 128;
    
    for (i = 0; i < magic_len; i++) {
        hash = hash * 31 + (unsigned char)magic[i];
    }
    
    for (i = 0; i < key_len && i < TEAR_AUTH_KEY_LEN; i++) {
        int val = i + (hash >> (i & 7));
        int abs_val = (val < 0) ? -val : val;
        out_key[i] = 'A' + (abs_val % 26);
        hash = i + hash * 17;
    }
    
    out_key[key_len] = '\0';
}

/* Check if TearGame module is loaded */
static inline int tear_is_loaded(void)
{
    long result = prctl(TEAR_MAGIC, TEAR_CMD_MAGIC, 0, 0, 0);
    return (result == TEAR_MAGIC) ? 1 : 0;
}

/* Authenticate with the module */
static inline int tear_auth(const char *magic)
{
    char key_str[128];
    char key[TEAR_AUTH_KEY_LEN + 1];
    time_t now = time(NULL);
    
    tear_generate_key(magic, now, key, TEAR_AUTH_KEY_LEN);
    snprintf(key_str, sizeof(key_str), "%s:%ld:%s", magic, (long)now, key);
    
    return prctl(TEAR_MAGIC, TEAR_CMD_AUTH, key_str, 0, 0);
}

/* Read memory from target process */
static inline int tear_read(int pid, uint64_t addr, void *buffer, size_t size)
{
    struct tear_copy_memory cm = {
        .pid = pid,
        .reserved = 0,
        .addr = addr,
        .buffer = (uint64_t)buffer,
        .size = size
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_READ_MEMORY, &cm, 0, 0);
}

/* Safe read memory */
static inline int tear_read_safe(int pid, uint64_t addr, void *buffer, size_t size)
{
    struct tear_copy_memory cm = {
        .pid = pid,
        .reserved = 0,
        .addr = addr,
        .buffer = (uint64_t)buffer,
        .size = size
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_READ_SAFE, &cm, 0, 0);
}

/* Write memory to target process */
static inline int tear_write(int pid, uint64_t addr, void *buffer, size_t size)
{
    struct tear_copy_memory cm = {
        .pid = pid,
        .reserved = 0,
        .addr = addr,
        .buffer = (uint64_t)buffer,
        .size = size
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_WRITE_MEMORY, &cm, 0, 0);
}

/* Safe write memory */
static inline int tear_write_safe(int pid, uint64_t addr, void *buffer, size_t size)
{
    struct tear_copy_memory cm = {
        .pid = pid,
        .reserved = 0,
        .addr = addr,
        .buffer = (uint64_t)buffer,
        .size = size
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_WRITE_SAFE, &cm, 0, 0);
}

/*
 * ============================================================================
 * 批量读取API (Batch Read API)
 * ============================================================================
 */

/**
 * tear_read_batch - 批量读取多个地址到连续缓冲区
 * @pid: 目标进程ID
 * @items: tear_batch_item数组，包含地址和大小
 * @count: 条目数量
 * @buffer: 输出缓冲区（必须足够大以容纳所有数据）
 * @buffer_size: 缓冲区大小
 * 
 * 返回: 0=成功, 负数=错误
 * 注意: 每个item的result字段会被更新为实际读取字节数或错误码
 */
static inline int tear_read_batch(int pid, struct tear_batch_item *items,
                                  uint32_t count, void *buffer, size_t buffer_size)
{
    struct tear_batch_read br = {
        .pid = pid,
        .count = count,
        .items = (uint64_t)items,
        .buffer = (uint64_t)buffer,
        .buffer_size = buffer_size
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_READ_BATCH, &br, 0, 0);
}

/**
 * tear_read_scatter - 分散读取：多地址到多缓冲区
 * @pid: 目标进程ID
 * @entries: tear_scatter_entry数组，每个条目包含独立的地址和缓冲区
 * @count: 条目数量
 * 
 * 返回: 0=成功, 负数=错误
 * 注意: 每个entry的result字段会被更新
 */
static inline int tear_read_scatter(int pid, struct tear_scatter_entry *entries,
                                    uint32_t count)
{
    struct tear_scatter_read sr = {
        .pid = pid,
        .count = count,
        .entries = (uint64_t)entries
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_READ_SCATTER, &sr, 0, 0);
}

/**
 * tear_write_batch - 批量写入多个地址
 * @pid: 目标进程ID
 * @items: tear_batch_item数组
 * @count: 条目数量
 * @buffer: 包含所有写入数据的连续缓冲区
 * @buffer_size: 缓冲区大小
 * 
 * 返回: 0=成功, 负数=错误
 */
static inline int tear_write_batch(int pid, struct tear_batch_item *items,
                                   uint32_t count, void *buffer, size_t buffer_size)
{
    struct tear_batch_write bw = {
        .pid = pid,
        .count = count,
        .items = (uint64_t)items,
        .buffer = (uint64_t)buffer,
        .buffer_size = buffer_size
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_WRITE_BATCH, &bw, 0, 0);
}

/**
 * tear_read_multi - 简化版批量读取（自动计算缓冲区偏移）
 * @pid: 目标进程ID
 * @addrs: 地址数组
 * @sizes: 大小数组
 * @buffers: 缓冲区指针数组
 * @count: 条目数量
 * 
 * 返回: 成功读取的条目数
 */
static inline int tear_read_multi(int pid, uint64_t *addrs, uint32_t *sizes,
                                  void **buffers, uint32_t count)
{
    struct tear_scatter_entry *entries;
    uint32_t i;
    int ret, success = 0;
    
    if (count > TEAR_BATCH_MAX_COUNT) count = TEAR_BATCH_MAX_COUNT;
    
    entries = (struct tear_scatter_entry *)malloc(count * sizeof(*entries));
    if (!entries) return -1;
    
    for (i = 0; i < count; i++) {
        entries[i].addr = addrs[i];
        entries[i].buffer = (uint64_t)buffers[i];
        entries[i].size = sizes[i];
        entries[i].result = 0;
    }
    
    ret = tear_read_scatter(pid, entries, count);
    
    if (ret == 0) {
        for (i = 0; i < count; i++) {
            if (entries[i].result >= 0) success++;
        }
    }
    
    free(entries);
    return (ret == 0) ? success : ret;
}

/* Find PID by process name */
static inline int tear_find_pid(const char *name)
{
    struct tear_get_pid gp = {
        .name_ptr = (uint64_t)name,
        .result = 0,
        .reserved = 0
    };
    if (prctl(TEAR_MAGIC, TEAR_CMD_FIND_PID, &gp, 0, 0) == 0)
        return gp.result;
    return 0;
}

/* Find PID using cache (stealth) */
static inline int tear_find_pid_stealth(const char *name)
{
    struct tear_get_pid gp = {
        .name_ptr = (uint64_t)name,
        .result = 0,
        .reserved = 0
    };
    if (prctl(TEAR_MAGIC, TEAR_CMD_FIND_PID_STEALTH, &gp, 0, 0) == 0)
        return gp.result;
    return 0;
}

/* Get module base address */
static inline uint64_t tear_get_module_base(int pid, const char *name)
{
    struct tear_module_base mb = {
        .pid = pid,
        .reserved = 0,
        .name_ptr = (uint64_t)name,
        .result = 0
    };
    if (prctl(TEAR_MAGIC, TEAR_CMD_GET_MODULE_BASE, &mb, 0, 0) == 0)
        return mb.result;
    return 0;
}

/* Get module BSS address */
static inline uint64_t tear_get_module_bss(int pid, const char *name)
{
    struct tear_module_base mb = {
        .pid = pid,
        .reserved = 0,
        .name_ptr = (uint64_t)name,
        .result = 0
    };
    if (prctl(TEAR_MAGIC, TEAR_CMD_GET_MODULE_BSS, &mb, 0, 0) == 0)
        return mb.result;
    return 0;
}

/* Initialize touch device */
static inline int tear_touch_init(int width, int height)
{
    struct tear_touch_init ti = {
        .width = width,
        .height = height
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_TOUCH_INIT, &ti, 0, 0);
}

/* Touch down */
static inline int tear_touch_down(int slot, int x, int y)
{
    struct tear_touch_event te = {
        .slot = slot,
        .x = x,
        .y = y
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_TOUCH_DOWN, &te, 0, 0);
}

/* Touch move */
static inline int tear_touch_move(int slot, int x, int y)
{
    struct tear_touch_event te = {
        .slot = slot,
        .x = x,
        .y = y
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_TOUCH_MOVE, &te, 0, 0);
}

/* Touch up */
static inline int tear_touch_up(int slot)
{
    struct tear_touch_event te = {
        .slot = slot,
        .x = 0,
        .y = 0
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_TOUCH_UP, &te, 0, 0);
}

/* Tap at position */
static inline int tear_touch_tap(int x, int y, int delay_ms)
{
    int ret;
    ret = tear_touch_down(0, x, y);
    if (ret != 0) return ret;
    
    if (delay_ms > 0) {
        struct timespec ts = {
            .tv_sec = delay_ms / 1000,
            .tv_nsec = (delay_ms % 1000) * 1000000
        };
        nanosleep(&ts, NULL);
    }
    
    return tear_touch_up(0);
}

/* Swipe from point to point */
static inline int tear_touch_swipe(int x1, int y1, int x2, int y2, 
                                   int steps, int delay_ms)
{
    int i;
    int dx = (x2 - x1) / (steps > 0 ? steps : 1);
    int dy = (y2 - y1) / (steps > 0 ? steps : 1);
    int step_delay = delay_ms / (steps > 0 ? steps : 1);
    struct timespec ts = {
        .tv_sec = step_delay / 1000,
        .tv_nsec = (step_delay % 1000) * 1000000
    };
    
    tear_touch_down(0, x1, y1);
    
    for (i = 1; i <= steps; i++) {
        nanosleep(&ts, NULL);
        tear_touch_move(0, x1 + dx * i, y1 + dy * i);
    }
    
    tear_touch_move(0, x2, y2);
    nanosleep(&ts, NULL);
    
    return tear_touch_up(0);
}

/*
 * ============================================================================
 * 便捷宏 (Convenience Macros)
 * ============================================================================
 */

/* 类型安全的读取宏 */
#define tear_read_type(pid, addr, type) \
    ({ type __val; tear_read((pid), (addr), &__val, sizeof(type)); __val; })

/* 读取整数类型 */
#define tear_read_i8(pid, addr)  tear_read_type(pid, addr, int8_t)
#define tear_read_i16(pid, addr) tear_read_type(pid, addr, int16_t)
#define tear_read_i32(pid, addr) tear_read_type(pid, addr, int32_t)
#define tear_read_i64(pid, addr) tear_read_type(pid, addr, int64_t)

#define tear_read_u8(pid, addr)  tear_read_type(pid, addr, uint8_t)
#define tear_read_u16(pid, addr) tear_read_type(pid, addr, uint16_t)
#define tear_read_u32(pid, addr) tear_read_type(pid, addr, uint32_t)
#define tear_read_u64(pid, addr) tear_read_type(pid, addr, uint64_t)

/* 读取浮点类型 */
#define tear_read_f32(pid, addr) tear_read_type(pid, addr, float)
#define tear_read_f64(pid, addr) tear_read_type(pid, addr, double)

/* 读取指针 (64位) */
#define tear_read_ptr(pid, addr) tear_read_type(pid, addr, uint64_t)

/* 类型安全的写入宏 */
#define tear_write_type(pid, addr, val) \
    ({ typeof(val) __val = (val); tear_write((pid), (addr), &__val, sizeof(__val)); })

/* 写入整数类型 */
#define tear_write_i8(pid, addr, val)  tear_write_type(pid, addr, (int8_t)(val))
#define tear_write_i16(pid, addr, val) tear_write_type(pid, addr, (int16_t)(val))
#define tear_write_i32(pid, addr, val) tear_write_type(pid, addr, (int32_t)(val))
#define tear_write_i64(pid, addr, val) tear_write_type(pid, addr, (int64_t)(val))

#define tear_write_u8(pid, addr, val)  tear_write_type(pid, addr, (uint8_t)(val))
#define tear_write_u16(pid, addr, val) tear_write_type(pid, addr, (uint16_t)(val))
#define tear_write_u32(pid, addr, val) tear_write_type(pid, addr, (uint32_t)(val))
#define tear_write_u64(pid, addr, val) tear_write_type(pid, addr, (uint64_t)(val))

/* 写入浮点类型 */
#define tear_write_f32(pid, addr, val) tear_write_type(pid, addr, (float)(val))
#define tear_write_f64(pid, addr, val) tear_write_type(pid, addr, (double)(val))

/*
 * ============================================================================
 * 链式读取 (Chain Read)
 * ============================================================================
 * 用于读取多级指针，如 [[base + 0x10] + 0x20] + 0x30
 */

/**
 * tear_read_chain - 链式读取指针
 * @pid: 目标进程ID
 * @base: 基地址
 * @offsets: 偏移量数组
 * @count: 偏移量数量
 * 
 * 返回: 最终计算出的地址，失败返回0
 * 
 * 示例: 
 *   uint64_t offsets[] = {0x10, 0x20, 0x30, 0x48};
 *   uint64_t final_addr = tear_read_chain(pid, base, offsets, 4);
 *   // 相当于: [[[base + 0x10] + 0x20] + 0x30] + 0x48
 */
static inline uint64_t tear_read_chain(int pid, uint64_t base, 
                                       const uint64_t *offsets, int count)
{
    uint64_t addr = base;
    int i;
    
    for (i = 0; i < count - 1; i++) {
        addr = tear_read_ptr(pid, addr + offsets[i]);
        if (addr == 0) return 0;  /* 空指针，链断裂 */
    }
    
    /* 最后一个偏移直接加，不解引用 */
    return addr + offsets[count - 1];
}

/**
 * tear_read_chain_value - 链式读取最终值
 * @pid: 目标进程ID
 * @base: 基地址
 * @offsets: 偏移量数组
 * @count: 偏移量数量
 * @buffer: 输出缓冲区
 * @size: 读取大小
 * 
 * 返回: 0=成功, 负数=失败
 */
static inline int tear_read_chain_value(int pid, uint64_t base,
                                        const uint64_t *offsets, int count,
                                        void *buffer, size_t size)
{
    uint64_t final_addr = tear_read_chain(pid, base, offsets, count);
    if (final_addr == 0) return -1;
    return tear_read(pid, final_addr, buffer, size);
}

/* 链式读取特定类型的便捷宏 */
#define tear_read_chain_i32(pid, base, offsets, count) \
    ({ \
        uint64_t __addr = tear_read_chain((pid), (base), (offsets), (count)); \
        (__addr != 0) ? tear_read_i32((pid), __addr) : 0; \
    })

#define tear_read_chain_i64(pid, base, offsets, count) \
    ({ \
        uint64_t __addr = tear_read_chain((pid), (base), (offsets), (count)); \
        (__addr != 0) ? tear_read_i64((pid), __addr) : 0; \
    })

#define tear_read_chain_f32(pid, base, offsets, count) \
    ({ \
        uint64_t __addr = tear_read_chain((pid), (base), (offsets), (count)); \
        (__addr != 0) ? tear_read_f32((pid), __addr) : 0.0f; \
    })

#define tear_read_chain_f64(pid, base, offsets, count) \
    ({ \
        uint64_t __addr = tear_read_chain((pid), (base), (offsets), (count)); \
        (__addr != 0) ? tear_read_f64((pid), __addr) : 0.0; \
    })

/*
 * ============================================================================
 * 字符串读取
 * ============================================================================
 */

/**
 * tear_read_string - 读取字符串
 * @pid: 目标进程ID
 * @addr: 字符串地址
 * @buffer: 输出缓冲区
 * @maxlen: 最大读取长度
 * 
 * 返回: 实际字符串长度，失败返回-1
 */
static inline int tear_read_string(int pid, uint64_t addr, 
                                   char *buffer, size_t maxlen)
{
    size_t i;
    
    if (tear_read(pid, addr, buffer, maxlen) != 0)
        return -1;
    
    /* 确保null终止 */
    buffer[maxlen - 1] = '\0';
    
    /* 查找实际长度 */
    for (i = 0; i < maxlen; i++) {
        if (buffer[i] == '\0')
            return (int)i;
    }
    
    return (int)(maxlen - 1);
}

/**
 * tear_read_wstring - 读取宽字符串 (UTF-16)
 * @pid: 目标进程ID
 * @addr: 字符串地址
 * @buffer: 输出缓冲区
 * @maxlen: 最大字符数（不是字节数）
 * 
 * 返回: 实际字符串长度，失败返回-1
 */
static inline int tear_read_wstring(int pid, uint64_t addr,
                                    uint16_t *buffer, size_t maxlen)
{
    size_t i;
    
    if (tear_read(pid, addr, buffer, maxlen * sizeof(uint16_t)) != 0)
        return -1;
    
    buffer[maxlen - 1] = 0;
    
    for (i = 0; i < maxlen; i++) {
        if (buffer[i] == 0)
            return (int)i;
    }
    
    return (int)(maxlen - 1);
}

/*
 * ============================================================================
 * 隐藏API (Hiding API)
 * ============================================================================
 */

/* 隐藏命令码 */
#define TEAR_CMD_HIDE_FILE          0xA001
#define TEAR_CMD_UNHIDE_FILE        0xA002
#define TEAR_CMD_HIDE_PROCESS       0xA003
#define TEAR_CMD_HIDE_PROCESS_NAME  0xA004
#define TEAR_CMD_UNHIDE_PROCESS     0xA005

/* 隐藏文件参数 */
struct tear_hide_file {
    uint64_t name_ptr;          /* 文件名指针 */
    uint64_t parent_path_ptr;   /* 父目录路径指针（可选） */
} __attribute__((packed));

/* 隐藏进程参数 */
struct tear_hide_proc {
    int32_t pid;                /* 进程ID */
    uint32_t reserved;
    uint64_t name_ptr;          /* 进程名指针 */
} __attribute__((packed));

/**
 * tear_hide_file - 隐藏文件/文件夹
 * @name: 文件/文件夹名称（支持 *xxx 通配符）
 * 
 * 返回: 0=成功, 负数=失败
 * 
 * 注意: 隐藏的文件仍可正常访问，只是不出现在目录列表中
 */
static inline int tear_hide_file(const char *name)
{
    struct tear_hide_file args = {
        .name_ptr = (uint64_t)name,
        .parent_path_ptr = 0
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_HIDE_FILE, &args, 0, 0);
}

/**
 * tear_unhide_file - 取消隐藏文件/文件夹
 * @name: 文件/文件夹名称
 * 
 * 返回: 0=成功, 负数=失败
 */
static inline int tear_unhide_file(const char *name)
{
    struct tear_hide_file args = {
        .name_ptr = (uint64_t)name,
        .parent_path_ptr = 0
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_UNHIDE_FILE, &args, 0, 0);
}

/**
 * tear_hide_process - 按PID隐藏进程
 * @pid: 要隐藏的进程ID
 * 
 * 返回: 0=成功, 负数=失败
 * 
 * 注意: 隐藏的进程仍正常运行，只是不出现在 ps/top/proc 中
 */
static inline int tear_hide_process(int pid)
{
    struct tear_hide_proc args = {
        .pid = pid,
        .reserved = 0,
        .name_ptr = 0
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_HIDE_PROCESS, &args, 0, 0);
}

/**
 * tear_hide_process_name - 按名称隐藏进程
 * @name: 进程名称
 * 
 * 返回: 0=成功, 负数=失败
 * 
 * 注意: 所有匹配的进程都会被隐藏
 */
static inline int tear_hide_process_name(const char *name)
{
    struct tear_hide_proc args = {
        .pid = 0,
        .reserved = 0,
        .name_ptr = (uint64_t)name
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_HIDE_PROCESS_NAME, &args, 0, 0);
}

/**
 * tear_unhide_process - 取消隐藏进程
 * @pid: 要取消隐藏的进程ID
 * 
 * 返回: 0=成功, 负数=失败
 */
static inline int tear_unhide_process(int pid)
{
    struct tear_hide_proc args = {
        .pid = pid,
        .reserved = 0,
        .name_ptr = 0
    };
    return prctl(TEAR_MAGIC, TEAR_CMD_UNHIDE_PROCESS, &args, 0, 0);
}

/**
 * tear_hide_self - 隐藏当前进程
 * 
 * 返回: 0=成功, 负数=失败
 */
static inline int tear_hide_self(void)
{
    return tear_hide_process(getpid());
}

#endif /* _TEARGAME_USER_H */
