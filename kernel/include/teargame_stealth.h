/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TearGame 隐藏功能头文件
 * 
 * 提供以下功能：
 * - 动态魔数生成和验证
 * - 常量时间操作（防止时序侧信道）
 * - 时序抖动（模糊时序特征）
 * - 写保护控制
 */

#ifndef _TEARGAME_STEALTH_H
#define _TEARGAME_STEALTH_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/random.h>
#include <linux/compiler.h>
#include <linux/mm.h>

#include "teargame_config.h"

/*
 * ============================================================================
 * 动态魔数系统
 * ============================================================================
 * 魔数每隔固定时间槽变化，防止静态监控检测
 */

/* 魔数种子 - 用于生成动态魔数 */
#define TEAR_MAGIC_SEED         0x4A319941

/* 时间槽大小（秒） */
#define TEAR_MAGIC_TIME_SLOT    10

/* 魔数高位掩码 - 用于快速筛选 */
#define TEAR_MAGIC_MASK         0xF0000000

/*
 * 生成动态魔数
 * 
 * @offset: 时间槽偏移 (-1, 0, 1) 用于边界容错
 * @return: 当前时间槽的魔数
 */
static inline u32 tear_dynamic_magic(int offset)
{
    struct timespec64 ts;
    u64 slot;
    u32 magic;
    
    ktime_get_real_ts64(&ts);
    slot = (ts.tv_sec / TEAR_MAGIC_TIME_SLOT) + offset;
    
    /* 哈希混淆 - 使用黄金比例常数 */
    magic = (u32)(slot * 0x9E3779B9);
    magic ^= TEAR_MAGIC_SEED;
    magic = ((magic << 13) | (magic >> 19)) ^ 0xDEADBEEF;
    magic ^= (u32)(slot >> 32);
    
    /* 确保高位有特定特征用于快速筛选 */
    magic = (magic & ~TEAR_MAGIC_MASK) | (TEAR_MAGIC_SEED & TEAR_MAGIC_MASK);
    
    return magic;
}

/*
 * 获取当前魔数的高位特征
 */
static inline u32 tear_magic_high_nibble(void)
{
    return TEAR_MAGIC_SEED & TEAR_MAGIC_MASK;
}

/*
 * ============================================================================
 * 常量时间操作
 * ============================================================================
 * 防止时序侧信道攻击
 */

/*
 * 常量时间32位比较
 * 无论输入如何，执行时间恒定
 * 
 * @return: 0表示相等，非0表示不等
 */
static inline u32 tear_ct_cmp32(u32 a, u32 b)
{
    u32 diff = a ^ b;
    
    /* 使用位运算确保常量时间 */
    diff |= diff >> 16;
    diff |= diff >> 8;
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    
    return diff & 1;
}

/*
 * 常量时间魔数验证
 */
static inline bool tear_verify_magic_ct(u32 provided, u32 expected)
{
    return tear_ct_cmp32(provided, expected) == 0;
}

/*
 * 验证魔数（检查当前和相邻时间槽）
 * 允许边界容错，防止时间槽切换时失败
 */
static inline bool tear_verify_magic(u32 provided)
{
    /* 使用常量时间比较，检查三个时间槽 */
    u32 match = 0;
    
    match |= tear_ct_cmp32(provided, tear_dynamic_magic(0)) ^ 1;
    match |= tear_ct_cmp32(provided, tear_dynamic_magic(-1)) ^ 1;
    match |= tear_ct_cmp32(provided, tear_dynamic_magic(1)) ^ 1;
    
    return match != 0;
}

/*
 * 常量时间内存比较
 * 
 * @a: 第一个缓冲区
 * @b: 第二个缓冲区
 * @n: 比较长度
 * @return: 0表示相等，非0表示不等
 */
static inline int tear_ct_memcmp(const void *a, const void *b, size_t n)
{
    const volatile unsigned char *pa = a;
    const volatile unsigned char *pb = b;
    unsigned char diff = 0;
    
    while (n--) {
        diff |= *pa++ ^ *pb++;
    }
    
    return diff;
}

/*
 * 常量时间字符串比较
 * 
 * @a: 第一个字符串
 * @b: 第二个字符串
 * @maxlen: 最大比较长度
 * @return: 0表示相等，非0表示不等
 */
static inline int tear_ct_strcmp(const char *a, const char *b, size_t maxlen)
{
    unsigned char diff = 0;
    size_t i;
    unsigned char ca, cb;
    unsigned char end_a = 0, end_b = 0;
    
    for (i = 0; i < maxlen; i++) {
        /* 读取字符，处理已到达末尾的情况 */
        ca = end_a ? 0 : (unsigned char)a[i];
        cb = end_b ? 0 : (unsigned char)b[i];
        
        diff |= ca ^ cb;
        
        /* 标记是否到达字符串末尾 */
        end_a |= (ca == 0);
        end_b |= (cb == 0);
        
        /* 两个字符串都结束则退出 */
        if (end_a && end_b)
            break;
    }
    
    return diff;
}

/*
 * 常量时间条件选择
 * 根据条件选择 a 或 b，执行时间恒定
 * 
 * @condition: 条件（非0选择a，0选择b）
 * @a: 条件为真时的值
 * @b: 条件为假时的值
 */
static inline u64 tear_ct_select(int condition, u64 a, u64 b)
{
    u64 mask = (u64)(-(long long)(!!condition));
    return (a & mask) | (b & ~mask);
}

/*
 * ============================================================================
 * 时序抖动
 * ============================================================================
 * 添加随机延迟，模糊操作的时序特征
 */

/*
 * 执行随机延迟
 * 使用空循环产生0-127个周期的延迟
 */
static inline void tear_jitter(void)
{
    unsigned int loops;
    volatile unsigned int i;
    volatile unsigned int dummy = 0;
    
    /* 获取随机延迟值 */
    loops = prandom_u32() & 0x7F;
    
    /* 空循环产生延迟 */
    for (i = 0; i < loops; i++) {
        dummy ^= i;
        barrier();  /* 防止编译器优化 */
    }
    
    /* 防止 dummy 被优化掉 */
    (void)dummy;
}

/*
 * 执行较长的随机延迟
 * 用于更敏感的操作
 */
static inline void tear_jitter_long(void)
{
    unsigned int loops;
    volatile unsigned int i;
    volatile unsigned int dummy = 0;
    
    loops = prandom_u32() & 0x1FF;  /* 0-511 */
    
    for (i = 0; i < loops; i++) {
        dummy ^= i;
        dummy = (dummy << 1) | (dummy >> 31);
        barrier();
    }
    
    (void)dummy;
}

/* 便捷宏 */
#define TEAR_JITTER()       tear_jitter()
#define TEAR_JITTER_LONG()  tear_jitter_long()

/*
 * ============================================================================
 * 写保护控制
 * ============================================================================
 * 用于修改只读内核数据结构
 */

#ifdef CONFIG_ARM64
/*
 * ARM64 禁用写保护
 * 通过修改 SCTLR_EL1 寄存器
 */
static inline unsigned long tear_disable_write_protect(void)
{
    unsigned long flags;
    unsigned long sctlr;
    
    local_irq_save(flags);
    
    asm volatile(
        "mrs %0, sctlr_el1\n"
        "bic x1, %0, #(1 << 19)\n"  /* 清除 WXN 位 */
        "msr sctlr_el1, x1\n"
        "isb\n"
        : "=r"(sctlr)
        :
        : "x1", "memory"
    );
    
    return flags;
}

static inline void tear_enable_write_protect(unsigned long flags)
{
    asm volatile(
        "mrs x0, sctlr_el1\n"
        "orr x0, x0, #(1 << 19)\n"  /* 设置 WXN 位 */
        "msr sctlr_el1, x0\n"
        "isb\n"
        :
        :
        : "x0", "memory"
    );
    
    local_irq_restore(flags);
}

/*
 * 修改页表属性以允许写入
 * ARM64 上通常不需要此功能，使用 tear_disable_write_protect 代替
 */
static inline void tear_set_memory_rw(unsigned long addr)
{
    (void)addr;
}

static inline void tear_set_memory_ro(unsigned long addr)
{
    (void)addr;
}

#else /* x86_64 */

static inline unsigned long tear_disable_write_protect(void)
{
    unsigned long flags;
    unsigned long cr0;
    
    local_irq_save(flags);
    
    cr0 = read_cr0();
    write_cr0(cr0 & ~0x10000);  /* 清除 WP 位 */
    
    return flags;
}

static inline void tear_enable_write_protect(unsigned long flags)
{
    unsigned long cr0;
    
    cr0 = read_cr0();
    write_cr0(cr0 | 0x10000);  /* 设置 WP 位 */
    
    local_irq_restore(flags);
}

#endif /* CONFIG_ARM64 */

/*
 * ============================================================================
 * 数据混淆
 * ============================================================================
 * 混淆敏感数据结构
 */

/* 运行时XOR密钥 */
static u64 __tear_obf_key;

/*
 * 初始化混淆密钥
 */
static inline void tear_obf_init(void)
{
    __tear_obf_key = prandom_u32();
    __tear_obf_key |= ((u64)prandom_u32() << 32);
}

/*
 * 混淆指针
 */
static inline void *tear_obf_ptr(void *ptr)
{
    return (void *)((unsigned long)ptr ^ __tear_obf_key);
}

/*
 * 解混淆指针
 */
static inline void *tear_deobf_ptr(void *obf_ptr)
{
    return (void *)((unsigned long)obf_ptr ^ __tear_obf_key);
}

/*
 * 混淆64位值
 */
static inline u64 tear_obf_u64(u64 val)
{
    return val ^ __tear_obf_key;
}

/*
 * 解混淆64位值
 */
static inline u64 tear_deobf_u64(u64 obf_val)
{
    return obf_val ^ __tear_obf_key;
}

/*
 * ============================================================================
 * 快速路径检查
 * ============================================================================
 */

/*
 * 快速检查是否可能是 TearGame 调用
 * 只检查高位特征，用于快速筛选
 */
static inline bool tear_quick_check(u32 option)
{
    return (option & TEAR_MAGIC_MASK) == tear_magic_high_nibble();
}

#endif /* _TEARGAME_STEALTH_H */
