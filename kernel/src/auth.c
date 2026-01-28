// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 认证系统 v2.0
 * 
 * 提供基于时间的密钥验证，带有锁定保护
 * 
 * 安全特性:
 * - 常量时间密钥比较（防止时序侧信道攻击）
 * - 失败尝试计数和锁定机制
 * - 时间窗口验证
 */

#include "teargame.h"
#include "teargame_stealth.h"
#include <linux/timekeeping.h>

/*
 * ============================================================================
 * 认证状态
 * ============================================================================
 */
static struct tear_auth_state auth_state = {
    .verified = ATOMIC_INIT(0),
    .attempts = ATOMIC_INIT(0),
    .lockout_until = 0,
};

/*
 * ============================================================================
 * 私有辅助函数
 * ============================================================================
 */

/*
 * 根据魔术字符串和时间戳生成预期密钥
 */
static void generate_expected_key(const char *magic, long timestamp, 
                                  char *out_key, size_t key_len)
{
    int hash;
    int i;
    unsigned int magic_len;
    
    /* 从时间戳计算初始哈希 */
    hash = (int)(timestamp * TEAR_AUTH_HASH_SEED) - 0x7ACE8F1A;
    
    /* 混入魔术字符串 */
    magic_len = 0;
    while (magic[magic_len] && magic_len < 128)
        magic_len++;
    
    if (magic_len > 0) {
        for (i = 0; i < magic_len; i++) {
            hash = hash * 31 + (unsigned char)magic[i];
        }
    }
    
    /* 生成密钥字符 */
    for (i = 0; i < key_len && i < TEAR_AUTH_KEY_LEN; i++) {
        int val = i + (hash >> (i & 7));
        int abs_val = (val < 0) ? -val : val;
        
        /* 映射到 A-Z */
        out_key[i] = 'A' + (abs_val % 26);
        
        /* 更新哈希 */
        hash = i + hash * 17;
    }
    
    out_key[key_len] = '\0';
}

/*
 * 检查是否当前被锁定
 */
static bool is_locked_out(void)
{
    unsigned long now;
    
    if (auth_state.lockout_until == 0)
        return false;
    
    now = tear_jiffies();
    
    if (tear_time_after(now, auth_state.lockout_until)) {
        /* 锁定已过期 */
        auth_state.lockout_until = 0;
        atomic_set(&auth_state.attempts, 0);
        return false;
    }
    
    return true;
}

/*
 * 记录失败的认证尝试
 */
static void record_failed_attempt(void)
{
    int attempts;
    
    attempts = atomic_inc_return(&auth_state.attempts);
    
    if (attempts >= TEAR_AUTH_MAX_ATTEMPTS) {
        /* 触发锁定 */
        auth_state.lockout_until = tear_jiffies() + 
                                   (TEAR_AUTH_LOCKOUT_SEC * HZ);
        tear_warn("认证尝试次数过多，已锁定 %d 秒\n",
                  TEAR_AUTH_LOCKOUT_SEC);
    }
}

/*
 * ============================================================================
 * 公共API
 * ============================================================================
 */

/*
 * 初始化认证系统
 */
void tear_auth_init(void)
{
    atomic_set(&auth_state.verified, 0);
    atomic_set(&auth_state.attempts, 0);
    auth_state.lockout_until = 0;
    spin_lock_init(&auth_state.lock);
    
    tear_debug("认证系统已初始化\n");
}

/*
 * 清理认证系统
 */
void tear_auth_cleanup(void)
{
    atomic_set(&auth_state.verified, 0);
    atomic_set(&auth_state.attempts, 0);
    auth_state.lockout_until = 0;
    
    tear_debug("认证系统已清理\n");
}

/*
 * 检查是否已认证
 */
bool tear_auth_is_verified(void)
{
    return atomic_read(&auth_state.verified) == 1;
}

/*
 * 检查认证状态（返回0或错误码）
 */
int tear_auth_check(void)
{
    if (tear_auth_is_verified())
        return 0;
    return -EPERM;
}

/*
 * 从用户空间验证认证密钥
 * 
 * 预期格式: "magic:timestamp:key"
 * - magic: 用于哈希的任意字符串
 * - timestamp: Unix时间戳（秒）
 * - key: 16字符生成的密钥
 */
int tear_auth_verify_key(void __user *key_ptr)
{
    char key_buf[128];
    char expected_key[TEAR_AUTH_KEY_LEN + 1];
    char *magic_end;
    char *ts_end;
    char *magic_str;
    char *ts_str;
    char *provided_key;
    long user_timestamp;
    struct timespec64 ts;
    long now_timestamp;
    long ret;
    
    /* 检查锁定 */
    if (is_locked_out()) {
        tear_debug("认证被拒绝: 已锁定\n");
        return -EAGAIN;
    }
    
    /* 验证指针 */
    if (!key_ptr) {
        tear_debug("认证被拒绝: 空密钥指针\n");
        return -EINVAL;
    }
    
    /* 从用户空间复制密钥 */
    memset(key_buf, 0, sizeof(key_buf));
    ret = strncpy_from_user(key_buf, key_ptr, sizeof(key_buf) - 1);
    if (ret <= 0) {
        tear_debug("认证被拒绝: 从用户空间复制失败\n");
        record_failed_attempt();
        return -EFAULT;
    }
    
    /* 确保null终止 */
    key_buf[sizeof(key_buf) - 1] = '\0';
    
    /* 解析格式: magic:timestamp:key */
    magic_str = key_buf;
    
    magic_end = strchr(magic_str, ':');
    if (!magic_end) {
        tear_debug("认证被拒绝: 格式无效（缺少第一个冒号）\n");
        record_failed_attempt();
        return -EINVAL;
    }
    *magic_end = '\0';
    
    ts_str = magic_end + 1;
    ts_end = strchr(ts_str, ':');
    if (!ts_end) {
        tear_debug("认证被拒绝: 格式无效（缺少第二个冒号）\n");
        record_failed_attempt();
        return -EINVAL;
    }
    *ts_end = '\0';
    
    provided_key = ts_end + 1;
    
    /* 解析时间戳 */
    ret = kstrtol(ts_str, 10, &user_timestamp);
    if (ret != 0) {
        tear_debug("认证被拒绝: 时间戳无效\n");
        record_failed_attempt();
        return -EINVAL;
    }
    
    /* 获取当前时间 */
    ktime_get_real_ts64(&ts);
    now_timestamp = ts.tv_sec;
    
    /* 检查时间窗口 */
    if (user_timestamp < (now_timestamp - TEAR_AUTH_TIME_WINDOW) ||
        user_timestamp > (now_timestamp + TEAR_AUTH_TIME_WINDOW)) {
        tear_debug("认证被拒绝: 时间戳超出窗口 "
                   "(用户=%ld, 当前=%ld)\n", user_timestamp, now_timestamp);
        record_failed_attempt();
        return -EINVAL;
    }
    
    /* 生成预期密钥 */
    generate_expected_key(magic_str, user_timestamp, 
                          expected_key, TEAR_AUTH_KEY_LEN);
    
    /* 比较密钥（使用常量时间比较，防止时序侧信道攻击） */
    if (tear_ct_strcmp(provided_key, expected_key, TEAR_AUTH_KEY_LEN) != 0) {
        tear_debug("认证被拒绝: 密钥不匹配\n");
        /* 添加时序抖动，混淆失败时序 */
        TEAR_JITTER_LONG();
        record_failed_attempt();
        return -EINVAL;
    }
    
    /* 成功时也添加抖动，使成功和失败的时序难以区分 */
    TEAR_JITTER();
    
    /* 认证成功 */
    atomic_set(&auth_state.verified, 1);
    atomic_set(&auth_state.attempts, 0);
    
    tear_info("认证成功\n");
    return 0;
}
