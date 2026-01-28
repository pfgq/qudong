// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 反调试模块
 * 
 * 检测各种调试和分析工具：
 * - 内核调试器 (KGDB)
 * - 用户空间调试器 (gdb, lldb, strace等)
 * - 动态分析工具 (frida, ida等)
 * - 反汇编工具
 */

#include "teargame.h"
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>

/*
 * ============================================================================
 * 可疑进程名列表
 * ============================================================================
 */

/* 调试器和分析工具 */
static const char *suspicious_debuggers[] = {
    "gdb",
    "lldb", 
    "strace",
    "ltrace",
    "ptrace",
    NULL
};

/* 逆向分析工具 */
static const char *suspicious_reversers[] = {
    "ida",
    "ida64",
    "idaq",
    "idaq64",
    "ghidra",
    "radare2",
    "r2",
    "rizin",
    "cutter",
    "objdump",
    "readelf",
    "nm",
    NULL
};

/* 动态注入工具 */
static const char *suspicious_injectors[] = {
    "frida",
    "frida-server",
    "frida-agent",
    "frida-gadget",
    "xposed",
    "substrate",
    "cydia",
    NULL
};

/* 虚拟机/模拟器检测 */
static const char *suspicious_emulators[] = {
    "qemu",
    "qemu-system",
    "bochs",
    "vmware",
    "virtualbox",
    NULL
};

/*
 * ============================================================================
 * 检测状态
 * ============================================================================
 */

static struct {
    bool kgdb_detected;
    bool debugger_detected;
    bool analyzer_detected;
    bool injector_detected;
    unsigned long last_check;
    spinlock_t lock;
} antidbg_state;

/*
 * ============================================================================
 * 内部检测函数
 * ============================================================================
 */

/*
 * 在进程名列表中查找匹配
 */
static bool match_process_name(const char *comm, const char **list)
{
    int i;
    
    for (i = 0; list[i] != NULL; i++) {
        /* 精确匹配 */
        if (strcmp(comm, list[i]) == 0)
            return true;
        
        /* 部分匹配（进程名可能被截断） */
        if (strstr(comm, list[i]) != NULL)
            return true;
    }
    
    return false;
}

/*
 * 使用 kprobe 技巧获取符号地址 (5.7+ 内核 kallsyms_lookup_name 未导出)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long tear_lookup_name(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long addr = 0;
    
    if (register_kprobe(&kp) < 0)
        return 0;
    
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    
    return addr;
}
#else
#define tear_lookup_name(name) kallsyms_lookup_name(name)
#endif

/*
 * 检测内核调试器 (KGDB)
 */
static bool detect_kgdb(void)
{
#ifdef CONFIG_KGDB
    /* 
     * 尝试查找 kgdb_connected 符号
     */
    static int *kgdb_connected_ptr = NULL;
    static bool looked_up = false;
    
    if (!looked_up) {
        unsigned long addr = tear_lookup_name("kgdb_connected");
        if (addr)
            kgdb_connected_ptr = (int *)addr;
        looked_up = true;
    }
    
    if (kgdb_connected_ptr && *kgdb_connected_ptr != 0) {
        tear_debug("检测到KGDB调试器已连接\n");
        return true;
    }
#endif

    return false;
}

/*
 * 检测用户空间调试器进程
 */
static bool detect_debugger_processes(void)
{
    struct task_struct *task;
    bool found = false;
    
    rcu_read_lock();
    
    for_each_process(task) {
        /* 检查调试器 */
        if (match_process_name(task->comm, suspicious_debuggers)) {
            tear_debug("检测到可疑调试器进程: %s (pid=%d)\n", 
                       task->comm, task->pid);
            found = true;
            break;
        }
    }
    
    rcu_read_unlock();
    return found;
}

/*
 * 检测逆向分析工具
 */
static bool detect_reverse_tools(void)
{
    struct task_struct *task;
    bool found = false;
    
    rcu_read_lock();
    
    for_each_process(task) {
        if (match_process_name(task->comm, suspicious_reversers)) {
            tear_debug("检测到逆向分析工具: %s (pid=%d)\n", 
                       task->comm, task->pid);
            found = true;
            break;
        }
    }
    
    rcu_read_unlock();
    return found;
}

/*
 * 检测动态注入工具
 */
static bool detect_injection_tools(void)
{
    struct task_struct *task;
    bool found = false;
    
    rcu_read_lock();
    
    for_each_process(task) {
        if (match_process_name(task->comm, suspicious_injectors)) {
            tear_debug("检测到动态注入工具: %s (pid=%d)\n", 
                       task->comm, task->pid);
            found = true;
            break;
        }
    }
    
    rcu_read_unlock();
    return found;
}

/*
 * 检测当前进程是否被 ptrace
 */
static bool detect_ptrace_on_current(void)
{
    struct task_struct *current_task = current;
    
    if (current_task->ptrace != 0) {
        tear_debug("当前进程正在被ptrace\n");
        return true;
    }
    
    return false;
}

/*
 * 检测 /proc/self/status 中的 TracerPid
 * 注意：这在内核模块中用处有限，主要用于提供给用户空间API
 */
static pid_t get_tracer_pid(struct task_struct *task)
{
    struct task_struct *tracer = NULL;
    pid_t tracer_pid = 0;
    
    rcu_read_lock();
    
    /* 检查是否有 ptracer */
    if (task->ptrace) {
        tracer = task->parent;
        if (tracer)
            tracer_pid = tracer->pid;
    }
    
    rcu_read_unlock();
    return tracer_pid;
}

/*
 * 检测断点指令（ARM64 BRK）
 * 注意：这需要读取目标进程的内存
 */
static bool detect_breakpoints(pid_t pid, unsigned long addr, size_t len)
{
    /* ARM64 断点指令: BRK #0 = 0xD4200000 */
    const u32 arm64_brk = 0xD4200000;
    const u32 arm64_brk_mask = 0xFFE00000;
    
    /* 这需要实际读取内存来检测，在此仅提供接口 */
    (void)pid;
    (void)addr;
    (void)len;
    (void)arm64_brk;
    (void)arm64_brk_mask;
    
    return false;
}

/*
 * ============================================================================
 * 公共API
 * ============================================================================
 */

/*
 * 检测内核调试器
 */
bool tear_detect_kgdb(void)
{
    return detect_kgdb();
}

/*
 * 检测调试器进程
 */
bool tear_detect_debugger_process(void)
{
    return detect_debugger_processes() || detect_reverse_tools();
}

/*
 * 检测动态注入工具
 */
bool tear_detect_injection_tools(void)
{
    return detect_injection_tools();
}

/*
 * 综合调试检测
 * 检查所有可能的调试/分析活动
 */
bool tear_is_being_debugged(void)
{
    unsigned long flags;
    bool result = false;
    unsigned long now = jiffies;
    
    spin_lock_irqsave(&antidbg_state.lock, flags);
    
    /* 缓存检测结果，避免频繁扫描 */
    if (time_after(now, antidbg_state.last_check + HZ)) {
        antidbg_state.kgdb_detected = detect_kgdb();
        antidbg_state.debugger_detected = detect_debugger_processes();
        antidbg_state.analyzer_detected = detect_reverse_tools();
        antidbg_state.injector_detected = detect_injection_tools();
        antidbg_state.last_check = now;
    }
    
    result = antidbg_state.kgdb_detected ||
             antidbg_state.debugger_detected ||
             antidbg_state.analyzer_detected ||
             antidbg_state.injector_detected;
    
    spin_unlock_irqrestore(&antidbg_state.lock, flags);
    
    return result;
}

/*
 * 检测指定进程是否被调试
 */
bool tear_is_process_traced(pid_t pid)
{
    struct pid *pid_struct;
    struct task_struct *task;
    bool traced = false;
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task)
        return false;
    
    traced = (task->ptrace != 0);
    
    if (traced) {
        pid_t tracer = get_tracer_pid(task);
        tear_debug("进程 %d 正在被 %d 追踪\n", pid, tracer);
    }
    
    put_task_struct(task);
    return traced;
}

/*
 * 获取详细的调试状态
 */
int tear_get_debug_status(struct tear_debug_status *status)
{
    unsigned long flags;
    
    if (!status)
        return -EINVAL;
    
    spin_lock_irqsave(&antidbg_state.lock, flags);
    
    status->kgdb_connected = antidbg_state.kgdb_detected;
    status->debugger_present = antidbg_state.debugger_detected;
    status->analyzer_present = antidbg_state.analyzer_detected;
    status->injector_present = antidbg_state.injector_detected;
    status->current_traced = detect_ptrace_on_current();
    
    spin_unlock_irqrestore(&antidbg_state.lock, flags);
    
    return 0;
}

/*
 * ============================================================================
 * 模块初始化/清理
 * ============================================================================
 */

int teargame_antidbg_init(void)
{
    spin_lock_init(&antidbg_state.lock);
    antidbg_state.kgdb_detected = false;
    antidbg_state.debugger_detected = false;
    antidbg_state.analyzer_detected = false;
    antidbg_state.injector_detected = false;
    antidbg_state.last_check = 0;
    
    tear_info("反调试模块已初始化\n");
    
    /* 初始检测 */
    if (tear_is_being_debugged()) {
        tear_warn("警告: 检测到调试/分析活动\n");
    }
    
    return 0;
}

void teargame_antidbg_exit(void)
{
    tear_debug("反调试模块已清理\n");
}
