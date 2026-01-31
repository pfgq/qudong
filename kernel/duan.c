#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/sched/signal.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("perf-ioctl");
MODULE_DESCRIPTION("ARM64 perf ioctl realtime register watch");

#define DEVICE_NAME "perf_hook"

/* ioctl 定义 */
#define PERF_HOOK_MAGIC      'p'
#define PERF_IOCTL_PRINT_REG _IOW(PERF_HOOK_MAGIC, 2, struct perf_hook_req)

/* ioctl 结构 */
struct perf_hook_req {
    pid_t          pid;        /* 目标进程 PID */
    unsigned long  addr;       /* 执行断点地址（用户 VA） */
    int            reg;        /* 0~30 => x0~x30 */
    unsigned long  value;      /* 未使用（只打印） */
};

/* 全局状态（单实例示例） */
static struct perf_event *g_event;
static struct task_struct *g_task;
static struct perf_hook_req g_req;

/* 按 PID 找 task */
static struct task_struct *find_task_by_pid(pid_t pid)
{
    struct task_struct *p;
    for_each_process(p) {
        if (p->pid == pid) {
            get_task_struct(p);
            return p;
        }
    }
    return NULL;
}

/* perf 执行断点回调：实时打印寄存器 */
static void bp_handler(struct perf_event *bp,
                       struct perf_sample_data *data,
                       struct pt_regs *regs)
{
    if (!regs)
        return;

    /* 双保险校验 */
    if (current->pid != g_req.pid)
        return;
    if (regs->pc != g_req.addr)
        return;
    if (g_req.reg < 0 || g_req.reg > 30)
        return;

    /* 实时打印 xN */
    pr_info("[perf-rt] pid=%d pc=%lx x%d=%lx\n",
            current->pid,
            regs->pc,
            g_req.reg,
            regs->regs[g_req.reg]);

    /* 注意：
     * - 不 disable
     * - 不 release
     * => 每次命中都会打印
     */
}

/* 安装 perf 执行断点 */
static int install_perf_hook(void)
{
    struct perf_event_attr attr;

    hw_breakpoint_init(&attr);
    attr.type    = PERF_TYPE_BREAKPOINT;
    attr.bp_type = HW_BREAKPOINT_X;      /* 执行断点 */
    attr.bp_addr = g_req.addr;           /* 用户 VA */
    attr.bp_len  = HW_BREAKPOINT_LEN_4;

    g_event = perf_event_create_kernel_counter(
        &attr,
        -1,             /* 所有 CPU */
        g_task,         /* 绑定目标 task（关键） */
        bp_handler,
        NULL
    );

    if (IS_ERR(g_event)) {
        g_event = NULL;
        return -EINVAL;
    }

    pr_info("[perf-rt] installed pid=%d addr=%lx watch x%d\n",
            g_req.pid, g_req.addr, g_req.reg);
    return 0;
}

/* ioctl 处理 */
static long perf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    if (cmd != PERF_IOCTL_PRINT_REG)
        return -EINVAL;

    if (copy_from_user(&g_req, (void __user *)arg, sizeof(g_req)))
        return -EFAULT;

    if (g_event)
        return -EBUSY;

    g_task = find_task_by_pid(g_req.pid);
    if (!g_task)
        return -ESRCH;

    return install_perf_hook();
}

/* 字符设备 */
static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = perf_ioctl,
};

static int major;

static int __init perf_init(void)
{
    major = register_chrdev(0, DEVICE_NAME, &fops);
    pr_info("[perf-rt] loaded, major=%d\n", major);
    return 0;
}

static void __exit perf_exit(void)
{
    if (g_event) {
        perf_event_release_kernel(g_event);
        g_event = NULL;
    }
    if (g_task) {
        put_task_struct(g_task);
        g_task = NULL;
    }
    unregister_chrdev(major, DEVICE_NAME);
    pr_info("[perf-rt] unloaded\n");
}

module_init(perf_init);
module_exit(perf_exit);
