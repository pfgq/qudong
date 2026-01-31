#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/sched/signal.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");

#define DEVICE_NAME "perf_hook"

/* ioctl 定义 */
#define PERF_HOOK_MAGIC   'p'
#define PERF_IOCTL_SET_HOOK   _IOW(PERF_HOOK_MAGIC, 1, struct perf_hook_req)
#define PERF_IOCTL_PRINT_REG  _IOW(PERF_HOOK_MAGIC, 2, struct perf_hook_req)

struct perf_hook_req {
    pid_t          pid;
    unsigned long  addr;
    int            reg;
    unsigned long  value;
};

/* 全局状态（单 hook 示例） */
static struct perf_event *g_event;
static struct task_struct *g_task;
static struct perf_hook_req g_req;
static bool g_print_only;

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

/* perf handler */
static void bp_handler(struct perf_event *bp,
                       struct perf_sample_data *data,
                       struct pt_regs *regs)
{
    if (!regs)
        return;

    if (regs->pc != g_req.addr)
        return;

    if (g_req.reg < 0 || g_req.reg > 30)
        return;

    if (g_print_only) {
        pr_info("[perf-ioctl] HIT pid=%d pc=%lx x%d=%lx\n",
                current->pid,
                regs->pc,
                g_req.reg,
                regs->regs[g_req.reg]);
    } else {
        pr_info("[perf-ioctl] HIT pid=%d pc=%lx x%d old=%lx new=%lx\n",
                current->pid,
                regs->pc,
                g_req.reg,
                regs->regs[g_req.reg],
                g_req.value);

        regs->regs[g_req.reg] = g_req.value;
    }

    /* 命中一次即释放，防止 busy */
    perf_event_disable(bp);
    perf_event_release_kernel(bp);
    g_event = NULL;
}

/* 安装 perf hook */
static int install_perf_hook(void)
{
    struct perf_event_attr attr;

    hw_breakpoint_init(&attr);
    attr.type    = PERF_TYPE_BREAKPOINT;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = g_req.addr;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;

    g_event = perf_event_create_kernel_counter(
        &attr,
        -1,
        g_task,
        bp_handler,
        NULL
    );

    if (IS_ERR(g_event)) {
        g_event = NULL;
        return -EINVAL;
    }

    pr_info("[perf-ioctl] hook installed pid=%d addr=%lx reg=x%d\n",
            g_req.pid, g_req.addr, g_req.reg);

    return 0;
}

/* ioctl */
static long perf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    if (copy_from_user(&g_req, (void __user *)arg, sizeof(g_req)))
        return -EFAULT;

    if (g_event)
        return -EBUSY;

    g_task = find_task_by_pid(g_req.pid);
    if (!g_task)
        return -ESRCH;

    g_print_only = (cmd == PERF_IOCTL_PRINT_REG);

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
    pr_info("[perf-ioctl] loaded, major=%d\n", major);
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
    pr_info("[perf-ioctl] unloaded\n");
}

module_init(perf_init);
module_exit(perf_exit);
