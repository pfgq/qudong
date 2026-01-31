#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/sched/signal.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("perf-rw");
MODULE_DESCRIPTION("ARM64 perf RW watch with user bp_len");

#define DEVICE_NAME "perf_hook"

/* ioctl 定义 */
#define PERF_HOOK_MAGIC     'p'
#define PERF_IOCTL_RW_WATCH _IOW(PERF_HOOK_MAGIC, 3, struct perf_hook_req)

/* ioctl 结构 */
struct perf_hook_req {
    pid_t          pid;
    unsigned long  addr;
    int            reg;
    unsigned int   bp_len;   /* 1 / 2 / 4 / 8 */
};

/* ===== 全局 ===== */
static struct perf_event *g_event;
static struct task_struct *g_task;
static struct perf_hook_req g_req;

/* char dev */
static dev_t devno;
static struct cdev perf_cdev;
static struct class *perf_class;
static struct device *perf_device;

/* PID → task */
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

/* 用户 bp_len → perf bp_len */
static int convert_bp_len(unsigned int len)
{
    switch (len) {
    case 1: return HW_BREAKPOINT_LEN_1;
    case 2: return HW_BREAKPOINT_LEN_2;
    case 4: return HW_BREAKPOINT_LEN_4;
    case 8: return HW_BREAKPOINT_LEN_8;
    default:
        return -EINVAL;
    }
}

/* RW handler */
static void bp_handler(struct perf_event *bp,
                       struct perf_sample_data *data,
                       struct pt_regs *regs)
{
    if (!regs)
        return;

    if (current->pid != g_req.pid)
        return;

    if (g_req.reg < 0 || g_req.reg > 30)
        return;

    pr_info("[perf-rw] pid=%d pc=%lx x%d=%lx (addr=%lx len=%u)\n",
            current->pid,
            regs->pc,
            g_req.reg,
            regs->regs[g_req.reg],
            g_req.addr,
            g_req.bp_len);
}

/* install RW watch */
static int install_rw_watch(void)
{
    struct perf_event_attr attr;
    int hw_len;

    hw_len = convert_bp_len(g_req.bp_len);
    if (hw_len < 0)
        return -EINVAL;

    hw_breakpoint_init(&attr);
    attr.type    = PERF_TYPE_BREAKPOINT;
    attr.bp_type = HW_BREAKPOINT_R | HW_BREAKPOINT_W;
    attr.bp_addr = g_req.addr;
    attr.bp_len  = hw_len;

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

    pr_info("[perf-rw] installed pid=%d addr=%lx len=%u\n",
            g_req.pid, g_req.addr, g_req.bp_len);
    return 0;
}

/* ioctl */
static long perf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    if (cmd != PERF_IOCTL_RW_WATCH)
        return -EINVAL;

    if (copy_from_user(&g_req, (void __user *)arg, sizeof(g_req)))
        return -EFAULT;

    if (g_event)
        return -EBUSY;

    g_task = find_task_by_pid(g_req.pid);
    if (!g_task)
        return -ESRCH;

    return install_rw_watch();
}

static const struct file_operations perf_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = perf_ioctl,
};

/* init */
static int __init perf_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&devno, 0, 1, DEVICE_NAME);
    if (ret)
        return ret;

    cdev_init(&perf_cdev, &perf_fops);
    ret = cdev_add(&perf_cdev, devno, 1);
    if (ret)
        goto err_cdev;

    perf_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(perf_class)) {
        ret = PTR_ERR(perf_class);
        goto err_class;
    }

    perf_device = device_create(perf_class, NULL, devno, NULL, DEVICE_NAME);
    if (IS_ERR(perf_device)) {
        ret = PTR_ERR(perf_device);
        goto err_device;
    }

    pr_info("[perf-rw] loaded, /dev/%s created\n", DEVICE_NAME);
    return 0;

err_device:
    class_destroy(perf_class);
err_class:
    cdev_del(&perf_cdev);
err_cdev:
    unregister_chrdev_region(devno, 1);
    return ret;
}

/* exit */
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

    device_destroy(perf_class, devno);
    class_destroy(perf_class);
    cdev_del(&perf_cdev);
    unregister_chrdev_region(devno, 1);

    pr_info("[perf-rw] unloaded\n");
}

module_init(perf_init);
module_exit(perf_exit);
