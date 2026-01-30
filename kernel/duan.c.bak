#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/sched/signal.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("perf-hook");
MODULE_DESCRIPTION("ARM64 perf hook: change x0 for specific uid at address");

/* ========= 你要改的参数 ========= */

#define TARGET_UID     24698
#define TARGET_ADDR    0x00000059e745c880ULL   /* 执行断点地址 */
#define NEW_X0_VALUE   0x7BAB60A400ULL         /* 要写入 x0 的地址 */

/* ================================= */

static struct perf_event *g_event;
static struct task_struct *g_task;

/* 按 UID 找一个 task（默认取第一个） */
static struct task_struct *find_task_by_uid(uid_t uid)
{
    struct task_struct *p;

    for_each_process(p) {
        if (__kuid_val(task_uid(p)) == uid) {
            get_task_struct(p);
            return p;
        }
    }
    return NULL;
}

/* perf 断点回调 */
static void bp_handler(struct perf_event *bp,
                       struct perf_sample_data *data,
                       struct pt_regs *regs)
{
    if (!regs)
        return;

    /* 精确 PC 匹配，防误伤 */
    if (regs->pc != TARGET_ADDR)
        return;

    /* 再次确认 UID（双保险） */
    if (__kuid_val(current_uid()) != TARGET_UID)
        return;

    pr_info("[perf-hook] HIT pid=%d pc=%lx old_x0=%lx\n",
            current->pid, regs->pc, regs->regs[0]);

    /* 核心：修改 x0 为一个地址 */
    regs->regs[0] = NEW_X0_VALUE;

    pr_info("[perf-hook] x0 changed -> %lx\n", regs->regs[0]);

    /* 防止重复命中 */
    perf_event_disable(bp);
}

static int __init perf_hook_init(void)
{
    struct perf_event_attr attr;

    pr_info("[perf-hook] init\n");

    g_task = find_task_by_uid(TARGET_UID);
    if (!g_task) {
        pr_err("[perf-hook] no task found for uid %d\n", TARGET_UID);
        return -ESRCH;
    }

    pr_info("[perf-hook] bind to pid=%d comm=%s uid=%d\n",
            g_task->pid, g_task->comm, TARGET_UID);

    hw_breakpoint_init(&attr);
    attr.type     = PERF_TYPE_BREAKPOINT;
    attr.bp_type  = HW_BREAKPOINT_X;           /* 执行断点 */
    attr.bp_addr  = TARGET_ADDR;
    attr.bp_len   = HW_BREAKPOINT_LEN_4;
    attr.disabled = 0;

    g_event = perf_event_create_kernel_counter(
        &attr,
        -1,             /* 所有 CPU */
        g_task,         /* 绑定目标 task（关键） */
        bp_handler,
        NULL
    );

    if (IS_ERR(g_event)) {
        pr_err("[perf-hook] perf_event_create failed\n");
        put_task_struct(g_task);
        return PTR_ERR(g_event);
    }

    pr_info("[perf-hook] installed at %px for uid %d\n",
            (void *)TARGET_ADDR, TARGET_UID);

    return 0;
}

static void __exit perf_hook_exit(void)
{
    if (g_event) {
        perf_event_release_kernel(g_event);
        g_event = NULL;
    }

    if (g_task) {
        put_task_struct(g_task);
        g_task = NULL;
    }

    pr_info("[perf-hook] exit\n");
}

module_init(perf_hook_init);
module_exit(perf_hook_exit);
