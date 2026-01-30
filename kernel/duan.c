#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("arm64-perf");
MODULE_DESCRIPTION("perf hook: set x0 for specific uid at address");

#define TARGET_UID        24698
#define TARGET_ADDR       0x59e745c880UL
#define NEW_X0_VALUE      0x7BAB60A400ULL

static struct perf_event *bp_event;

static void bp_handler(struct perf_event *bp,
                       struct perf_sample_data *data,
                       struct pt_regs *regs)
{
    kuid_t uid;

    if (!regs)
        return;

    /* 只处理精确 PC */
    if (regs->pc != TARGET_ADDR)
        return;

    uid = current_uid();
    if (__kuid_val(uid) != TARGET_UID)
        return;

    /* 核心操作：改 x0 */
    regs->regs[0] = NEW_X0_VALUE;

    /* 不改 PC：原地继续执行 */
}

static int __init hook_init(void)
{
    struct perf_event_attr attr;

    pr_info("[perf-hook] init\n");

    hw_breakpoint_init(&attr);
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = TARGET_ADDR;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;

    /*
     * 绑定到当前 task：
     * 实际使用中你通常：
     *  - 先找到 uid=12345 的 task_struct
     *  - 把 current 换成那个 task
     */
    bp_event = perf_event_create_kernel_counter(
        &attr,
        -1,             /* 所有 CPU */
        current,        /* 绑定 task（示例） */
        bp_handler,
        NULL
    );

    if (IS_ERR(bp_event)) {
        pr_err("[perf-hook] create perf event failed\n");
        return PTR_ERR(bp_event);
    }

    pr_info("[perf-hook] installed at %px for uid %d\n",
            (void *)TARGET_ADDR, TARGET_UID);
    return 0;
}

static void __exit hook_exit(void)
{
    if (bp_event) {
        perf_event_release_kernel(bp_event);
        bp_event = NULL;
    }
    pr_info("[perf-hook] exit\n");
}

module_init(hook_init);
module_exit(hook_exit);
