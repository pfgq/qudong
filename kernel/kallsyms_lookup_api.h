#ifndef _KALLSYMS_LOOKUP_API_H_
#define _KALLSYMS_LOOKUP_API_H_

#include "ver_control.h"
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/slab.h>

#ifndef KSYM_NAME_LEN
#define KSYM_NAME_LEN 512
#endif

static unsigned long (*kallsyms_lookup_name_sym)(const char *name);
static struct perf_event* (*register_user_hw_breakpoint_sym)(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk);
static void (*unregister_hw_breakpoint_sym)(struct perf_event *bp);
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
static int (*modify_user_hw_breakpoint_sym)(struct perf_event *bp, struct perf_event_attr *attr);
#endif

static unsigned long find_sym_in_kallsyms(const char *name)
{
    struct file *f = NULL;
    mm_segment_t old_fs;
    char *buf = NULL;
    ssize_t len;
    unsigned long addr = 0;
    loff_t pos = 0;     // <-- 移到最前面
    char *cur;          // <-- 提前声明
    char *line;         // <-- 提前声明
    unsigned long t_addr;
    char t_type;
    char t_name[KSYM_NAME_LEN];

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf)
        return 0;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    f = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(f)) {
        set_fs(old_fs);
        kfree(buf);
        return 0;
    }

    while ((len = kernel_read(f, buf, PAGE_SIZE - 1, &pos)) > 0) {
        buf[len] = '\0';
        cur = buf;
        while ((line = strsep(&cur, "\n")) != NULL) {
            if (strstr(line, name)) {
                if (sscanf(line, "%lx %c %s", &t_addr, &t_type, t_name) == 3) {
                    if (strcmp(t_name, name) == 0) {
                        addr = t_addr;
                        goto out;
                    }
                }
            }
        }
    }
out:
    filp_close(f, NULL);
    set_fs(old_fs);
    kfree(buf);
    return addr;
}


static unsigned long generic_kallsyms_lookup_name(const char *name)
{
    if (!kallsyms_lookup_name_sym) {
        kallsyms_lookup_name_sym = (void *)find_sym_in_kallsyms("kallsyms_lookup_name");
        printk_debug(KERN_EMERG "get_kallsyms_func:%px\n", kallsyms_lookup_name_sym);
        if (!kallsyms_lookup_name_sym)
            return 0;
    }
    return kallsyms_lookup_name_sym(name);
}

static bool init_kallsyms_lookup(void)
{
    register_user_hw_breakpoint_sym = (void *)generic_kallsyms_lookup_name("register_user_hw_breakpoint");
    printk_debug(KERN_EMERG "register_user_hw_breakpoint_sym:%px\n", register_user_hw_breakpoint_sym);
    if (!register_user_hw_breakpoint_sym) { return false; }

    unregister_hw_breakpoint_sym = (void *)generic_kallsyms_lookup_name("unregister_hw_breakpoint");
    printk_debug(KERN_EMERG "unregister_hw_breakpoint_sym:%px\n", unregister_hw_breakpoint_sym);
    if (!unregister_hw_breakpoint_sym) { return false; }

#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
    modify_user_hw_breakpoint_sym = (void *)generic_kallsyms_lookup_name("modify_user_hw_breakpoint");
    printk_debug(KERN_EMERG "modify_user_hw_breakpoint_sym:%px\n", modify_user_hw_breakpoint_sym);
    if (!modify_user_hw_breakpoint_sym) { return false; }
#endif

    return true;
}

#endif
