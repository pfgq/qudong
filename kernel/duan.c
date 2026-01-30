#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("test");
MODULE_DESCRIPTION("KernelSU lookup test");

/* KernelSU 导出的符号 */
extern unsigned long ksu_lookup_name(const char *name);

static int __init ksu_test_init(void)
{
    unsigned long addr1;
    unsigned long addr2;

    printk(KERN_ERR "[ksu_test] init\n");

    addr1 = ksu_lookup_name("kallsyms_lookup_name");
    addr2 = ksu_lookup_name("sys_call_table");

    printk(KERN_ERR "[ksu_test] kallsyms_lookup_name = %px\n",
           (void *)addr1);
    printk(KERN_ERR "[ksu_test] sys_call_table        = %px\n",
           (void *)addr2);

    if (!addr1 || !addr2) {
        printk(KERN_ERR "[ksu_test] lookup failed\n");
        return -EINVAL;
    }

    printk(KERN_ERR "[ksu_test] lookup success\n");
    return 0;
}

static void __exit ksu_test_exit(void)
{
    printk(KERN_ERR "[ksu_test] exit\n");
}

module_init(ksu_test_init);
module_exit(ksu_test_exit);
