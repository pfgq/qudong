#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

static unsigned long kallsyms_lookup_name_addr = 0;

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};

static int __init get_kallsyms_init(void)
{
    int ret;

    printk(KERN_ERR "[duan] get_kallsyms_init enter\n");

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[duan] register_kprobe failed, ret=%d\n", ret);
        return ret;
    }

    kallsyms_lookup_name_addr = (unsigned long)kp.addr;
    printk(KERN_ERR "[duan] kallsyms_lookup_name addr = 0x%lx\n",
           kallsyms_lookup_name_addr);

    unregister_kprobe(&kp);

    return 0;
}

static void __exit get_kallsyms_exit(void)
{
    printk(KERN_ERR "[duan] get_kallsyms_exit\n");
}

module_init(get_kallsyms_init);
module_exit(get_kallsyms_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("duan");
MODULE_DESCRIPTION("get kallsyms_lookup_name address via kprobe");
