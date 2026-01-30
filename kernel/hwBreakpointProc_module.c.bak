#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>

int __init init_module(void) {
    unsigned long addr = kallsyms_lookup_name("printk");
    printk(KERN_INFO "kallsyms_lookup_name('printk') = %lx\n", addr);
    if (!addr) {
        printk(KERN_EMERG "Failed to lookup printk\n");
        return -EBADF;
    }
    printk(KERN_INFO "Test module loaded\n");
    return 0;
}

void __exit cleanup_module(void) {
    printk(KERN_INFO "Test module unloaded\n");
}

MODULE_LICENSE("GPL");
