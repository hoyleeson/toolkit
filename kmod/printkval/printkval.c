#include <linux/init.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>

void print_kval(const char *symbol)
{
    bool *fi = (bool *)kallsyms_lookup_name(symbol);
    if (!fi) {
        printk("Not found symbol %s\n", symbol);
        return;
    }
    printk("kval %s:%d\n", symbol, *fi);
}

static int __init print_kval_init(void)
{
    print_kval("force_irqthreads");
    printk("print kmod init successed.\n");
    return 0;
}


static void __exit print_kval_exit(void)
{
    printk("print kmod release.\n");
}

module_init(print_kval_init);
module_exit(print_kval_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hoyleeson");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("print_kval module");

