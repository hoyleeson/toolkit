#include <linux/init.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <asm/paravirt.h>
#include <asm/syscall.h>
#include <linux/sys.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/binfmts.h>
#include <linux/version.h>
#include <net/sock.h>
#include <net/netlink.h>

#include <linux/proc_fs.h>
#include <net/tcp.h>

void print_module_list(void)
{
    struct module *mod;
    struct module *m = &__this_module;
    struct list_head *entry;

    entry = &m->list;
    printk("module list:\n");
    while (entry) {
        mod = list_entry(entry, struct module, list);
        printk("    %s, %p, %p\n", mod->name, mod->init, mod->exit); 
        entry = entry->next;
        if (entry->next == &m->list)
            break;
    }
}

static int __init print_kmod_init(void)
{
    print_module_list();
    printk("print kmod init successed.\n");
    return 0;
}


static void __exit print_kmod_exit(void)
{
    printk("print kmod release.\n");
}

module_init(print_kmod_init);
module_exit(print_kmod_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hoyleeson");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("print_kmod module");

