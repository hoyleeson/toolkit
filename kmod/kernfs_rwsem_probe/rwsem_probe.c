#include <linux/init.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/cgroup-defs.h>

unsigned long (*diag_kallsyms_lookup_name)(const char *name);

static int (*diag_kallsyms_on_each_symbol)(int (*fn)(void *, const char *,
            struct module *, unsigned long), void *data);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>
static struct kprobe kprobe_kallsyms_lookup_name = {
    .symbol_name = "kallsyms_lookup_name"
};

int diag_init_symbol(void)
{
    register_kprobe(&kprobe_kallsyms_lookup_name);
    diag_kallsyms_lookup_name = (void *)kprobe_kallsyms_lookup_name.addr;
    unregister_kprobe(&kprobe_kallsyms_lookup_name);

    printk("diag_kallsyms_lookup_name is %p\n", diag_kallsyms_lookup_name);

    if (!diag_kallsyms_lookup_name) {
        return -EINVAL;
    }

    diag_kallsyms_on_each_symbol = (void *)diag_kallsyms_lookup_name("kallsyms_on_each_symbol");
    if (!diag_kallsyms_on_each_symbol) {
        return -EINVAL;
    }

    return 0;
}
#else
#endif

static inline int snxprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list args;
    int i;

    if (unlikely(!size))
        return 0;

    va_start(args, fmt);
    i = vsnprintf(buf, size, fmt, args);
    va_end(args);

    return (i > size) ? size : i;
}

static int kernfs_dop_revalidate_kret_entry_handler(struct kretprobe_instance *ri,
        struct pt_regs *regs)
{
    int i = 0;
    char buf[10][32];
    char outbuf[256] = {};
    int len = 0;
    struct dentry *dentry, *parent;

    len += snxprintf(outbuf + len, 256 - len, "[%s]: ", current->comm);
    dentry = (struct dentry *)regs->di;
    if (dentry) {
        if (dentry->d_sb && dentry->d_sb->s_type && dentry->d_sb->s_type->name)
            len += snxprintf(outbuf + len, 256 - len, "fs:%s, ", dentry->d_sb->s_type->name);


        if (dentry->d_name.name) {
            snprintf(buf[i], 30, "%s", dentry->d_name.name);
        } else {
            snprintf(buf[i], 30, "%s", dentry->d_iname);
        }
    }
    for (i = 1; i < 10; i++) {
        if (dentry) {
            parent = dentry->d_parent;
            if (!parent || parent == dentry)
                break;

            dentry = parent;

            if (dentry->d_name.name) {
                snprintf(buf[i], 30, "%s", dentry->d_name.name);
            } else {
                snprintf(buf[i], 30, "%s", dentry->d_iname);
            }
        }
    }

    for (; i > 0; i--) {
        len += snxprintf(outbuf + len, 256 - len, "/%s", buf[i - 1]);
    }
    printk("%s\n", outbuf);
    return 0;
}

static int kernfs_dop_revalidate_kret_handler(struct kretprobe_instance *ri,
        struct pt_regs *regs)
{
    return 0;
}


static struct kretprobe my_kretprobe[] = {
    {
        .kp.symbol_name = "kernfs_dop_revalidate",
        .handler = kernfs_dop_revalidate_kret_handler,
        .entry_handler = kernfs_dop_revalidate_kret_entry_handler,
    },
};

static int __init rwsem_probe_init(void)
{
    int i;
    int ret;

    diag_init_symbol();

    for (i = 0; i < ARRAY_SIZE(my_kretprobe); i++) {
        ret = register_kretprobe(&my_kretprobe[i]);
        if (ret < 0) {
            pr_err("register_kretprobe %s failed, returned %d\n",
                    my_kretprobe[i].kp.symbol_name, ret);
            goto fail;
        }
        pr_info("Planted kretprobe at %s\n", my_kretprobe[i].kp.symbol_name);
    }

    printk("resem probe kmod init successed.%d\n", HZ);

    return 0;

fail:
    while (i > 0) {
        unregister_kretprobe(&my_kretprobe[i - 1]);
    }
    return -EINVAL;
}

static void __exit rwsem_probe_exit(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(my_kretprobe); i++) {
        unregister_kretprobe(&my_kretprobe[i]);
        pr_info("kretprobe at %s unregistered\n", my_kretprobe[i].kp.symbol_name);
    }

    printk("resem probe kmod release.\n");
}

module_init(rwsem_probe_init);
module_exit(rwsem_probe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hoyleeson");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("rwsem_probe module");

