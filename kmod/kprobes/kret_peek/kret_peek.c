/*
 * Here's a sample kernel module showing the use of jprobes to dump
 * the arguments of ip_rcv().
 *
 * For more information on theory of operation of jprobes, see
 * Documentation/kprobes.txt
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the
 * console whenever _do_fork() is invoked to create a new process.
 * (Some messages may be suppressed if syslogd is configured to
 * eliminate duplicate messages.)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/if_packet.h>
#include <linux/netdevice.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <linux/trace_events.h>
#include <linux/filter.h>

int kret_nf_unregister_net_hook(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk("kret:%lu\n", jiffies);
    return 0;
}
int kentry_nf_unregister_net_hook(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk("kentry:%lu\n", jiffies);
    return 0;
}


int kret_nf_queue_nf_hook_drop(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk("queue_ret:%lu\n", jiffies);
    return 0;
}
int kentry_nf_queue_nf_hook_drop(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk("queue_entry:%lu\n", jiffies);
    return 0;
}



static struct kretprobe my_kretprobe[] = {
    {
        .kp.symbol_name = "nf_unregister_net_hook",
        .handler = kret_nf_unregister_net_hook,
        .entry_handler = kentry_nf_unregister_net_hook,
    },
    {
        .kp.symbol_name = "nf_queue_nf_hook_drop",
        .handler = kret_nf_queue_nf_hook_drop,
        .entry_handler = kentry_nf_queue_nf_hook_drop,
    }

};

static int __init kretprobe_init(void)
{
    int i;
	int ret;

    for (i = 0; i < ARRAY_SIZE(my_kretprobe); i++) {
        ret = register_kretprobe(&my_kretprobe[i]);
        if (ret < 0) {
            pr_err("register_kretprobe failed, returned %d\n", ret);
            goto fail;
        }
        pr_info("Planted kretprobe at %s\n", my_kretprobe[i].kp.symbol_name);
    }
	return 0;
fail:
    while (i > 0) {
        unregister_kretprobe(&my_kretprobe[i - 1]);
    }
    return -EINVAL;
}

static void __exit kretprobe_exit(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(my_kretprobe); i++) {
        unregister_kretprobe(&my_kretprobe[i]);
        pr_info("kretprobe at %s unregistered\n", my_kretprobe[i].kp.symbol_name);
    }
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
