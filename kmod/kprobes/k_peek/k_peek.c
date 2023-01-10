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

int rename_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    printk("-->\n");
    return 0;
}

static struct kprobe my_kprobe[] = {
    {
        .symbol_name = "perf_event_set_bpf_prog",
        .pre_handler = rename_pre_handler,
    },
};

static int __init kprobe_init(void)
{
    int i;
	int ret;

    for (i = 0; i < ARRAY_SIZE(my_kprobe); i++) {
        ret = register_kprobe(&my_kprobe[i]);
        if (ret < 0) {
            pr_err("register_kprobe failed, returned %d\n", ret);
            goto fail;
        }
        pr_info("Planted kprobe at %s\n", my_kprobe[i].symbol_name);
    }
	return 0;
fail:
    while (i > 0) {
        unregister_kprobe(&my_kprobe[i - 1]);
    }
    return -EINVAL;
}

static void __exit kprobe_exit(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(my_kprobe); i++) {
        unregister_kprobe(&my_kprobe[i]);
        pr_info("jprobe at %s unregistered\n", my_kprobe[i].symbol_name);
    }
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
