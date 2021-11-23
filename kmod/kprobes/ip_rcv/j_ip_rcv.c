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

/*
 * Jumper probe for ip_rcv
 * Mirror principle enables access to arguments of the probed routine
 * from the probe handler.
 */
static int j_ip_rcv(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev)
{
    if (skb->pkt_type == PACKET_OTHERHOST) {
        skb->pkt_type = PACKET_HOST;
        pr_debug("skb->pkt_type change %d to %d.\n", PACKET_OTHERHOST, skb->pkt_type);
    }

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

static struct jprobe my_jprobe = {
	.entry			= j_ip_rcv,
	.kp = {
		.symbol_name	= "ip_rcv",
	},
};

static int __init jprobe_init(void)
{
	int ret;

	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		pr_err("register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	pr_info("Planted jprobe at %p, handler addr %p\n",
	       my_jprobe.kp.addr, my_jprobe.entry);
	return 0;
}

static void __exit jprobe_exit(void)
{
	unregister_jprobe(&my_jprobe);
	pr_info("jprobe at %p unregistered\n", my_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
