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

static int j___skb_checksum_complete(struct sk_buff *skb)
{
    __wsum csum;
    __sum16 sum;

    csum = skb_checksum(skb, 0, skb->len, 0);
    sum = csum_fold(csum_add(skb->csum, csum));
    printk("skb len:%d, csum:%d, sum:%d\n", skb->len, csum, sum);

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

#if 0
static int j_dev_change_xdp_fd(struct net_device *dev, int fd)
{
    bool flags = true;
    const struct net_device_ops *ops = dev->netdev_ops;

    if (!ops->ndo_xdp) {
        flags = false;
    }
    printk("%s support ndo_xdp.\n", flags ? "" : "No");

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}
#endif

static struct jprobe my_jprobe[] = {
    {
        .entry			= j_ip_rcv,
        .kp = {
            .symbol_name	= "ip_rcv",
        },
    },
    {
        .entry			= j___skb_checksum_complete,
        .kp = {
            .symbol_name	= "__skb_checksum_complete",
        },
    },
#if 0
    {
        .entry			= j_dev_change_xdp_fd,
        .kp = {
            .symbol_name	= "dev_change_xdp_fd",
        },
    },
#endif
};

static int __init jprobe_init(void)
{
    int i;
	int ret;

    for (i = 0; i < ARRAY_SIZE(my_jprobe); i++) {
        ret = register_jprobe(&my_jprobe[i]);
        if (ret < 0) {
            pr_err("register_jprobe failed, returned %d\n", ret);
            goto fail;
        }
        pr_info("Planted jprobe at %p, handler addr %p\n",
                my_jprobe[i].kp.addr, my_jprobe[i].entry);
    }
	return 0;
fail:
    while (i > 0) {
        unregister_jprobe(&my_jprobe[i - 1]);
    }
    return -EINVAL;
}

static void __exit jprobe_exit(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(my_jprobe); i++) {
        unregister_jprobe(&my_jprobe[i]);
        pr_info("jprobe at %p unregistered\n", my_jprobe[i].kp.addr);
    }
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
