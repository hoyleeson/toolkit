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
#include <net/udp.h>

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
    printk("jprobe: skb len:%d, skb->csum:%d, csum:%d, sum:%d\n", skb->len, skb->csum, csum, sum);

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

__sum16 j___skb_checksum_complete_head(struct sk_buff *skb, int len)
{
    __wsum csum;
    __sum16 sum;

    csum = skb_checksum(skb, 0, skb->len, 0);
    sum = csum_fold(csum_add(skb->csum, csum));
    printk("jprobe j___skb_checksum_complete_head: skb len:%d, skb->csum:%d, csum:%d, sum:%d\n",
            skb->len, skb->csum, csum, sum);

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

int j_udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
    printk("j_udp_queue_rcv_skb, skb->len:%d\n", skb->len);

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

int j_udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
                int flags, int *addr_len)
{
    printk("j_udp_recvmsg, len:%lu\n", len);

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

int j___udp4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable, int proto)
{
    printk("j___udp4_lib_rcv, skb->len:%d, skb->csum:%d, skb->ip_summed:%d, "
            "skb->csum_valid:%d,skb->csum_complete_sw:%d, skb->csum_bad:%d\n",
            skb->len, skb->csum, skb->ip_summed,
            skb->csum_valid, skb->csum_complete_sw, skb->csum_bad);

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

static int j_ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    printk("ip_finish_output2 probe entry\n");
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

struct jprobe_entrys {
    bool enabled;
    struct jprobe jprobe;
};

static struct jprobe_entrys my_jprobe[] = {
    {
        .enabled = false,
        .jprobe = {
            .entry			= j_ip_rcv,
            .kp = {
                .symbol_name	= "ip_rcv",
            },
        },
    },
    {
        .enabled = true,
        .jprobe = {
            .entry			= j___skb_checksum_complete,
            .kp = {
                .symbol_name	= "__skb_checksum_complete",
            },
        },
    },
    {
        .enabled = true,
        .jprobe = {
            .entry			= j___skb_checksum_complete_head,
            .kp = {
                .symbol_name	= "__skb_checksum_complete_head",
            },
        },
    },
    {
        .enabled = true,
        .jprobe = {
            .entry			= j_udp_queue_rcv_skb,
            .kp = {
                .symbol_name	= "udp_queue_rcv_skb",
            },
        },
    },
    {
        .enabled = true,
        .jprobe = {
            .entry			= j_udp_recvmsg,
            .kp = {
                .symbol_name	= "udp_recvmsg",
            },
        },
    },
    {
        .enabled = true,
        .jprobe = {
            .entry			= j___udp4_lib_rcv,
            .kp = {
                .symbol_name	= "__udp4_lib_rcv",
            },
        },
    },

    {
        .enabled = false,
        .jprobe = {
            .entry			= j_ip_finish_output2,
            .kp = {
                .symbol_name	= "ip_finish_output2",
            },
        },
    },
#if 0
    {
        .enabled = false,
        .jprobe = {
            .entry			= j_dev_change_xdp_fd,
            .kp = {
                .symbol_name	= "dev_change_xdp_fd",
            },
        },
    },
#endif
};

static int __init jprobe_init(void)
{
    int i;
	int ret;

    for (i = 0; i < ARRAY_SIZE(my_jprobe); i++) {
        if (!my_jprobe[i].enabled)
            continue;
        ret = register_jprobe(&my_jprobe[i].jprobe);
        if (ret < 0) {
            pr_err("register_jprobe failed, returned %d\n", ret);
            goto fail;
        }
        pr_info("Planted jprobe at %p, handler addr %p\n",
                my_jprobe[i].jprobe.kp.addr, my_jprobe[i].jprobe.entry);
    }
	return 0;
fail:
    while (--i > 0) {
        if (!my_jprobe[i].enabled)
            continue;
        unregister_jprobe(&my_jprobe[i].jprobe);
    }
    return -EINVAL;
}

static void __exit jprobe_exit(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(my_jprobe); i++) {
        if (!my_jprobe[i].enabled)
            continue;

        unregister_jprobe(&my_jprobe[i].jprobe);
        pr_info("jprobe at %p unregistered\n", my_jprobe[i].jprobe.kp.addr);
    }
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
