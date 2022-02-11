#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_bridge.h>
#include <linux/version.h>

#include <linux/proc_fs.h>
#include <net/tcp.h>

/* 
 * set skb mark:
 *  iptables -t mangle -A OUTPUT -j MARK --set-mark a2345678
 * */

#define NF_IP_PRI_TOA      (NF_IP_PRI_MANGLE + 5)

#define TCPOPT_LABEL    (83)
#define TCPOLEN_LABEL   (6)

#define TOA_MARK_MAGIC      (0xa)
#define TOA_MARK_MASK       (0x0fffffff)

/* Parse TCP options in skb, try to get client ip, port
 * @param skb [in] received skb, it should be a ack/get-ack packet.
 * @return NULL if we don't get client ip/port;
 *         value of toa_data in ret_ptr if we get client ip/port.
 */
static u32 get_toa_data(struct sk_buff *skb)
{
    struct tcphdr *th;
    int length;
    unsigned char *ptr;

    if (!skb)
        return 0;

    th = tcp_hdr(skb);
    length = (th->doff * 4) - sizeof(struct tcphdr);
    ptr = (unsigned char *)(th + 1);

    while (length > 0) {
        int opcode = *ptr++;
        int opsize;
        switch (opcode) {
            case TCPOPT_EOL:
                return 0;
            case TCPOPT_NOP:    /* Ref: RFC 793 section 3.1 */
                length--;
                continue;
            default:
                opsize = *ptr++;
                if (opsize < 2)    /* "silly options" */
                    return 0;
                if (opsize > length)
                    /* don't parse partial options */
                    return 0;
                if (TCPOPT_LABEL == opcode &&
                        TCPOLEN_LABEL == opsize) {
                    u32 label;

                    memcpy(&label, ptr, sizeof(u32));
                    return ntohl(label);
                }
                ptr += opsize - 2;
                length -= opsize;
        }
    }
    return 0;
}

static int tcp_option_add_label(__be32 *ptr, u32 label)
{
    *ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_LABEL << 8) | TCPOLEN_LABEL);
    *ptr++ = htonl(label);

    return TCPOLEN_LABEL + 2;
}

static bool toa_mark_match(u32 mark)
{
    if (!mark)
        return false;

    if ((mark >> 28) != TOA_MARK_MAGIC)
        return false;
    return true;
}

static void toa_v4_recalc_csum(struct sk_buff *skb, __be32 saddr, __be32 daddr)
{
    struct tcphdr *th = tcp_hdr(skb);

#if 0
    int csum;
    th->check = 0;
    csum = csum_tcpudp_nofold(saddr, daddr, skb->len, IPPROTO_TCP, 0);
    th->check = csum_fold(skb_checksum(skb, 0, skb->len, csum));
    skb->ip_summed = CHECKSUM_NONE;
#else
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        th->check = ~tcp_v4_check(skb->len, saddr, daddr, 0);
        skb->csum_start = skb_transport_header(skb) - skb->head;
        skb->csum_offset = offsetof(struct tcphdr, check);
    } else {
        th->check = tcp_v4_check(skb->len, saddr, daddr,
                csum_partial(th, th->doff << 2, skb->csum));
    }
#endif
}

static unsigned int toa_nf_packet_setlabel(int af, struct sk_buff *skb)
{
    int llen;
    u32 label;
    struct iphdr *iph;
    struct tcphdr *th;
    char iph_buf[64];
    char th_buf[64];
    int iphl, thl;

    if (!toa_mark_match(skb->mark))
        return NF_ACCEPT; 

    iph = ip_hdr(skb);
    /* Only process tcp. */
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    th = tcp_hdr(skb);
    if (!th->syn) {
        return NF_ACCEPT;
    }

    label = skb->mark & TOA_MARK_MASK;

    if (unlikely(skb_is_nonlinear(skb) && (skb_linearize(skb) < 0)))
        return NF_ACCEPT;

    iphl = ip_hdrlen(skb);
    skb_copy_from_linear_data(skb, iph_buf, iphl);
    thl = tcp_hdrlen(skb);
    skb_copy_from_linear_data_offset(skb, ip_hdrlen(skb), th_buf, thl);
    if (sizeof(th_buf) - tcp_hdrlen(skb) < 8) {
        return NF_ACCEPT;
    }
    llen = tcp_option_add_label((__be32 *)(th_buf + tcp_hdrlen(skb)), label);

    thl += llen;
    th = (struct tcphdr *)th_buf;
    th->doff = thl >> 2;

    __skb_pull(skb, ip_hdrlen(skb) + tcp_hdrlen(skb));

    skb_push(skb, thl);
    skb_copy_to_linear_data(skb, th_buf, thl);
    skb_reset_transport_header(skb);

    iph = (struct iphdr *)iph_buf;
    /* tcp checksum */
    toa_v4_recalc_csum(skb, iph->saddr, iph->daddr);

    skb_push(skb, iphl);
    skb_copy_to_linear_data(skb, iph_buf, iphl);
    skb_reset_network_header(skb);    
    iph = ip_hdr(skb);
    iph->tot_len = htons(ntohs(iph->tot_len) + llen);

    /* ip checksum */
    ip_send_check(iph);
    return NF_ACCEPT;
}

static unsigned int toa_nf_packet_setlabel6(int af, struct sk_buff *skb)
{
    return NF_ACCEPT;
}

static unsigned int toa_nf_packet_in(int af, struct sk_buff *skb)
{
    u32 label;
    struct iphdr *iph;
    struct tcphdr *th;

    iph = ip_hdr(skb);
    /* Only process tcp. */
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    th = tcp_hdr(skb);
    if (!th->syn) {
        return NF_ACCEPT;
    }

    label = get_toa_data(skb);
    if (label)
        printk("get toa label:%08x\n", label);

    return NF_ACCEPT;
}

#ifdef RHEL_RELEASE_CODE
/* centos / redhat */
#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6, 10)
static unsigned int toa_nfhook_packet_out(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
#elif RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 6)
    static unsigned int toa_nfhook_packet_out(const struct nf_hook_ops *ops,
            struct sk_buff *skb,
            const struct net_device *in,
            const struct net_device *out,
#ifndef __GENKSYMS__
            const struct nf_hook_state *state
#else
            int (*okfn)(struct sk_buff *)
#endif
            )
#else
static unsigned int toa_nfhook_packet_out(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
#endif
#else
    /* Ubuntu */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int toa_nfhook_packet_out(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int toa_nfhook_packet_out(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int toa_nfhook_packet_out(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
#else
static unsigned int toa_nfhook_packet_out(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
#endif
#endif
{
#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#else
    if (net_eq(state->net, &init_net))
        return NF_ACCEPT;
#endif
#endif

    return toa_nf_packet_setlabel(AF_INET, skb);
}

#ifdef RHEL_RELEASE_CODE
/* centos / redhat */
#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6, 10)
static unsigned int toa_nfhook_packet_out6(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
#elif RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 6)
    static unsigned int toa_nfhook_packet_out6(const struct nf_hook_ops *ops,
            struct sk_buff *skb,
            const struct net_device *in,
            const struct net_device *out,
#ifndef __GENKSYMS__
            const struct nf_hook_state *state
#else
            int (*okfn)(struct sk_buff *)
#endif
            )
#else
static unsigned int toa_nfhook_packet_out6(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
#endif

#else
    /* Ubuntu */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int toa_nfhook_packet_out6(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int toa_nfhook_packet_out6(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int toa_nfhook_packet_out6(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
#else
static unsigned int toa_nfhook_packet_out6(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
#endif
#endif
{
#if 0
    if (!toa_ipv6_enabled())
        return NF_ACCEPT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#else
    if (net_eq(state->net, &init_net))
        return NF_ACCEPT;
#endif
#endif

    return toa_nf_packet_setlabel6(AF_INET6, skb);
}

#ifdef RHEL_RELEASE_CODE
/* centos / redhat */
#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6, 10)
static unsigned int toa_nfhook_packet_in(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
#elif RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 6)
static unsigned int toa_nfhook_packet_in(const struct nf_hook_ops *ops,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
#ifndef __GENKSYMS__
                                      const struct nf_hook_state *state
#else
                                      int (*okfn)(struct sk_buff *)
#endif
                                     )
#else
static unsigned int toa_nfhook_packet_in(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
#endif
#else
/* Ubuntu */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int toa_nfhook_packet_in(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int toa_nfhook_packet_in(const struct nf_hook_ops *ops,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int toa_nfhook_packet_in(const struct nf_hook_ops *ops,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
#else
static unsigned int toa_nfhook_packet_in(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
#endif
#endif
{
    return toa_nf_packet_in(AF_INET, skb);
}


#ifdef RHEL_RELEASE_CODE
/* centos / redhat */
#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6, 10)
static unsigned int toa_nfhook_packet_in6(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
#elif RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 6)
static unsigned int toa_nfhook_packet_in6(const struct nf_hook_ops *ops,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
#ifndef __GENKSYMS__
                                      const struct nf_hook_state *state
#else
                                      int (*okfn)(struct sk_buff *)
#endif
                                     )
#else
static unsigned int toa_nfhook_packet_in6(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
#endif
#else
/* Ubuntu */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int toa_nfhook_packet_in6(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int toa_nfhook_packet_in6(const struct nf_hook_ops *ops,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int toa_nfhook_packet_in6(const struct nf_hook_ops *ops,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
#else
static unsigned int toa_nfhook_packet_in6(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
#endif
#endif
{
#if 0
    if (!toa_ipv6_enabled())
        return NF_ACCEPT;
#endif
    return toa_nf_packet_in(AF_INET6, skb);
}


static struct nf_hook_ops toa_filter_ops[] __read_mostly = {
    {
        .hook       = toa_nfhook_packet_out,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
        .owner      = THIS_MODULE,
#endif
        .pf         = NFPROTO_IPV4,
        .hooknum    = NF_INET_LOCAL_OUT,
        .priority   = NF_IP_PRI_TOA,
    },
    {
        .hook       = toa_nfhook_packet_out6,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
        .owner      = THIS_MODULE,
#endif
        .pf         = NFPROTO_IPV6,
        .hooknum    = NF_INET_LOCAL_OUT,
        .priority   = NF_IP_PRI_TOA,
    },
    {
        .hook       = toa_nfhook_packet_in,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
        .owner      = THIS_MODULE,
#endif
        .pf         = NFPROTO_IPV4,
        .hooknum    = NF_INET_PRE_ROUTING,
        .priority   = NF_IP_PRI_TOA,
    },
    {
        .hook       = toa_nfhook_packet_in6,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
        .owner      = THIS_MODULE,
#endif
        .pf         = NFPROTO_IPV6,
        .hooknum    = NF_INET_PRE_ROUTING,
        .priority   = NF_IP_PRI_TOA,
    },
};

static int __init toa_label_kmod_init(void)
{
    int ret;

    ret = nf_register_hooks(toa_filter_ops, ARRAY_SIZE(toa_filter_ops));
    if (ret < 0) {
        printk("Can't register fw nf hooks.\n");
        goto hook_err;
    }
    printk("toa label kmod init successed.\n");
    return 0;
hook_err:
    return ret;
}


static void __exit toa_label_kmod_exit(void)
{
    nf_unregister_hooks(toa_filter_ops, ARRAY_SIZE(toa_filter_ops));
    printk("toa label kmod release.\n");
}

module_init(toa_label_kmod_init);
module_exit(toa_label_kmod_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hoyleeson");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("toa_label_kmod module");

