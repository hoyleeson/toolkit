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
 *  iptables -t mangle -A OUTPUT -j MARK --set-mark 0xa2345678
 * */

#define NF_IP_PRI_TOMARK      (NF_IP_PRI_MANGLE + 5)

#define TCPOPT_MARK    (85)
#define TCPOLEN_MARK   (12)

#define TOMARK_MARK_MAGIC      (0xa)
#define TOMARK_MARK_MASK       (0x0fffffff)

static inline unsigned int optlen(const u_int8_t *opt, unsigned int offset)
{
    /* Beware zero-length options: make finite progress */
    if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0)
        return 1;
    else
        return opt[offset+1];
}

static int tomark_packet_set_mark(int af, struct sk_buff *skb, u64 mark)
{
    u8 *opt;
    __be32 *pos;
    unsigned int i;
    __be16 newlen;
    __be16 oldval;
    int len, tcp_hdrlen;
    struct tcphdr *tcph;
    unsigned int tcphoff;
    struct iphdr *iph = ip_hdr(skb);

    if (!skb_make_writable(skb, skb->len))
        return -1;

    tcphoff = iph->ihl * 4;
    len = skb->len - tcphoff;
    if (len < (int)sizeof(struct tcphdr))
        return -1;

    tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
    tcp_hdrlen = tcph->doff * 4;

    if (len < tcp_hdrlen || tcp_hdrlen < sizeof(struct tcphdr))
        return -1;

    opt = (u_int8_t *)tcph;
    for (i = sizeof(struct tcphdr); i <= tcp_hdrlen - TCPOLEN_MARK; i += optlen(opt, i)) {
        if (opt[i] == TCPOPT_MARK && opt[i+1] == TCPOLEN_MARK) {
            return 0;
        }
    }

    /* There is data after the header so the option can't be added
     * without moving it, and doing so may make the SYN packet
     * itself too large. Accept the packet unmodified instead.
     */
    if (len > tcp_hdrlen)
        return 0;

    /* tcph->doff has 4 bits, do not wrap it to 0 */
    if (tcp_hdrlen >= 15 * 4)
        return 0;

    /*
     * MSS Option not found ?! add it..
     */
    if (skb_tailroom(skb) < TCPOLEN_MARK) {
        if (pskb_expand_head(skb, 0,
                    TCPOLEN_MARK - skb_tailroom(skb),
                    GFP_ATOMIC))
            return -1;
        tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
    }

    skb_put(skb, TCPOLEN_MARK);

    opt = (u_int8_t *)tcph + sizeof(struct tcphdr);
    memmove(opt + TCPOLEN_MARK, opt, len - sizeof(struct tcphdr));

    inet_proto_csum_replace2(&tcph->check, skb,
            htons(len), htons(len + TCPOLEN_MARK), true);

    pos = (__be32 *)opt;
    *pos = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_MARK << 8) | TCPOLEN_MARK);
    inet_proto_csum_replace4(&tcph->check, skb, 0, *pos, false);

    pos++;
    *pos = htonl(mark & 0xffffffff);
    inet_proto_csum_replace4(&tcph->check, skb, 0, *pos, false);

    pos++;
    *pos = htonl((mark >> 32) & 0xffffffff);
    inet_proto_csum_replace4(&tcph->check, skb, 0, *pos, false);

    oldval = ((__be16 *)tcph)[6];
    tcph->doff += TCPOLEN_MARK/4;
    inet_proto_csum_replace2(&tcph->check, skb,
            oldval, ((__be16 *)tcph)[6], false);

    newlen = htons(ntohs(iph->tot_len) + TCPOLEN_MARK);
    csum_replace2(&iph->check, iph->tot_len, newlen);
    iph->tot_len = newlen;
    return 0;
}

/* Parse TCP options in skb, try to get client ip, port
 * @param skb [in] received skb, it should be a ack/get-ack packet.
 * @return NULL if we don't get client ip/port;
 *         value of tomark_data in ret_ptr if we get client ip/port.
 */
static u64 tomark_packet_get_mark(struct sk_buff *skb)
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
                if (TCPOPT_MARK == opcode &&
                        TCPOLEN_MARK == opsize) {
                    u64 mark;
                    u32 *pos = (u32 *)ptr;

                    mark = ((u64)ntohl(*pos) << 32) | ntohl(*(pos + 1));
                    return mark;
                }
                ptr += opsize - 2;
                length -= opsize;
        }
    }
    return 0;
}

static bool tomark_mark_match(u32 mark)
{
    if (!mark)
        return false;

    if ((mark >> 28) != TOMARK_MARK_MAGIC)
        return false;
    return true;
}

static inline bool tomark_ipv6_enabled(void)
{
    return false;
}

/* use for tests */
static u32 get_fake_id(void)
{
    return 0xbeafdead;
}

static unsigned int tomark_nf_packet_setlabel(int af, struct sk_buff *skb)
{
    int rc;
    u32 label;
    u64 mark;
    struct iphdr *iph;
    struct tcphdr *th;

    if (!tomark_mark_match(skb->mark))
        return NF_ACCEPT; 

    iph = ip_hdr(skb);
    /* Only process tcp. */
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    th = tcp_hdr(skb);
    if (!th->syn) {
        return NF_ACCEPT;
    }

    label = skb->mark & TOMARK_MARK_MASK;
    mark = get_fake_id();
    mark = (mark << 32) | label;

    rc = tomark_packet_set_mark(af, skb, mark);
    if (rc) {

    }
    return NF_ACCEPT;
}


static unsigned int tomark_nf_packet_in(int af, struct sk_buff *skb)
{
    u64 mark;
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

    mark = tomark_packet_get_mark(skb);
    if (mark) {
        u32 label, id;
        label = mark & 0xffffffff;
        id = (mark >> 32) & 0xffffffff;
        printk("get tomark label:%08x %08x\n", id, label);
    }

    return NF_ACCEPT;
}

static unsigned int tomark_nfhook_packet_out(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    return tomark_nf_packet_setlabel(AF_INET, skb);
}

static unsigned int tomark_nfhook_packet_out6(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    if (!tomark_ipv6_enabled())
        return NF_ACCEPT;

    return tomark_nf_packet_setlabel(AF_INET6, skb);
}

static unsigned int tomark_nfhook_packet_in(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    return tomark_nf_packet_in(AF_INET, skb);
}

static unsigned int tomark_nfhook_packet_in6(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    if (!tomark_ipv6_enabled())
        return NF_ACCEPT;

    return tomark_nf_packet_in(AF_INET6, skb);
}


static struct nf_hook_ops tomark_filter_ops[] __read_mostly = {
    {
        .hook       = tomark_nfhook_packet_out,
        .pf         = NFPROTO_IPV4,
        .hooknum    = NF_INET_LOCAL_OUT,
        .priority   = NF_IP_PRI_TOMARK,
    },
    {
        .hook       = tomark_nfhook_packet_out6,
        .pf         = NFPROTO_IPV6,
        .hooknum    = NF_INET_LOCAL_OUT,
        .priority   = NF_IP_PRI_TOMARK,
    },
    {
        .hook       = tomark_nfhook_packet_in,
        .pf         = NFPROTO_IPV4,
        .hooknum    = NF_INET_PRE_ROUTING,
        .priority   = NF_IP_PRI_TOMARK,
    },
    {
        .hook       = tomark_nfhook_packet_in6,
        .pf         = NFPROTO_IPV6,
        .hooknum    = NF_INET_PRE_ROUTING,
        .priority   = NF_IP_PRI_TOMARK,
    },
};

static int __init tomark_kmod_init(void)
{
    int ret;

    ret = nf_register_hooks(tomark_filter_ops, ARRAY_SIZE(tomark_filter_ops));
    if (ret < 0) {
        printk("Can't register tomark nf hooks.\n");
        goto hook_err;
    }
    printk("tomark kmod init successed.\n");
    return 0;
hook_err:
    return ret;
}


static void __exit tomark_kmod_exit(void)
{
    nf_unregister_hooks(tomark_filter_ops, ARRAY_SIZE(tomark_filter_ops));
    printk("tomark kmod release.\n");
}

module_init(tomark_kmod_init);
module_exit(tomark_kmod_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sinoy Lee<sinoylee@gmail.com>");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("tomark_kmod module");

