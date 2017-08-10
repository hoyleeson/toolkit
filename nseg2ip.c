#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <netinet/in.h>

static inline char *ip_ntoa(__be32 ip)
{
    static char b[18];
    char *p;

    p = (char *)&ip;
#define UC(b)   (((int)b)&0xff)
    (void)snprintf(b, sizeof(b),
                   "%u.%u.%u.%u", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
    return (b);
}

static inline __be32 inet_make_mask(int logmask)
{
    if (logmask)
        return htonl(~((1U << (32 - logmask)) - 1));
    return 0;
}

static inline int inet_mask_len(__be32 mask)
{
    __u32 hmask = ntohl(mask);
    if (!hmask)
        return 0;
    return 32 - (ffs(hmask) - 1);
}

static void help(void)
{
    printf("./nseg2ip x.x.x.x/x\n");
}

static void print_allip(__be32 ip, int mask)
{
    uint32_t start;
    uint32_t end;
    uint32_t addr;

    start = ntohl(ip & mask);
    end = ntohl((ip & mask) | (~mask));

    printf("addr start:%s, ", ip_ntoa(htonl(start)));
    printf("end:%s\n", ip_ntoa(htonl(end)));

    addr = start;
    while (addr <= end) {
        printf("%s\n", ip_ntoa(htonl(addr)));
        addr++;
    }
}

int main(int argc, char **argv)
{
    __be32 ip;
    int masklen;
    struct in_addr in;
    char *ptr, *p;

    if (argc < 2) {
        help();
        exit(1);
    }

    ptr = argv[1];
    p = strchr(ptr, '/');
    if (!p) {
        help();
        exit(1);
    }

    *p++ = '\0';

    inet_aton(ptr, &in);

    ip = in.s_addr;
    masklen = atoi(p);

    printf("ip:%08x, masklen:%d\n", ip, masklen);

    print_allip(ip, inet_make_mask(masklen));
    return 0;
}

