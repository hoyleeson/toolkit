#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

uint32_t str_to_ipaddr(const char *ip)
{
    struct in_addr in;
    if (inet_aton(ip, &in) < 0) {
        return 0;
    }
    return in.s_addr;
}

int main(int argc, char **argv)
{
    uint32_t addr;
    if (argc < 2)
        return 0;

    addr = str_to_ipaddr(argv[1]);
    printf("0x%x\n", addr);
}
