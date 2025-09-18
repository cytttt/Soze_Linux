// gcc -O2 -Wall -o set_weight tools/set_weight.c -lnl-3 -lnl-genl-3
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CCLL_FAMILY "ccll"
#define CCLL_CMD_SET_WEIGHT 1
#define CCLL_A_SADDR  1
#define CCLL_A_DADDR  2
#define CCLL_A_SPORT  3
#define CCLL_A_DPORT  4
#define CCLL_A_WEIGHT 5

static uint32_t ip_to_u32(const char *ip)
{
    struct in_addr a;
    if (inet_aton(ip, &a) == 0) {
        fprintf(stderr, "invalid IP: %s\n", ip);
        exit(1);
    }
    return a.s_addr; // already network-order
}

int main(int argc, char **argv)
{
    const char *saddr = NULL, *daddr = NULL;
    int sport = 0, dport = 0;
    unsigned int weight = 0;

    for (int i=1; i<argc; ++i) {
        if (!strcmp(argv[i], "--saddr") && i+1<argc) saddr = argv[++i];
        else if (!strcmp(argv[i], "--daddr") && i+1<argc) daddr = argv[++i];
        else if (!strcmp(argv[i], "--sport") && i+1<argc) sport = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dport") && i+1<argc) dport = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--weight") && i+1<argc) weight = (unsigned int)strtoul(argv[++i], NULL, 10);
        else {
            fprintf(stderr, "usage: %s --saddr A.B.C.D --sport P --daddr A.B.C.D --dport P --weight N(1e5)\n", argv[0]);
            return 2;
        }
    }

    if (!saddr || !daddr || !sport || !dport || !weight) {
        fprintf(stderr, "missing args\n");
        return 2;
    }

    struct nl_sock *sk = nl_socket_alloc();
    if (!sk) { perror("nl_socket_alloc"); return 1; }
    if (genl_connect(sk)) { perror("genl_connect"); return 1; }

    int fid = genl_ctrl_resolve(sk, CCLL_FAMILY);
    if (fid < 0) { fprintf(stderr, "genl_ctrl_resolve(%s) failed: %d\n", CCLL_FAMILY, fid); return 1; }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) { perror("nlmsg_alloc"); return 1; }

    void *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fid, 0, 0, CCLL_CMD_SET_WEIGHT, 1);
    if (!hdr) { fprintf(stderr, "genlmsg_put failed\n"); nlmsg_free(msg); return 1; }

    nla_put_u32(msg, CCLL_A_SADDR,  ip_to_u32(saddr));               // u32 (network order)
    nla_put_u32(msg, CCLL_A_DADDR,  ip_to_u32(daddr));
    nla_put_u16(msg, CCLL_A_SPORT,  htons((uint16_t)sport));         // u16 (network order)
    nla_put_u16(msg, CCLL_A_DPORT,  htons((uint16_t)dport));
    nla_put_u32(msg, CCLL_A_WEIGHT, weight);                         // u32 (1e5 scale)

    int ret = nl_send_auto(sk, msg);
    if (ret < 0) { fprintf(stderr, "nl_send_auto: %d\n", ret); nlmsg_free(msg); return 1; }

    // 可選：等 ACK
    ret = nl_wait_for_ack(sk);
    if (ret < 0) { fprintf(stderr, "nl_wait_for_ack: %d\n", ret); }

    nlmsg_free(msg);
    nl_socket_free(sk);

    printf("OK: %s:%d -> %s:%d weight=%u/1e5\n", saddr, sport, daddr, dport, weight);
    return ret < 0 ? 1 : 0;
}