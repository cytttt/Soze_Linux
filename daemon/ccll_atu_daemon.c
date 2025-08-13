// -----------------------------------------------------------------------------
// Userspace attachment (example):
//  tc qdisc add dev <RX_IF> clsact
//  tc filter add dev <RX_IF>  ingress bpf da obj atu_tcp_option_skeleton.o sec tc/rx_ingress_cache_atu
//  tc filter add dev <RX_IF>  egress  bpf da obj atu_tcp_option_skeleton.o sec tc/rx_egress_add_ack_opt
//  tc qdisc add dev <TX_IF> clsact
//  tc filter add dev <TX_IF>  ingress bpf da obj atu_tcp_option_skeleton.o sec tc/tx_ingress_parse_ack_opt
//
// Verify maps:
//  bpftool map show
//  bpftool map dump id <MAP_ID>
//
// Sender kernel module bridge:
//  - Your CC module can read latest ATU via a small userspace daemon which polls
//    sk_storage using libbpf and forwards (netlink/ioctl) into a per-socket table
//    in the module. Alternatively, if your kernel exports sk_storage helpers for
//    in-kernel consumers, read directly (version & symbol dependent).
// -----------------------------------------------------------------------------
// =====================================================================
// Userspace daemon (libbpf) to forward ATU → kernel module
// File: ccll_atu_daemon.c
// Build: gcc -O2 -g -Wall ccll_atu_daemon.c -o ccll_atu_daemon -lbpf
// Run:   ./ccll_atu_daemon --map /sys/fs/bpf/ack_atu_by_flow --dev /dev/ccll_ctl
// =====================================================================

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>

struct flow4_key_user {
    uint32_t saddr; // network order
    uint32_t daddr;
    uint16_t sport; // network order
    uint16_t dport;
    uint8_t  proto; // 6 = TCP
    uint8_t  pad[3];
};

struct ccll_atu_msg {
    struct flow4_key_user k; // 5-tuple
    uint32_t numer;          // host order numerator
    uint32_t denom;          // host order denominator
};

struct atu_value {
    uint32_t numer;
    uint32_t denom;
};

static volatile int stop;

static void on_sigint(int sig) { (void)sig; stop = 1; }

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --map <pinned_map_path> [--dev /dev/ccll_ctl] [--interval-ms 50]\n",
        argv0);
}

int main(int argc, char **argv) {
    const char *map_path = "/sys/fs/bpf/ack_atu_by_flow";
    const char *dev_path = "/dev/ccll_ctl"; // your kernel module char device
    int interval_ms = 50;

    static struct option opts[] = {
        {"map", required_argument, NULL, 'm'},
        {"dev", optional_argument, NULL, 'd'},
        {"interval-ms", optional_argument, NULL, 'i'},
        {0, 0, 0, 0},
    };

    int c;
    while ((c = getopt_long(argc, argv, "m:d:i:", opts, NULL)) != -1) {
        switch (c) {
        case 'm': map_path = optarg; break;
        case 'd': dev_path = optarg; break;
        case 'i': interval_ms = atoi(optarg); break;
        default: usage(argv[0]); return 1;
        }
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s) failed: %s\n", map_path, strerror(errno));
        return 1;
    }

    int dev_fd = open(dev_path, O_WRONLY | O_CLOEXEC);
    if (dev_fd < 0) {
        fprintf(stderr, "open(%s) failed: %s — will print to stdout instead.\n",
                dev_path, strerror(errno));
    }

    void *key = NULL, *next_key = NULL;
    struct atu_value value = {0};

    while (!stop) {
        // Iterate the map once per loop
        int r = bpf_map_get_next_key(map_fd, key, &next_key);
        if (r < 0 && errno != ENOENT) {
            fprintf(stderr, "get_next_key error: %s\n", strerror(errno));
            // Small backoff
            usleep(1000 * interval_ms);
            continue;
        }
        if (r != 0) {
            // No keys; sleep and restart
            usleep(1000 * interval_ms);
            key = NULL; next_key = NULL;
            continue;
        }

        struct flow4_key_user k = {0};
        memcpy(&k, &next_key, sizeof(k) < sizeof(next_key) ? sizeof(k) : sizeof(next_key));
        // Lookup value
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            struct ccll_atu_msg msg = { .k = k, .numer = value.numer, .denom = value.denom };
            if (dev_fd >= 0) {
                ssize_t w = write(dev_fd, &msg, sizeof(msg));
                if (w < 0) fprintf(stderr, "write(/dev/ccll_ctl) failed: %s\n", strerror(errno));
            } else {
                // Fallback: print CSV to stdout
                printf("%u,%u,%u,%u,%u,%u,%u\n",
                       k.saddr, k.daddr, k.sport, k.dport, k.proto,
                       msg.numer, msg.denom);
                fflush(stdout);
            }
        }
        key = next_key; // continue iteration
    }

    if (dev_fd >= 0) close(dev_fd);
    close(map_fd);
    return 0;
}