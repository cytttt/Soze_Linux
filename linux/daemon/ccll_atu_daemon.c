// =====================================================================
// ATU userspace daemon (libbpf) to mirror ACK ATU map -> kernel module
// Build: gcc -O2 -g daemon/ccll_atu_daemon.c -o ccll_atu_daemon -lbpf
// Run:   ./ccll_atu_daemon --map /sys/fs/bpf/tc/ack_atu_by_flow --dev /dev/ccll_ctl
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
#include <bpf/bpf.h>

struct flow4_key_user {
    uint32_t saddr; // network order
    uint32_t daddr; // network order
    uint16_t sport; // network order
    uint16_t dport; // network order
    uint8_t  proto; // 6 = TCP
};

struct atu_value {
    uint32_t numer; // host order
    uint32_t denom; // host order
};

// Kernel-compatible structure for /dev/ccll_ctl communication
struct ccll_ctl_update {
    uint32_t saddr;    // network order (matches __be32)
    uint32_t daddr;    // network order (matches __be32)
    uint16_t sport;    // network order (matches __be16)
    uint16_t dport;    // network order (matches __be16)
    uint32_t numer;    // host order
    uint32_t denom;    // host order
    uint64_t timestamp; // in ns
    uint32_t valid;    // validity flag
};

static volatile int g_stop = 0;
static void on_sig(int sig) { (void)sig; g_stop = 1; }

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --map <pinned_map_path> [--dev /dev/ccll_ctl] [--interval-ms 50]\n",
        argv0);
}

static int get_map_info(int fd, __u32 *key_sz, __u32 *val_sz) {
    struct bpf_map_info info;
    __u32 len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(fd, &info, &len) < 0) {
        return -1;
    }
    if (key_sz) *key_sz = info.key_size;
    if (val_sz) *val_sz = info.value_size;
    return 0;
}

int main(int argc, char **argv) {
    const char *map_path = "/sys/fs/bpf/tc/ack_atu_by_flow";
    const char *dev_path = "/dev/ccll_ctl";
    int interval_ms = 50;

    static struct option opts[] = {
        {"map", required_argument,  NULL, 'm'},
        {"dev", optional_argument,  NULL, 'd'},
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

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s) failed: %s\n", map_path, strerror(errno));
        return 1;
    }

    __u32 map_key_sz = 0, map_val_sz = 0;
    if (get_map_info(map_fd, &map_key_sz, &map_val_sz) < 0) {
        fprintf(stderr, "bpf_obj_get_info_by_fd failed: %s\n", strerror(errno));
        return 1;
    }
    if (map_key_sz != sizeof(struct flow4_key_user)) {
        fprintf(stderr, "[warn] map key_size=%u differs from userspace struct=%zu (tail padding in kernel is normal). Will iterate with %u bytes and parse first %zu bytes.\n",
                map_key_sz, sizeof(struct flow4_key_user), map_key_sz, sizeof(struct flow4_key_user));
    }

    void *cur_key_buf = calloc(1, map_key_sz ? map_key_sz : sizeof(struct flow4_key_user));
    void *next_key_buf = calloc(1, map_key_sz ? map_key_sz : sizeof(struct flow4_key_user));
    if (!cur_key_buf || !next_key_buf) {
        fprintf(stderr, "calloc key buffers failed\n");
        return 1;
    }

    int dev_fd = open(dev_path, O_WRONLY | O_CLOEXEC);
    if (dev_fd < 0) {
        fprintf(stderr, "open(%s) failed: %s — will print to stdout instead.\n",
                dev_path, strerror(errno));
    }

    struct atu_value value;
    int have_key = 0;

    while (!g_stop) {
        int err;
        if (!have_key) {
            err = bpf_map_get_next_key(map_fd, NULL, next_key_buf);
        } else {
            err = bpf_map_get_next_key(map_fd, cur_key_buf, next_key_buf);
        }

        if (err) {
            if (errno != ENOENT) {
                fprintf(stderr, "bpf_map_get_next_key: %s\n", strerror(errno));
            }
            have_key = 0;
            usleep(1000 * interval_ms);
            continue;
        }

        memset(&value, 0, sizeof(value));
        if (0 == bpf_map_lookup_elem(map_fd, next_key_buf, &value)) {
            struct flow4_key_user fk;
            memset(&fk, 0, sizeof(fk));
            memcpy(&fk, next_key_buf, sizeof(fk)); // 只取前面這些欄位

            if (dev_fd >= 0) {
                // Create kernel-compatible structure
                struct ccll_ctl_update kernel_msg = {
                    .saddr = fk.saddr,
                    .daddr = fk.daddr,
                    .sport = fk.sport,
                    .dport = fk.dport,
                    .numer = value.numer,
                    .denom = value.denom,
                    .timestamp = 0, // Will be set by kernel if needed
                    .valid = 1      // Mark as valid
                };
                ssize_t w = write(dev_fd, &kernel_msg, sizeof(kernel_msg));
                if (w < 0) {
                    fprintf(stderr, "write(%s) failed: %s\n", dev_path, strerror(errno));
                }
            } else {
                printf("%u,%u,%u,%u,%u,%u,%u\n",
                       fk.saddr, fk.daddr,
                       fk.sport, fk.dport,
                       fk.proto, value.numer, value.denom);
                fflush(stdout);
            }
        }

        memcpy(cur_key_buf, next_key_buf, map_key_sz);
        have_key = 1;
    }

    if (dev_fd >= 0) close(dev_fd);
    close(map_fd);

    free(cur_key_buf);
    free(next_key_buf);

    return 0;
}