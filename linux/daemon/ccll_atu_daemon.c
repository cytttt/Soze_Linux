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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <inttypes.h>

// Structure representing the key format expected from the BPF map for IPv4 flows.
// Contains source/destination addresses and ports, and protocol number.
struct flow4_key_user {
    uint32_t saddr; // network order
    uint32_t daddr; // network order
    uint16_t sport; // network order
    uint16_t dport; // network order
    uint8_t  proto; // 6 = TCP
};

// Structure representing the value stored in the ATU map.
// Contains numerator and denominator values in host byte order.
struct atu_value {
    uint32_t numer; // host order
    uint32_t denom; // host order
};

// Kernel-compatible structure for /dev/ccll_ctl communication.
// This structure mirrors the flow key and value data to the kernel device.
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

// --- Simple per-flow cache to avoid spamming kernel with identical updates ---
#define MAX_CACHE 4096
#define RESEND_NS (500ULL * 1000 * 1000)  // 500ms min interval for identical (key,value)

struct cache_entry {
    struct flow4_key_user key;   // key in the direction we SEND (after flip if enabled)
    struct atu_value       val;  // numer/denom
    uint64_t               last_sent_ns;
    int                    in_use;
};

static struct cache_entry g_cache[MAX_CACHE];

static int key_eq(const struct flow4_key_user *a, const struct flow4_key_user *b) {
    return a->saddr == b->saddr && a->daddr == b->daddr &&
           a->sport == b->sport && a->dport == b->dport && a->proto == b->proto;
}

static int val_eq(const struct atu_value *a, const struct atu_value *b) {
    return a->numer == b->numer && a->denom == b->denom;
}

// Return index in cache if found, else -1
static int cache_find(const struct flow4_key_user *k) {
    for (int i = 0; i < MAX_CACHE; i++) {
        if (g_cache[i].in_use && key_eq(&g_cache[i].key, k))
            return i;
    }
    return -1;
}

// Return index to insert/update (either existing, or first free, or 0 as fallback)
static int cache_place(const struct flow4_key_user *k) {
    int free_idx = -1;
    for (int i = 0; i < MAX_CACHE; i++) {
        if (g_cache[i].in_use) {
            if (key_eq(&g_cache[i].key, k))
                return i;
        } else if (free_idx < 0) {
            free_idx = i;
        }
    }
    return free_idx >= 0 ? free_idx : 0;
}

static const char* ip4_ntop(uint32_t be_addr, char buf[INET_ADDRSTRLEN]) {
    // be_addr is in network byte order; inet_ntop expects that
    return inet_ntop(AF_INET, &be_addr, buf, INET_ADDRSTRLEN) ? buf : "<invalid>";
}

static volatile int g_stop = 0;
static int g_flip_direction = 1; // default: flip server->client (map) to client->server (kernel)
// Signal handler to catch termination signals (SIGINT, SIGTERM) and set stop flag.
static void on_sig(int sig) { (void)sig; g_stop = 1; }

// Prints usage information for the daemon.
static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s --map <pinned_map_path> [--dev /dev/ccll_ctl] [--interval-ms 50] [--no-flip]\n"
            "  --map          Path to pinned BPF map (default: /sys/fs/bpf/tc/ack_atu_by_flow)\n"
            "  --dev          Path to char device (default: /dev/ccll_ctl)\n"
            "  --interval-ms  Poll interval in milliseconds (default: 50)\n"
            "  --no-flip      Do NOT flip direction (by default the daemon flips\n"
            "                 10.0.0.1:5000->10.0.0.2:ephem to 10.0.0.2:ephem->10.0.0.1:5000)\n",
            argv0);
}

// Helper function to fetch BPF map key and value sizes given a map file descriptor.
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
    // Default paths and interval
    const char *map_path = "/sys/fs/bpf/tc/ack_atu_by_flow";
    const char *dev_path = "/dev/ccll_ctl";
    int interval_ms = 50;

    // Command line options definition
    static struct option opts[] = {
        {"map", required_argument,  NULL, 'm'},
        {"dev", required_argument,  NULL, 'd'},
        {"interval-ms", required_argument, NULL, 'i'},
        {"no-flip", no_argument,    NULL, 'F'},
        {0, 0, 0, 0},
    };

    // Parse command line arguments
    int c;
    while ((c = getopt_long(argc, argv, "m:d:i:F", opts, NULL)) != -1) {
        switch (c) {
        case 'm': map_path = optarg; break;
        case 'd':
            if (optarg && optarg[0])
                dev_path = optarg;
            break;
        case 'i': interval_ms = atoi(optarg); break;
        case 'F': g_flip_direction = 0; break;
        default: usage(argv[0]); return 1;
        }
    }

    // Ensure dev_path is set to default if empty
    if (!dev_path || !dev_path[0]) {
        dev_path = "/dev/ccll_ctl";
    }

    // Setup signal handlers to catch termination signals
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    // Enable strict libbpf mode for better error checking
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // Open the pinned BPF map at the specified path
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s) failed: %s\n", map_path, strerror(errno));
        return 1;
    }

    // Retrieve key and value sizes of the BPF map
    __u32 map_key_sz = 0, map_val_sz = 0;
    if (get_map_info(map_fd, &map_key_sz, &map_val_sz) < 0) {
        fprintf(stderr, "bpf_obj_get_info_by_fd failed: %s\n", strerror(errno));
        return 1;
    }
    // Warn if key size differs from expected userspace struct size (due to kernel padding)
    if (map_key_sz != sizeof(struct flow4_key_user)) {
        fprintf(stderr, "[warn] map key_size=%u differs from userspace struct=%zu (tail padding in kernel is normal). Will iterate with %u bytes and parse first %zu bytes.\n",
                map_key_sz, sizeof(struct flow4_key_user), map_key_sz, sizeof(struct flow4_key_user));
    }

    // Allocate buffers for current and next keys used in map iteration
    void *cur_key_buf = calloc(1, map_key_sz ? map_key_sz : sizeof(struct flow4_key_user));
    void *next_key_buf = calloc(1, map_key_sz ? map_key_sz : sizeof(struct flow4_key_user));
    if (!cur_key_buf || !next_key_buf) {
        fprintf(stderr, "calloc key buffers failed\n");
        return 1;
    }

    // Open the kernel device to write updates; fallback to stdout if fails
    int dev_fd = open(dev_path, O_WRONLY | O_CLOEXEC);
    if (dev_fd < 0) {
        fprintf(stderr, "open(%s) failed: %s — will print to stdout instead.\n",
                dev_path, strerror(errno));
    }

    struct atu_value value;
    int have_key = 0;

    fprintf(stderr, "[daemon] map=%s dev=%s interval=%dms flip=%s\n",
            map_path, dev_path, interval_ms, g_flip_direction ? "on" : "off");

    // Main loop: iterate over BPF map entries and mirror updates to kernel device or stdout
    while (!g_stop) {
        int err;
        // Get next key from map, starting from NULL or current key
        if (!have_key) {
            err = bpf_map_get_next_key(map_fd, NULL, next_key_buf);
        } else {
            err = bpf_map_get_next_key(map_fd, cur_key_buf, next_key_buf);
        }

        // Handle end of map iteration or errors
        if (err) {
            if (errno != ENOENT) {
                fprintf(stderr, "bpf_map_get_next_key: %s\n", strerror(errno));
            }
            // Reset iteration and sleep before retry
            have_key = 0;
            usleep(1000 * interval_ms);
            continue;
        }

        // Lookup the value for the next key
        memset(&value, 0, sizeof(value));
        if (0 == bpf_map_lookup_elem(map_fd, next_key_buf, &value)) {
            struct flow4_key_user fk;
            memset(&fk, 0, sizeof(fk));
            // Copy only the expected key size portion to struct
            memcpy(&fk, next_key_buf, sizeof(fk)); 

            // Only care TCP (proto==6)
            if (fk.proto == 6) {
                // Prepare key for kernel: flip direction by default
                struct flow4_key_user k = fk;
                if (g_flip_direction) {
                    uint32_t tsaddr = k.saddr;  k.saddr = k.daddr;  k.daddr = tsaddr;
                    uint16_t tsport = k.sport;  k.sport = k.dport;  k.dport = tsport;
                }

                // Timestamp in ns (monotonic)
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                uint64_t ts_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;

                // Debounce: send only if (a) value changed from last sent for this key, or
                //           (b) last send older than RESEND_NS.
                int idx = cache_find(&k);
                int should_send = 0;
                if (idx < 0) {
                    // First time seeing this key: send once to seed kernel
                    should_send = 1;
                    idx = cache_place(&k);
                } else {
                    // Only send when numer/denom actually change
                    if (!val_eq(&g_cache[idx].val, &value))
                        should_send = 1;
                }

                if (should_send) {
                    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN], cbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
                    fprintf(stderr,
                            "[daemon] map  %s:%u -> %s:%u (proto=%u)  ATU=%u/%u\n",
                            ip4_ntop(fk.saddr, a), ntohs(fk.sport),
                            ip4_ntop(fk.daddr, b), ntohs(fk.dport),
                            fk.proto, value.numer, value.denom);
                    fprintf(stderr,
                            "[daemon] send %s:%u -> %s:%u ts=%" PRIu64 "\n",
                            ip4_ntop(k.saddr, cbuf), ntohs(k.sport),
                            ip4_ntop(k.daddr, dbuf), ntohs(k.dport),
                            ts_ns);

                    if (dev_fd >= 0) {
                        struct ccll_ctl_update kernel_msg = {
                            .saddr = k.saddr,
                            .daddr = k.daddr,
                            .sport = k.sport,
                            .dport = k.dport,
                            .numer = value.numer,
                            .denom = value.denom,
                            .timestamp = ts_ns,
                            .valid = 1
                        };
                        ssize_t w = write(dev_fd, &kernel_msg, sizeof(kernel_msg));
                        if (w < 0) {
                            fprintf(stderr, "write(%s) failed: %s\n", dev_path, strerror(errno));
                        } else if (w != sizeof(kernel_msg)) {
                            fprintf(stderr, "[daemon] short write: ret=%zd (expected %zu)\n", w, sizeof(kernel_msg));
                        } else {
                            fprintf(stderr, "[daemon] wrote to /dev/ccll_ctl OK\n");
                        }
                    } else {
                        // stdout fallback in CSV (network-order integers)
                        printf("%u,%u,%u,%u,%u,%u,%u\n",
                               k.saddr, k.daddr, k.sport, k.dport, fk.proto, value.numer, value.denom);
                        fflush(stdout);
                    }

                    // Update cache slot
                    g_cache[idx].key = k;
                    g_cache[idx].val = value;
                    g_cache[idx].in_use = 1;
                }
            }
        }

        // Update current key buffer to next key for iteration
        memcpy(cur_key_buf, next_key_buf, map_key_sz);
        have_key = 1;
    }

    // Cleanup: close device and map file descriptors and free allocated buffers
    if (dev_fd >= 0) close(dev_fd);
    close(map_fd);

    free(cur_key_buf);
    free(next_key_buf);

    fprintf(stderr, "[daemon] exiting\n");
    return 0;
}