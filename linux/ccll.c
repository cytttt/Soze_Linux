/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

// Linux kernel headers (available during kernel module compilation)
#include <linux/kernel.h>     // Core kernel definitions
#include <linux/types.h>      // Basic type definitions
#include <linux/skbuff.h>     // Socket buffer structures
#include <linux/vmalloc.h>    // Virtual memory allocation
#include <linux/module.h>     // Kernel module support
#include <net/tcp.h>          // TCP protocol definitions
#include <net/inet_sock.h>    // Internet socket structures
#include <linux/math64.h>     // 64-bit math operations
#include <linux/printk.h>     // Kernel logging functions
#include <linux/ktime.h>      // Kernel time functions
#include <linux/bpf.h>        // eBPF support
#include <linux/filter.h>     // Packet filtering support
#include <linux/hashtable.h>  // Hash table support
#include <linux/slab.h>       // kmalloc and kfree
#include <linux/fs.h>         // file_operations
#include <linux/uaccess.h>    // copy_from_user
#include <linux/net.h>        // sock related
#include <linux/in.h>         // IPPROTO_TCP
#include <linux/socket.h>     // socket related
#include <net/sock.h>         // sock structures
#include <linux/inet.h>       // in_aton

// static u64 min_rate __read_mostly = 1000000;     // Kbps
// static u64 max_rate __read_mostly = 100000000;   // Kbps
static u64 ln10e5_min_rate __read_mostly = 1381551;     // ln(Kbps) * 100,000
static u64 ln10e5_max_rate __read_mostly = 1842068;     // ln(Kbps) * 100,000
static u32 __maybe_unused delay_scale __read_mostly = 8000;        // us

/* C2L2 constant */
#define FPS 100000ULL
// K_p = 0.1
static u32 k_p_scale __read_mostly = 100;
static u32 k_p_fraction __read_mostly = 1;

static u32 atu_scale __read_mostly = 10000;
static u32 atu_frac_lb __read_mostly = 9200; // X
static u32 atu_frac_range __read_mostly = 500; // Y

static u32 __maybe_unused ccll_weight __read_mostly = 1;

// ATU integration parameters
static bool atu_enabled __read_mostly = true;
static u32 atu_timeout_ms __read_mostly = 100;  // ATU data timeout in milliseconds

// Module parameters for ATU configuration
module_param(atu_enabled, bool, 0644);
MODULE_PARM_DESC(atu_enabled, "Enable ATU-based congestion control");

module_param(atu_timeout_ms, uint, 0644);
MODULE_PARM_DESC(atu_timeout_ms, "ATU data timeout in milliseconds");

// just use ccll value
// static u64 ln10e5_min_rate __read_mostly = 1381551;     // ln(Kbps) * 100,000
// static u64 ln10e5_max_rate __read_mostly = 1842068;     // ln(Kbps) * 100,000

// module_param(beta, int, 0644);
// MODULE_PARM_DESC(beta, "beta for multiplicative increase");

/* C2L2 CC Parameters */

struct ccllcc {
    u32 curr_rtt;
    u32 min_rtt;
    u64 cwndx10e3;
    u32 max_atu;
    u64 rate_kbps;
    
    // Add ATU tracking fields
    u32 last_atu_numer;
    u32 last_atu_denom;
    u64 last_atu_update;
};


static inline void ccllcc_reset(struct ccllcc *ca)
{
    pr_info("c2l2: reset\n");
    // ca->last_cwnd = 1;
    ca->curr_rtt = 0;
    ca->min_rtt = 0;
    ca->cwndx10e3 = 2000;
    ca->rate_kbps = 1000; // TODO
}

static void ccllcc_init(struct sock *sk)
{
    struct ccllcc *ca = inet_csk_ca(sk);
    pr_info("c2l2: init\n");

    ccllcc_reset(ca);
    
    /* Initialize rate tracking fields */
    ca->last_atu_numer = 0;
    ca->last_atu_denom = 1;
    ca->last_atu_update = 0;
    ca->rate_kbps = 1000;  // Initial rate: 1 Mbps

    tcp_sk(sk)->snd_ssthresh = 0;
}


// static void ccllcc_cwnd_event(struct sock *sk, enum tcp_ca_event event) { }

static inline u64 exp_approx(u64 x) {
    u64 res;
    u64 tmp;
    int i;

    res = 100000;
    res += x;
    
    tmp = x * x / 2 / 100000;
    res += tmp;
    
    for (i = 3; i < 50; ++i) {
        tmp = tmp * x / i / 100000;
        res += tmp;
        if (tmp < 1000) {
            // printf("iterations: %d \n", i);
            break;
        }
    }
    // printf("%" PRIu64 "\n", res / 1000);

    return res / 100000;
}


static inline u64 log_approx(u64 x) {
    // input: value * 100000, > 0
    // output: ln(value) * 100000
    u64 res = 0;
    u64 term = 0;
    u64 y = 0;
    u64 y2 = 0;
    u64 x_plus;
    u64 x_minus;
    int i;

    if (x == 0)
        return 0;

    // let x_real = x / 100000
    // ln(x_real) = 2 * (y + y^3/3 + y^5/5 + ...) where y = (x-1)/(x+1)
    x_plus = x + 100000;
    x_minus = x - 100000;

    y = x_minus * 100000 / x_plus; // y = (x-1)/(x+1), scaled by 1e5
    y2 = y * y / 100000;

    term = y;
    res = term;

    for (i = 3; i < 50; i += 2) {
        u64 div;
        term = term * y2 / 100000;
        div = term / i;
        res += div;
        if (div < 10)
            break;
    }

    return 2 * res / 1;  // ln(x) * 100000
}

static u32 ccllcc_ssthresh(struct sock *sk) { return 0; }

static void ccllcc_state(struct sock *sk, u8 new_state) { }

static void ccllcc_cwnd_event(struct sock *sk, enum tcp_ca_event ev) {
    struct ccllcc *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);

    /* Log cwnd_event with 4-tuple and cwnd/ssthresh; rate-limited to avoid spam */
    pr_info_ratelimited("ccll: cwnd_event ev=%d s=%pI4:%u -> d=%pI4:%u cwnd=%u ssthresh=%u\n",
                        (int)ev,
                        &inet->inet_saddr, ntohs(inet->inet_sport),
                        &inet->inet_daddr, ntohs(inet->inet_dport),
                        tp->snd_cwnd, tp->snd_ssthresh);
    
    switch (ev) {
    case CA_EVENT_CWND_RESTART:
    case CA_EVENT_COMPLETE_CWR:
    case CA_EVENT_LOSS:
        ccllcc_reset(ca);
        pr_info_ratelimited("ccll: cwnd_event reset done (ev=%d)\n", (int)ev);
        break;
    default:
        break;
    }
}

// ATU state structure (must match eBPF definition)
struct atu_state {
    u32 numer;        // ATU numerator from header
    u32 denom;        // ATU denominator from header
    u64 timestamp;    // When this data was last updated
    u32 valid;        // Whether the data is valid
};

// Per-flow key for hash table (IPv4 5-tuple)
struct atu_flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    u8 protocol;
};

// Per-flow ATU entry stored in hash table
struct atu_flow_entry {
    struct hlist_node hnode;
    struct atu_flow_key key;
    struct atu_state state;
};

// Hash table for per-flow ATU data
#define ATU_FLOW_HASH_BITS 10
static DEFINE_HASHTABLE(atu_flow_table, ATU_FLOW_HASH_BITS);

// Spinlock to protect hash table
static DEFINE_SPINLOCK(atu_flow_lock);

// Helper function to compare keys
static bool atu_flow_key_equal(const struct atu_flow_key *k1, const struct atu_flow_key *k2)
{
    return (k1->saddr == k2->saddr) &&
           (k1->daddr == k2->daddr) &&
           (k1->sport == k2->sport) &&
           (k1->dport == k2->dport) &&
           (k1->protocol == k2->protocol);
}

// Helper function to compute hash for key
static u32 atu_flow_key_hash(const struct atu_flow_key *key)
{
    u32 hash = jhash_1word((u32)key->saddr, 0);
    hash = jhash_1word((u32)key->daddr, hash);
    hash = jhash_1word((u32)key->sport << 16 | key->dport, hash);
    hash = jhash_1word((u32)key->protocol, hash);
    return hash;
}

// Helper function to find entry in hash table
static struct atu_flow_entry *atu_flow_find(const struct atu_flow_key *key)
{
    struct atu_flow_entry *entry;
    u32 hash = atu_flow_key_hash(key);
    hash_for_each_possible(atu_flow_table, entry, hnode, hash) {
        if (atu_flow_key_equal(&entry->key, key))
            return entry;
    }
    return NULL;
}

// Helper function to update or insert entry in hash table
static void atu_flow_update(const struct atu_flow_key *key, const struct atu_state *state)
{
    unsigned long flags;
    struct atu_flow_entry *entry;

    spin_lock_irqsave(&atu_flow_lock, flags);
    entry = atu_flow_find(key);
    if (entry) {
        entry->state = *state;
    } else {
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            entry->key = *key;
            entry->state = *state;
            hash_add(atu_flow_table, &entry->hnode, atu_flow_key_hash(key));
        }
    }
    spin_unlock_irqrestore(&atu_flow_lock, flags);
}

// Extract 5-tuple key from sock (IPv4 only)
static bool get_atu_flow_key(struct sock *sk, struct atu_flow_key *key)
{
    struct inet_sock *inet = inet_sk(sk);

    if (!sk || !inet)
        return false;

    if (sk->sk_family != AF_INET)
        return false;

    key->saddr = inet->inet_saddr;
    key->daddr = inet->inet_daddr;
    key->sport = inet->inet_sport;  // network byte order
    key->dport = inet->inet_dport;  // network byte order
    key->protocol = IPPROTO_TCP;

    return true;
}

/*
 * Helper function to try accessing eBPF SK_STORAGE map or per-flow hash table
 * 1. eBPF simulation via sk_user_data (if valid).
 * 2. Per-flow hash table maintained by the module.
 */
static struct atu_state *try_get_atu_from_bpf(struct sock *sk)
{
    struct atu_state *atu_info = NULL;
    struct atu_flow_key key;
    struct atu_flow_entry *entry;
    unsigned long flags;

    // 1. Try direct SK_STORAGE access simulation
    if (sk->sk_user_data) {
        atu_info = (struct atu_state *)sk->sk_user_data;
        if (atu_info->valid)
            return atu_info;
    }

    // 2. Lookup per-flow hash table
    if (!get_atu_flow_key(sk, &key))
        return NULL;

    spin_lock_irqsave(&atu_flow_lock, flags);
    entry = atu_flow_find(&key);
    if (entry && entry->state.valid) {
        atu_info = &entry->state;
        spin_unlock_irqrestore(&atu_flow_lock, flags);
        return atu_info;
    }
    spin_unlock_irqrestore(&atu_flow_lock, flags);

    return NULL;
}

// Function to retrieve ATU from SK_STORAGE or per-flow hash table
static int lookup_atu_from_header(struct sock *sk, u32 *atu_value)
{
    pr_infol("ccll: lookup atu from header enter\n");
    struct atu_state *atu_info;
    u32 scaled_atu;
    u64 current_time;
    u64 timeout_ns = 0;

    atu_info = try_get_atu_from_bpf(sk);

    // If no ATU or not valid, return default constant (do not create dummy entry)
    if (!atu_info || !atu_info->valid) {
        *atu_value = 8000; // 80% default
        return 0;
    }

    // Check if ATU is enabled
    if (!atu_enabled) {
        *atu_value = 8000;
        return 0;
    }

    // Check if data is fresh (configurable timeout)
    current_time = ktime_get_ns();
    timeout_ns = (u64)atu_timeout_ms * 1000000ULL; // ms to ns
    if (atu_info->timestamp &&
        (current_time - atu_info->timestamp) > timeout_ns) {
        *atu_value = 8000;
        return 0;
    }

    // Validate denominator
    if (atu_info->denom == 0) {
        *atu_value = 8000;
        return 0;
    }

    scaled_atu = (u32)div64_u64((u64)atu_info->numer * atu_scale, atu_info->denom);
    if (scaled_atu < (atu_scale / 10)) {
        scaled_atu = atu_scale / 10;
    } else if (scaled_atu > atu_scale) {
        scaled_atu = atu_scale;
    }
    *atu_value = scaled_atu;
    return 0;
}

static void ccllcc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct ccllcc *ca = inet_csk_ca(sk);
    u32 rtt;
    u32 atu;
    u64 update;
    u32 cwnd;
    u64 per_pkt_update;

    if (!tcp_is_cwnd_limited(sk)) {
        pr_info("ccll: cong_avoid skip: not cwnd-limited "
                "(cwnd=%u, inflight=%u, acked=%u)\n",
                tp->snd_cwnd, tcp_packets_in_flight(tp), acked);
        return;
    }

    pr_info("ccll: cong_avoid enter (cwnd=%u, ssthresh=%u, inflight=%u, acked=%u)\n",
            tp->snd_cwnd, tp->snd_ssthresh, tcp_packets_in_flight(tp), acked);

    // Get current RTT
    rtt = ca->curr_rtt;
    if (rtt == 0)
        rtt = 1;

    // Always get latest ATU; do not fallback to cached max_atu
    lookup_atu_from_header(sk, &atu);
    ca->max_atu = atu;

    // C2L2 Algorithm: Calculate update based on ATU
    if (atu < atu_frac_lb) {
        update = exp_approx((ln10e5_max_rate - log_approx(ca->rate_kbps * FPS)) * k_p_fraction / k_p_scale);
    }
    else if (atu >= atu_frac_lb && atu <= atu_frac_lb + atu_frac_range) {
        update = exp_approx(
            (ln10e5_max_rate
                - log_approx(ca->rate_kbps * FPS)
                + log_approx(exp_approx((ln10e5_min_rate - ln10e5_max_rate) * (atu - atu_frac_lb) / atu_frac_range) * FPS)
            ) * k_p_fraction / k_p_scale);
    }
    else if (atu > atu_frac_lb + atu_frac_range && atu <= atu_scale) {
        update = exp_approx(
            (ln10e5_min_rate
                - log_approx(ca->rate_kbps * FPS)
                + log_approx((atu_scale - atu) * FPS / (atu_scale - atu_frac_lb - atu_frac_range))
            ) * k_p_fraction / k_p_scale);
    } else {
        update = FPS;
    }

    // Calculate cwnd from current rate
    cwnd = (ca->rate_kbps * rtt) / (1500 * 8 * 1000);
    if (cwnd == 0) cwnd = 1;

    // Calculate per_packet_update
    per_pkt_update = exp_approx(log_approx(update * FPS) / cwnd);

    // Update rate
    ca->rate_kbps = (ca->rate_kbps * per_pkt_update) / FPS;

    // Set new congestion window
    tp->snd_cwnd = max_t(u32, (ca->rate_kbps * rtt) / (1500 * 8 * 1000), 2U);
    pr_info("ccll: cong avoid leave\n");
}

static void ccllcc_acked(struct sock *sk, const struct ack_sample *sample) {
    struct ccllcc *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    u32 rtt;

    /* Log incoming ACK sample (even duplicates will be filtered below) */
    pr_info_ratelimited("ccll: pkts_acked pre rtt_us=%d inflight=%d s=%pI4:%u -> d=%pI4:%u cwnd=%u\n",
                        sample->rtt_us, sample->in_flight,
                        &inet->inet_saddr, ntohs(inet->inet_sport),
                        &inet->inet_daddr, ntohs(inet->inet_dport),
                        tp->snd_cwnd);

    /* Some calls are for duplicates without timestamps */
    if (sample->rtt_us < 0)
        return;

    /* Update RTT measurements */
    rtt = sample->rtt_us;
    if (rtt == 0)
        rtt = 1;
    
    ca->curr_rtt = rtt;
    
    /* Update min_rtt */
    if (ca->min_rtt == 0 || rtt < ca->min_rtt)
        ca->min_rtt = rtt;
    
    /* Initialize rate_kbps if not set */
    if (ca->rate_kbps == 0) {
        ca->rate_kbps = (tp->snd_cwnd * 1500 * 8 * 1000) / rtt;
    }

    pr_info_ratelimited("ccll: pkts_acked post rtt_us=%u min_rtt=%u cwnd=%u rate_kbps=%llu\n",
                        ca->curr_rtt, ca->min_rtt, tp->snd_cwnd,
                        (unsigned long long)ca->rate_kbps);
}

static struct tcp_congestion_ops ccll __read_mostly = {
    .init       = ccllcc_init,
    .ssthresh   = ccllcc_ssthresh,
    .cong_avoid = ccllcc_cong_avoid,
    .set_state  = ccllcc_state,
    .undo_cwnd  = tcp_reno_undo_cwnd,
    .cwnd_event = ccllcc_cwnd_event,
    .pkts_acked = ccllcc_acked,
    .owner      = THIS_MODULE,
    .name       = "ccll",
};

// /dev/ccll_ctl device implementation

#define ccll_CTL_DEV_NAME "ccll_ctl"
static int ccll_ctl_major = 0;

struct ccll_ctl_update {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    u32 numer;
    u32 denom;
    u64 timestamp; // in ns
    u32 valid;
};

static ssize_t ccll_ctl_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    struct ccll_ctl_update update;
    struct atu_flow_key key;
    struct atu_state state;

    if (count != sizeof(update))
        return -EINVAL;

    if (copy_from_user(&update, buf, sizeof(update)))
        return -EFAULT;

    // Fill key and state structs
    key.saddr = update.saddr;
    key.daddr = update.daddr;
    key.sport = update.sport;
    key.dport = update.dport;
    key.protocol = IPPROTO_TCP;

    state.numer = update.numer;
    state.denom = update.denom;
    state.timestamp = update.timestamp;
    state.valid = update.valid;

    pr_info_ratelimited("ccll_ctl: update %pI4:%u -> %pI4:%u numer=%u denom=%u valid=%u ts=%llu\n",
        &key.saddr, ntohs(key.sport), &key.daddr, ntohs(key.dport),
        state.numer, state.denom, state.valid,
        (unsigned long long)state.timestamp);

    atu_flow_update(&key, &state);

    return sizeof(update);
}

static const struct file_operations ccll_ctl_fops = {
    .owner = THIS_MODULE,
    .write = ccll_ctl_write,
};

// Module init and exit for /dev/ccll_ctl
static int __init ccll_ctl_init(void)
{
    ccll_ctl_major = register_chrdev(0, ccll_CTL_DEV_NAME, &ccll_ctl_fops);
    if (ccll_ctl_major < 0) {
        pr_err("ccll: failed to register ccll_ctl char device\n");
        return ccll_ctl_major;
    }
    pr_info("ccll: ccll_ctl char device registered with major %d\n", ccll_ctl_major);
    return 0;
}

static void ccll_ctl_exit(void)
{
    unregister_chrdev(ccll_ctl_major, ccll_CTL_DEV_NAME);
    pr_info("ccll: ccll_ctl char device unregistered\n");

    // Cleanup hash table entries
    {
        struct atu_flow_entry *entry;
        struct hlist_node *tmp;
        int bkt;
        unsigned long flags;

        spin_lock_irqsave(&atu_flow_lock, flags);
        hash_for_each_safe(atu_flow_table, bkt, tmp, entry, hnode) {
            hash_del(&entry->hnode);
            kfree(entry);
        }
        spin_unlock_irqrestore(&atu_flow_lock, flags);
    }
}

static int __init ccll_register(void)
{
    int ret;

    pr_info("c2l2: register\n");
    BUILD_BUG_ON(sizeof(struct ccllcc) > ICSK_CA_PRIV_SIZE);
    ret = tcp_register_congestion_control(&ccll);
    if (ret == 0) {
        pr_info("ccll: C2L2 Congestion Control registered\n");
        pr_info("ccll: ATU integration %s (timeout: %u ms)\n", 
                atu_enabled ? "enabled" : "disabled", atu_timeout_ms);
        pr_info("ccll: ATU scale: %u, bounds: %u%% - 100%%\n", 
                atu_scale, atu_scale / 10 / (atu_scale / 100));
    }

    ret = ccll_ctl_init();
    if (ret < 0) {
        tcp_unregister_congestion_control(&ccll);
        return ret;
    }

    return 0;
}


static void __exit ccll_unregister(void)
{
    pr_info("c2l2: unregister\n");
    ccll_ctl_exit();
    tcp_unregister_congestion_control(&ccll);
    pr_info("ccll: C2L2 Congestion Control unregistered\n");
}


module_init(ccll_register);
module_exit(ccll_unregister);

MODULE_AUTHOR("Weitao Wang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("C2L2 Congestion Control");
MODULE_VERSION("1.0");
