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

/* =====================================================================
 *  C2L2 / CCLL Congestion Control (Sender-side)
 *  - Pure Netfilter (ACK parser) + CC module
 *  - Receiver path handled by eBPF (no userspace)
 *  File layout:
 *    [1] Includes
 *    [2] Config & Module Params
 *    [3] Type Definitions
 *    [4] Globals
 *    [5] Math Helpers
 *    [6] ATU Flow Table Helpers
 *    [7] Netfilter (ACK parser)
 *    [8] CC Helpers
 *    [9] CC Callbacks (init/acked/cong_avoid/...)
 *   [10] Module Init/Exit & Metadata
 * ===================================================================== */

// ========================= [1] Includes =========================
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
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/genetlink.h>
#include <linux/netlink.h>

/* ========================= [2] Config & Module Params ========================= */

// static u64 min_rate __read_mostly = 1000000;     // Kbps
// static u64 max_rate __read_mostly = 100000000;   // Kbps
static u64 ln10e5_min_rate __read_mostly = 1381551;     // ln(Kbps) * 100,000
static u64 ln10e5_max_rate __read_mostly = 1842068;     // ln(Kbps) * 100,000
static u32 __maybe_unused delay_scale __read_mostly = 8000;        // us

/* C2L2 constant */
#define FPS 100000ULL
#define ATU_OPT_KIND 253
#define ATU_OPT_LEN  10

static bool nf_atu_enabled = true;
module_param(nf_atu_enabled, bool, 0644);
MODULE_PARM_DESC(nf_atu_enabled, "Enable Netfilter ACK parser for ATU updates");
// K_p = 0.1
static u32 k_p_scale __read_mostly = 100;
static u32 k_p_fraction __read_mostly = 20;  /* Kp = 0.10 = k_p_fraction / k_p_scale */

static u32 atu_scale __read_mostly = 10000;
static u32 atu_frac_lb __read_mostly = 8500; // X
static u32 atu_frac_range __read_mostly = 1000; // Y

static u32 __maybe_unused ccll_weight __read_mostly = 1;

// ATU integration parameters
static bool atu_enabled __read_mostly = true;
static u32 atu_timeout_ms __read_mostly = 500;  // ATU data timeout in milliseconds

// Module parameters for ATU configuration
module_param(atu_enabled, bool, 0644);
MODULE_PARM_DESC(atu_enabled, "Enable ATU-based congestion control");

module_param(atu_timeout_ms, uint, 0644);
MODULE_PARM_DESC(atu_timeout_ms, "ATU data timeout in milliseconds");

/* Per-flow weight control (multiplicative factor on T), scaled by 1e5 */
static u32 weight_scale __read_mostly = 100000;     /* 1.0 * 1e5 */
static u32 default_weight __read_mostly = 100000;   /* default 1.0x */
module_param(default_weight, uint, 0644);
MODULE_PARM_DESC(default_weight, "Default per-flow weight (1e5 = 1.0x)");

/* Enable/disable Generic Netlink control channel (for setting weights) */
static bool weight_ctl_enabled = true;
module_param(weight_ctl_enabled, bool, 0644);
MODULE_PARM_DESC(weight_ctl_enabled, "Enable Generic Netlink control for per-flow weight");

// just use ccll value
// static u64 ln10e5_min_rate __read_mostly = 1381551;     // ln(Kbps) * 100,000
// static u64 ln10e5_max_rate __read_mostly = 1842068;     // ln(Kbps) * 100,000

// module_param(beta, int, 0644);
// MODULE_PARM_DESC(beta, "beta for multiplicative increase");

/* ============================== [3] Type Definitions ============================== */

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

/* ATU state and flow-key types (shared with eBPF expectation) */
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
    u32 weight;        // per-flow multiplicative weight (1e5 scale)
};

/* Forward declaration: helper to parse TCP ACK and ATU option in Netfilter hook */
static bool parse_ack_atu_and_key(struct sk_buff *skb,
                                  u32 *numer, u32 *denom,
                                  struct atu_flow_key *key_out);
static struct nf_hook_ops ccll_nf_ops;


/* ================================= [4] Globals ================================= */

// Hash table for per-flow ATU data
#define ATU_FLOW_HASH_BITS 10
static DEFINE_HASHTABLE(atu_flow_table, ATU_FLOW_HASH_BITS);

// Spinlock to protect hash table
static DEFINE_SPINLOCK(atu_flow_lock);

/* ================================ [5] Math Helpers ================================ */

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

/* =========================== [6] ATU Flow Table Helpers =========================== */

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
        /* Preserve weight, only update ATU state */
        entry->state = *state;
    } else {
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            entry->key = *key;
            entry->state = *state;
            entry->weight = default_weight; /* initialize weight */
            hash_add(atu_flow_table, &entry->hnode, atu_flow_key_hash(key));
        }
    }
    spin_unlock_irqrestore(&atu_flow_lock, flags);
}
/* ---------------- Generic Netlink: per-flow weight control ---------------- */

#define CCLL_GENL_FAMILY_NAME  "ccll"
#define CCLL_GENL_VERSION      0x1

enum ccll_genl_cmd {
    CCLL_C_UNSPEC,
    CCLL_C_SET_WEIGHT,   /* set weight for 4-tuple flow */
    __CCLL_C_MAX,
};
#define CCLL_C_MAX (__CCLL_C_MAX - 1)

enum ccll_genl_attr {
    CCLL_A_UNSPEC,
    CCLL_A_SADDR,     /* u32: IPv4 src (network order) */
    CCLL_A_DADDR,     /* u32: IPv4 dst (network order) */
    CCLL_A_SPORT,     /* u16: src port (network order) */
    CCLL_A_DPORT,     /* u16: dst port (network order) */
    CCLL_A_WEIGHT,    /* u32: 1e5 scaled */
    __CCLL_A_MAX,
};
#define CCLL_A_MAX (__CCLL_A_MAX - 1)

static const struct nla_policy ccll_genl_policy[CCLL_A_MAX + 1] = {
    [CCLL_A_SADDR]  = { .type = NLA_U32 },
    [CCLL_A_DADDR]  = { .type = NLA_U32 },
    [CCLL_A_SPORT]  = { .type = NLA_U16 },
    [CCLL_A_DPORT]  = { .type = NLA_U16 },
    [CCLL_A_WEIGHT] = { .type = NLA_U32 },
};

static struct genl_family ccll_genl_family = {
    .hdrsize = 0,
    .name    = CCLL_GENL_FAMILY_NAME,
    .version = CCLL_GENL_VERSION,
    .maxattr = CCLL_A_MAX,
    .netnsok = true,
    .module  = THIS_MODULE,
};

static int ccll_genl_set_weight(struct sk_buff *skb, struct genl_info *info)
{
    struct atu_flow_key key;
    struct atu_flow_entry *entry;
    unsigned long flags;
    u32 w;

    if (!info || !info->attrs[CCLL_A_SADDR] || !info->attrs[CCLL_A_DADDR] ||
        !info->attrs[CCLL_A_SPORT] || !info->attrs[CCLL_A_DPORT] ||
        !info->attrs[CCLL_A_WEIGHT])
        return -EINVAL;

    key.saddr   = nla_get_u32(info->attrs[CCLL_A_SADDR]);
    key.daddr   = nla_get_u32(info->attrs[CCLL_A_DADDR]);
    key.sport   = nla_get_u16(info->attrs[CCLL_A_SPORT]);
    key.dport   = nla_get_u16(info->attrs[CCLL_A_DPORT]);
    key.protocol = IPPROTO_TCP;

    w = nla_get_u32(info->attrs[CCLL_A_WEIGHT]);
    /* clamp weight to [0.1, 10.0] in 1e5 scale for safety */
    if (w < 10000)  w = 10000;      /* 0.1x */
    if (w > 1000000) w = 1000000;   /* 10x */

    spin_lock_irqsave(&atu_flow_lock, flags);
    entry = atu_flow_find(&key);
    if (!entry) {
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            memset(&entry->state, 0, sizeof(entry->state));
            entry->key = key;
            entry->weight = w;
            hash_add(atu_flow_table, &entry->hnode, atu_flow_key_hash(&key));
        }
    } else {
        entry->weight = w;
    }
    spin_unlock_irqrestore(&atu_flow_lock, flags);

    pr_info_ratelimited("ccll_genl: set_weight %pI4:%u -> %pI4:%u w=%u\n",
                        &key.saddr, ntohs(key.sport), &key.daddr, ntohs(key.dport), w);
    return 0;
}

static const struct genl_ops ccll_genl_ops[] = {
    {
        .cmd    = CCLL_C_SET_WEIGHT,
        .flags  = 0,
        .policy = ccll_genl_policy,
        .doit   = ccll_genl_set_weight,
    },
};

static int ccll_genl_register(void)
{
    int ret;

    ret = genl_register_family(&ccll_genl_family);
    if (ret)
        return ret;

    ret = genl_register_ops(&ccll_genl_family, &ccll_genl_ops[0]);
    if (ret) {
        genl_unregister_family(&ccll_genl_family);
        return ret;
    }
    pr_info("ccll: genetlink weight control registered\n");
    return 0;
}

static void ccll_genl_unregister(void)
{
    genl_unregister_family(&ccll_genl_family);
    pr_info("ccll: genetlink weight control unregistered\n");
}
/* Get per-flow weight (1e5 scale). Falls back to default_weight if not present. */
static u32 get_flow_weight(struct sock *sk)
{
    struct atu_flow_key key;
    struct atu_flow_entry *entry;
    unsigned long flags;
    u32 w = default_weight;

    if (!get_atu_flow_key(sk, &key))
        return w;

    spin_lock_irqsave(&atu_flow_lock, flags);
    entry = atu_flow_find(&key);
    if (entry && entry->weight)
        w = entry->weight;
    spin_unlock_irqrestore(&atu_flow_lock, flags);
    return w;
}

/* ============================= [7] Netfilter (ACK parser) ============================= */

/* Parse incoming TCP ACK on LOCAL_IN and extract ATU option and flow key.
 * Returns true on success and fills numer/denom/key_out. */
static bool parse_ack_atu_and_key(struct sk_buff *skb,
                                  u32 *numer, u32 *denom,
                                  struct atu_flow_key *key_out)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *opt, *end;

    if (!skb)
        return false;

    /* Ensure we can read IPv4 header */
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return false;
    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return false;

    /* Ensure we can read full TCP header */
    if (!pskb_may_pull(skb, ip_hdrlen(skb) + sizeof(struct tcphdr)))
        return false;
    th = (struct tcphdr *)((u8 *)iph + ip_hdrlen(skb));
    if (!th)
        return false;

    /* Only care about ACKs */
    if (!th->ack)
        return false;

    /* No options? */
    if (th->doff <= sizeof(struct tcphdr) / 4)
        return false;

    /* Ensure TCP options area is linear */
    if (!pskb_may_pull(skb, ip_hdrlen(skb) + th->doff * 4))
        return false;
    iph = ip_hdr(skb);
    th = (struct tcphdr *)((u8 *)iph + ip_hdrlen(skb));

    opt = (u8 *)th + sizeof(struct tcphdr);
    end = (u8 *)th + th->doff * 4;

    while (opt + 1 < end) {
        u8 kind = opt[0];
        u8 len;

        if (kind == TCPOPT_EOL)
            break;
        if (kind == TCPOPT_NOP) {
            opt++;
            continue;
        }
        if (opt + 2 > end)
            break;
        len = opt[1];
        if (len < 2 || opt + len > end)
            break;

        if (kind == ATU_OPT_KIND && len == ATU_OPT_LEN) {
            u32 n, d;
            /* Layout: [kind=253][len=10][numer(4)][denom(4)]
             * If there are NOPs for alignment they appear as separate bytes,
             * not counted in len. */
            memcpy(&n, opt + 2, 4);
            memcpy(&d, opt + 6, 4);
            n = ntohl(n);
            d = ntohl(d);

            if (denom)
                *denom = d;
            if (numer)
                *numer = n;

            /* Build key consistent with get_atu_flow_key(): sender-flow view */
            key_out->saddr    = iph->daddr;   /* local */
            key_out->daddr    = iph->saddr;   /* peer  */
            key_out->sport    = th->dest;     /* local port */
            key_out->dport    = th->source;   /* peer  port */
            key_out->protocol = IPPROTO_TCP;
            return true;
        }
        opt += len;
    }
    return false;
}

static unsigned int ccll_nf_local_in(void *priv, struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    u32 numer = 0, denom = 0;
    struct atu_flow_key key;
    struct atu_state st;

    if (!nf_atu_enabled)
        return NF_ACCEPT;

    if (!parse_ack_atu_and_key(skb, &numer, &denom, &key))
        return NF_ACCEPT;

    if (denom == 0)
        return NF_ACCEPT;

    st.numer = numer;
    st.denom = denom;
    st.timestamp = ktime_get_ns();
    st.valid = 1;

    pr_info_ratelimited("ccll_nf: ATU ACK %pI4:%u -> %pI4:%u n=%u d=%u\n",
                        &key.saddr, ntohs(key.sport),
                        &key.daddr, ntohs(key.dport),
                        st.numer, st.denom);

    atu_flow_update(&key, &st);
    return NF_ACCEPT;
}

static int ccll_nf_register(void)
{
    int ret;
    ccll_nf_ops.hook     = ccll_nf_local_in;
    ccll_nf_ops.pf       = PF_INET;
    ccll_nf_ops.hooknum  = NF_INET_LOCAL_IN;
    ccll_nf_ops.priority = NF_IP_PRI_FIRST;
    ret = nf_register_net_hook(&init_net, &ccll_nf_ops);
    if (ret)
        pr_err("ccll: nf_register_net_hook failed %d\n", ret);
    else
        pr_info("ccll: Netfilter ACK hook registered\n");
    return ret;
}

static void ccll_nf_unregister(void)
{
    nf_unregister_net_hook(&init_net, &ccll_nf_ops);
    pr_info("ccll: Netfilter ACK hook unregistered\n");
}

/* ================================== [8] CC Helpers ================================== */

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

// Retrieve ATU from the per-flow hash table using a lock-and-copy to avoid torn reads.
// Returns:
//   0         -> *atu_value is valid
//  -EAGAIN    -> no info yet; caller should keep previous state
//  -ETIMEDOUT -> (no longer used; staleness is logged but tolerated)
//  -EINVAL    -> invalid record (e.g., denom == 0)
static int lookup_atu_from_header(struct sock *sk, u32 *atu_value)
{
    struct atu_state s;                 /* on-stack copy to avoid torn reads */
    struct atu_flow_key key;
    struct atu_flow_entry *entry;
    unsigned long flags;
    u32 scaled_atu = 0;
    u64 now_ns, timeout_ns;

    pr_info_ratelimited("ccll: lookup atu from header enter\n");

    if (!atu_enabled) {
        *atu_value = 8000;
        return 0;
    }

    /* Build sender-flow key from sock */
    if (!get_atu_flow_key(sk, &key)) {
        pr_info_ratelimited("ccll: ATU key build failed (AF not IPv4)\n");
        return -EAGAIN;
    }

    /* Lock, find, copy state, unlock */
    spin_lock_irqsave(&atu_flow_lock, flags);
    entry = atu_flow_find(&key);
    if (!entry || !entry->state.valid) {
        spin_unlock_irqrestore(&atu_flow_lock, flags);
        pr_info_ratelimited("ccll: ATU not available yet (enabled=%d)\n", atu_enabled ? 1 : 0);
        return -EAGAIN;
    }
    s = entry->state;  /* copy while holding lock */
    spin_unlock_irqrestore(&atu_flow_lock, flags);

    /* Validate */
    if (s.denom == 0) {
        pr_info_ratelimited("ccll: ATU invalid denom=0 (numer=%u)\n", s.numer);
        return -EINVAL;
    }

    /* Freshness (soft check; we still use stale with a log) */
    now_ns = ktime_get_ns();
    timeout_ns = (u64)atu_timeout_ms * 1000000ULL; // ms->ns
    if (s.timestamp && (now_ns - s.timestamp) > timeout_ns) {
        pr_info_ratelimited("ccll: ATU present but stale by %llums (timeout=%ums) — using it anyway\n",
                            (unsigned long long)((now_ns - s.timestamp)/1000000ULL),
                            atu_timeout_ms);
    }

    /* Scale: atu = numer/denom * atu_scale, clamped to [atu_scale/10, atu_scale] */
    scaled_atu = (u32)div64_u64((u64)s.numer * atu_scale, s.denom);
    if (scaled_atu < (atu_scale / 10))
        scaled_atu = atu_scale / 10;
    else if (scaled_atu > atu_scale)
        scaled_atu = atu_scale;

    *atu_value = scaled_atu;
    pr_info_ratelimited("ccll: ATU ok scaled=%u (n=%u d=%u)\n", scaled_atu, s.numer, s.denom);
    return 0;
}

/* ============================= [9] CC Callbacks ============================= */

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
    case CA_EVENT_LOSS:
        // ccllcc_reset(ca);
        pr_info_ratelimited("ccll: cwnd_event LOSS observed (ev=%d) — keeping state\n", (int)ev);
    ca->cwndx10e3 = max_t(u64, ca->cwndx10e3, (u64)tcp_sk(sk)->snd_cwnd * 1000ULL);
        break;
    case CA_EVENT_CWND_RESTART: {
        u32 target = max_t(u32, (u32)(ca->cwndx10e3 / 1000ULL), 2U);
        if (tp->snd_cwnd < target)
            tp->snd_cwnd = target;
        pr_info_ratelimited("ccll: cwnd_event restart (set floor, target=%u, cwnd=%u)\n",
                target, tp->snd_cwnd);
        break;
    }
    default:
        break;
    }
}

static void ccllcc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct ccllcc *ca = inet_csk_ca(sk);
    u32 cwnd_target = max_t(u32, (u32)(ca->cwndx10e3 / 1000ULL), 2U);
    u32 inflight = tcp_packets_in_flight(tp);

    if (!tcp_is_cwnd_limited(sk)) {
        if (tp->snd_cwnd < cwnd_target)
            tp->snd_cwnd = cwnd_target;
        pr_info_ratelimited("ccll: cong_avoid (not-limited/waiting-ok) cwnd=%u inflight=%u target=%u\n",
                            tp->snd_cwnd, inflight, cwnd_target);
        return;
    }

    if (tp->snd_cwnd < cwnd_target)
        tp->snd_cwnd = cwnd_target;

    pr_info_ratelimited("ccll: cong_avoid (limited) cwnd=%u inflight=%u target=%u\n",
                        tp->snd_cwnd, inflight, cwnd_target);
}

static void ccllcc_acked(struct sock *sk, const struct ack_sample *sample)
{
    struct ccllcc *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    u32 rtt;
    u32 atu = 0;
    int rc;
    u64 update;
    u32 cwnd;
    u64 per_pkt_update;
    u32 cwnd_target;

    /* ---------- PRE: raw sample ---------- */
    pr_info_ratelimited(
        "ccll: pkts_acked pre rtt_us=%d inflight=%d s=%pI4:%u -> d=%pI4:%u cwnd=%u rate_kbps(before)=%llu\n",
        sample->rtt_us, sample->in_flight,
        &inet->inet_saddr, ntohs(inet->inet_sport),
        &inet->inet_daddr, ntohs(inet->inet_dport),
        tp->snd_cwnd, (unsigned long long)ca->rate_kbps);

    /* Some calls are for duplicates without timestamps */
    if (sample->rtt_us < 0)
        return;

    /* ---------- RTT update ---------- */
    rtt = (sample->rtt_us > 0) ? sample->rtt_us : 1;
    if (rtt > 1000000)
        rtt = 1000000; /* clamp to 1s to keep math sane */
    ca->curr_rtt = rtt;
    if (ca->min_rtt == 0 || rtt < ca->min_rtt)
        ca->min_rtt = rtt;
    pr_info_ratelimited("ccll: rtt update rtt_us=%u min_rtt=%u\n", ca->curr_rtt, ca->min_rtt);

    /* ---------- initial rate bootstrap (once) ---------- */
    if (ca->rate_kbps == 0) {
        ca->rate_kbps = max_t(u64,
            (tcp_sk(sk)->snd_cwnd * 1500ULL * 8ULL * 1000ULL) / rtt,
            1ULL);
        pr_info_ratelimited("ccll: bootstrap rate_kbps=%llu from cwnd=%u rtt=%u\n",
                            (unsigned long long)ca->rate_kbps, tp->snd_cwnd, rtt);
    }

    /* ---------- ATU lookup (with reason) ---------- */
    pr_info_ratelimited("ccll: lookup atu from header enter\n");
    {
        bool have_atu = false;
        rc = lookup_atu_from_header(sk, &atu);
        if (rc == 0) {
            ca->max_atu = atu; /* remember fresh value */
            have_atu = true;
            pr_info_ratelimited("ccll: ATU fresh -> %u (cache now %u)\n", atu, ca->max_atu);
        } else if (ca->max_atu) {
            atu = ca->max_atu; /* use cached value */
            have_atu = true;
            pr_info_ratelimited("ccll: ATU using cache -> %u (rc=%d)\n", atu, rc);
        } else {
            /* No ATU available yet: be neutral (no adjustment this ACK) */
            have_atu = false;
            pr_info_ratelimited("ccll: ATU missing and no cache — neutral update this ACK\n");
        }

        /* Stash the decision into a local flag by reusing rc: rc==0 means have_atu */
        rc = have_atu ? 0 : -EAGAIN;
    }

    /* ---------- compute update using piecewise T(ATU) ---------- */
    if (rc == 0) {
        /* We have a valid ATU; proceed with T(ATU) logic */
        /* Precompute log(rate) in 1e5-scale */
        u64 rate_scaled = ca->rate_kbps * FPS;       /* r * 1e5 */
        u64 lg_rate = log_approx(rate_scaled);       /* ln(r) * 1e5 */

        /* r_min / r_max provided as ln(Kbps)*1e5 constants */
        const u64 lg_rmin = ln10e5_min_rate;
        const u64 lg_rmax = ln10e5_max_rate;

        u64 lg_T;    /* ln(T) * 1e5 */

        if (atu < atu_frac_lb) {
            /* Region A: T = r_max */
            lg_T = lg_rmax;
            pr_info_ratelimited("ccll: T(ATU) region A: atu=%u < X=%u  lg_T=%llu\n",
                                atu, atu_frac_lb, (unsigned long long)lg_T);
        } else if (atu <= atu_frac_lb + atu_frac_range) {
            /* Region B: geometric interpolation between r_max and r_min */
            u64 delta = (u64)(atu - atu_frac_lb);
            u64 span  = (u64)atu_frac_range ? (u64)atu_frac_range : 1ULL;
            /* ((ATU - X)/Y) in 1e5-scale */
            u64 frac1e5 = delta * 100000ULL / span;
            /* lg_T = lg_rmax + frac * (lg_rmin - lg_rmax) */
            s64 diff = (s64)lg_rmin - (s64)lg_rmax;
            s64 add  = (s64)(diff * (s64)frac1e5 / 100000LL);
            lg_T = (u64)((s64)lg_rmax + add);
            pr_info_ratelimited("ccll: T(ATU) region B: atu=%u in [%u,%u] frac=%llu/1e5 lg_T=%llu\n",
                                atu, atu_frac_lb, atu_frac_lb + atu_frac_range,
                                (unsigned long long)frac1e5,
                                (unsigned long long)lg_T);
        } else {
            /* Region C: linear tail from r_min toward zero */
            u64 num, den, frac_scaled, lg_frac; /* C90: declare at top of block */
            num = (u64)(atu_scale - atu);
            den = (u64)(atu_scale - atu_frac_lb - atu_frac_range);
            if (den == 0)
                den = 1;  /* safety */
            /* ln(num/den) = ln(num*1e5) - ln(den*1e5), but we reuse log_approx(num*1e5/den) */
            frac_scaled = (num * FPS) / den;   /* (num/den) * 1e5 */
            lg_frac     = log_approx(frac_scaled);   /* ln(frac) * 1e5 */
            lg_T = lg_rmin + lg_frac;
            pr_info_ratelimited("ccll: T(ATU) region C: atu=%u..%u num=%llu den=%llu lg_frac=%llu lg_T=%llu\n",
                                atu_frac_lb + atu_frac_range, atu,
                                (unsigned long long)num, (unsigned long long)den,
                                (unsigned long long)lg_frac, (unsigned long long)lg_T);
        }

        /* Apply per-flow weight: T' = T * weight */
        {
            u32 w = get_flow_weight(sk);
            u64 lg_w = log_approx((u64)w); /* ln(weight) * 1e5, weight is 1e5-scaled */
            lg_T += lg_w;
            pr_info_ratelimited("ccll: apply weight w=%u lg_w=%llu => lg_T'=%llu\n",
                                w, (unsigned long long)lg_w, (unsigned long long)lg_T);
        }

        /* U = (T/r)^{Kp} ; compute in log domain then exponentiate */
        {
            s64 lgU = ((s64)lg_T - (s64)lg_rate) * (s64)k_p_fraction / (s64)k_p_scale;
            update = exp_approx((u64)(lgU > 0 ? lgU : 0)); /* guard tiny negatives */
            pr_info_ratelimited("ccll: update from U=(T/r)^Kp: lgT=%llu lgR=%llu Kp=%u/%u update=%llu\n",
                                (unsigned long long)lg_T, (unsigned long long)lg_rate,
                                k_p_fraction, k_p_scale, (unsigned long long)update);
        }
    } else {
        /* No ATU available: neutral update (update = 1.0) */
        update = 100000; /* 1.0 * FPS */
        pr_info_ratelimited("ccll: neutral update (no ATU)\n");
    }

    /* ---------- cwnd/rate update debug ---------- */
    cwnd = (u32)max_t(u64, (ca->rate_kbps * (u64)rtt) / (1500ULL * 8ULL * 1000ULL), 1ULL);
    {
        u64 lg_upd = log_approx(update * FPS);
        per_pkt_update = exp_approx(lg_upd / (cwnd ? cwnd : 1));
        pr_info_ratelimited(
            "ccll: rate step cwnd=%u lg(update*FPS)=%llu per_pkt_update=%llu\n",
            cwnd, (unsigned long long)lg_upd, (unsigned long long)per_pkt_update);
    }

    /* apply rate */
    {
        u64 before = ca->rate_kbps;
        ca->rate_kbps = (ca->rate_kbps * per_pkt_update);
        pr_info_ratelimited("ccll: rate apply before=%llu after=%llu\n",
                            (unsigned long long)before,
                            (unsigned long long)ca->rate_kbps);
    }

    /* recompute target cwnd */
    cwnd_target = max_t(u32, (u32)((ca->rate_kbps * (u64)rtt) / (1500ULL * 8ULL * 1000ULL)), 2U);
    ca->cwndx10e3 = (u64)cwnd_target * 1000ULL;

    /* ---------- POST summary ---------- */
    pr_info_ratelimited(
        "ccll: pkts_acked post rtt_us=%u min_rtt=%u atu=%u rate_kbps=%llu cwnd_target=%u inflight=%u\n",
        ca->curr_rtt, ca->min_rtt, atu,
        (unsigned long long)ca->rate_kbps, cwnd_target,
        tcp_packets_in_flight(tp));
}

/* ====================== TCP Congestion Ops Registration ====================== */

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

/* ============================== [10] Module Init/Exit ============================== */

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

    /* Register Netfilter ACK hook if enabled */
    if (nf_atu_enabled) {
        ret = ccll_nf_register();
        if (ret < 0) {
            tcp_unregister_congestion_control(&ccll);
            return ret;
        }
    }

    /* Register Generic Netlink control for per-flow weight */
    if (weight_ctl_enabled) {
        ret = ccll_genl_register();
        if (ret < 0) {
            if (nf_atu_enabled)
                ccll_nf_unregister();
            tcp_unregister_congestion_control(&ccll);
            return ret;
        }
    }

    return 0;
}


static void __exit ccll_unregister(void)
{
    pr_info("c2l2: unregister\n");
    if (weight_ctl_enabled)
        ccll_genl_unregister();
    if (nf_atu_enabled)
        ccll_nf_unregister();
    tcp_unregister_congestion_control(&ccll);
    pr_info("ccll: C2L2 Congestion Control unregistered\n");
}

/* ============================== Module Metadata ============================== */

module_init(ccll_register);
module_exit(ccll_unregister);

MODULE_AUTHOR("Weitao Wang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("C2L2 Congestion Control");
MODULE_VERSION("1.0");
