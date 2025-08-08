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

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <linux/math64.h>
#include <linux/printk.h>
#include <linux/ktime.h>
// static u64 min_rate __read_mostly = 1000000;     // Kbps
// static u64 max_rate __read_mostly = 100000000;   // Kbps
static u64 ln10e5_min_rate __read_mostly = 1381551;     // ln(Kbps) * 100,000
static u64 ln10e5_max_rate __read_mostly = 1842068;     // ln(Kbps) * 100,000
static u32 delay_scale __read_mostly = 8000;        // us

/* C2L2 constant */
#define FPS 100000ULL
// K_p = 0.1
static u32 k_p_scale __read_mostly = 100;
static u32 k_p_fraction __read_mostly = 1;

static u32 atu_scale __read_mostly = 10000;
static u32 atu_frac_lb __read_mostly = 9200; // X
static u32 atu_frac_range __read_mostly = 500; // Y

static u32 ccll_weight __read_mostly = 1;
// just use soze value
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
    ca->last_cwnd = 1;
    ca->curr_rtt = 0;
    ca->min_rtt = 0;
    ca->cwndx10e3 = 2000;
    ca->rate_kbps = 1; // TODO
}

static void ccllcc_init(struct sock *sk)
{
    pr_info("c2l2: init\n");
    struct ccllcc *ca = inet_csk_ca(sk);

    ccllcc_reset(ca);
    
    /* Initialize rate tracking fields */
    ca->last_atu_numer = 0;
    ca->last_atu_denom = 1;
    ca->last_atu_update = 0;
    ca->rate_kbps = 1000;  // Initial rate: 1 Mbps

    tcp_sk(sk)->snd_ssthresh = 0;
}


static void ccllcc_cwnd_event(struct sock *sk, enum tcp_ca_event event) { }

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

    if (x == 0) return 0;

    u64 res = 0;
    u64 term;
    u64 y;
    int i;

    // let x_real = x / 100000
    // ln(x_real) = 2 * (y + y^3/3 + y^5/5 + ...) where y = (x-1)/(x+1)

    u64 x_plus = x + 100000;
    u64 x_minus = x - 100000;

    y = x_minus * 100000 / x_plus; // y = (x-1)/(x+1), scaled by 1e5
    u64 y2 = y * y / 100000;

    term = y;
    res = term;

    for (i = 3; i < 50; i += 2) {
        term = term * y2 / 100000;
        u64 div = term / i;
        res += div;
        if (div < 10) break;
    }

    return 2 * res / 1;  // ln(x) * 100000
}

static u32 ccllcc_ssthresh(struct sock *sk) { return 0; }

static void ccllcc_state(struct sock *sk, u8 new_state) { }

static void ccllcc_cwnd_event(struct sock *sk, enum tcp_ca_event ev) {
    struct ccllcc *ca = inet_csk_ca(sk);
    
    switch (ev) {
    case CA_EVENT_CWND_RESTART:
    case CA_EVENT_COMPLETE_CWR:
    case CA_EVENT_LOSS:
        ccllcc_reset(ca);
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

// External reference to the BPF map (similar to TCP-INT)
extern struct bpf_map map_atu_state;

// Function to retrieve ATU from SK_STORAGE (similar to TCP-INT approach)
static int lookup_atu_from_header(struct sock *sk, u32 *atu_value)
{
    struct atu_state *atu_info;
    u32 scaled_atu;
    u64 current_time;
    
    // Get ATU state from socket storage (similar to TCP-INT)
    // In real implementation, this would use bpf_sk_storage_get
    // atu_info = bpf_sk_storage_get(&map_atu_state, sk, NULL, 0);
    
    // For now, simulate ATU data retrieval
    // In production, this would come from the eBPF SK_STORAGE map
    static struct atu_state simulated_atu = {
        .numer = 8000,
        .denom = 10000,
        .timestamp = 0,
        .valid = 1
    };
    atu_info = &simulated_atu;
    
    if (!atu_info || !atu_info->valid) {
        // No ATU data available, return default
        *atu_value = 8000; // 80% default
        return 0;
    }
    
    // Check if data is fresh (within last 100ms)
    current_time = ktime_get_ns();
    if (atu_info->timestamp && 
        (current_time - atu_info->timestamp) > 100000000ULL) {
        // Stale data, use default
        *atu_value = 8000;
        return 0;
    }
    
    // Validate denominator
    if (atu_info->denom == 0) {
        *atu_value = 8000; // Default on invalid data
        return 0;
    }
    
    // Calculate scaled ATU: (numer/denom) * atu_scale
    // Use 64-bit arithmetic to avoid overflow
    scaled_atu = (u32)div64_u64((u64)atu_info->numer * atu_scale, 
                                atu_info->denom);
    
    // Clamp to reasonable bounds (10% to 100%)
    if (scaled_atu < (atu_scale / 10)) {
        scaled_atu = atu_scale / 10; // Minimum 10%
    } else if (scaled_atu > atu_scale) {
        scaled_atu = atu_scale; // Maximum 100%
    }
    
    *atu_value = scaled_atu;
    return 0;
}

static void ccllcc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct ccllcc *ca = inet_csk_ca(sk);
    
    if (!tcp_is_cwnd_limited(sk))
        return;
    
    // Get current RTT
    u32 rtt = ca->curr_rtt;
    if (rtt == 0)
        rtt = 1;
    
    // Get ATU from max_atu_h header
    u32 atu;
    if (lookup_atu_from_header(sk, &atu) != 0) {
        atu = ca->max_atu;  // Use cached value if header not available
    }
    ca->max_atu = atu;  // Update cached value
    
    // C2L2 Algorithm: Calculate update based on ATU
    u64 update;
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
        update = FPS;  // Default update if ATU out of range
    }
    
    // Calculate cwnd from current rate
    u32 cwnd = (ca->rate_kbps * rtt) / (1500 * 8 * 1000);
    if (cwnd == 0) cwnd = 1;
    
    // Calculate per_packet_update
    u64 per_pkt_update = exp_approx(log_approx(update * FPS) / cwnd);
    
    // Update rate
    ca->rate_kbps = (ca->rate_kbps * per_pkt_update) / FPS;
    
    // Set new congestion window
    tp->snd_cwnd = max_t(u32, (ca->rate_kbps * rtt) / (1500 * 8 * 1000), 2U);
}

static void ccllcc_acked(struct sock *sk, const struct ack_sample *sample) {
    struct ccllcc *ca = inet_csk_ca(sk);

    /* Some calls are for duplicates without timestamps */
    if (sample->rtt_us < 0)
        return;

    /* Update RTT measurements */
    u32 rtt = sample->rtt_us;
    if (rtt == 0)
        rtt = 1;
    
    ca->curr_rtt = rtt;
    
    /* Update min_rtt */
    if (ca->min_rtt == 0 || rtt < ca->min_rtt)
        ca->min_rtt = rtt;
    
    /* Initialize rate_kbps if not set */
    if (ca->rate_kbps == 0) {
        struct tcp_sock *tp = tcp_sk(sk);
        ca->rate_kbps = (tp->snd_cwnd * 1500 * 8 * 1000) / rtt;
    }
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


static int __init ccll_register(void)
{
    pr_info("c2l2: register\n");
    BUILD_BUG_ON(sizeof(struct ccllcc) > ICSK_CA_PRIV_SIZE);
    return tcp_register_congestion_control(&ccll);
}


static void __exit ccll_unregister(void)
{
    pr_info("c2l2: unregister\n");
    tcp_unregister_congestion_control(&ccll);
}


module_init(ccll_register);
module_exit(ccll_unregister);

MODULE_AUTHOR("Weitao Wang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("C2L2 Congestion Control");
MODULE_VERSION("1.0");
