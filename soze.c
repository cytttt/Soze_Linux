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

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>
#include <linux/printk.h>
#include <linux/bpf.h>
#include <linux/btf.h>
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

static void ccllcc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct ccllcc *ca = inet_csk_ca(sk);
    
    if (!tcp_is_cwnd_limited(sk))
        return;
    
    // Get ATU information
    u32 atu_numer, atu_denom;
    u64 maxATU_kbps = 1000;  // Default fallback
    
    if (lookup_atu_from_tcpint(sk, &atu_numer, &atu_denom) == 0 && atu_denom > 0) {
        maxATU_kbps = ((u64)atu_numer * 1000) / atu_denom;
        
        // Apply utility function
        u32 delay_diff = (ca->curr_rtt > ca->min_rtt) ? 
                        (ca->curr_rtt - ca->min_rtt) : 0;
        u64 utility = exp_approx(delay_diff);
        maxATU_kbps = (maxATU_kbps * utility) / 100000;
    }
    
    // Rest of your C2L2 algorithm...
    u64 current_rate_kbps = ((u64)tp->snd_cwnd * 1500 * 8 * 1000) / ca->curr_rtt;
    u64 cwnd = (current_rate_kbps * ca->curr_rtt) / (1500 * 8 * 1000);
    
    u64 per_packet_update = (cwnd > 0) ? (maxATU_kbps * 1000) / cwnd : maxATU_kbps;
    current_rate_kbps = (current_rate_kbps * per_packet_update) / 1000;
    
    tp->snd_cwnd = max_t(u32, (u32)((current_rate_kbps * ca->curr_rtt) / (1500 * 8 * 1000)), 2U);
}

static void ccllcc_acked(struct sock *sk, const struct ack_sample *sample) {

    pr_info("c2l2: ack\n");
    struct ccllcc *ca = inet_csk_ca(sk);

    /* Some calls are for duplicates without timetamps */
    if (sample->rtt_us < 0)
        return;

    rtt = sample->rtt_us;  // / USEC_PER_MSEC
    if (rtt == 0)
        rtt = 1;

    u32 atu;
    u32 cwnd;
    /* Assume there exist max_atu paremeter*/
    atu = ca->max_atu;

    /* calculate update*/
    // TODO log approx ??
    u64 update;
    if (atu < atu_frac_lb) {
        update = exp_approx((ln10e5_max_rate - log_approx(ca->rate_kbps * FPS)) * k_p_frac / k_p_scale);
    }
    else if (atu >= atu_frac_lb && atu <= atu_frac_lb + atu_frac_range) {
        update = exp_approx(
            (ln10e5_max_rate 
                - log_approx(ca->rate_kbps * FPS)
                + log_approx(exp_approx((ln10e5_min_rate - ln10e5_max_rate) * (atu - atu_frac_lb) / atu_frac_range) * FPS)
            ) * k_p_frac / k_p_scale);
    }
    else if (atu > atu_frac_lb + atu_frac_range && atu <= atu_scale) {
        update = exp_approx(
            (ln10e5_min_rate 
                - log_approx(ca->rate_kbps * FPS)
                + log_approx((atu_scale - atu) * FPS / (atu_scale - atu_frac_lb - atu_frac_range))
            ) * k_p_frac / k_p_scale);
    }

    /* calculate cwnd */
    cwnd = ca->rate_kbps * rtt / (sample->acked * 8 * 1000 * 1000);

    /* calculare per_packet_update */
    u64 per_pkt_udpate;
    per_pkt_update = exp_approx(log_approx(update * FPS) / cwnd);

    /* update r */
    u64 rate_kbps = ca->rate_kbps;
    rate_kbps = rate_kbp * per_pkt_update;
    ca->rate_kbps = rate_kbps;
    tp->snd_cwnd = ca->rate_kbps * rtt / (sample->acked * 8 * 1000 * 1000);
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
