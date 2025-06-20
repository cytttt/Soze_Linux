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
// static u64 min_rate __read_mostly = 1000000;     // Kbps
// static u64 max_rate __read_mostly = 100000000;   // Kbps
static u64 ln10e5_min_rate __read_mostly = 1381551;     // ln(Kbps) * 100,000
static u64 ln10e5_max_rate __read_mostly = 1842068;     // ln(Kbps) * 100,000
static u32 delay_scale __read_mostly = 8000;        // us

// module_param(beta, int, 0644);
// MODULE_PARM_DESC(beta, "beta for multiplicative increase");

/* Soze CC Parameters */
struct sozecc {
    u32 last_cwnd;      /* the last snd_cwnd */
    u32 curr_rtt;       /* the current rtt */
    u32 min_rtt;        /* the minimal rtt */
    u32 cwndx10e3;      /* the congestion window times 1000 */
};

static inline void sozecc_reset(struct sozecc *ca)
{
    pr_info("soze: reset\n");
    ca->last_cwnd = 1;
    ca->curr_rtt = 0;
    ca->min_rtt = 0;
    ca->cwndx10e3 = 2000;
}

static void sozecc_init(struct sock *sk)
{
    pr_info("soze: init\n");
    struct sozecc *ca = inet_csk_ca(sk);

    sozecc_reset(ca);

    tcp_sk(sk)->snd_ssthresh = 0;
}

static void sozecc_cwnd_event(struct sock *sk, enum tcp_ca_event event) { }

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

static void soze_debug_print(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct sozecc *ca = inet_csk_ca(sk);

    u32 flight = tp->snd_nxt - tp->snd_una;
    u32 obs_delay = ca->curr_rtt > ca->min_rtt ? ca->curr_rtt - ca->min_rtt : 0;

    pr_info("soze: cwnd=%u ssthresh=%u flight=%u\n",
            tp->snd_cwnd, tp->snd_ssthresh, flight);

    pr_info("soze: rtt=%u min_rtt=%u delay=%u rcv_rtt=%u rcv_wnd=%u\n",
            ca->curr_rtt, ca->min_rtt, obs_delay,
            tp->rcv_rtt_est.rtt_us, tp->rcv_wnd);

    pr_info("soze: delivered=%u ca->cwndx10e3=%u\n",
            tp->delivered, ca->cwndx10e3);
}

static void sozecc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    pr_info("soze: cong avoid\n");
    struct tcp_sock *tp = tcp_sk(sk);
    struct sozecc *ca = inet_csk_ca(sk);

    // debug
    soze_debug_print(sk);

    u32 cwnd;
    u64 obs_rate_kbps;
    u32 obs_delay_us;
    u64 r_link_kbps;

    if (!tcp_is_cwnd_limited(sk))
        return;
    
    if (ca->curr_rtt == 0 || ca->min_rtt == 0) {
        pr_warn("soze: skip cong_avoid due to invalid RTT (curr=%u, min=%u)\n",
            ca->curr_rtt, ca->min_rtt);
        return;
    }

    cwnd = tp->snd_cwnd;
    ca->last_cwnd = cwnd;
    
    obs_rate_kbps = cwnd * 1500 * 8 * 1000 * 1000 / ca->curr_rtt;
    obs_delay_us = ca->curr_rtt - ca->min_rtt;
    r_link_kbps = exp_approx(ln10e5_max_rate - obs_delay_us * (ln10e5_max_rate - ln10e5_min_rate) / delay_scale);
    
    if (obs_rate_kbps == 0) {
        pr_warn("soze: skip update due to obs_rate_kbps=0\n");
        return;
    }
    ca->cwndx10e3 = ca->cwndx10e3 * r_link_kbps / obs_rate_kbps;

    tp->snd_cwnd = ca->cwndx10e3 / 1000;

    pr_info("soze: obs_rate=%llu, r_link=%llu, cwndx10e3=%u\n",
        obs_rate_kbps, r_link_kbps, ca->cwndx10e3);

}

static u32 sozecc_ssthresh(struct sock *sk) { return 0; }

static void sozecc_state(struct sock *sk, u8 new_state) { }

static void sozecc_acked(struct sock *sk, const struct ack_sample *sample)
{
    pr_info("soze: ack\n");
    struct sozecc *ca = inet_csk_ca(sk);
    u32 rtt;

    /* Some calls are for duplicates without timetamps */
    if (sample->rtt_us < 0)
        return;

    rtt = sample->rtt_us;  // / USEC_PER_MSEC
    if (rtt == 0)
        rtt = 1;

    ca->curr_rtt = rtt;

    /* first time call or link delay decreases */
    if (ca->min_rtt == 0 || ca->min_rtt > rtt)
        ca->min_rtt = rtt;
}

static struct tcp_congestion_ops soze __read_mostly = {
    .init       = sozecc_init,
    .ssthresh   = sozecc_ssthresh,
    .cong_avoid = sozecc_cong_avoid,
    .set_state  = sozecc_state,
    .undo_cwnd  = tcp_reno_undo_cwnd,
    .cwnd_event = sozecc_cwnd_event,
    .pkts_acked = sozecc_acked,
    .owner      = THIS_MODULE,
    .name       = "soze",
};

static int __init soze_register(void)
{
    pr_info("soze: register\n");
    BUILD_BUG_ON(sizeof(struct sozecc) > ICSK_CA_PRIV_SIZE);
    return tcp_register_congestion_control(&soze);
}

static void __exit soze_unregister(void)
{
    pr_info("soze: unregister\n");
    tcp_unregister_congestion_control(&soze);
}

module_init(soze_register);
module_exit(soze_unregister);

MODULE_AUTHOR("Weitao Wang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Soze Congestion Control");
MODULE_VERSION("1.0");
