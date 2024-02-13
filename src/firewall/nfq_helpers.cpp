/*
 * Copyright © 2021, Radu-Alexandru Mantu <andru.mantu@gmail.com>
 *
 * This file is part of app-fw.
 *
 * app-fw is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * app-fw is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with app-fw. If not, see <https://www.gnu.org/licenses/>.
 */

#include <netinet/in.h>     /* IPPROTO_*     */
#include <netinet/ip.h>     /* iphdr         */
#include <netinet/tcp.h>    /* tcphdr        */
#include <netinet/udp.h>    /* udphdr        */
#include <string.h>         /* memmove       */

#include <set>              /* set           */
#include <vector>           /* vector        */

#include "netlink_helpers.h"
#include "ebpf_helpers.h"
#include "sock_cache.h"
#include "hash_cache.h"
#include "nfq_helpers.h"
#include "filter.h"
#include "csum.h"
#include "signer.h"
#include "util.h"

using namespace std;

/* elapsed time counters */
static struct timeval start_marker;

uint64_t nfqinh_extract_ctr   = 0;
uint64_t nfqinh_delayedev_ctr = 0;
uint64_t nfqinh_verdict_ctr   = 0;
uint64_t nfqinh_report_ctr    = 0;

uint64_t nfqouth_extract_ctr   = 0;
uint64_t nfqouth_delayedev_ctr = 0;
uint64_t nfqouth_verdict_ctr   = 0;
uint64_t nfqouth_report_ctr    = 0;

uint64_t nfqfwdh_extract_ctr   = 0;
uint64_t nfqfwdh_delayedev_ctr = 0;
uint64_t nfqfwdh_verdict_ctr   = 0;
uint64_t nfqfwdh_report_ctr    = 0;

/* processed packets counters */
uint64_t nfqinh_packets_ctr  = 0;
uint64_t nfqouth_packets_ctr = 0;
uint64_t nfqfwdh_packets_ctr = 0;

/* operational parameters */
static uint32_t batch_max_count = 1;    /* max num of batched packets     */
static uint64_t batch_timeout   = -1;   /* batched verdict trnsm. timeout */

static uint32_t            in_buffered_pkts = 0;
static uint32_t            in_latest_pkt_id = 0;
static uint32_t            in_prev_verdict  = NF_MAX_VERDICT;
static uint64_t            in_oldest_ts     = 0;
static struct nfq_q_handle *in_qh           = NULL;

static uint32_t            out_buffered_pkts = 0;
static uint32_t            out_latest_pkt_id = 0;
static uint32_t            out_prev_verdict  = NF_MAX_VERDICT;
static uint64_t            out_oldest_ts     = 0;
static struct nfq_q_handle *out_qh           = NULL;

__attribute__((unused)) static struct nfq_q_handle *fwd_qh = NULL;

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* maybe_transmit_verdict - transmit verdict if limits exceeded
 *  @force      : if !0, transmit verdict regardless of limits checks
 *  @chain_mask : selects affected chains
 *                  INPUT  = 1 << INPUT_CHAIN
 *                  OUTPUT = 1 << OUTPUT_CHAIN
 *
 *  @return : 0 if everything went well; !0 otherwise
 */
int32_t
maybe_transmit_verdict(uint32_t force,
                       uint32_t chain_mask)
{
    tscval_t ts;                    /* current time                       */
    uint64_t       elapsed_time;    /* time since oldest pkt was received */
    ssize_t        ans;             /* answer                             */

    /* get current time */
    rdtsc(ts.low, ts.high);

    /* check if OUTPUT batch warrants eviction                       *
     * NOTE: not applicable if no packets are buffered at the moment */
    elapsed_time = (ts.raw - out_oldest_ts) * 1'000'000 / BASE_FREQ;

    if (chain_mask & (1 << OUTPUT_CHAIN)
    &&  out_buffered_pkts != 0
    &&  (force
     ||  out_buffered_pkts >= batch_max_count
     ||  elapsed_time >= batch_timeout))
    {
        /* transmit batch verdict */
        ans = nfq_set_verdict_batch(out_qh, out_latest_pkt_id,
                                    out_prev_verdict);
        RET(ans == -1, -1, "unable to set batch verdict");
        /* DEBUG(">>> OUTPUT verdict set for %u packets", out_buffered_pkts); */

        /* reset batch counters (that matter) */
        out_buffered_pkts = 0;
    }

    /* check if INPUT batch warrants eviction                       *
     * NOTE: not applicable if no packets are buffered at the moment */
    elapsed_time = (ts.raw - in_oldest_ts) * 1'000'000 / BASE_FREQ;

    if (chain_mask & (1 << INPUT_CHAIN)
    &&  in_buffered_pkts != 0
    &&  (force
     ||  in_buffered_pkts >= batch_max_count
     ||  elapsed_time >= batch_timeout))
    {
        /* transmit batch verdict */
        ans = nfq_set_verdict_batch(in_qh, in_latest_pkt_id,
                                    in_prev_verdict);
        RET(ans == -1, -1, "unable to set batch verdict");
        /* DEBUG(">>> INPUT verdict set for %u packets", in_buffered_pkts); */

        /* reset batch counters (that matter) */
        in_buffered_pkts = 0;
    }

    return 0;
}

/* nfq_helper_init - packet verdict handler module initializer
 *  @_batch_max_count : maximum number of batched packets
 *  @_batch_timeout   : verdict transmission timeout for batch
 *
 *  @return : 0 if everything went well; -1 on error
 */
int32_t
nfq_helper_init(uint32_t            _batch_max_count,
                uint64_t            _batch_timeout,
                struct nfq_q_handle *_in_qh,
                struct nfq_q_handle *_out_qh,
                struct nfq_q_handle *_fwd_qh)
{
    batch_max_count = _batch_max_count;
    batch_timeout   = _batch_timeout;

    in_qh  = _in_qh;
    out_qh = _out_qh;
    fwd_qh = _fwd_qh;

    return 0;
}

/* nfq_in_handler - input chain callback routine for NetfilterQueue
 *  @qh    : netfilter queue handle
 *  @nfmsg : general form of address family dependent message
 *  @nfd   : nfq related data for packet evaluation
 *  @data  : data parameter passed unchanged by nfq_create_queue()
 *
 *  @return : 0 if ok, -1 on error (handled by nfq_set_verdict())
 */
int32_t nfq_in_handler(struct nfq_q_handle *qh,
                       struct nfgenmsg     *nfmsg,
                       struct nfq_data     *nfd,
                       void                *data)
{
    tscval_t ts;                            /* current time                   */
    struct nfqnl_msg_packet_hdr *ph;        /* nfq meta header                */
    struct iphdr                *iph;       /* ip header                      */
    struct tcphdr               *tcph;      /* tcp header                     */
    struct nfq_op_param         *nfq_opp;   /* nfq operational parameters     */
    uint32_t                    verdict;    /* nfq verdict                    */
    uint32_t                    force;      /* don't skip verdict for reasons */
    int32_t                     ans;        /* answer                         */

    ARM_TIMER(start_marker);

    /* cast reference to nfq operational parameters */
    nfq_opp = (struct nfq_op_param *) data;

    /* get nfq packet header (w/ metadata) */
    ph = nfq_get_msg_packet_hdr(nfd);
    RET(!ph, -1, "unable to retrieve packet meta hdr (%s)", strerror(errno));

    /* extract raw packet */
    ans = nfq_get_payload(nfd, (uint8_t **) &iph);
    RET(ans == -1, -1, "unable to retrieve packet data (%s)", strerror(errno));

    UPDATE_TIMER(nfqinh_extract_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* process any delayed events that have timed out */
    nl_delayed_ev_handle(nfq_opp->proc_delay);
    ebpf_delayed_ev_handle(nfq_opp->proc_delay);

    UPDATE_TIMER(nfqinh_delayedev_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* get verdict for current packet or use default policy */
    verdict = get_verdict(iph, INPUT_CHAIN);
    if (verdict == NF_MAX_VERDICT + 1) {
        verdict = nfq_opp->policy_in;
        /* DEBUG("DEFAULT POLICY"); */
    } else {
        /* DEBUG("%s", verdict == NF_ACCEPT ? "ACCEPT" : "DROP"); */
    }

    UPDATE_TIMER(nfqinh_verdict_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* force verdict if current packet has different verdict from batch */
    if (verdict != in_prev_verdict && in_buffered_pkts > 0) {
        ans = maybe_transmit_verdict(1, 1 << INPUT_CHAIN);
        ALERT(ans, "unable to set batch verdict");
    }

    /* get current time */
    rdtsc(ts.low, ts.high);

    /* update batch stats */
    in_prev_verdict  = verdict;
    in_latest_pkt_id = ntohl(ph->packet_id);
    if (in_buffered_pkts++ == 0)
        in_oldest_ts = ts.raw;

    /* force verdict transmission on TCP SYN / PSH */
    force = 0;
    if (iph->protocol == IPPROTO_TCP) {
        tcph   = (struct tcphdr *) &((uint8_t *) iph)[iph->ihl * 4];
        force = tcph->syn || tcph->psh;
    }

    /* see if current packet puts us over the limit */
    ans = maybe_transmit_verdict(force, 1 << INPUT_CHAIN);
    ALERT(ans, "unable to set batch verdict");

    UPDATE_TIMER(nfqinh_report_ctr, start_marker);
    nfqinh_packets_ctr++;

    return ans;
}

/* nfq_out_handler - output chain callback routine for NetfilterQueue
 *  @qh    : netfilter queue handle
 *  @nfmsg : general form of address family dependent message
 *  @nfd   : nfq related data for packet evaluation
 *  @data  : data parameter passed unchanged by nfq_create_queue()
 *
 *  @return : 0 if ok, -1 on error (handled by nfq_set_verdict())
 */
int32_t nfq_out_handler(struct nfq_q_handle *qh,
                    struct nfgenmsg         *nfmsg,
                    struct nfq_data         *nfd,
                    void                    *data)
{
    tscval_t                    ts;         /* current time                   */
    struct nfqnl_msg_packet_hdr *ph;        /* nfq meta header                */
    struct iphdr                *iph;       /* ip header                      */
    struct tcphdr               *tcph;      /* tcp header                     */
    struct nfq_op_param         *nfq_opp;   /* nfq operational parameters     */
    void                        *mod_data;  /* modified packet buffer         */
    uint32_t                    verdict;    /* nfq verdict                    */
    uint32_t                    force;      /* don't skip verdict for reasons */
    int32_t                     ans;        /* answer                         */

    ARM_TIMER(start_marker);

    /* cast reference to nfq operational parameters */
    nfq_opp = (struct nfq_op_param *) data;

    /* get nfq packet header (w/ metadata) */
    ph = nfq_get_msg_packet_hdr(nfd);
    RET(!ph, -1, "unable to retrieve packet meta hdr (%s)", strerror(errno));

    /* extract raw packet */
    ans = nfq_get_payload(nfd, (uint8_t **) &iph);
    RET(ans == -1, -1, "unable to retrieve packet data (%s)", strerror(errno));
    RET(ans != ntohs(iph->tot_len), -1, "Payload size & total len mismatch");

    UPDATE_TIMER(nfqouth_extract_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* process any delayed events that have timed out */
    nl_delayed_ev_handle(nfq_opp->proc_delay);
    ebpf_delayed_ev_handle(nfq_opp->proc_delay);

    UPDATE_TIMER(nfqouth_delayedev_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* get verdict for current packet or use default policy */
    verdict = get_verdict(iph, OUTPUT_CHAIN);
    if (verdict == NF_MAX_VERDICT + 1) {
        verdict = nfq_opp->policy_out;
        /* DEBUG("DEFAULT POLICY"); */
    } else {
        /* DEBUG("%s", verdict == NF_ACCEPT ? "ACCEPT" : "DROP"); */
    }

    UPDATE_TIMER(nfqouth_verdict_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* if verdict is positive, append signature option */
    if (verdict == NF_ACCEPT) {
        mod_data = add_sig((uint8_t *) iph);
        GOTO(!mod_data, out_unmodified, "unable to insert signature option");

        /* late switch to unmodified path if dummy signer selected *
         * or if verdict batching is enabled                       */
        if (mod_data == iph || batch_max_count > 1) {
            goto out_unmodified;
        }

        /* communicate packet verdict to nfq, w/ signature */
        iph = (struct iphdr *) mod_data;
        ans = nfq_set_verdict(qh, ntohl(ph->packet_id), verdict,
                    ntohs(iph->tot_len), (const unsigned char *) mod_data);
        ALERT(ans == -1, "unable to set packet verdict");

        UPDATE_TIMER(nfqouth_report_ctr, start_marker);
        nfqouth_packets_ctr++;

        return ans;
    }

out_unmodified:
    /* return value (if no verdicts are being sent this time) */
    ans = 0;

    /* force verdict if current packet has different verdict from batch */
    if (verdict != out_prev_verdict && out_buffered_pkts > 0) {
        ans = maybe_transmit_verdict(1, 1 << OUTPUT_CHAIN);
        ALERT(ans, "unable to set batch verdict");
    }

    /* get current time */
    rdtsc(ts.low, ts.high);

    /* update batch stats */
    out_prev_verdict  = verdict;
    out_latest_pkt_id = ntohl(ph->packet_id);
    if (out_buffered_pkts++ == 0)
        out_oldest_ts = ts.raw;

    /* force verdict transmission on TCP SYN / PSH */
    force = 0;
    if (iph->protocol == IPPROTO_TCP) {
        tcph   = (struct tcphdr *) &((uint8_t *) iph)[iph->ihl * 4];
        force = tcph->syn || tcph->psh;
    }

    /* see if current packet puts us over the limit */
    ans = maybe_transmit_verdict(force, 1 << OUTPUT_CHAIN);
    ALERT(ans, "unable to set batch verdict");

    UPDATE_TIMER(nfqouth_report_ctr, start_marker);
    nfqouth_packets_ctr++;

    return ans;
}

/* nfq_fwd_handler - output chain callback routine for NetfilterQueue
 *  @qh    : netfilter queue handle
 *  @nfmsg : general form of address family dependent message
 *  @nfd   : nfq related data for packet evaluation
 *  @data  : data parameter passed unchanged by nfq_create_queue()
 *
 *  @return : 0 if ok, -1 on error (handled by nfq_set_verdict())
 */
int32_t nfq_fwd_handler(struct nfq_q_handle *qh,
                    struct nfgenmsg         *nfmsg,
                    struct nfq_data         *nfd,
                    void                    *data)
{
    struct nfqnl_msg_packet_hdr *ph;        /* nfq meta header            */
    struct iphdr                *iph;       /* ip header                  */
    struct nfq_op_param         *nfq_opp;   /* nfq operational parameters */
    uint32_t                    verdict;    /* nfq verdict                */
    int32_t                     ans;        /* answer                     */

    ARM_TIMER(start_marker);

    /* cast reference to nfq operational parameters */
    nfq_opp = (struct nfq_op_param *) data;

    /* get nfq packet header (w/ metadata) */
    ph = nfq_get_msg_packet_hdr(nfd);
    RET(!ph, -1, "unable to retrieve packet meta hdr (%s)", strerror(errno));

    /* extract raw packet */
    ans = nfq_get_payload(nfd, (uint8_t **) &iph);
    RET(ans == -1, -1, "unable to retrieve packet data (%s)", strerror(errno));
    RET(ans != ntohs(iph->tot_len), -1, "Payload size & total len mismatch");

    UPDATE_TIMER(nfqfwdh_extract_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* process any delayed events that have timed out */
    nl_delayed_ev_handle(nfq_opp->proc_delay);
    ebpf_delayed_ev_handle(nfq_opp->proc_delay);

    UPDATE_TIMER(nfqfwdh_delayedev_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* get verdict for current packet or use default policy */
    verdict = get_verdict(iph, FORWARD_CHAIN);
    if (verdict == NF_MAX_VERDICT + 1) {
        verdict = nfq_opp->policy_fwd;
        /* DEBUG("DEFAULT POLICY"); */
    } else {
        /* DEBUG("%s", verdict == NF_ACCEPT ? "ACCEPT" : "DROP"); */
    }

    UPDATE_TIMER(nfqfwdh_verdict_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* communicate packet verdict to nfq, w/o signature */
    ans = nfq_set_verdict(qh, ntohl(ph->packet_id), verdict, 0, NULL);
    ALERT(ans == -1, "unable to set packet verdict");

    UPDATE_TIMER(nfqfwdh_report_ctr, start_marker);
    nfqfwdh_packets_ctr++;

    return ans;
}

