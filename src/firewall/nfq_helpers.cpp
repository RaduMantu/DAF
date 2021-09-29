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

#include <set>              /* set           */
#include <vector>           /* vector        */

#include "netlink_helpers.h"
#include "ebpf_helpers.h"
#include "sock_cache.h"
#include "hash_cache.h"
#include "nfq_helpers.h"
#include "gpg_helpers.h"
#include "filter.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
 ******************************************************************************/

/* _chain_common_filter - common component of INPUT / OUTPUT chain filters
 *  @iph   : pointer to packet buffer
 *  @chain : {INPUT,OUTPUT}_CHAIN (see filter.h)
 *
 *  @return : NF_{ACCEPT,DROP} if packet matched a rule
 *            NF_MAX_VERDICT + 1 if packet did not match any rule
 *
 *  The reason why we don't return NF_MAX_VERDICT is that it coincides with
 *  NF_STOP, which is deprecated but still exists.
 *
 *  NF_MAX_VERDICT + 1 can be returned under multiple circumstances:
 *      - packet matched no rule but it _was_ analyzed
 *      - unable to get digest of objects mmapped by found processes
 */
uint32_t _chain_common_filter(struct iphdr *iph, uint32_t chain)
{
    struct tcphdr             *tcph;        /* tcp header                 */
    struct udphdr             *udph;        /* udp header                 */
    uint32_t                  src_ip;       /* network order src ip       */
    uint32_t                  dst_ip;       /* network order dst ip       */
    uint8_t                   l4_proto;     /* layer 4 protocol           */
    uint16_t                  src_port;     /* network order src port     */
    uint16_t                  dst_port;     /* network order dst port     */
    unordered_set<uint32_t>   *pid_set_p;   /* pointer to set of pids     */
    vector<vector<uint8_t *>> hashes;       /* per process ordered hashes */
    uint8_t                   *md;          /* pointer to digest buffer   */
    size_t                    pid_idx;      /* index of analyzed pid      */
    int32_t                   ans;          /* answer                     */

    /* extract layer 3 features (for readablity & ease of access) */
    src_ip   = iph->saddr;
    dst_ip   = iph->daddr;
    l4_proto = iph->protocol;

    /* extract layer 4 features (based on protocol) */
    switch (l4_proto) {
        case IPPROTO_TCP:
            tcph = (struct tcphdr *) &((uint8_t *) iph)[iph->ihl * 4];

            src_port = tcph->source;
            dst_port = tcph->dest;

            break;
        case IPPROTO_UDP:
            udph = (struct udphdr *) &((uint8_t *) iph)[iph->ihl * 4];

            src_port = udph->source;
            dst_port = udph->dest;

            break;
        /* filter match function will not be able to access to l4 fields _or_ *
         * the memory mapped objects of the processes that have access to the *
         * associated socket (reason why we're even doing this here), but it  *
         * _might_ be able to apply l3 filtering rules if only those are      *
         * specified                                                          */
        default:
            goto map_fetch_bypass;
    }

    /* find pids that have access to this port & ip configuration             *
     * NOTE: netlink socket diagnostics are always from the perspective of    *
     *       the localhost; meaning that on OUTPUT, src_* is actually src_*;  *
     *       on INPUT however, src_* will actually be dst_* in the invokation *
     *       of sc_get_pid()                                                  */
    if (chain == OUTPUT_CHAIN)
        pid_set_p = sc_get_pid(l4_proto, src_ip, dst_ip, src_port, dst_port);
    else
        pid_set_p = sc_get_pid(l4_proto, dst_ip, src_ip, dst_port, src_port);
    if (!pid_set_p)
        goto map_fetch_bypass;

    /* resize vector of object digest vectors based on number of processes */
    hashes.resize(pid_set_p->size());

    /* get hashes of memory mapped objects (alphabetically ordered by path) */
    pid_idx = 0;
    for (auto pid_it : *pid_set_p) {
        auto maps = hc_get_maps(pid_it);

        for (auto& map_it : maps) {
            /* get sha256 digest of object (unlikely to fail -> report it) */
            md = hc_get_sha256((char *) map_it.c_str());
            RET(!md, NF_MAX_VERDICT + 1, "could not get sha256 digest of %s",
                map_it.c_str()); 

            /* push hashes to vector in object's order in set */
            hashes[pid_idx].push_back(md);
        }

        /* continue to next process */
        pid_idx++;
    }

map_fetch_bypass:
    /* get verdict for current packet                                         *
     * NOTE: the return value can also be NF_MAX_VERDICT; caller is expected  *
     *       to apply its default policy (ACCEPT or DROP) if this is returned */
    return get_verdict((void *) iph, hashes, chain); 
}

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

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
    struct nfqnl_msg_packet_hdr *ph;        /* nfq meta header            */
    struct iphdr                *iph;       /* ip header                  */
    struct nfq_op_param         *nfq_opp;   /* nfq operational parameters */
    uint32_t                    verdict;    /* nfq verdict                */
    int32_t                     ans;        /* answer                     */

    /* cast reference to nfq operational parameters */
    nfq_opp = (struct nfq_op_param *) data;

    /* get nfq packet header (w/ metadata) */
    ph = nfq_get_msg_packet_hdr(nfd);
    RET(!ph, -1, "Unable to retrieve packet meta hdr (%s)", strerror(errno));

    /* extract raw packet */
    ans = nfq_get_payload(nfd, (uint8_t **) &iph);
    RET(ans == -1, -1, "Unable to retrieve packet data (%s)", strerror(errno));
    RET(ans != ntohs(iph->tot_len), -1, "Payload size & total len mismatch");

    /* process any delayed events that have timed out */
    nl_delayed_ev_handle(nfq_opp->proc_delay);
    ebpf_delayed_ev_handle(nfq_opp->proc_delay);

    /* get verdict for current packet or use default policy */
    verdict = _chain_common_filter(iph, INPUT_CHAIN);
    if (verdict == NF_MAX_VERDICT + 1)
        verdict = nfq_opp->policy_in;

    /* communicate packet verdict to nfq */
    return nfq_set_verdict(qh, ntohl(ph->packet_id), verdict, 0, NULL);
}

/* nfq_out_handler - output chain callback routine for NetfilterQueue
 *  @qh    : netfilter queue handle
 *  @nfmsg : general form of address family dependent message
 *  @nfd   : nfq related data for packet evaluation
 *  @data  : data parameter passed unchanged by nfq_create_queue()
 *
 *  @return : 0 if ok, -1 on error (handled by nfq_set_verdict())
 */
int nfq_out_handler(struct nfq_q_handle *qh,
                    struct nfgenmsg     *nfmsg,
                    struct nfq_data     *nfd,
                    void                *data)
{
    struct nfqnl_msg_packet_hdr *ph;        /* nfq meta header            */
    struct iphdr                *iph;       /* ip header                  */
    struct nfq_op_param         *nfq_opp;   /* nfq operational parameters */
    uint32_t                    verdict;    /* nfq verdict                */
    int32_t                     ans;        /* answer                     */

    /* cast reference to nfq operational parameters */
    nfq_opp = (struct nfq_op_param *) data;

    /* get nfq packet header (w/ metadata) */
    ph = nfq_get_msg_packet_hdr(nfd);
    RET(!ph, -1, "Unable to retrieve packet meta hdr (%s)", strerror(errno));

    /* extract raw packet */
    ans = nfq_get_payload(nfd, (uint8_t **) &iph);
    RET(ans == -1, -1, "Unable to retrieve packet data (%s)", strerror(errno));
    RET(ans != ntohs(iph->tot_len), -1, "Payload size & total len mismatch");

    /* process any delayed events that have timed out */
    nl_delayed_ev_handle(nfq_opp->proc_delay);
    ebpf_delayed_ev_handle(nfq_opp->proc_delay);

    /* get verdict for current packet or use default policy */
    verdict = _chain_common_filter(iph, OUTPUT_CHAIN);
    if (verdict == NF_MAX_VERDICT + 1) {
        DEBUG("MAX VERDICT");
        verdict = nfq_opp->policy_out;
    } else {
        DEBUG("%s", verdict == NF_ACCEPT ? "ACCEPT" : "DROP");
    }

    /* communicate packet verdict to nfq */
    return nfq_set_verdict(qh, ntohl(ph->packet_id), verdict, 0, NULL);
}

