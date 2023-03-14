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
    verdict = get_verdict(iph, INPUT_CHAIN);
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
int32_t nfq_out_handler(struct nfq_q_handle *qh,
                    struct nfgenmsg         *nfmsg,
                    struct nfq_data         *nfd,
                    void                    *data)
{
    struct nfqnl_msg_packet_hdr *ph;        /* nfq meta header            */
    struct iphdr                *iph;       /* ip header                  */
    struct nfq_op_param         *nfq_opp;   /* nfq operational parameters */
    void                        *mod_data;  /* modified packet buffer     */
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
    verdict = get_verdict(iph, OUTPUT_CHAIN);
    if (verdict == NF_MAX_VERDICT + 1) {
        verdict = nfq_opp->policy_out;
    } else {
        DEBUG("%s", verdict == NF_ACCEPT ? "ACCEPT" : "DROP");
    }

    /* if verdict is positive, append signature option */
    if (verdict == NF_ACCEPT) {
        mod_data = add_sig((uint8_t *) iph);
        GOTO(!mod_data, out_unmodified, "unable to insert signature option");

        /* late switch to unmodified path if dummy signer selected */
        if (mod_data == iph)
            goto out_unmodified;

        /* communicate packet verdict to nfq, w/ signature */
        iph = (struct iphdr *) mod_data;
        return nfq_set_verdict(qh, ntohl(ph->packet_id), verdict,
                    ntohs(iph->tot_len), (const unsigned char *) mod_data);
    }

out_unmodified:
    /* communicate packet verdict to nfq, w/o signature */
    return nfq_set_verdict(qh, ntohl(ph->packet_id), verdict, 0, NULL);
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
    verdict = get_verdict(iph, FORWARD_CHAIN);
    if (verdict == NF_MAX_VERDICT + 1) {
        verdict = nfq_opp->policy_fwd;
    } else {
        DEBUG("%s", verdict == NF_ACCEPT ? "ACCEPT" : "DROP");
    }

    /* communicate packet verdict to nfq, w/o signature */
    return nfq_set_verdict(qh, ntohl(ph->packet_id), verdict, 0, NULL);
}

