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
#include "filter.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
 ******************************************************************************/


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
int nfq_in_handler(struct nfq_q_handle *qh,
                   struct nfgenmsg     *nfmsg,
                   struct nfq_data     *nfd,
                   void                *data)
{
    struct nfqnl_msg_packet_hdr *ph;        /* nfq meta header            */
    struct iphdr                *iph;       /* ip header                  */
    struct nfq_op_param         *nfq_opp;   /* nfq operational parameters */
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

    /* TODO */
    DEBUG("INPUT chain is working!");

    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
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
    struct tcphdr               *tcph;      /* tcp header                 */
    struct udphdr               *udph;      /* udp header                 */
    struct nfq_op_param         *nfq_opp;   /* nfq operational parameters */
    int32_t                     ans;        /* answer                     */
    uint16_t                    src_port;   /* network order src port     */
    uint16_t                    dst_port;   /* network order dst port     */
    uint32_t                    verdict;    /* nfq verdict                */
    unordered_set<uint32_t>     *pid_set_p; /* pointer to set of pids     */
    vector<vector<uint8_t *>>   hashes;     /* per process ordered hashes */
    size_t                      pid_idx;    /* index of analyzed pid      */

    /* cast reference to nfq operational parameters */
    nfq_opp = (struct nfq_op_param *) data;

    /* get nfq packet header (w/ metadata) */
    ph = nfq_get_msg_packet_hdr(nfd);
    RET(!ph, -1, "Unable to retrieve packet meta hdr (%s)", strerror(errno));

    /* extract raw packet */
    ans = nfq_get_payload(nfd, (uint8_t **) &iph);
    RET(ans == -1, -1, "Unable to retrieve packet data (%s)", strerror(errno));
    RET(ans != ntohs(iph->tot_len), -1, "Payload size & total len mismatch");

    DEBUG("OUTPUT chain is working!");

    /* extract port based on layer 4 protocol */
    switch (iph->protocol) {
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
        default:
            goto output_pass_unchanged;
    }

    /* process any delayed events that have timed out */
    nl_delayed_ev_handle(nfq_opp->proc_delay);
    ebpf_delayed_ev_handle(nfq_opp->proc_delay);

    /* find pids that have access to this src port */
    pid_set_p = sc_get_pid(iph->protocol, iph->saddr, iph->daddr, src_port,
                    dst_port);
    if (!pid_set_p)
        goto map_fetch_bypass;

    /* resize vector of md vectors based on number of processes */
    hashes.resize(pid_set_p->size());

    /* get mapped objects from pids and hashes from objects */
    pid_idx = 0;
    for (auto pid_it : *pid_set_p) {
        auto maps = hc_get_maps(pid_it);

        for (auto& map_it : maps) {
            /* get sha256 digest of object                              *
             * NOTE: unlikely to fail; if it does, drop packet probably *
             *       something fishy going on                           */
            uint8_t *md = hc_get_sha256((char *) map_it.c_str());
            GOTO(!md, output_drop, "could not get sha256 digest of %s",
                map_it.c_str());

            /* location in memory of hash should never change */
            hashes[pid_idx].push_back(md);
        }
    } 

map_fetch_bypass:
    /* get verdict for current packet */
    verdict = get_verdict((void *) iph, hashes, OUTPUT_CHAIN);
    return nfq_set_verdict(qh, ntohl(ph->packet_id), verdict, 0, NULL);

    /* TODO: rewrite these out (maybe) */
output_pass_unchanged:
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
output_drop:
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
}

