#include <unordered_set>    /* unordered_set */
#include <netinet/in.h>     /* IPPROTO_*     */
#include <netinet/ip.h>     /* iphdr         */
#include <netinet/tcp.h>    /* tcphdr        */
#include <netinet/udp.h>    /* udphdr        */

#include "netlink_helpers.h"
#include "ebpf_helpers.h"
#include "sock_cache.h"
#include "hash_cache.h"
#include "filter.h"
#include "util.h"

using namespace std;

/* nfq_handler - callback routine for NetfilterQueue
 *  @qh    : netfilter queue handle
 *  @nfmsg : general form of address family dependent message
 *  @nfd   : nfq related data for packet evaluation
 *  @data  : data parameter passed unchanged by nfq_create_queue()
 *
 *  @return : 0 if ok, -1 on error (handled by nfq_set_verdict())
 */
int nfq_handler(struct nfq_q_handle *qh,
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
    unordered_set<uint32_t>     *pid_set_p; /* pointer to set of pids     */

    /* cast reference to nfq operational parameters */
    nfq_opp = (struct nfq_op_param *) data;

    /* get nfq packet header (w/ metadata) */
    ph = nfq_get_msg_packet_hdr(nfd);
    RET(!ph, -1, "Unable to retrieve packet meta hdr (%s)", strerror(errno));

    /* extract raw packet */
    ans = nfq_get_payload(nfd, (uint8_t **) &iph);
    RET(ans == -1, -1, "Unable to retrieve packet data (%s)", strerror(errno));
    RET(ans != ntohs(iph->tot_len), -1, "Payload size & total len mismatch");

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
            goto pass_unchanged;
    }

    /* just debug info */
    DEBUG("packet | "
          "src_ip:%hhu.%hhu.%hhu.%hhu "
          "dst_ip:%hhu.%hhu.%hhu.%hhu "
          "proto: %s "
          "src_port:%hu "
          "dst_port:%hu ",
          (iph->saddr >>  0) & 0xff, (iph->saddr >>  8) & 0xff,
          (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff,
          (iph->daddr >>  0) & 0xff, (iph->daddr >>  8) & 0xff,
          (iph->daddr >> 16) & 0xff, (iph->daddr >> 24) & 0xff,
          iph->protocol == IPPROTO_TCP ? "TCP" : "UDP",
          ntohs(src_port), ntohs(dst_port));

    /* process any delayed events that have timed out */
    nl_delayed_ev_handle(nfq_opp->proc_delay);
    ebpf_delayed_ev_handle(nfq_opp->proc_delay);

    /* find pids that have access to this src port */
    pid_set_p = sc_get_pid(iph->protocol, iph->saddr, iph->daddr, src_port,
                    dst_port);
    GOTO(!pid_set_p, pass_unchanged, "unable to find pid set for packet");

    /* more debug info */
    for (auto pid_it : *pid_set_p) {
        printf(">>> pid: %u\n", pid_it);
        
        auto maps = hc_get_maps(pid_it);
        for (auto& map_it : maps) {
            uint8_t *md = hc_get_sha256((char *) map_it.c_str());

            printf(" >> %45s -- ", map_it.c_str());
            for (size_t i=0; i<32; ++i)
                printf("%02hhx", md[i]);
            printf("\n");
        }
    }

    /* pass unchanged */
pass_unchanged:
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

