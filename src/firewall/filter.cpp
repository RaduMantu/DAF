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

#include <unistd.h>             /* read, close          */
#include <sys/socket.h>         /* accept               */
#include <sys/uio.h>            /* writev               */
#include <netinet/ip.h>         /* iphdr                */
#include <netinet/udp.h>        /* udphdr               */
#include <netinet/tcp.h>        /* tcphdr               */
#include <linux/netfilter.h>    /* NF_MAX_VERDICT       */
#include <openssl/sha.h>        /* SHA256_DIGEST_LENGTH */
#include <openssl/evp.h>        /* EVP_*                */

#include <unordered_set>        /* unordered set */
#include <iterator>             /* advance       */
#include <vector>               /* vector        */
#include <string>               /* string        */

#include "filter.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

static vector<struct flt_crit> input_chain;
static vector<struct flt_crit> output_chain;

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
 ******************************************************************************/

/* _send_chain - sends chain rules as response to client
 *  @us_dsock_fd : unix data socket file descriptor
 *  @chain       : reference to selected chain
 *
 *  @return : 0 if everything went ok
 */
static int32_t
_send_chain(int32_t us_dsock_fd, vector<struct flt_crit>& chain)
{
    struct iovec    iov[2];         /* buffer aggregators */
    struct ctl_msg  rspm = { 0 };   /* response message   */
    ssize_t         wb;             /* written bytes      */

    /* sanity check (chain must be either input or output) */
    RET((&chain != &input_chain) && (&chain != &output_chain), -1,
        "chain reference must be either input or output chains");

    /* compare chain reference for identity */
    rspm.msg.flags = (&chain == &input_chain) ? CTL_INPUT : CTL_OUTPUT;

    /* set first iov to the message field of the response */
    iov[0].iov_base = (void *) &rspm.msg;
    iov[0].iov_len  = sizeof(rspm.msg);
    /* the second iov will always contain a rule structure */
    iov[1].iov_len  = sizeof(struct flt_crit);

    /* for all rules in chain */
    for (auto it = chain.begin(); it < chain.end(); ++it) {
        /* set base of second iov and send */
        iov[1].iov_base = (void *) &(*it);

        wb = writev(us_dsock_fd, iov, sizeof(iov) / sizeof(*iov));
        RET(wb == -1, -1, "unable to send response (%s)", strerror(errno));

        /* increment position counter */
        rspm.msg.pos++;
    }

    return 0;
}

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* get_verdict - establishes accept / drop verdict for packet
 *  @pkt    : packet buffer
 *  @maps   : vector of hashes for memory mapped objects, for each process
 *  @chain  : {INPUT,OUTPUT}_CHAIN (see filter.h)
 *
 *  @return : NF_{ACCEPT,DROP} if packet matched a rule
 *            NF_MAX_VERDICT + 1 if packet did not match any rule
 *
 *  Returning NF_MAX_VERDICT + 1 will eventually lead to the chain's default
 *  rule being applied.
 */
uint32_t get_verdict(void *pkt, vector<vector<uint8_t *>>& maps, uint32_t chain)
{
    uint8_t                 md_agg[SHA256_DIGEST_LENGTH];   /* digest buffer */
    EVP_MD_CTX              *ctx;           /* sha256 context                */
    vector<struct flt_crit> *sel_chain;     /* pointer to selected chain     */
    struct iphdr            *iph;           /* ip header                     */
    struct tcphdr           *tcph;          /* tch header                    */
    struct udphdr           *udph;          /* udp header                    */
    uint8_t                 matched;        /* matching object was found     */
    int32_t                 ans;            /* answer                        */

    /* get reference to correct chain */
    if (chain == INPUT_CHAIN)
        sel_chain = &input_chain;
    else if (chain == OUTPUT_CHAIN)
        sel_chain = &output_chain;
    else {
        WAR("invalid chain identifier");
        return NF_MAX_VERDICT + 1;
    }

    /* cast packet buffer to iphdr */
    iph = (struct iphdr *) pkt;

    /* for each rule in chain */
    for (auto& rule : *sel_chain) {
        /* check layer 3 fields */
        if ((rule.flags & FLT_SRC_IP)
            && (((iph->saddr & rule.src_ip_mask) != rule.src_ip)
                == !(rule.flags & FLT_SRC_IP_INV)))
            continue;
        if ((rule.flags & FLT_DST_IP)
            && (((iph->daddr & rule.dst_ip_mask) != rule.dst_ip)
                == !(rule.flags & FLT_DST_IP_INV)))
            continue;
        if ((rule.flags & FLT_L4_PROTO)
            && ((iph->protocol != rule.l4_proto)
                == !(rule.flags & FLT_L4_PROTO_INV)))
            continue;

        /* check layer 4 fields (depending on protocol) */
        switch (iph->protocol) {
            case IPPROTO_TCP:
                tcph = (struct tcphdr *) &((uint8_t *) iph)[iph->ihl * 4];

                if ((rule.flags & FLT_SRC_PORT)
                    && ((tcph->source != rule.src_port)
                        == !(rule.flags & FLT_SRC_PORT_INV)))
                    continue;
                if ((rule.flags & FLT_DST_PORT)
                    && ((tcph->dest != rule.dst_port)
                        == !(rule.flags & FLT_DST_PORT_INV)))
                    continue;

                break;
            case IPPROTO_UDP:
                udph = (struct udphdr *) &((uint8_t *) iph)[iph->ihl * 4];

                if ((rule.flags & FLT_SRC_PORT)
                    && ((udph->source != rule.src_port)
                        == !(rule.flags & FLT_SRC_PORT_INV)))
                    continue;
                if ((rule.flags & FLT_DST_PORT)
                    && ((udph->dest != rule.dst_port)
                        == !(rule.flags & FLT_DST_PORT_INV)))
                    continue;

                break;
            /* ignore rule for unkown l4 protocol */
            default:
                continue;
        }

        /* if not checking process identity, consider this a match */
        if (!(rule.flags & FLT_HASH))
            return (rule.verdict & VRD_ACCEPT) ? NF_ACCEPT : NF_DROP;

        /* check single hash match                                  *
         * NOTE: if verdict is DROP, one process is enough to match *
         *       if verdict is ACCEPT, all process must match       *
         *       check inversion does not affect the above          */
        if (rule.flags & FLT_SINGLE_HASH) {
            /* for each process that could have sent this packet */
            for (auto& pm : maps) {
                /* initial assumption is that no objects match */
                matched = 0;

                /* for each object hash in current process */
                for (auto& h : pm) {
                    /* match found */
                    if (!memcmp(h, rule.sha256_md, sizeof(rule.sha256_md))
                        == !(rule.flags & FLT_HASH_INV))
                    {
                        /* if verdict is DROP, condition is satisfied */
                        if (rule.verdict & VRD_DROP)
                            return NF_DROP;

                        /* if verdict is ACCEPT, move on to next process */
                        matched = 1;
                        break;
                    }
                }

                /* if verdict is ACCEPT and no match was found, condition is *
                 * not satisfiable; abort early                              */
                if (!matched && (rule.verdict & VRD_ACCEPT))
                    break;
            }

            /* if verdict is ACCEPT */
            if (rule.verdict & VRD_ACCEPT) {
                /* no matches means packet doesn't match rule; go to next one */
                if (!matched)
                    continue;

                /* a match here means a match on every process; use verdict */
                return NF_ACCEPT;
            }

            /* if verdict is DROP and no matches were found, go to next rule */
            continue;
        }
        /* aggregate hash check */
        else if (rule.flags & FLT_AGGREGATE_HASH) {
            /* for each process that could have sent this packet */
            for (auto& pm : maps) {
                /* initial assumption is that all objects don't match */
                matched = 0;

                /* create new EVP context */
                ctx = EVP_MD_CTX_new();
                if(!ans) {
                    WAR("unable to create EVP context");
                    continue;
                }

                /* initialize SHA256 context for aggregate hash */
                ans = EVP_DigestInit(ctx, EVP_sha256());
                if (ans != 1) {
                    WAR("unable to initialize SHA256 context");
                    goto process_loop_end;
                }

                /* for each object hash in current process */
                for (auto& h : pm) {
                    /* update sha256 context */
                    ans = EVP_DigestUpdate(ctx, h, SHA256_DIGEST_LENGTH);
                    if (ans != 1) {
                        WAR("unable to update SHA256 context");
                        goto process_loop_end;
                    }
                }

                /* finalize hashing process */
                ans = EVP_DigestFinal(ctx, md_agg, NULL);
                if(ans != 1) {
                    WAR("unable to finalize SHA256");
                    continue;
                }

                /* match found */
                if (!memcmp(md_agg, rule.sha256_md, sizeof(rule.sha256_md))
                    == !(rule.flags & FLT_HASH_INV))
                {
                    /* if verdict is DROP, condition is satisfied */
                    if (rule.verdict & VRD_DROP)
                        return NF_DROP;

                    /* if verdict is ACCEPT, move on to next process */
                    matched = 1;
                    continue;
                }
                /* match not found */
                else {
                    /* if verdict is ACCEPT, condition in not satisfiable */
                    matched = 0;
                    break;

                    /* if verdict is DROP, move on to next process */
                    continue;
                }

process_loop_end:
                /* bypasss hash finalization and match check  *
                 * something went wrong in the inner for loop */
                EVP_MD_CTX_free(ctx);
            }

            /* if verdict is ACCEPT */
            if (rule.verdict & VRD_ACCEPT) {
                /* no matches means packet doesn't match rule; go to next one */
                if (!matched)
                    continue;

                /* a match here means a match on every process; use verdict */
                return NF_ACCEPT;
            }

            /* if verdict is drop and no matches were found, go to next rule */
            continue;
        }
    }

    /* no rule was matched; fall back to chain default policy */
    return NF_MAX_VERDICT + 1;
}

/* flt_handle_ctl - handles request by user's rule manager
 *  @us_csock_fd : unix connect socket
 *
 *  @return : 0 if everything went ok
 *
 * NOTE: not adding data socket to any epoll instance
 *       call to this function is blocking
 *
 * TODO: add client authentication
 */
int32_t flt_handle_ctl(int32_t us_csock_fd)
{
    vector<struct flt_crit>::iterator it;     /* iterator to certain element */
    vector<struct flt_crit>  *sel_chain;      /* pointer to selected chain   */
    struct ctl_msg           reqm, rspm;      /* request / response message  */
    int32_t                  us_dsock_fd;     /* unix data socket            */
    ssize_t                  rb, wb;          /* read / written bytes        */
    int32_t                  ans;             /* answer                      */

    /* clean message buffers */
    memset(&reqm, 0, sizeof(reqm));
    memset(&rspm, 0, sizeof(rspm));

    /* accept new connection */
    us_dsock_fd = accept(us_csock_fd, NULL, NULL);
    RET(us_dsock_fd == -1, -1, "unable to accept new connection (%s)",
        strerror(errno));

    /* read request from client */
    rb = read(us_dsock_fd, &reqm, sizeof(reqm));
    GOTO(rb == -1, clean_data_socket,
        "unable to read data from client (%s)", strerror(errno));

    /* select appropriate response for each request */
    switch (reqm.msg.flags & CTL_REQ_MASK) {
        case CTL_LIST:
            DEBUG("received LIST request");

            /* send responses */
            if (reqm.msg.flags & CTL_INPUT) {
                ans = _send_chain(us_dsock_fd, input_chain);
                GOTO(ans, clean_data_socket, "unable to send input chain");
            }
            if (reqm.msg.flags & CTL_OUTPUT) {
                ans = _send_chain(us_dsock_fd, output_chain);
                GOTO(ans, clean_data_socket, "unable to send output chain");
            }

            /* send final short response with CTL_END flag set */
            rspm.msg.flags |= CTL_END;
            goto common_short_resp;
        case CTL_INSERT:
            DEBUG("received INSERT request");

            /* get pointer to selected chain */
            if (reqm.msg.flags & CTL_INPUT)
                sel_chain = &input_chain;
            else if (reqm.msg.flags & CTL_OUTPUT)
                sel_chain = &output_chain;
            else {
                WAR("no chain specified");
                rspm.msg.flags |= CTL_NACK;
                goto common_short_resp;
            }

            /* get iterator to insert position in selected chain          *
             * NOTE: iterator must not exceed .end() by abusing advance() */
            if (reqm.msg.pos > sel_chain->size())
                it = sel_chain->end();
            /* NOTE: advance should be constant time for vector<> iterator *
             *       since it is LegacyBidirectionalIterator               */
            else {
                it = sel_chain->begin();
                advance(it, reqm.msg.pos);
            }

            /* insert rule */
            sel_chain->insert(it, reqm.rule);

            /* send short ACK response */
            rspm.msg.flags |= CTL_ACK;
            goto common_short_resp;
        case CTL_APPEND:
            DEBUG("received APPEND request");

            /* append rule */
            if (reqm.msg.flags & CTL_INPUT)
                input_chain.push_back(reqm.rule);
            else if (reqm.msg.flags & CTL_OUTPUT)
                output_chain.push_back(reqm.rule);
            else {
                WAR("no chain specified");
                rspm.msg.flags |= CTL_NACK;
                goto common_short_resp;
            }

            /* send short ACK response */
            rspm.msg.flags |= CTL_ACK;
            goto common_short_resp;
        case CTL_DELETE:
            DEBUG("received DELETE request");

            /* get pointer to selected chain */
            if (reqm.msg.flags & CTL_INPUT)
                sel_chain = &input_chain;
            else if (reqm.msg.flags & CTL_OUTPUT)
                sel_chain = &output_chain;
            else {
                WAR("no chain specified");
                rspm.msg.flags |= CTL_NACK;
                goto common_short_resp;
            }

            /* calcualte deletion iterator and abort if beyond vector end */
            it = sel_chain->begin();
            advance(it, reqm.msg.pos);
            if (it >= sel_chain->end()) {
                WAR("deletion index out of range");
                rspm.msg.flags |= CTL_NACK;
                goto common_short_resp;
            }

            /* remove element */
            sel_chain->erase(it);

            /* send short ACK response */
            rspm.msg.flags |= CTL_ACK;
common_short_resp:
            wb = write(us_dsock_fd, &rspm.msg, sizeof(rspm.msg));
            GOTO(wb == -1, clean_data_socket,
                "unable to write data to client (%s)", strerror(errno));

            break;
        default:
            GOTO(1, clean_data_socket, "unkown client request code %04hx",
                reqm.msg.flags);
    }

clean_data_socket:
    /* close data socket */
    ans = close(us_dsock_fd);
    ALERT(ans == -1, "error closing unix data socket (%s)", strerror(errno));

    return 0;
}
