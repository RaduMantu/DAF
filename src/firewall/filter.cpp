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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>             /* read, close          */
#include <sched.h>              /* setns                */
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
#include "sock_cache.h"
#include "hash_cache.h"
#include "netns_cache.h"
#include "signer.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

static vector<struct flt_crit> input_chain;
static vector<struct flt_crit> output_chain;

/* operational parameters */
uint8_t validate_input;      /* validate signature on INPUT chain   */
uint8_t validate_forward;    /* validate signature on FORWARD chain */
uint8_t skip_same_ns_switch; /* skip same netns switches            */

/* current network namespace */
uint64_t curr_netns_dev;
uint64_t curr_netns_ino;

/* elapsed time counters */
static struct timeval start_marker;
static struct timeval start_marker_2;

uint64_t verd_hmac_verif_ctr      = 0;
uint64_t verd_field_extr_ctr      = 0;
uint64_t verd_hashes_clear_ctr    = 0;
uint64_t verd_netns_lookup_ctr    = 0;
uint64_t verd_netns_set_ctr       = 0;
uint64_t verd_pidset_lookup_ctr   = 0;
uint64_t verd_pidset_hashcalc_ctr = 0;
uint64_t verd_hashes_resize_ctr   = 0;
uint64_t verd_hashes_lookup_ctr   = 0;
uint64_t verd_hash_calc_ctr       = 0;
uint64_t verd_hash_push_ctr       = 0;
uint64_t verd_hash_verif_ctr      = 0;

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

/* filter_init - initializes filter internal structures
 *  @val_fwd        : validate signature on FORWARD chain
 *  @val_in         : validate signature on INPUT chain
 *  @skip_ns_switch : skip same netns switch during rule evaluation
 *
 *  @return : 0 if everything went well
 */
int32_t
filter_init(uint8_t val_fwd, uint8_t val_in, uint8_t skip_ns_switch)
{
    validate_forward    = val_fwd;
    validate_input      = val_in;
    skip_same_ns_switch = skip_ns_switch;

    return 0;
}

/* get_verdict - establishes accept / drop verdict for packet
 *  @pkt    : packet buffer
 *  @chain  : {INPUT,OUTPUT}_CHAIN (see filter.h)
 *
 *  @return : NF_{ACCEPT,DROP} if packet matched a rule
 *            NF_MAX_VERDICT + 1 if packet did not match any rule
 *
 *  The reason why we don't return NF_MAX_VERDICT is that it coincides with
 *  NF_STOP, which is deprecated but still exists.
 *
 *  Returning NF_MAX_VERDICT + 1 will eventually lead to the chain's default
 *  rule being applied. It can be returned under multiple circumstances:
 *      - packet matched no rule but it _was_ analyzed
 *      - unable to get digest of objects mmapped by found processes
 */
uint32_t
get_verdict(void *pkt, uint32_t chain)
{
    uint8_t                   md_agg[SHA256_DIGEST_LENGTH]; /* digest buffer */
    EVP_MD_CTX                *ctx;         /* sha256 context                */
    vector<struct flt_crit>   *sel_chain;   /* pointer to selected chain     */
    struct iphdr              *iph;         /* ip header                     */
    struct tcphdr             *tcph;        /* tcp header                    */
    struct udphdr             *udph;        /* udp header                    */
    uint8_t                   matched;      /* matching object was found     */
    uint8_t                   *data;        /* easy byte-sized access to pkt */
    int32_t                   ans;          /* answer                        */
    uint8_t                   l4_proto;     /* layer 4 protocol              */
    uint32_t                  src_ip;       /* network order src ip          */
    uint32_t                  dst_ip;       /* network order dst ip          */
    uint16_t                  src_port;     /* network order src port        */
    uint16_t                  dst_port;     /* network order dst port        */
    unordered_set<uint32_t>   *pid_set_p;   /* pointer to set of pids        */
    vector<vector<uint8_t *>> hashes;       /* per process ordered hashes    */
    uint8_t                   known_l4;     /* supported l4 protocol         */
    size_t                    pid_idx;      /* index of analyzed pid         */
    uint8_t                   *md;          /* pointer to digest buffer      */
    uint64_t                  netns_dev;    /* network namespace device num  */
    uint64_t                  netns_ino;    /* network namespace inode num   */

    /* set initial values */
    iph  = (struct iphdr *) pkt;
    data = (uint8_t *) pkt;
    pid_set_p = NULL;
    known_l4  = 1;

    ARM_TIMER(start_marker);

    /* depending on chain, perform signature validation if needed *
     * also, set the sel_chain ptr to the current chain           */
    switch (chain) {
        case INPUT_CHAIN:
            sel_chain = &input_chain;

            if (validate_input) {
                /* drop if no options (and signature) available  *
                 * NOTE: at the moment, checking only L3 options */
                if (iph->ihl == 5)
                    return NF_DROP;

                /* check if option is our singature                *
                 * NOTE: for now, assuming ours is the only option */
                if (data[20] != SIG_OP_CP)
                    return NF_DROP;

                /* check signature itself */
                ans = verify_hmac(data, &data[22]);
                RET(ans == -1, NF_MAX_VERDICT + 1, "unable to verify signature");
                if (ans == 0)
                    return NF_DROP;
            }

            break;
        case OUTPUT_CHAIN:
            sel_chain = &output_chain;

            break;
        case FORWARD_CHAIN:
            if (validate_forward) {
                /* drop if no options (and signature) available  *
                 * NOTE: at the moment, checking only L3 options */
                if (iph->ihl == 5)
                    return NF_DROP;

                /* check if option is our singature                *
                 * NOTE: for now, assuming ours is the only option */
                if (data[20] != SIG_OP_CP)
                    return NF_DROP;

                /* check signature itself */
                ans = verify_hmac(data, &data[22]);
                RET(ans == -1, NF_MAX_VERDICT + 1,
                    "unable to verify signature");
                if (ans == 0)
                    return NF_DROP;
            }

            /* no other rules to check; ACCEPT by default */
            return NF_ACCEPT;
        default:
            RET(1, NF_MAX_VERDICT + 1, "invlid chain: %u", chain);
    }

    UPDATE_TIMER(verd_hmac_verif_ctr, start_marker);
    ARM_TIMER(start_marker);

    /* extract layer 3 features (for readablity & ease of access) */
    src_ip   = iph->saddr;
    dst_ip   = iph->daddr;
    l4_proto = iph->protocol;

    /* extract layer 4 features (based on protocol)                 *
     * NOTE: {src,dst}_port must not be used unitialized further on */
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
        default:
            known_l4 = 0;
    }

    UPDATE_TIMER(verd_field_extr_ctr, start_marker);

    /* for each rule in chain */
    for (auto& rule : *sel_chain) {
        /* clear any object hashes from previous iterations */
        ARM_TIMER(start_marker);
        hashes.clear();
        UPDATE_TIMER(verd_hashes_clear_ctr, start_marker);

        /* check layer 3 fields */
        if ((rule.flags & FLT_SRC_IP)
            && (((src_ip & rule.src_ip_mask) != rule.src_ip)
                == !(rule.flags & FLT_SRC_IP_INV)))
            continue;
        if ((rule.flags & FLT_DST_IP)
            && (((dst_ip & rule.dst_ip_mask) != rule.dst_ip)
                == !(rule.flags & FLT_DST_IP_INV)))
            continue;
        if ((rule.flags & FLT_L4_PROTO)
            && ((l4_proto != rule.l4_proto)
                == !(rule.flags & FLT_L4_PROTO_INV)))
            continue;

        /* skip to next rule if layer 4 protocol unsupported */
        if (!known_l4)
            continue;

        /* check layer 4 fields */
        if ((rule.flags & FLT_SRC_PORT)
            && ((src_port != rule.src_port)
                == !(rule.flags & FLT_SRC_PORT_INV)))
            continue;
        if ((rule.flags & FLT_DST_PORT)
            && ((dst_port != rule.dst_port)
                == !(rule.flags & FLT_DST_PORT_INV)))
            continue;

        /* if not checking process identity, consider this a match */
        if (!(rule.flags & FLT_HASH))
            return (rule.verdict & VRD_ACCEPT) ? NF_ACCEPT : NF_DROP;

        /* get current rule's namespace descriptors */
        ARM_TIMER(start_marker);
        auto [ netns_dev, netns_ino ] = nnc_fd_to_ns(rule.netns_fd);
        UPDATE_TIMER(verd_netns_lookup_ctr, start_marker);

        RET(netns_dev == -1 && netns_ino == -1, NF_MAX_VERDICT + 1,
            "unable to get target namespace device & inode numbers");

        /* switch to rule-specific namespace if different from current one *
         * NOTE: rule insertion was successful only because the net ns was *
         *       cached; it's safe to assume that it's readily available   */
        if (!skip_same_ns_switch
        || netns_dev != curr_netns_dev
        || netns_ino != curr_netns_ino)
        {
            ARM_TIMER(start_marker);
            ans = setns(rule.netns_fd, CLONE_NEWNET);
            UPDATE_TIMER(verd_netns_set_ctr, start_marker);

            RET(ans == -1, NF_MAX_VERDICT + 1,
                "unable to switch namespaces (%s)", strerror(errno));

            curr_netns_dev = netns_dev;
            curr_netns_ino = netns_ino;
        }

        /* obtain set of potential endpoint processes ids                     *
         * failure to do so means that the match criteria can not be verified */
        ARM_TIMER(start_marker);
        pid_set_p = sc_get_pid(l4_proto, src_ip, dst_ip,
                        chain == INPUT_CHAIN ? dst_port : src_port,
                        chain == INPUT_CHAIN ? src_port : dst_port,
                        netns_dev, netns_ino);
        UPDATE_TIMER(verd_pidset_lookup_ctr, start_marker);

        if (!pid_set_p)
            continue;

        /* get hashes of memory mapped objects (alphabetically ordered by path) */
        ARM_TIMER(start_marker_2);

        ARM_TIMER(start_marker);
        hashes.resize(pid_set_p->size());
        UPDATE_TIMER(verd_hashes_resize_ctr, start_marker);
        pid_idx = 0;

        for (auto pid_it : *pid_set_p) {
            ARM_TIMER(start_marker);
            auto maps = hc_get_maps(pid_it);
            UPDATE_TIMER(verd_hashes_lookup_ctr, start_marker);

            for (auto& map_it : maps) {
                /* get sha256 digest of object (unlikely to fail -> report it) */
                ARM_TIMER(start_marker);
                md = hc_get_sha256((char *) map_it.c_str());
                UPDATE_TIMER(verd_hash_calc_ctr, start_marker);

                RET(!md, NF_MAX_VERDICT + 1, "could not get sha256 digest of %s",
                    map_it.c_str());

                /* push hashes to vector in object's order in set */
                ARM_TIMER(start_marker);
                hashes[pid_idx].push_back(md);
                UPDATE_TIMER(verd_hash_push_ctr, start_marker);
            }

            /* continue to next process */
            pid_idx++;
        }

        UPDATE_TIMER(verd_pidset_hashcalc_ctr, start_marker_2);
        ARM_TIMER(start_marker);

        /* check single hash match                                  *
         * NOTE: if verdict is DROP, one process is enough to match *
         *       if verdict is ACCEPT, all processes must match     *
         *       check inversion does not affect the above          */
        if (rule.flags & FLT_SINGLE_HASH) {
            /* for each process that could have sent this packet */
            for (auto& pm : hashes) {
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
            for (auto& pm : hashes) {
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

        UPDATE_TIMER(verd_hash_verif_ctr, start_marker);
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

            /* get reference to target net namespace */
            reqm.rule.netns_fd = nnc_get_fd(reqm.rule.netns_file);
            if (reqm.rule.netns_fd == -1) {
                WAR("invalid netns magic file");
                rspm.msg.flags |= CTL_NACK;
                goto common_short_resp;
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
                sel_chain = &input_chain;
            else if (reqm.msg.flags & CTL_OUTPUT)
                sel_chain = &output_chain;
            else {
                WAR("no chain specified");
                rspm.msg.flags |= CTL_NACK;
                goto common_short_resp;
            }

            /* get reference to target net namespace */
            reqm.rule.netns_fd = nnc_get_fd(reqm.rule.netns_file);
            if (reqm.rule.netns_fd == -1) {
                WAR("invalid netns magic file");
                rspm.msg.flags |= CTL_NACK;
                goto common_short_resp;
            }

            /* append rule */
            sel_chain->push_back(reqm.rule);

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

            /* release reference to target net namespace */
            ans = nnc_release_ns(it->netns_file);
            ALERT(ans == -1, "unable to release namespace");

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

