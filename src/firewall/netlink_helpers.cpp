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

#include <unistd.h>             /* read, write, close, getpid, readlink */
#include <string.h>             /* memset                               */
#include <sys/socket.h>         /* socket                               */
#include <linux/netlink.h>      /* NETLINK_CONNECTOR                    */
#include <linux/sock_diag.h>    /* SOCK_DIAG_BY_FAMILY                  */
#include <linux/inet_diag.h>    /* inet_diag_req_v2                     */
#include <queue>                /* priority_queue                       */

#include "sock_cache.h"         /* socket cache API                     */
#include "hash_cache.h"         /* object hash cache API                */
#include "proc_events.h"        /* timestamped event struct definition  */
#include "netlink_helpers.h"
#include "util.h"

using namespace std;

#pragma clang diagnostic ignored "-Wenum-compare-switch"

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

/* internal data structures
 *  exit_events - pids of processes that have exited (to be processed later)
 */
static priority_queue<struct ts_event<uint32_t>> exit_events;

/******************************************************************************
 ********************************* PUBLIC API *********************************
 ******************************************************************************/

int32_t nl_socket(int socket_type, int netlink_family);
int32_t nl_proc_ev_connect(void);
int32_t nl_proc_ev_subscribe(int nl_fd, bool enable);
int32_t nl_proc_ev_handle(int nl_fd);
void    nl_delayed_ev_handle(uint64_t delta_t);
int32_t nl_sock_diag(int32_t  nl_fd, uint8_t  protocol, uint32_t src_addr,
                     uint32_t dst_addr, uint16_t src_port, uint16_t dst_port,
                     uint32_t *inode_p);

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* nl_socket - opens a netlink socket but does not bind it
 *  @socket_type    : SOCK_RAW or SOCK_DGRAM; they are equivalent
 *  @netlink_family : kernel module to interact with; choice between:
 *                      NETLINK_CONNECTOR -- kernel proc event subscription
 *                      NETLINK_INET_DIAG -- inet socket info querying
 *                    man(7) netlink for more options
 *
 *  @return : socket fd or -1 on error
 */
int32_t nl_socket(int socket_type, int netlink_family)
{
    return socket(AF_NETLINK, socket_type, netlink_family);
}

/* nl_connect - connects to netlink for proc event monitoring
 *
 *  @return : socket fd or -1 on error
 */
int32_t nl_proc_ev_connect(void)
{
    int nl_fd;                  /* netlink socket */
    int ans;                    /* answer         */
    struct sockaddr_nl nl_sa;   /* socket address */

    /* open netlink socket for kernel connector */
    nl_fd = nl_socket(SOCK_DGRAM, NETLINK_CONNECTOR);
    RET(nl_fd == -1, -1, "netlink socket open failed");

    /* bind socket */
    nl_sa.nl_family = AF_NETLINK;
    nl_sa.nl_groups = CN_IDX_PROC;
    nl_sa.nl_pid    = getpid();

    ans = bind(nl_fd, (struct sockaddr *) &nl_sa, sizeof(nl_sa));
    GOTO(ans == -1, cleanup, "could not bind netlink socket");

    /* everything went ok */
    return nl_fd;

    /* close netlink socket when failing to bind */
cleanup:
    close(nl_fd);
    return -1;
}

/* nl_proc_ev_subscribe - sets proc event subscription status
 *  @nl_fd  : netlink socket file descriptor
 *  @enable : subscription status to set
 *
 *  @return : 0 if everything went well
 */
int32_t nl_proc_ev_subscribe(int nl_fd, bool enable)
{
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;                 /* netlink header  */
        struct __attribute__((packed)) {        /* netlink payload */
            struct cn_msg         cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } msg;       /* netlink datagram */
    int ans;        /* answer           */

    /* configure header and payload values */
    memset(&msg, 0, sizeof(msg));

    msg.nl_hdr.nlmsg_len  = sizeof(msg);    /* total length        */
    msg.nl_hdr.nlmsg_pid  = getpid();       /* subscribing process */
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;     /* no fragmentation    */

    /* read more in Documentation/connector/connector.txt */
    msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);  /* data length         */
    msg.cn_msg.id.idx = CN_IDX_PROC;                 /* unique connector ID */
    msg.cn_msg.id.val = CN_VAL_PROC;                 /* unique connector ID */

    msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    /* send subscription request via socket */
    ans = write(nl_fd, &msg, sizeof(msg));
    RET(ans == -1, -1, "unable to send netlink subscription request");

    return 0;
}

/* nl_proc_ev_handle - process netlink proc event datagram
 *  @msg : netlink message buffer (contains proc event data)
 *
 *  @return : 0 if everything went well
 */
int32_t nl_proc_ev_handle(nldgram_t *msg)
{
    int32_t  ans;       /* answer     */
    uint32_t pid;       /* process id */

    /* determine event type */
    switch (msg->proc_ev.what) {
        case PROC_EVENT_FORK:
            /* update socket cache state */
            sc_proc_fork(msg->proc_ev.event_data.fork.parent_pid,
                         msg->proc_ev.event_data.fork.child_pid);

            break;
        case PROC_EVENT_EXEC:
            /* update socket cache state */
            sc_proc_exec(msg->proc_ev.event_data.exec.process_pid);

            break;
        case PROC_EVENT_PTRACE:

            break;
        case PROC_EVENT_EXIT:
            /* register exit event to be handled later, in NFQ handler */
            pid = msg->proc_ev.event_data.exit.process_pid;
            exit_events.emplace(pid);

            break;
        /* don't care */
        default:
            break;
    }

    return 0;
}

/* nl_delayed_ev_handle - handles delayed events
 *  @delta_t : minimum time difference in microsecs between emplacing the event
 *             and actually processing it
 *
 * for example, we don't want to process exit events for processes immediately
 * and free up the socket cache internal structures because packets still on
 * the path, that have not reached the Netfilter Queue & were processed will no
 * longer be recognized.
 */
void nl_delayed_ev_handle(uint64_t delta_t)
{
    tscval_t ts;    /* cycles (or us) since system boot */

    /* get elapsed time since system boot in microsecs */
    rdtsc(ts.low, ts.high);
    ts.raw = ts.raw * 1'000'000 / BASE_FREQ;

    /* for each event, ordered by emplacement time */
    while (exit_events.size()) {
        auto &ce = exit_events.top();

        /* break if time since emplacement is lower than delta */
        if (ts.raw - ce.ts < delta_t)
            break;

        /* process event (timeout already occurred) */
        sc_proc_exit(ce.ev_val);
        hc_proc_exit(ce.ev_val);

        /* pop element that was just processed from queue */
        exit_events.pop();
    }
}

/* nl_sock_diag - returns the inode of a specific named socket
 *  @protocol : IPPROTO_{TCP,UDP}
 *  @src_addr : network order source ip address      (0 if ignored)
 *  @dst_addr : network order destination ip address (0 if ignored)
 *  @src_port : network order source port            (0 if ignored)
 *  @dst_port : network order destination port       (0 if ignored)
 *  @inode_p  : pointer to buffer where inode will be stored
 *
 *  @return : 0 if everything went well
 *
 * If the address and port filters are not sufficient to uniquely identify a
 * socket, the function will terminate with error, return the inode of the
 * first resulting entry and print a warning. If the function fails for any
 * other reason, the inode buffer will be zeroed out.
 */
int32_t nl_sock_diag(uint8_t  protocol,
                     uint32_t src_addr,
                     uint32_t dst_addr,
                     uint16_t src_port,
                     uint16_t dst_port,
                     uint32_t *inode_p)
{
    struct msghdr           msg;            /* message chunk integrator   */
    struct nlmsghdr         nlh;            /* netlink header             */
    struct nlmsghdr         *nlh_it;        /* netlink header iterator    */
    struct inet_diag_req_v2 conn_req;       /* netlink diagnostic request */
    struct sockaddr_nl      sa;             /* socket address             */
    struct iovec            iov[2];         /* buffer aggregators         */
    struct inet_diag_msg    *diag_msg;      /* netlink diagnositc reponse */
    uint8_t                 recv_buf[4096]; /* netlink response buffer    */
    int32_t                 nl_fd;          /* netlink socket             */
    ssize_t                 ans;            /* answer                     */
    int32_t                 ret = -1;       /* return code                */

    /* open netlink socket for socket diagnostics */
    nl_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    RET(nl_fd == -1, 1, "unable to open netlink socket (%s)", strerror(errno));

    /* initial zeroing of structures */
    memset(&msg,      0, sizeof(msg));
    memset(&sa,       0, sizeof(sa));
    memset(&nlh,      0, sizeof(nlh));
    memset(&conn_req, 0, sizeof(conn_req));
    memset(inode_p,   0, sizeof(*inode_p));

    /* configure request parameters */
    sa.nl_family = AF_NETLINK;                        /* socket protocol     */

    conn_req.sdiag_family   = AF_INET;                /* target addr family  */
    conn_req.sdiag_protocol = protocol;               /* target protocol     */
    conn_req.idiag_states   = ~0;                     /* include all states  */

    nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(conn_req)); /* message length      */
    nlh.nlmsg_type  = SOCK_DIAG_BY_FAMILY;            /* message type        */
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;     /* request diag list   */

    conn_req.id.idiag_src[0] = src_addr;              /* src ip addr filter  */
    conn_req.id.idiag_dst[0] = dst_addr;              /* dst ip addr filter  */
    conn_req.id.idiag_sport  = src_port;              /* src port filter     */
    conn_req.id.idiag_dport  = dst_port;              /* dst port filter     */

    iov[0].iov_base = (void *) &nlh;                  /* include nl header   */
    iov[0].iov_len  = sizeof(nlh);                    /* nl header size      */
    iov[1].iov_base = (void *) &conn_req;             /* include payload     */
    iov[1].iov_len  = sizeof(conn_req);               /* payload size        */

    msg.msg_name    = (void*) &sa;                    /* sock address        */
    msg.msg_namelen = sizeof(sa);                     /* length of sock addr */
    msg.msg_iov     = iov;                            /* message segments    */
    msg.msg_iovlen  = 2;                              /* number of segments  */

    /* send socket diagnostic request */
    ans = sendmsg(nl_fd, &msg, 0);
    GOTO(ans == -1, clean_nl, "unable to send socket diagnostic request");

    /* wait for response (can come in multiple instances) */
    while (1) {
        ans = recv(nl_fd, recv_buf, sizeof(recv_buf), 0);
        GOTO(ans == -1, clean_nl, "unable to receive diagnostic data");

        /* for all parts of the full message */
        nlh_it = (struct nlmsghdr*) recv_buf;
        while(NLMSG_OK(nlh_it, ans)){
            /* check for error or response end */
            GOTO(nlh_it->nlmsg_type == NLMSG_ERROR, clean_nl, "NLMSG_ERROR");
            if (nlh_it->nlmsg_type == NLMSG_DONE) {
                ret = (*inode_p == 0);
                goto clean_nl;
            }

            /* extract payload from current message */
            diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh_it);

            /* check if filtering criteria were insufficient   *
             * NOTE: insufficient criteria -> multiple matches */
            if (*inode_p) {
                WAR("insufficient filtering criteria");
                goto clean_nl;
            }

            /* set inode value */
            *inode_p = diag_msg->idiag_inode;

            /* skip to next message in response                               *
             * NOTE: we don't just return 0 here because we want to check for *
             *       more responses; would indicate that filtering criteria   *
             *       were insufficient                                        */
            nlh_it = NLMSG_NEXT(nlh_it, ans);
        }
    }

clean_nl:
    close(nl_fd);

    /* unreachable */
    return ret;
}

