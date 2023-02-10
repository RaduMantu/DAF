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

#include <stdio.h>
#include <stdint.h>             /* [u]int*_t */
#include <signal.h>             /* signal, siginterrupt */
#include <unistd.h>             /* read, write, close, unlink */
#include <netinet/in.h>         /* IPPROTO_* */
#include <netinet/ip.h>         /* iphdr */
#include <netinet/tcp.h>        /* tcphdr */
#include <netinet/udp.h>        /* udphdr */
#include <sys/socket.h>         /* socket */
#include <sys/un.h>             /* sockaddr_un */
#include <sys/inotify.h>        /* inotify */
#include <sys/epoll.h>          /* epoll */
#include <sys/resource.h>       /* setrlimit */
#include <bpf/libbpf.h>         /* eBPF API */
#include <vector>               /* vector */

#include "firewall_args.h"
#include "netlink_helpers.h"
#include "ebpf_helpers.h"
#include "nfq_helpers.h"
#include "sock_cache.h"
#include "hash_cache.h"
#include "filter.h"
#include "signer.h"
#include "util.h"

using namespace std;

#define CTL_SOCK_NAME "/tmp/app_fw.socket"

static bool bml = false;    /* break main loop */

/* sigint_handler - sets <break main loop> variable to true
 */
static void sigint_handler(int)
{
    bml = true;
}

/* main - program entry point
 *  @argc : number of command line arguments & program name
 *  @argv : array of command line arguments & program name
 *
 *  @return : 0 if everything went well
 */
int32_t
main(int argc, char *argv[])
{
    int32_t                   ans;              /* answer                     */
    int32_t                   netlink_fd;       /* netlink socket             */
    int32_t                   inotify_fd;       /* inotify file descriptor    */
    int32_t                   nfqueue_fd_in;    /* nfq input file descriptor  */
    int32_t                   nfqueue_fd_out;   /* nfq output file descriptor */
    int32_t                   nfqueue_fd_fwd;   /* nfq fwd file descriptor    */
    int32_t                   bpf_map_fd;       /* eBPF map file descriptor   */
    int32_t                   epoll_fd;         /* main epoll file descriptor */
    int32_t                   epoll_p0_fd;      /* priority 0 (top) epoll fd  */
    int32_t                   epoll_p1_fd;      /* priority 1 epoll fd        */
    int32_t                   epoll_sel_fd;     /* selected epoll fd          */
    struct epoll_event        epoll_ev[2];      /* epoll events               */
    struct sigaction          act;              /* signal response action     */
    struct rlimit             rlim;             /* resource limit             */
    struct bpf_object         *bpf_obj;         /* eBPF object file           */
    struct bpf_program        *bpf_prog;        /* eBPF program in obj        */
    vector<struct bpf_link *> bpf_links;        /* links to attached programs */
    struct ring_buffer        *bpf_ringbuf;     /* eBPF ring buffer reference */
    struct nfq_handle         *nf_handle_in;    /* NFQUEUE input handle       */
    struct nfq_q_handle       *nfq_handle_in;   /* netfilter input handle     */
    struct nfq_handle         *nf_handle_out;   /* NFQUEUE output handle      */
    struct nfq_q_handle       *nfq_handle_out;  /* netfilter output handle    */
    struct nfq_op_param       nfq_opp;          /* nfq operational parameters */
    struct sockaddr_un        us_name;          /* unix socket name           */
    int32_t                   us_csock_fd;      /* unix connection socket     */
    uint8_t                   pkt_buff[0xffff]; /* nfq packet buffer          */
    char                      usr_input[256];   /* user stdin input buffer    */
    ssize_t                   rb;               /* bytes read                 */

    /* parse command line arguments */
    ans = argp_parse(&argp, argc, argv, 0, 0, &cfg);
    DIE(ans, "error parsing cli arguments");
    INFO("parsed cli arguments");

    /* set gracious behaviour for Ctrl^C signal                            *
     * because SA_RESTART is not set, interrupted syscalls fail with EINTR */
    memset(&act, 0, sizeof(act));
    act.sa_handler = sigint_handler;
    ans = sigaction(SIGINT, &act, NULL);
    DIE(ans == -1, "unable to set new SIGINT handler (%s)", strerror(errno));

    /* increase resource limit for eBPF ringbuffer */
    rlim = {RLIM_INFINITY, RLIM_INFINITY};
    ans = setrlimit(RLIMIT_MEMLOCK, &rlim);
    DIE(ans == -1, "unable to set resource limit (%s)", strerror(errno));
    INFO("set new resource limits");

    /* initialize socket cache context */
    ans = sc_init();
    DIE(ans, "unable to initialize socket cache context");
    INFO("initialized socket cache context");

    /* initialize hash cache context */
    ans = hc_init(cfg.retain_maps, cfg.no_rescan);
    DIE(ans, "unable to initialize hash cache context");
    INFO("initialized hash cache context");

    /* initialze packet signer context */
    ans = signer_init(cfg.secret_path, cfg.sig_type);
    DIE(ans, "unable to initialize packet signer context");
    INFO("initialized packet signer context");

    /* create ctl unix socket */
    us_csock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    DIE(us_csock_fd == -1, "unable to open AF_UNIX socket (%s)",
        strerror(errno));
    INFO("created ctl unix socket");

    /* bind ctl unix socket to name */
    memset(&us_name, 0, sizeof(us_name));
    us_name.sun_family = AF_UNIX;
    strncpy(us_name.sun_path, CTL_SOCK_NAME, sizeof(us_name.sun_path) - 1);

    ans = bind(us_csock_fd, (struct sockaddr *) &us_name, sizeof(us_name));
    GOTO(ans == -1, clean_us_csock_fd,
        "unable to bind ctl unix socket to name (%s)", strerror(errno));
    INFO("bound ctl unix socket to name");

    /* connect to netlink */
    netlink_fd = nl_proc_ev_connect();
    GOTO(netlink_fd == -1, clean_us_csock_fd,
        "failed to establish netlink connection");
    INFO("netlink connection established");

    /* create inotify instance */
    inotify_fd = inotify_init1(IN_CLOEXEC);
    GOTO(inotify_fd == -1, clean_netlink_fd,
        "failed to create inotify instance (%s)", strerror(errno));
    INFO("inotify instance created");

    /* open eBPF object file */
    bpf_obj = bpf_object__open_file(cfg.ebpf_path, NULL);
    GOTO(libbpf_get_error(bpf_obj), clean_inotify_fd,
        "unable to open eBPF object");
    INFO("opened eBPF object file");

    /* load eBPF object into kernel verifier */
    ans = bpf_object__load(bpf_obj);
    GOTO(ans, clean_bpf_obj, "unable to load eBPF object");
    INFO("loaded eBPF object file (passed verification)");

    /* get reference to map of RINGBUF type */
    bpf_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "buffer");
    GOTO(bpf_map_fd < 0, clean_bpf_obj, "ubable to find ringbuffer map");
    INFO("got eBPF ringbuffer map");

    /* create ringbuffer */
    bpf_ringbuf = ring_buffer__new(bpf_map_fd, process_ebpf_sample, NULL, NULL);
    GOTO(!bpf_ringbuf, clean_bpf_obj, "unable to create ringbuffer");
    INFO("created eBPF ringbuffer");

    /* set netfilter queue operational parameters */
    nfq_opp.proc_delay = cfg.proc_delay;
    nfq_opp.policy_in  = cfg.policy_in;
    nfq_opp.policy_out = cfg.policy_out;

    /* prepare input NFQ */
    nf_handle_in = nfq_open();
    GOTO(!nf_handle_in, clean_bpf_rb,
        "unable to open input nfq handle (%s)", strerror(errno));
    INFO("opened input nfq handle");

    nfq_handle_in = nfq_create_queue(nf_handle_in, cfg.queue_num_in,
                        nfq_in_handler, &nfq_opp);
    GOTO(!nfq_handle_in, clean_nf_handle_in);
    INFO("bound to netfilter queue: %d", cfg.queue_num_in);

    ans = nfq_set_mode(nfq_handle_in, NFQNL_COPY_PACKET, sizeof(pkt_buff));
    GOTO(ans < 0, clean_nf_queue_in, "unable to set input nfq mode (%s)",
        strerror(errno));
    INFO("configured nfq input packet handling parameters");

    nfqueue_fd_in = nfq_fd(nf_handle_in);
    INFO("obtained file descriptor of associated nfq output socket");

    /* prepare output NFQ */
    nf_handle_out = nfq_open();
    GOTO(!nf_handle_out, clean_nf_handle_out,
        "unable to open output nfq handle (%s)", strerror(errno));
    INFO("opened output nfq handle");

    nfq_handle_out = nfq_create_queue(nf_handle_out, cfg.queue_num_out,
                        nfq_out_handler, &nfq_opp);
    GOTO(!nfq_handle_out, clean_nf_handle_out,
        "unable to bind to output nfqueue (%s)", strerror(errno));
    INFO("bound to netfilter queue: %d", cfg.queue_num_out);

    ans = nfq_set_mode(nfq_handle_out, NFQNL_COPY_PACKET, sizeof(pkt_buff));
    GOTO(ans < 0, clean_nf_queue_out, "unable to set output nfq mode (%s)",
        strerror(errno));
    INFO("configured nfq output packet handling parameters");

    nfqueue_fd_out = nfq_fd(nf_handle_out);
    INFO("obtained file descriptor of associated nfq output socket");

    /* create top level epoll instance */
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    GOTO(epoll_fd == -1, clean_nf_queue_out, "failed to create epoll instance (%s)",
        strerror(errno));
    INFO("top level epoll instance created");

    /* create priority ordering epoll instances */
    epoll_p0_fd = epoll_create1(EPOLL_CLOEXEC);
    GOTO(epoll_p0_fd == -1, clean_epoll_fd,
        "failed to create epoll instance (%s)", strerror(errno));
    INFO("priority-0 epoll instance created");

    epoll_p1_fd = epoll_create1(EPOLL_CLOEXEC);
    GOTO(epoll_p1_fd == -1, clean_epoll_fd_p0,
        "failed to create epoll instance (%s)", strerror(errno));
    INFO("priority-1 epoll instance created");

    /* add ctl unix socket to epoll watchlist (top prio) */
    epoll_ev[0].data.fd = us_csock_fd;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, us_csock_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add ctl unix socket to epoll monitor (%s)", strerror(errno));
    INFO("ctl unix socket added to epoll-p0 monitor");

    /* add netlink socket to epoll watchlist (top prio) */
    epoll_ev[0].data.fd = netlink_fd;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, netlink_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add netlink to epoll monitor (%s)", strerror(errno));
    INFO("netlink socket added to epoll-p0 monitor");

    /* add inotify instance to epoll watchlist (top prio) */
    epoll_ev[0].data.fd = inotify_fd;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, inotify_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add inotify to epoll monitor (%s)", strerror(errno));
    INFO("inotify instance added to epoll-p0 monitor");

    /* add eBPF ringbuffer to epoll watchlist (top prio) */
    epoll_ev[0].data.fd = bpf_map_fd;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, bpf_map_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add eBPF ringbuffer to epoll monitor (%s)", strerror(errno));
    INFO("eBPF ringbuffer added to epoll-p0 monitor");

    /* add input netfilter queue to epoll watchlist (bottom prio) */
    epoll_ev[0].data.fd = nfqueue_fd_in;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_p1_fd, EPOLL_CTL_ADD, nfqueue_fd_in, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add netfilter input queue to epoll-p1 monitor (%s)",
        strerror(errno));
    INFO("netfilter input queue added to epoll monitor");

    /* add output netfilter queue to epoll watchlist (bottom prio) */
    epoll_ev[0].data.fd = nfqueue_fd_out;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_p1_fd, EPOLL_CTL_ADD, nfqueue_fd_out, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add netfilter output queue to epoll-p1 monitor (%s)",
        strerror(errno));
    INFO("netfilter output queue added to epoll monitor");

    /* add stdin to epoll watchlist (bottom prio) */
    epoll_ev[0].data.fd = STDIN_FILENO;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, STDIN_FILENO, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add stdin to epoll-p1 monitor");
    INFO("stdin added to epoll monitor");

    /* add priority ordering epoll instances to top level epoll selector */
    epoll_ev[0].data.fd = epoll_p0_fd;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, epoll_p0_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add epoll-p0 to epoll monitor (%s)", strerror(errno));
    INFO("epoll-p0 added to top level epoll monitor");

    epoll_ev[0].data.fd = epoll_p1_fd;
    epoll_ev[0].events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, epoll_p1_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add epoll-p1 to epoll monitor (%s)", strerror(errno));
    INFO("epoll-p1 added to top level epoll monitor");

    /* listen for new connections on ctl unix socket */
    ans = listen(us_csock_fd, 1);
    GOTO(ans == -1, clean_epoll_fd_p1, "failed to listen on unix socket (%s)",
        strerror(errno));
    INFO("listening for new connections on ctl unix socket");

    /* subscribe to netlink proc events */
    ans = nl_proc_ev_subscribe(netlink_fd, true);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to subscribe to netlink proc events");
    INFO("now subscribed to netlink proc events");

    /* attach all available eBPF programs to respective tracepoints */
    bpf_object__for_each_program(bpf_prog, bpf_obj) {
        struct bpf_link *bpf_link = bpf_program__attach(bpf_prog);
        GOTO(!bpf_link, clean_netlink_sub, "unable to attach eBPF program: %s",
            bpf_program__name(bpf_prog));

        /* keep track of links for later unload */
        bpf_links.push_back(bpf_link);
    }

    /* main loop */
    INFO("main loop starting");
    while (!bml) {
        /* wait for top level epoll event */
        ans = epoll_wait(epoll_fd, epoll_ev, 2, -1);
        DIE(ans == -1 && errno != EINTR, "error waiting for epoll events (%s)",
            strerror(errno));

        /* determine if any of the (max 2) events were top priority */
        epoll_sel_fd = epoll_p1_fd;
        for (size_t i=0; i<ans; ++i)
            if (epoll_ev[i].data.fd == epoll_p0_fd) {
                epoll_sel_fd = epoll_p0_fd;
                break;
            }

        /* we know that event is available on selected priority level *
         * here we prioritize events relating to sockets, not NFQ     */
        ans = epoll_wait(epoll_sel_fd, &epoll_ev[0], 1, -1);
        DIE(ans == -1 && errno != EINTR, "error waiting for epoll events (%s)",
            strerror(errno));

        /* handle event */
        if (epoll_ev[0].data.fd == us_csock_fd) {
            ans = flt_handle_ctl(us_csock_fd);
        } else if (epoll_ev[0].data.fd == netlink_fd) {
            ans = nl_proc_ev_handle(netlink_fd);
        } else if (epoll_ev[0].data.fd == inotify_fd) {
            /* TODO */
        } else if (epoll_ev[0].data.fd == bpf_map_fd) {
            ans = ring_buffer__consume(bpf_ringbuf);
            ALERT(ans < 0, "failed to consume eBPF ringbuffer sample");
        } else if (epoll_ev[0].data.fd == nfqueue_fd_out) {
            rb = read(nfqueue_fd_out, pkt_buff, sizeof(pkt_buff));
            if(rb == -1) {
                WAR("failed to read packet from nf queue (%s)",
                    strerror(errno));
                continue;
            }

            nfq_handle_packet(nf_handle_out, (char *) pkt_buff, rb);
        } else if (epoll_ev[0].data.fd == nfqueue_fd_in) {
            rb = read(nfqueue_fd_in, pkt_buff, sizeof(pkt_buff));
            if(rb == -1) {
                WAR("failed to read packet from nf queue (%s)",
                    strerror(errno));
                continue;
            }

            nfq_handle_packet(nf_handle_in, (char *) pkt_buff, rb);
        } else if (epoll_ev[0].data.fd == STDIN_FILENO) {
            rb = read(STDIN_FILENO, usr_input, sizeof(usr_input));
            if(rb == -1) {
                WAR("failed to read stdin input (%s)", strerror(errno));
                continue;
            }

            /* print debug info on user request */
            sc_dump_state();
        }
    }
    WAR("exited main loop");

clean_bpf_links:
    for (auto& bpf_link : bpf_links) {
        ans = bpf_link__destroy(bpf_link);
        ALERT(ans, "failed to destroy eBPF link");
        INFO("destroyed eBPF program link");
    }

clean_netlink_sub:
    ans = nl_proc_ev_subscribe(netlink_fd, false);
    ALERT(ans == -1, "failed to unsubscribe from netlink proc events");
    INFO("unsubscribed from netlink proc events");

clean_epoll_fd_p1:
    ans = close(epoll_p1_fd);
    ALERT(ans == -1, "failed to close epoll instance (%s)", strerror(errno));
    INFO("closed epoll-p1 instance");

clean_epoll_fd_p0:
    ans = close(epoll_p0_fd);
    ALERT(ans == -1, "failed to close epoll instance (%s)", strerror(errno));
    INFO("closed epoll-p0 instance");

clean_epoll_fd:
    ans = close(epoll_fd);
    ALERT(ans == -1, "failed to close epoll instance (%s)", strerror(errno));
    INFO("closed top level epoll instance");

clean_nf_queue_out:
    nfq_destroy_queue(nfq_handle_out);
    INFO("destroyed netfilter output queue");

clean_nf_handle_out:
    ans = nfq_close(nf_handle_out);
    ALERT(ans, "failed to close nfq output handle");
    INFO("closed nfq output handle");

clean_nf_queue_in:
    nfq_destroy_queue(nfq_handle_in);
    INFO("destroyed netfilter input queue");

clean_nf_handle_in:
    ans = nfq_close(nf_handle_in);
    ALERT(ans, "failed to close nfq input handle");
    INFO("closed nfq output handle");

clean_bpf_rb:
    ring_buffer__free(bpf_ringbuf);
    INFO("freed eBPF ringbuffer");

clean_bpf_obj:
    bpf_object__close(bpf_obj);
    INFO("closed eBPF object");

clean_inotify_fd:
    ans = close(inotify_fd);
    ALERT(ans == -1, "failed to close inotify instance (%s)", strerror(errno));
    INFO("closed inotify instance");

clean_netlink_fd:
    ans = close(netlink_fd);
    ALERT(ans == -1, "failed to close netlink instance (%s)", strerror(errno));
    INFO("closed netlink instance");

clean_us_csock_fd:
    ans = close(us_csock_fd);
    ALERT(ans == -1, "failed to close ctl unix socket (%s)", strerror(errno));
    INFO("closed ctl unix socket");

    ans = unlink(CTL_SOCK_NAME);
    ALERT(ans == -1, "failed to unlink named socket %s (%s)", CTL_SOCK_NAME,
        strerror(errno));
    INFO("destroyed named unix socket");

    return 0;
}

