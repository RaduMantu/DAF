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
#include <stdint.h>             /* [u]int*_t                          */
#include <signal.h>             /* signal, siginterrupt, pthread_kill */
#include <unistd.h>             /* read, write, close, unlink, nice   */
#include <netinet/in.h>         /* IPPROTO_*                          */
#include <netinet/ip.h>         /* iphdr                              */
#include <netinet/tcp.h>        /* tcphdr                             */
#include <netinet/udp.h>        /* udphdr                             */
#include <sys/socket.h>         /* socket, getsockopt                 */
#include <sys/un.h>             /* sockaddr_un                        */
#include <sys/inotify.h>        /* inotify                            */
#include <sys/epoll.h>          /* epoll                              */
#include <sys/resource.h>       /* setrlimit                          */
#include <bpf/libbpf.h>         /* eBPF API                           */
#include <vector>               /* std::vector                        */
#include <queue>                /* std::queue                         */

#include <libnfnetlink/libnfnetlink.h>      /* nfnl_rcvbufsiz */

#include "firewall_args.h"
#include "netlink_helpers.h"
#include "ebpf_helpers.h"
#include "nfq_helpers.h"
#include "uring_helpers.h"
#include "sock_cache.h"
#include "hash_cache.h"
#include "filter.h"
#include "signer.h"
#include "util.h"

using namespace std;

/* NOTE: pkt buffer should have some extra space for netlink header. *
 *       expect arbitrary amounts of padding depending on the range  *
 *       set in nfq_set_mode().                                      */
#define PKT_MAX_SZ    (0xffff + 128)
#define CTL_SOCK_NAME "/tmp/app_fw.socket"

static bool terminate = false;    /* program pending termination */

/* configured by main thread */
static int32_t            us_csock_fd;      /* unix connection socket       */
static int32_t            netlink_fd;       /* netlink socket               */
static int32_t            inotify_fd;       /* inotify file descriptor      */
static int32_t            bpf_map_fd;       /* eBPF map file descriptor     */
static int32_t            nfqueue_fd_in;    /* nfq input file descriptor    */
static int32_t            nfqueue_fd_out;   /* nfq output file descriptor   */
static int32_t            nfqueue_fd_fwd;   /* nfq fwd file descriptor      */
static struct nfq_handle  *nf_handle_in;    /* NFQUEUE input handle         */
static struct nfq_handle  *nf_handle_out;   /* NFQUEUE output handle        */
static struct nfq_handle  *nf_handle_fwd;   /* NFQUEUE forward handle       */
static struct ring_buffer *bpf_ringbuf;     /* eBPF ring buffer reference   */

/* elapsed time counters */
static struct timeval program_start_marker;
static struct timeval start_marker;

static uint64_t fw_ctl_ctr       = 0;
static uint64_t netlink_ctr      = 0;
static uint64_t bpf_rb_ctr       = 0;
static uint64_t nfq_read_out_ctr = 0;
static uint64_t nfq_eval_out_ctr = 0;
static uint64_t nfq_read_in_ctr  = 0;
static uint64_t nfq_eval_in_ctr  = 0;
static uint64_t nfq_read_fwd_ctr = 0;
static uint64_t nfq_eval_fwd_ctr = 0;

/* sigint_handler - sets <break main loop> variable to true
 */
static void
sigint_handler(int)
{
    terminate = true;
}

#ifdef ENABLE_STATS
/* print_stats - shows elapsed time statistics on STDIN
 */
static void
print_stats(void)
{
    uint64_t main_loop_elapsed = 0;
    UPDATE_TIMER(main_loop_elapsed, program_start_marker);

    uint8_t buff[128];
    read(STDIN_FILENO, buff, sizeof(buff));

    DEBUG("Elapsed times [ms]");
    DEBUG("  - Processing user command       : %8.2lf (%6.2lf%%)",
          fw_ctl_ctr / 1e3, 1e2 * fw_ctl_ctr / main_loop_elapsed);
    DEBUG("  - Processing netlink events     : %8.2lf (%6.2lf%%)",
          netlink_ctr / 1e3, 1e2 * netlink_ctr / main_loop_elapsed);
    DEBUG("  - Processing eBPF events        : %8.2lf (%6.2lf%%)",
          bpf_rb_ctr / 1e3, 1e2 * bpf_rb_ctr / main_loop_elapsed);

    DEBUG("  - Reading NFQ packet (OUT)      : %8.2lf (%6.2lf%%)",
          nfq_read_out_ctr / 1e3, 1e2 * nfq_read_out_ctr / main_loop_elapsed);
    DEBUG("  - Evaluating NFQ packet (OUT)   : %8.2lf (%6.2lf%%)",
          nfq_eval_out_ctr / 1e3, 1e2 * nfq_eval_out_ctr / main_loop_elapsed);
    DEBUG("    - Extracting packet           : %8.2lf (%6.2lf%%)",
          nfqouth_extract_ctr / 1e3,
          1e2 * nfqouth_extract_ctr / main_loop_elapsed);
    DEBUG("    - Delayed events              : %8.2lf (%6.2lf%%)",
          nfqouth_delayedev_ctr / 1e3,
          1e2 * nfqouth_delayedev_ctr / main_loop_elapsed);
    DEBUG("    - Verdict calculation         : %8.2lf (%6.2lf%%)",
          nfqouth_verdict_ctr / 1e3,
          1e2 * nfqouth_verdict_ctr / main_loop_elapsed);
    DEBUG("    - Verdict reporting           : %8.2lf (%6.2lf%%)",
          nfqouth_report_ctr / 1e3,
          1e2 * nfqouth_report_ctr / main_loop_elapsed);

    DEBUG("  - Reading NFQ packet (IN)       : %8.2lf (%6.2lf%%)",
          nfq_read_in_ctr / 1e3, 1e2 *  nfq_read_in_ctr / main_loop_elapsed);
    DEBUG("  - Evaluating NFQ packet (IN)    : %8.2lf (%6.2lf%%)",
          nfq_eval_in_ctr / 1e3, 1e2 * nfq_eval_in_ctr / main_loop_elapsed);
    DEBUG("    - Extracting packet           : %8.2lf (%6.2lf%%)",
          nfqinh_extract_ctr / 1e3,
          1e2 * nfqinh_extract_ctr / main_loop_elapsed);
    DEBUG("    - Delayed events              : %8.2lf (%6.2lf%%)",
          nfqinh_delayedev_ctr / 1e3,
          1e2 * nfqinh_delayedev_ctr / main_loop_elapsed);
    DEBUG("    - Verdict calculation         : %8.2lf (%6.2lf%%)",
          nfqinh_verdict_ctr / 1e3,
          1e2 * nfqinh_verdict_ctr / main_loop_elapsed);
    DEBUG("    - Verdict reporting           : %8.2lf (%6.2lf%%)",
          nfqinh_report_ctr / 1e3,
          1e2 * nfqinh_report_ctr / main_loop_elapsed);

    DEBUG("  - Reading NFQ packet (FWD)      : %8.2lf (%6.2lf%%)",
          nfq_read_fwd_ctr / 1e3, 1e2 * nfq_read_fwd_ctr / main_loop_elapsed);
    DEBUG("  - Evaluating NFQ packet (FWD)   : %8.2lf (%6.2lf%%)",
          nfq_eval_fwd_ctr / 1e3, 1e2 * nfq_eval_fwd_ctr / main_loop_elapsed);
    DEBUG("    - Extracting packet           : %8.2lf (%6.2lf%%)",
          nfqfwdh_extract_ctr / 1e3,
          1e2 * nfqfwdh_extract_ctr / main_loop_elapsed);
    DEBUG("    - Delayed events              : %8.2lf (%6.2lf%%)",
          nfqfwdh_delayedev_ctr / 1e3,
          1e2 * nfqfwdh_delayedev_ctr / main_loop_elapsed);
    DEBUG("    - Verdict calculation         : %8.2lf (%6.2lf%%)",
          nfqfwdh_verdict_ctr / 1e3,
          1e2 * nfqfwdh_verdict_ctr / main_loop_elapsed);
    DEBUG("    - Verdict reporting           : %8.2lf (%6.2lf%%)",
          nfqfwdh_report_ctr / 1e3,
          1e2 * nfqfwdh_report_ctr / main_loop_elapsed);

    DEBUG("");
    DEBUG("  - Packet HMAC verification      : %8.2lf (%6.2lf%%)",
          verd_hmac_verif_ctr / 1e3,
          1e2 * verd_hmac_verif_ctr / main_loop_elapsed);
    DEBUG("  - L3,4 field extraction         : %8.2lf (%6.2lf%%)",
          verd_field_extr_ctr / 1e3,
          1e2 * verd_field_extr_ctr / main_loop_elapsed);
    DEBUG("  - Previous obj hashset clear    : %8.2lf (%6.2lf%%)",
          verd_hashes_clear_ctr / 1e3,
          1e2 * verd_hashes_clear_ctr / main_loop_elapsed);
    DEBUG("  - Network namespace lookup      : %8.2lf (%6.2lf%%)",
          verd_netns_lookup_ctr / 1e3,
          1e2 * verd_netns_lookup_ctr / main_loop_elapsed);
    DEBUG("  - Network namespace change      : %8.2lf (%6.2lf%%)",
          verd_netns_set_ctr / 1e3,
          1e2 * verd_netns_set_ctr / main_loop_elapsed);
    DEBUG("  - Pidset lookup                 : %8.2lf (%6.2lf%%)",
          verd_pidset_lookup_ctr / 1e3,
          1e2 * verd_pidset_lookup_ctr / main_loop_elapsed);
    DEBUG("  - Pidset obj hash calculation   : %8.2lf (%6.2lf%%)",
          verd_pidset_hashcalc_ctr / 1e3,
          1e2 * verd_pidset_hashcalc_ctr / main_loop_elapsed);
    DEBUG("    - Object hashset resize       : %8.2lf (%6.2lf%%)",
          verd_hashes_resize_ctr / 1e3,
          1e2 * verd_hashes_resize_ctr / main_loop_elapsed);
    DEBUG("    - Reference hashset lookup    : %8.2lf (%6.2lf%%)",
          verd_hashes_lookup_ctr / 1e3,
          1e2 * verd_hashes_lookup_ctr / main_loop_elapsed);
    DEBUG("    - Object hash calculation     : %8.2lf (%6.2lf%%)",
          verd_hash_calc_ctr / 1e3,
          1e2 * verd_hash_calc_ctr / main_loop_elapsed);
    DEBUG("    - Object hash push to hashset : %8.2lf (%6.2lf%%)",
          verd_hash_push_ctr / 1e3,
          1e2 * verd_hash_push_ctr / main_loop_elapsed);
    DEBUG("  - Object hash verification      : %8.2lf (%6.2lf%%)",
          verd_hash_verif_ctr / 1e3,
          1e2 * verd_hash_verif_ctr / main_loop_elapsed);

    DEBUG("");
    DEBUG("  - Total main loop time          : %8.2lf [ms]",
          main_loop_elapsed / 1e3);
    DEBUG("");
    DEBUG("  - Packets processed (OUTPUT)    : %8lu (%8.2lf pps)",
          nfqouth_packets_ctr,
          1e6 * nfqouth_packets_ctr / main_loop_elapsed);
    DEBUG("  - Packets processed (INPUT)     : %8lu (%8.2lf pps)",
          nfqinh_packets_ctr,
          1e6 * nfqinh_packets_ctr / main_loop_elapsed);
    DEBUG("  - Packets processed (FORWARD)   : %8lu (%8.2lf pps)",
          nfqfwdh_packets_ctr,
          1e6 * nfqfwdh_packets_ctr / main_loop_elapsed);
}
#endif /* ENABLE_STATS */

/* adjust_buffer_size - increases netlink socket recv buffer size
 *  @fd     : file descriptor of socket
 *  @handle : NetfilterQueue handle used internally for setsockopt()
 *
 *  return : 0 if everything went well; !0 otherwise
 *
 * NOTE: libnfnetlink will try to use SO_RCVBUFFORCE initially, thus overriding
 *       the system maximum of `net.core.rmem_max`. normally, this should work
 *       because in all likelyhood this process will have CAP_NET_ADMIN and the
 *       kernel will be newer than 2.6.14.
 *
 * NOTE: although this function _technically_ doubles the current socket size,
 *       the kernel will double it again to make space for bookkeeping overhead.
 *       for more information on this, see the SO_RCVBUF entry in man.7 socket.
 */
static int32_t
adjust_buffer_size(int32_t fd, struct nfq_handle *handle)
{
    ssize_t   ans;      /* answer               */
    uint32_t  sock_sz;  /* current socket size  */
    uint32_t  new_sz;   /* new socket size      */
    socklen_t opt_len;  /* sockopt variable len */

    /* get current netlink socket buffer size */
    opt_len = sizeof(sock_sz);
    ans = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *) &sock_sz, &opt_len);
    RET(ans == -1, -1, "unable to determine socket buffer size (%s)",
        strerror(errno));

    /* clamp new socket size */
    new_sz = sock_sz * 2;
    if (new_sz > cfg.max_nl_bufsz)
        new_sz = cfg.max_nl_bufsz;

    /* avoid one or more setsockopt() calls if not necessary */
    if (new_sz == sock_sz)
        return 0;

    /* attempt to double the socket size via the nfnl interface */
    ans = nfnl_rcvbufsiz(nfq_nfnlh(handle), new_sz);
    RET(ans == 0, -1, "unable to set netlink socket buffer size (%s)",
        strerror(errno));

    DEBUG("adjusted netlink socket buffer size: %u -> %u [bytes]",
          sock_sz, new_sz);

    return 0;
}

/******************************************************************************
 **************************** PROGRAM ENTRY POINT *****************************
 ******************************************************************************/

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
    struct sigaction          act;              /* signal response action     */
    struct rlimit             rlim;             /* resource limit             */
    struct bpf_object         *bpf_obj;         /* eBPF object file           */
    struct bpf_program        *bpf_prog;        /* eBPF program in obj        */
    vector<struct bpf_link *> bpf_links;        /* links to attached programs */
    struct nfq_q_handle       *nfq_handle_in;   /* netfilter input handle     */
    struct nfq_q_handle       *nfq_handle_out;  /* netfilter output handle    */
    struct nfq_q_handle       *nfq_handle_fwd;  /* netfilter forward handle   */
    struct nfq_op_param       nfq_opp;          /* nfq operational parameters */
    struct sockaddr_un        us_name;          /* unix socket name           */
    struct io_uring           *ring;            /* io_uring object            */
    struct io_uring_cqe       *cqe;             /* completion queue entry     */

    /* async io buffers & other data */
    uint8_t         pkt_buff_in[PKT_MAX_SZ];    /* INPUT packet buffer        */
    uint8_t         pkt_buff_out[PKT_MAX_SZ];   /* OUTPUT packet buffer       */
    uint8_t         pkt_buff_fwd[PKT_MAX_SZ];   /* FORWARD packet buffer      */
    nldgram_t       nl_msg;                     /* netlink proc event message */


    /* parse command line arguments */
    ans = argp_parse(&argp, argc, argv, 0, 0, &cfg);
    DIE(ans, "error parsing cli arguments");
    INFO("parsed cli arguments");

    /* set niceness to -20, regardless of inherited initial value */
    ans = nice(-40);
    ALERT(ans == -1, "unable to set niceness (%s)", strerror(errno));
    INFO("process niceness set to -20");

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

    /* initialize packet filter settings */
    ans = filter_init(cfg.fwd_validate, cfg.in_validate, cfg.skip_ns_switch);
    DIE(ans, "unable to initialize filter");
    INFO("initialized filter");

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

    /* initialize io_uring module */
    ring = uring_init(128, 3'600'000);
    DIE(!ring, "unable to initialize io_uring");
    INFO("initialized io_uring");

    /* create ctl unix socket */
    us_csock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    GOTO(us_csock_fd == -1, clean_iouring,
         "unable to open AF_UNIX socket (%s)", strerror(errno));
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
    nfq_opp.policy_fwd = cfg.policy_fwd;

    /* prepare input NFQ */
    nf_handle_in = nfq_open();
    GOTO(!nf_handle_in, clean_bpf_rb,
        "unable to open input nfq handle (%s)", strerror(errno));
    INFO("opened input nfq handle");

    nfq_handle_in = nfq_create_queue(nf_handle_in, cfg.queue_num_in,
                        nfq_in_handler, &nfq_opp);
    GOTO(!nfq_handle_in, clean_nf_handle_in,
        "unable to bind to input nfqueue (%s)", strerror(errno));
    INFO("bound to netfilter queue: %d", cfg.queue_num_in);

    ans = nfq_set_mode(nfq_handle_in, NFQNL_COPY_PACKET,
                       cfg.partial_read ? 80 : PKT_MAX_SZ);
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

    ans = nfq_set_mode(nfq_handle_out, NFQNL_COPY_PACKET, PKT_MAX_SZ);
    GOTO(ans < 0, clean_nf_queue_out, "unable to set output nfq mode (%s)",
        strerror(errno));
    INFO("configured nfq output packet handling parameters");

    nfqueue_fd_out = nfq_fd(nf_handle_out);
    INFO("obtained file descriptor of associated nfq output socket");

    /* prepare forward NFQ (optional) */
    if (cfg.fwd_validate) {
        nf_handle_fwd = nfq_open();
        GOTO(!nf_handle_fwd, clean_nf_queue_out,
             "unable to open input nfq handle (%s)", strerror(errno));
        INFO("opened forward nfq handle");

        nfq_handle_fwd = nfq_create_queue(nf_handle_fwd, cfg.queue_num_fwd,
                            nfq_fwd_handler, &nfq_opp);
        GOTO(!nfq_handle_fwd, clean_nf_handle_fwd,
             "unable to bind to forward nfqueue (%s)", strerror(errno));
        INFO("bound to netfilter queue: %d", cfg.queue_num_fwd);

        ans = nfq_set_mode(nfq_handle_fwd, NFQNL_COPY_PACKET, PKT_MAX_SZ);
        GOTO(ans < 0, clean_nf_queue_fwd, "unable to set forward nfq mode (%s)",
            strerror(errno));
        INFO("configured nfq forward packet handling parameters");

        nfqueue_fd_fwd = nfq_fd(nf_handle_fwd);
        INFO("obtained file descriptor of associated nfq forward socket");
    } else {
        nf_handle_fwd  = NULL;
        nfq_handle_fwd = NULL;
        nfqueue_fd_fwd = -1;
    }

    /* initialize packet verdict handling module */
    ans = nfq_helper_init(cfg.batch_max_count, cfg.batch_timeout,
                          nfq_handle_in, nfq_handle_out, nfq_handle_fwd);
    DIE(ans, "unable to initialize packet verdict handler module");
    INFO("initialized packet verdict handler module");

    /* listen for new connections on ctl unix socket */
    ans = listen(us_csock_fd, 1);
    GOTO(ans == -1, clean_nf_queue_fwd, "failed to listen on unix socket (%s)",
        strerror(errno));
    INFO("listening for new connections on ctl unix socket");

    /* subscribe to netlink proc events */
    ans = nl_proc_ev_subscribe(netlink_fd, true);
    GOTO(ans == -1, clean_nf_queue_fwd,
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

    /******************************* main loop ********************************/

    INFO("main loop starting");

    /* place initial requests on the submission queue */
    uring_add_read_request(NFQ_INPUT_READ,
            nfqueue_fd_in, pkt_buff_in, sizeof(pkt_buff_in));

    uring_add_read_request(NFQ_OUTPUT_READ,
            nfqueue_fd_out, pkt_buff_out, sizeof(pkt_buff_out));

    if (cfg.fwd_validate) {
        uring_add_read_request(NFQ_FORWARD_READ,
                nfqueue_fd_fwd, pkt_buff_fwd, sizeof(pkt_buff_fwd));
    }

    uring_add_poll_request(BPF_RINGBUF_POLL, bpf_map_fd, EPOLLIN);

    uring_add_read_request(NETLINK_PROC_READ,
            netlink_fd, &nl_msg, sizeof(nl_msg));

    uring_add_accept_request(CTL_ACCEPT, us_csock_fd, NULL, NULL);

    /* await event completions */
    while (!terminate) {
        /* check if new completion queue entry is available */
        ans = io_uring_peek_cqe(ring, &cqe);
        if (ans)
            goto try_verdict_transmission;

        /* match CQE with origin subsystem */
        switch (cqe->user_data) {
            case NFQ_INPUT_READ:
                /* double netlink socket if overfull */
                if (cqe->res == -ENOBUFS) {
                    WAR("netlink socket overfull; adjusting buffer size");
                    ans = adjust_buffer_size(nfqueue_fd_in, nf_handle_in);
                    GOTO(ans, clean_bpf_links,
                         "unable to adjust socket buffer size");
                }
                /* report unexpected error, but try again */
                elif (cqe->res < 0) {
                    ERROR("unable to read packet from nf queue (%s)",
                          strerror(-cqe->res));
                }
                /* establish verdict for packet */
                else {
                    nfq_handle_packet(nf_handle_in, (char *) pkt_buff_in,
                                      cqe->res);
                }

                /* refresh read request */
                uring_add_read_request(NFQ_INPUT_READ,
                        nfqueue_fd_in, pkt_buff_in, sizeof(pkt_buff_in));

                break;
            case NFQ_OUTPUT_READ:
                /* double netlink socket if overfull */
                if (cqe->res == -ENOBUFS) {
                    WAR("netlink socket overfull; adjusting buffer size");
                    ans = adjust_buffer_size(nfqueue_fd_out, nf_handle_out);
                    GOTO(ans, clean_bpf_links,
                         "unable to adjust socket buffer size");
                }
                /* report unexpected error, but try again */
                elif (cqe->res < 0) {
                    ERROR("unable to read packet from nf queue (%s)",
                          strerror(-cqe->res));
                }
                /* establish verdict for packet */
                else {
                    nfq_handle_packet(nf_handle_out, (char *) pkt_buff_out,
                                      cqe->res);
                }

                /* refresh read request */
                uring_add_read_request(NFQ_OUTPUT_READ,
                        nfqueue_fd_out, pkt_buff_out, sizeof(pkt_buff_out));

                break;
            case NFQ_FORWARD_READ:
                /* double netlink socket if overfull */
                if (cqe->res == -ENOBUFS) {
                    WAR("netlink socket overfull; adjusting buffer size");
                    ans = adjust_buffer_size(nfqueue_fd_fwd, nf_handle_fwd);
                    GOTO(ans, clean_bpf_links,
                         "unable to adjust socket buffer size");
                }
                /* report unexpected error, but try again */
                elif (cqe->res < 0) {
                    ERROR("unable to read packet from nf queue (%s)",
                          strerror(-cqe->res));
                }
                /* establish verdict for packet */
                else {
                    nfq_handle_packet(nf_handle_fwd, (char *) pkt_buff_fwd,
                                      cqe->res);
                }

                /* refresh read request */
                uring_add_read_request(NFQ_FORWARD_READ,
                        nfqueue_fd_fwd, pkt_buff_fwd, sizeof(pkt_buff_fwd));

                break;
            case BPF_RINGBUF_POLL:
                /* report unexpected error, but try again */
                if (cqe->res < 0) {
                    ERROR("unable to poll eBPF ring buffer fd (%s)",
                          strerror(-cqe->res));
                }
                /* consume new sample */
                else {
                    ans = ring_buffer__consume(bpf_ringbuf);
                    GOTO(ans < 0, clean_bpf_links,
                         "failed to consume eBPF ring buffer sample");
                }

                /* refresh poll request */
                uring_add_poll_request(BPF_RINGBUF_POLL, bpf_map_fd, EPOLLIN);

                break;
            case NETLINK_PROC_READ:
                /* report unexpected error, but try again */
                if (cqe->res < 0) {
                    ERROR("unable to read netlink proc event datagram (%s)",
                          strerror(-cqe->res));
                }
                /* update internal model */
                else {
                    ans = nl_proc_ev_handle(&nl_msg);
                    GOTO(ans, clean_bpf_links,
                         "unable to process netlink proc event");
                }

                /* refresh read request */
                uring_add_read_request(NETLINK_PROC_READ,
                        netlink_fd, &nl_msg, sizeof(nl_msg));

                break;
            case CTL_ACCEPT:
                /* report unexpected error, but try again */
                if (cqe->res < 0) {
                    ERROR("unable to accept controller connection (%s)",
                          strerror(-cqe->res));
                }
                /* let the appropriate handler take care of the rest *
                 * it's a rare and inexpensive synchronous operation *
                 * no use complicating the code further              */
                else {
                    ans = flt_handle_ctl(cqe->res);
                    GOTO(ans, clean_bpf_links,
                         "unable to process controller request");
                }

                /* refresh accept request */
                uring_add_accept_request(CTL_ACCEPT, us_csock_fd, NULL, NULL);

                break;
            default:
                WAR("unknown CQE source: %#lx", (uint64_t) cqe->user_data);
        }

        /* acknowledge completion queue event */
        io_uring_cqe_seen(ring, cqe);

try_verdict_transmission:
        /* enforce partial verdict transmission on timeout in case of lack *
         * of network activity                                             */
        ans = maybe_transmit_verdict(0,
                (1 << INPUT_CHAIN) | (1 << OUTPUT_CHAIN));
        ALERT(ans, "unable to set batch verdict");
    }

    WAR("exited main loop");

    /******************************** cleanup *********************************/

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

clean_nf_queue_fwd:
    /* bypass cleanup if FORWARD intercept not used */
    if (!cfg.fwd_validate)
        goto clean_nf_queue_out;

    nfq_destroy_queue(nfq_handle_fwd);
    INFO("destroyed netfilter forward queue");

clean_nf_handle_fwd:
    ans = nfq_close(nf_handle_fwd);
    ALERT(ans, "failed to close nfq forward handle");
    INFO("closed nfq forward handle");

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

clean_iouring:
    uring_deinit();
    INFO("destroyed io_uring object");

    return 0;
}

