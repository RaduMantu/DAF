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
#include <unistd.h>             /* read, write, close, unlink         */
#include <pthread.h>            /* pthread_*                          */
#include <netinet/in.h>         /* IPPROTO_*                          */
#include <netinet/ip.h>         /* iphdr                              */
#include <netinet/tcp.h>        /* tcphdr                             */
#include <netinet/udp.h>        /* udphdr                             */
#include <sys/socket.h>         /* socket                             */
#include <sys/un.h>             /* sockaddr_un                        */
#include <sys/inotify.h>        /* inotify                            */
#include <sys/epoll.h>          /* epoll                              */
#include <sys/resource.h>       /* setrlimit                          */
#include <bpf/libbpf.h>         /* eBPF API                           */
#include <vector>               /* std::vector                        */
#include <queue>                /* std::queue                         */

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

/* NOTE: pkt buffer should have some extra space for netlink header. *
 *       expect arbitrary amounts of padding depending on the range  *
 *       set in nfq_set_mode().                                      */
#define PKT_MAX_SZ    (0xffff + 128)
#define CTL_SOCK_NAME "/tmp/app_fw.socket"

static bool terminate = false;    /* program pending termination */

/* configured by main thread, used by workers */
static int32_t            us_csock_fd;      /* unix connection socket     */
static int32_t            netlink_fd;       /* netlink socket             */
static int32_t            inotify_fd;       /* inotify file descriptor    */
static int32_t            bpf_map_fd;       /* eBPF map file descriptor   */
static int32_t            nfqueue_fd_in;    /* nfq input file descriptor  */
static int32_t            nfqueue_fd_out;   /* nfq output file descriptor */
static int32_t            nfqueue_fd_fwd;   /* nfq fwd file descriptor    */
static struct nfq_handle  *nf_handle_in;    /* NFQUEUE input handle       */
static struct nfq_handle  *nf_handle_out;   /* NFQUEUE output handle      */
static struct nfq_handle  *nf_handle_fwd;   /* NFQUEUE forward handle     */
static struct ring_buffer *bpf_ringbuf;     /* eBPF ring buffer reference */

/* elapsed time counters */
static struct timeval program_start_marker;
static struct timeval start_marker;

static uint64_t epoll_ctr        = 0;
static uint64_t fw_ctl_ctr       = 0;
static uint64_t netlink_ctr      = 0;
static uint64_t bpf_rb_ctr       = 0;
static uint64_t nfq_read_out_ctr = 0;
static uint64_t nfq_eval_out_ctr = 0;
static uint64_t nfq_read_in_ctr  = 0;
static uint64_t nfq_eval_in_ctr  = 0;
static uint64_t nfq_read_fwd_ctr = 0;
static uint64_t nfq_eval_fwd_ctr = 0;

/* system event (0) and packet processing (1) worker data */
typedef struct {
    pthread_cond_t  cond;
    pthread_mutex_t mutex;
    queue<int32_t>  workload;
    int32_t         epoll_prio_fd;
} worker_data_t;

worker_data_t worker_ctx[2];

/* sigint_handler - sets <break main loop> variable to true
 */
static void
sigint_handler(int)
{
    terminate = true;
}

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
    DEBUG("  - Waiting for epoll             : %8.2lf (%6.2lf%%)",
          epoll_ctr / 1e3, 1e2 * epoll_ctr / main_loop_elapsed);
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

/* handle_event - worker thread helper function
 *  @fd : event source file descriptor
 *
 *  @return : 0 if everythig went well; -1 otherwise
 *
 * NOTE: always try to read PKT_MAX_SZ; NFQ will adjust the amount of
 *       transferred data depending on the nfq_set_mode() range arg.
 */
static int32_t
handle_event(int32_t fd)
{
    int32_t ans;                    /* answer            */
    ssize_t rb;                     /* read bytes        */
    uint8_t pkt_buff[PKT_MAX_SZ];   /* nfq packet buffer */

    /* handle event depending on fd value */
    if (fd == us_csock_fd) {
        ARM_TIMER(start_marker);
        ans = flt_handle_ctl(fd);
        UPDATE_TIMER(fw_ctl_ctr, start_marker);
        RET(ans, -1, "unable to handle rule manager request");
    } elif (fd == netlink_fd) {
        ARM_TIMER(start_marker);
        ans = nl_proc_ev_handle(fd);
        UPDATE_TIMER(netlink_ctr, start_marker);
        RET(ans, -1, "unable to handle netlink event");
    } elif (fd == bpf_map_fd) {
        ARM_TIMER(start_marker);
        ans = ring_buffer__consume(bpf_ringbuf);
        UPDATE_TIMER(bpf_rb_ctr, start_marker);
        RET(ans < 0, -1, "failed to consume eBPF ringbuffer sample");
    } elif (fd == nfqueue_fd_out) {
        ARM_TIMER(start_marker);
        rb = read(fd, pkt_buff, sizeof(pkt_buff));
        UPDATE_TIMER(nfq_read_out_ctr, start_marker);
        RET(rb == -1, -1, "failed to read packet from nf queue (%s)",
            strerror(errno));

        ARM_TIMER(start_marker);
        nfq_handle_packet(nf_handle_out, (char *) pkt_buff, rb);
        UPDATE_TIMER(nfq_eval_out_ctr, start_marker);
    } elif (fd == nfqueue_fd_in) {
        ARM_TIMER(start_marker);
        rb = read(fd, pkt_buff, sizeof(pkt_buff));
        UPDATE_TIMER(nfq_read_in_ctr, start_marker);
        RET(rb == -1, -1, "failed to read packet from nf queue (%s)",
            strerror(errno));

        ARM_TIMER(start_marker);
        nfq_handle_packet(nf_handle_in, (char *) pkt_buff, rb);
        UPDATE_TIMER(nfq_eval_in_ctr, start_marker);
    } elif (cfg.fwd_validate && fd == nfqueue_fd_fwd) {
        ARM_TIMER(start_marker);
        rb = read(fd, pkt_buff, sizeof(pkt_buff));
        UPDATE_TIMER(nfq_read_fwd_ctr, start_marker);
        RET(rb == -1, -1, "failed to read packet from nf queue (%s)",
            strerror(errno));

        ARM_TIMER(start_marker);
        nfq_handle_packet(nf_handle_fwd, (char *) pkt_buff, rb);
        UPDATE_TIMER(nfq_eval_fwd_ctr, start_marker);
    } elif (fd == STDIN_FILENO) {
        print_stats();
    }

    return 0;
}

/* worker - worker thread main function
 *  @_data : ptr to worker data structure
 *
 *  @return : NULL if exited normally (shouldn't happen)
 *            (void *) -1 on error
 *
 * Depending on the value of epfd_p, this thread will either process system
 * events (and update our representational model), or it will try to filter
 * incoming packets.
 *
 * Using multi-threading is more or less required in order to improve
 * performance. Otherwise, packet processing will be stalled by _any_ system
 * event that we monitor. However, this runs the risk of evaluating packets
 * based on a potentially (slightly) outdated system view.
 *
 * NOTE: This funciton will be called as-is from the main thread if
 *       multi-threading is not enabled.
 */
static void *
worker(void *_data)
{
    int32_t            fd;      /* pending fd in workload */
    int32_t            ans;     /* answer                 */
    struct epoll_event ev;      /* epoll event            */

    worker_data_t *data = (worker_data_t *) _data;

    /* main woker loop                                    *
     * NOTE: must be killed by main thread before exiting */
    while (1) {
        /* mutex owner is next to receive work                             *
         * NOTE: at the moment we have ony one worker; this will be needed *
         *       if we ever want to add support for multiple workers       */
        ans = pthread_mutex_lock(&data->mutex);
        RET(ans, (void *) -1, "unable to acquire mutex (%s)", strerror(errno));

        /* await work from main thread */
        if (data->workload.size() == 0) {
            ans = pthread_cond_wait(&data->cond, &data->mutex);
            RET(ans, (void *) -1, "unable to wait on condition (%s)",
                strerror(errno));

            /* spurious wakeup */
            if (data->workload.size() == 0) {
                ans = pthread_mutex_unlock(&data->mutex);
                RET(ans, (void *) -1, "unable to unlock mutex (%s)",
                    strerror(errno));

                continue;
            }
        }

        /* get pending fd from workload */
        fd = data->workload.front();
        data->workload.pop();

        /* release mutex ownership while working */
        ans = pthread_mutex_unlock(&data->mutex);
        RET(ans, (void *) -1, "unable to unlock mutex (%s)", strerror(errno));

        /* processed enqueued event */
        handle_event(fd);

        /* rearm file descriptor in epoll watchlist */
        ev.data.fd = fd;
        ev.events  = EPOLLIN | EPOLLONESHOT;

        ans = epoll_ctl(data->epoll_prio_fd, EPOLL_CTL_MOD, fd, &ev);
        RET(ans == -1, (void *) -1, "unable to rearm fd (%s)",
            strerror(errno));
    }

    return NULL;
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
    struct nfq_q_handle       *nfq_handle_in;   /* netfilter input handle     */
    struct nfq_q_handle       *nfq_handle_out;  /* netfilter output handle    */
    struct nfq_q_handle       *nfq_handle_fwd;  /* netfilter forward handle   */
    struct nfq_op_param       nfq_opp;          /* nfq operational parameters */
    struct sockaddr_un        us_name;          /* unix socket name           */
    char                      usr_input[256];   /* user stdin input buffer    */
    uint32_t                  worker_thread;    /* selected worker thread     */
    ssize_t                   rb;               /* bytes read                 */
    pthread_t                 threads[2];       /* worker threads (maybe)     */

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

    /* create ctl unix socket */
    us_csock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    DIE(us_csock_fd == -1, "unable to open AF_UNIX socket (%s)", strerror(errno));
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
    }

    /* create top level epoll instance */
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    GOTO(epoll_fd == -1, clean_nf_queue_fwd, "failed to create epoll instance (%s)",
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
    epoll_ev[0].events  = EPOLLIN | (cfg.parallelize ? EPOLLONESHOT : 0);

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, us_csock_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add ctl unix socket to epoll monitor (%s)", strerror(errno));
    INFO("ctl unix socket added to epoll-p0 monitor");

    /* add netlink socket to epoll watchlist (top prio) */
    epoll_ev[0].data.fd = netlink_fd;
    epoll_ev[0].events  = EPOLLIN | (cfg.parallelize ? EPOLLONESHOT : 0);

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, netlink_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add netlink to epoll monitor (%s)", strerror(errno));
    INFO("netlink socket added to epoll-p0 monitor");

    /* add inotify instance to epoll watchlist (top prio) */
    epoll_ev[0].data.fd = inotify_fd;
    epoll_ev[0].events  = EPOLLIN | (cfg.parallelize ? EPOLLONESHOT : 0);

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, inotify_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add inotify to epoll monitor (%s)", strerror(errno));
    INFO("inotify instance added to epoll-p0 monitor");

    /* add eBPF ringbuffer to epoll watchlist (top prio) */
    epoll_ev[0].data.fd = bpf_map_fd;
    epoll_ev[0].events  = EPOLLIN | (cfg.parallelize ? EPOLLONESHOT : 0);

    ans = epoll_ctl(epoll_p0_fd, EPOLL_CTL_ADD, bpf_map_fd, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add eBPF ringbuffer to epoll monitor (%s)", strerror(errno));
    INFO("eBPF ringbuffer added to epoll-p0 monitor");

    /* add input netfilter queue to epoll watchlist (bottom prio) */
    epoll_ev[0].data.fd = nfqueue_fd_in;
    epoll_ev[0].events  = EPOLLIN | (cfg.parallelize ? EPOLLONESHOT : 0);

    ans = epoll_ctl(cfg.uniform_prio ? epoll_p0_fd : epoll_p1_fd,
                    EPOLL_CTL_ADD, nfqueue_fd_in, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add netfilter input queue to epoll-p1 monitor (%s)",
        strerror(errno));
    INFO("netfilter input queue added to epoll-p1 monitor");

    /* add output netfilter queue to epoll watchlist (bottom prio) */
    epoll_ev[0].data.fd = nfqueue_fd_out;
    epoll_ev[0].events  = EPOLLIN | (cfg.parallelize ? EPOLLONESHOT : 0);

    ans = epoll_ctl(cfg.uniform_prio ? epoll_p0_fd : epoll_p1_fd,
                    EPOLL_CTL_ADD, nfqueue_fd_out, &epoll_ev[0]);
    GOTO(ans == -1, clean_epoll_fd_p1,
        "failed to add netfilter output queue to epoll-p1 monitor (%s)",
        strerror(errno));
    INFO("netfilter output queue added to epoll-p1 monitor");

    /* add forward netfilter queue to epoll watchlist (bottom prio) */
    if (cfg.fwd_validate) {
        epoll_ev[0].data.fd = nfqueue_fd_fwd;
        epoll_ev[0].events  = EPOLLIN | (cfg.parallelize ? EPOLLONESHOT : 0);

        ans = epoll_ctl(cfg.uniform_prio ? epoll_p0_fd : epoll_p1_fd,
                        EPOLL_CTL_ADD, nfqueue_fd_fwd, &epoll_ev[0]);
        GOTO(ans == -1, clean_epoll_fd_p1,
             "failed to add netfilter forward queue to epoll-p1 monitor (%s)",
             strerror(errno));
        INFO("netfilter forward queue added to epoll-p1 monitor");
    }

    /* add stdin to epoll watchlist (bottom prio)             *
     * NOTE: this will fail if ran from within a bash script  *
     *       stdin not used for anything at the moment anyway */
    epoll_ev[0].data.fd = STDIN_FILENO;
    epoll_ev[0].events  = EPOLLIN | (cfg.parallelize ? EPOLLONESHOT : 0);

    ans = epoll_ctl(cfg.uniform_prio ? epoll_p0_fd : epoll_p0_fd,
                    EPOLL_CTL_ADD, STDIN_FILENO, &epoll_ev[0]);
    /* GOTO(ans == -1, clean_epoll_fd_p1, */
    /*     "failed to add stdin to epoll-p1 monitor"); */
    /* INFO("stdin added to epoll monitor"); */

    /* add priority ordering epoll instances to top level epoll selector *
     * NOTE: this is predicated on actually having multiple priorities   *
     *       setting `-u` makes the epoll hierarchy redundant            */
    if (!cfg.uniform_prio) {
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
    }

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

    /* if parallelizeable, initialize & start threads */
    if (cfg.parallelize) {
        worker_ctx[0].epoll_prio_fd = epoll_p0_fd;
        worker_ctx[1].epoll_prio_fd = epoll_p1_fd;

        for (size_t i = 0; i < sizeof(worker_ctx) / sizeof(*worker_ctx); i++) {
            ans = pthread_mutex_init(&worker_ctx[i].mutex, NULL);
            GOTO(ans, clean_bpf_links, "unable to initialize mutex (%s)",
                 strerror(errno));

            ans = pthread_cond_init(&worker_ctx[i].cond, NULL);
            GOTO(ans, clean_bpf_links, "unable to initialize cond (%s)",
                 strerror(errno));

            ans = pthread_create(&threads[i], NULL, worker, &worker_ctx[i]);
            GOTO(ans, clean_bpf_links, "unable to create thread (%s)",
                 strerror(errno));

            INFO("started worker thread %lu", i);
        }
    }

    ARM_TIMER(program_start_marker);

    /* main loop */
    INFO("main loop starting");
    while (!terminate) {
        ARM_TIMER(start_marker);

        /* prioritize event class if using epoll hierarchization */
        if (!cfg.uniform_prio) {
            /* wait for top level epoll event */
            ans = epoll_wait(epoll_fd, epoll_ev, 2, -1);
            DIE(ans == -1 && errno != EINTR, "error waiting for epoll events (%s)",
                strerror(errno));

            /* determine if any of the (max 2) events were top priority */
            epoll_sel_fd  = epoll_p1_fd;
            worker_thread = 1;
            for (size_t i = 0; i < ans; i++)
                if (epoll_ev[i].data.fd == epoll_p0_fd) {
                    epoll_sel_fd  = epoll_p0_fd;
                    worker_thread = 0;
                    break;
                }
        }
        /* otherwise use the leaf epoll object with the highest priority */
        else {
            epoll_sel_fd = epoll_p0_fd;
            worker_thread = 0;
        }

        /* we know that event is available on selected priority level *
         * here we prioritize events relating to sockets, not NFQ     */
        ans = epoll_wait(epoll_sel_fd, &epoll_ev[0], 1, -1);
        DIE(ans == -1 && errno != EINTR, "error waiting for epoll events (%s)",
            strerror(errno));

        UPDATE_TIMER(epoll_ctr, start_marker);

        /* single-threaded path: handle it ourselves */
        if (!cfg.parallelize)
            handle_event(epoll_ev[0].data.fd);
        /* multi-threaded path: enqueue event for worker */
        else {
            worker_ctx[worker_thread].workload.push(epoll_ev[0].data.fd);

            ans = pthread_cond_signal(&worker_ctx[worker_thread].cond);
            DIE(ans, "unable to notify worker (%s)", strerror(errno));
        }
    }
    WAR("exited main loop");

clean_threads:
    if (cfg.parallelize) {
        for (size_t i = 0; i < sizeof(threads) / sizeof(*threads); i++) {
            ans = pthread_kill(threads[i], 0);
            DIE(ans, "unable to kill thread %lu (%s)", i, strerror(errno));
            INFO("killed worker thread %lu", i);
        }
    }

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

    return 0;
}

