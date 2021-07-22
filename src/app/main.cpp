#include <stdio.h>
#include <stdint.h>             /* [u]int*_t */
#include <signal.h>             /* signal, siginterrupt */
#include <unistd.h>             /* read, write, close */
#include <arpa/inet.h>
#include <netinet/in.h>         /* IPPROTO_* */
#include <netinet/ip.h>         /* iphdr */
#include <netinet/tcp.h>        /* tcphdr */
#include <netinet/udp.h>        /* udphdr */
#include <sys/socket.h>         /* socket */
#include <sys/inotify.h>        /* inotify */
#include <sys/epoll.h>          /* epoll */
#include <sys/resource.h>       /* setrlimit */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <vector>               /* vector */

#include "cli_args.h"
#include "netlink_helpers.h"
#include "nfq_helpers.h"
#include "ebpf_helpers.h"
#include "sock_cache.h"
#include "hash_cache.h"
#include "util.h"

using namespace std;


static bool bml = false;    /* break main loop */

/* sigint_handler - sets <break main loop> variable to true
 *  @<redacted> : signal number; don't care to access it
 */
static void sigint_handler(int)
{
    bml = true;
}



/* nfq_handler - callback routine for NetfilterQueue
 *  @qh    : netfilter queue handle
 *  @nfmsg : general form of address family dependent message
 *  @nfd   : nfq related data for packet evaluation
 *  @data  : data parameter passe unchanged by nfq_create_queue()
 *
 *  @return : 0 if ok, -1 on error (handled by nfq_set_verdict())
 */
int nfq_handler(struct nfq_q_handle *qh,
                struct nfgenmsg     *nfmsg,
                struct nfq_data     *nfd,
                void                *data)
{
    struct nfqnl_msg_packet_hdr *ph;        /* nfq meta header         */
    struct iphdr                *iph;       /* ip header               */
    struct tcphdr               *tcph;      /* tcp header              */
    struct udphdr               *udph;      /* udp header              */
    int32_t                     ans;        /* answer                  */
    uint16_t                    src_port;   /* network order src port  */
    uint16_t                    dst_port;   /* network order dst port  */
    unordered_set<uint32_t>     *pid_set_p; /* pointer to set of pids  */

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
    DEBUG("packet received "
          "src_ip:%hhu.%hhu.%hhu.%hhu "
          "dst_ip:%hhu.%hhu.%hhu.%hhu "
          "src_port:%hu "
          "dst_port:%hu ",
          (iph->saddr >>  0) & 0xff, (iph->saddr >>  8) & 0xff,
          (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff,
          (iph->daddr >>  0) & 0xff, (iph->daddr >>  8) & 0xff,
          (iph->daddr >> 16) & 0xff, (iph->daddr >> 24) & 0xff,
          ntohs(src_port), ntohs(dst_port));

    /* process any delayed events that have timed out */
    nl_delayed_ev_handle(cfg.proc_delay);
    ebpf_delayed_ev_handle(cfg.proc_delay);

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


/* main - program entry point
 *  @argc : number of command line arguments & program name
 *  @argv : array of command line arguments & program name
 *
 *  @return : 0 if everything went well
 */
int main(int argc, char *argv[])
{
    int                       ans;              /* answer                     */
    int                       netlink_fd;       /* netlink socket             */
    int                       inotify_fd;       /* inotify file descriptor    */
    int                       nfqueue_fd;       /* nfq file descriptor        */
    int                       bpf_map_fd;       /* eBPF map file descriptor   */
    int                       epoll_fd;         /* epoll file descriptor      */
    struct epoll_event        epoll_ev;         /* epoll event                */
    struct sigaction          act;              /* signal response action     */
    struct rlimit             rlim;             /* resource limit             */
    struct bpf_object         *bpf_obj;         /* eBPF object file           */
    struct bpf_program        *bpf_prog;        /* eBPF program in obj        */
    vector<struct bpf_link *> bpf_links;        /* links to attached programs */
    struct ring_buffer        *bpf_ringbuf;     /* eBPF ring buffer reference */
    struct nfq_handle         *nf_handle;       /* NFQUEUE handle             */
    struct nfq_q_handle       *nfq_handle;      /* netfilter queue handle     */
    uint8_t                   pkt_buff[0xffff]; /* nfq packet buffer          */
    char                      usr_input[256];   /* user stdin input buffer    */
    ssize_t                   rb;               /* bytes read                 */

    /* parse command line arguments */
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
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

    /* connect to netlink */
    netlink_fd = nl_proc_ev_connect();
    DIE(netlink_fd == -1, "failed to establish netlink connection");
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

    /* open netfilter queue handle */
    nf_handle = nfq_open();
    GOTO(!nf_handle, clean_bpf_rb, "unable to open nfq handle (%s)",
        strerror(errno));
    INFO("opened nfq handle");

    /* bind nfq handle to queue */
    nfq_handle = nfq_create_queue(nf_handle, cfg.queue_num, nfq_handler, NULL);
    GOTO(!nfq_handle, clean_nf_handle, "unable to bind to nfqueue (%s)",
        strerror(errno));
    INFO("bound to netfilter queue: %d", 0);

    /* set amount of data to be copied to userspace (max ip packet size) */
    ans = nfq_set_mode(nfq_handle, NFQNL_COPY_PACKET, sizeof(pkt_buff));
    GOTO(ans < 0, clean_nf_handle, "unable to set nfq mode (%s)",
        strerror(errno));
    INFO("configured nfq packet handling parameters");

    /* obtain fd of queue handle's associated socket */
    nfqueue_fd = nfq_fd(nf_handle);
    INFO("obtained file descriptor of associated nfq socket");

    /* create epoll instance */
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    GOTO(epoll_fd == -1, clean_nf_queue, "failed to create epoll instance (%s)",
        strerror(errno));
    INFO("epoll instance created");

    /* add netlink socket to epoll watchlist */
    epoll_ev.data.fd = netlink_fd;
    epoll_ev.events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, netlink_fd, &epoll_ev);
    GOTO(ans == -1, clean_epoll_fd,
        "failed to add netlink to epoll monitor (%s)", strerror(errno));
    INFO("netlink socket added to epoll monitor");

    /* add inotify instance to epoll watchlist */
    epoll_ev.data.fd = inotify_fd;
    epoll_ev.events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &epoll_ev);
    GOTO(ans == -1, clean_epoll_fd,
        "failed to add inotify to epoll monitor (%s)", strerror(errno));
    INFO("inotify instance added to epoll monitor");

    /* add eBPF ringbuffer to epoll watchlist */
    epoll_ev.data.fd = bpf_map_fd;
    epoll_ev.events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bpf_map_fd, &epoll_ev);
    GOTO(ans == -1, clean_epoll_fd,
        "failed to add eBPF ringbuffer to epoll monitor (%s)", strerror(errno));
    INFO("eBPF ringbuffer added to epoll monitor");

    /* add netfilter queue to epoll watchlist */
    epoll_ev.data.fd = nfqueue_fd;
    epoll_ev.events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, nfqueue_fd, &epoll_ev);
    GOTO(ans == -1, clean_epoll_fd,
        "failed to add netfilter queue to epoll monitor (%s)", strerror(errno));
    INFO("netfilter queue added to epoll monitor");

    /* add stdin to epoll watchlist (requests debug info) */
    epoll_ev.data.fd = STDIN_FILENO;
    epoll_ev.events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &epoll_ev);
    GOTO(ans == -1, clean_epoll_fd,
        "failed to add stdin to epoll monitor");
    INFO("stdin added to epoll monitor");

    /* subscribe to netlink proc events */
    ans = nl_proc_ev_subscribe(netlink_fd, true);
    GOTO(ans == -1, clean_epoll_fd,
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
        /* wait for epoll event */
        ans = epoll_wait(epoll_fd, &epoll_ev, 1, -1);
        DIE(ans == -1 && errno != EINTR, 
            "error while waiting for epoll events");

        /* handle event */
        if (epoll_ev.data.fd == netlink_fd) {
            ans = nl_proc_ev_handle(netlink_fd);
        } else if (epoll_ev.data.fd == inotify_fd) {
            /* TODO */
        } else if (epoll_ev.data.fd == bpf_map_fd) {
            ans = ring_buffer__consume(bpf_ringbuf);
            ALERT(ans < 0, "failed to consume eBPF ringbuffer sample");
        } else if (epoll_ev.data.fd == nfqueue_fd) {
            rb = read(nfqueue_fd, pkt_buff, sizeof(pkt_buff));
            CONT(rb == -1, "failed to read packet from nf queue (%s)",
                strerror(errno));

            nfq_handle_packet(nf_handle, (char *) pkt_buff, rb); 
        } else if (epoll_ev.data.fd == STDIN_FILENO) {
            rb = read(STDIN_FILENO, usr_input, sizeof(usr_input));
            CONT(rb == -1, "failed to read stdin input (%s)", strerror(errno));

            /* print debug info on user request */
            sc_dump_state();    
        }
    }
    WAR("exited main loop");

clean_bpf_links:
    /* unlink existing programs */
    for (auto& bpf_link : bpf_links) {
        ans = bpf_link__destroy(bpf_link);
        ALERT(ans, "failed to destroy eBPF link");
        INFO("destroyed eBPF program link");
    }

clean_netlink_sub:
    /* unsubscribe from netlink proc events */
    ans = nl_proc_ev_subscribe(netlink_fd, false);
    ALERT(ans == -1, "failed to unsubscribe from netlink proc events");
    INFO("unsubscribed from netlink proc events");

clean_epoll_fd:
    /* close epoll instance */
    ans = close(epoll_fd);
    ALERT(ans == -1, "failed to close epoll instance (%s)", strerror(errno));
    INFO("closed epoll instance");

clean_nf_queue:
    nfq_destroy_queue(nfq_handle);
    INFO("destroyed netfilter queue");

clean_nf_handle:
    ans = nfq_close(nf_handle);
    ALERT(ans, "failed to close nfq handle");
    INFO("closed nfq handle");

clean_bpf_rb:
    /* free eBPF ringbuffer */
    ring_buffer__free(bpf_ringbuf);
    INFO("freed eBPF ringbuffer");

clean_bpf_obj:
    bpf_object__close(bpf_obj);
    INFO("closed eBPF object");

clean_inotify_fd:
    /* close inotify instance */
    ans = close(inotify_fd);
    ALERT(ans == -1, "failed to close inotify instance (%s)", strerror(errno));
    INFO("closed inotify instance");

clean_netlink_fd:
    /* close netlink instance */
    ans = close(netlink_fd);
    ALERT(ans == -1, "failed to close netlink instance (%s)", strerror(errno));
    INFO("closed netlink instance");

    return 0;
}

