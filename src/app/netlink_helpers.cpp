#include <unistd.h>             /* read, write, close, getpid, readlink */
#include <string.h>             /* memset */
#include <sys/socket.h>         /* socket */
#include <linux/netlink.h>      /* NETLINK_CONNECTOR */
#include <linux/connector.h>    /* CN_IDX_PROC */
#include <linux/cn_proc.h>      /* proc_cn_mcast_op, PROC_EVENT_* */

#include "netlink_helpers.h"
#include "util.h"

/* nl_connect - connects to netlink
 *  @return : socket fd or -1 on error
 */
int nl_connect(void)
{
    int nl_fd;                  /* netlink socket */
    int ans;                    /* answer         */
    struct sockaddr_nl nl_sa;   /* socket address */
   
    /* open netlink socket for kernel connector */ 
    nl_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
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
int nl_proc_ev_subscribe(int nl_fd, bool enable)
{
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;                 /* netlink header  */
        struct __attribute__((packed)) {        /* netlink payload */
            struct cn_msg         cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;     /* netlink datagram */
    int ans;        /* answer           */

    /* configure header and payload values */
    memset(&nlcn_msg, 0, sizeof(nlcn_msg));

    nlcn_msg.nl_hdr.nlmsg_len  = sizeof(nlcn_msg);  /* total length        */
    nlcn_msg.nl_hdr.nlmsg_pid  = getpid();          /* subscribing process */
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;        /* no fragmentation    */

    /* read more in Documentation/connector/connector.txt */
    nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);    /* data length */
    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;           /* unique connector ID */
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;           /* unique connector ID */

    nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    /* send subscription request via socket */
    ans = write(nl_fd, &nlcn_msg, sizeof(nlcn_msg));
    RET(ans == -1, -1, "unable to send netlink subscription request");

    return 0;
}

/* nl_proc_ev_handle - handle single process event
 *  @nl_fd  : netlink socket file descriptor
 *
 *  @return : 0 if everything went well
 */
int nl_proc_ev_handle(int nl_fd)
{
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;             /* netlink header  */
        struct __attribute__((packed)) {    /* netlink payload */
            struct cn_msg     cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;         /* netlink datagram */
    int ans;            /* answer           */

    /* read netlink datagram */
    ans = read(nl_fd, &nlcn_msg, sizeof(nlcn_msg));
    RET(ans == -1, -1, "unable to read netlink datagram");

    /* determine event type */
    switch (nlcn_msg.proc_ev.what) {
        case PROC_EVENT_FORK:
            DEBUG("fork: (pid=%d, tid=%d) ==> (pid=%d, tid=%d)",
                nlcn_msg.proc_ev.event_data.fork.parent_pid,
                nlcn_msg.proc_ev.event_data.fork.parent_tgid,
                nlcn_msg.proc_ev.event_data.fork.child_pid,
                nlcn_msg.proc_ev.event_data.fork.child_tgid);
            break;
        case PROC_EVENT_EXEC:  
            char procfs_path[16];   /* /proc/<pid>/exe                      */
            char real_path[1024];   /* real path of /proc/<pid>/exe symlink */

            /* get exec-ed binary real path */
            snprintf(procfs_path, sizeof(procfs_path), "/proc/%u/exe",
                nlcn_msg.proc_ev.event_data.exec.process_pid);

            memset(real_path, 0, sizeof(real_path));
            ans = readlink(procfs_path, real_path, sizeof(real_path));
            RET(ans == -1, -1, "unable to resolve %s symlink", procfs_path);

            DEBUG("exec: (pid=%d, tid=%d) ==> %s",
                nlcn_msg.proc_ev.event_data.exec.process_pid,
                nlcn_msg.proc_ev.event_data.exec.process_tgid,
                real_path);
            break;
        case PROC_EVENT_PTRACE:
            DEBUG("ptrace: (pid=%d, tid=%d) ==> (pid=%d, tid=%d)",
                nlcn_msg.proc_ev.event_data.ptrace.tracer_pid,
                nlcn_msg.proc_ev.event_data.ptrace.tracer_tgid,
                nlcn_msg.proc_ev.event_data.ptrace.process_pid,
                nlcn_msg.proc_ev.event_data.ptrace.process_tgid);
            break;
        case PROC_EVENT_EXIT:
            DEBUG("exit: (pid=%d, tid=%d) ==> code=%d",
                nlcn_msg.proc_ev.event_data.exit.process_pid,
                nlcn_msg.proc_ev.event_data.exit.process_tgid,
                nlcn_msg.proc_ev.event_data.exit.exit_code);
            break;
        /* don't care */
        default:
            break;
    }

    return 0;
}

