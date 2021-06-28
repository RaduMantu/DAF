#include <stdio.h>
#include <signal.h>             /* signal, siginterrupt */
#include <unistd.h>             /* read, write, close */
#include <errno.h>              /* errno */
#include <sys/socket.h>         /* socket */
#include <sys/inotify.h>        /* inotify */
#include <sys/epoll.h>          /* epoll */

#include "netlink_helpers.h"
#include "util.h"


static bool bml = false;    /* break main loop */

/* sigint_handler - sets <break main loop> variable to true
 *  @<redacted> : signal number; don't care to access it
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
int main(int argc, char *argv[])
{
    int                netlink_fd;  /* netlink socket          */
    int                inotify_fd;  /* inotify file descriptor */
    int                epoll_fd;    /* epoll file descriptor   */
    struct epoll_event epoll_ev;    /* epoll event             */
    int                ans;         /* answer                  */
    sighandler_t       prv_sh;      /* previous signal handler */

    /* set gracious behaviour for Ctrl^C signal */
    prv_sh = signal(SIGINT, &sigint_handler);
    WAR(prv_sh == SIG_ERR, "unable to set new SIGINT handler (%d)", errno);
    INFO("replaced SIGINT handler");

    /* Ctrl^C may interrupt syscall; let it return EINTR and not restart */
    ans = siginterrupt(SIGINT, true);
    WAR(ans == -1, "unable to change syscall interrupt behaviour (%d)", errno);
    INFO("syscalls interrupted by SIGINT now fail with EINTR");

    /* connect to netlink */
    netlink_fd = nl_connect();
    DIE(netlink_fd == -1, "failed to establish netlink connection");
    INFO("netlink connection established");

    /* create inotify instance */
    inotify_fd = inotify_init1(IN_CLOEXEC);
    DIE(inotify_fd == -1, "failed to create inotify instance (%d)", errno);
    INFO("inotify instance created");

    /* create epoll instance */
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    DIE(epoll_fd == -1, "failed to create epoll instance (%d)", errno);
    INFO("epoll instance created");

    /* add netlink socket to epoll watchlist */
    epoll_ev.data.fd = netlink_fd;
    epoll_ev.events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, netlink_fd, &epoll_ev);
    DIE(ans == -1, "failed to add netlink to epoll monitor (%d)", errno);
    INFO("netlink socket added to epoll monitor");

    /* add inotify instance to epoll watchlist */
    epoll_ev.data.fd = inotify_fd;
    epoll_ev.events  = EPOLLIN;

    ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &epoll_ev);
    DIE(ans == -1, "failed to add inotify to epoll monitor (%d)", errno);
    INFO("inotify instance added to epoll monitor");

    /* subscribe to netlink proc events */
    ans = nl_proc_ev_subscribe(netlink_fd, true);
    DIE(ans == -1, "failed to subscribe to netlink proc events");
    INFO("now subscribed to netlink proc events");

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
            continue;
        }
        if (epoll_ev.data.fd == inotify_fd) {
            /* TODO */
            continue;
        }
    }
    INFO("successfully exited main loop");

    /* close epoll instance */
    close(epoll_fd);

    /* unsubscribe from netlink proc events */
    ans = nl_proc_ev_subscribe(netlink_fd, false);
    DIE(ans == -1, "failed to unsubscribe from netlink proc events");

    /* close netlink socket */
    close(netlink_fd);

    return 0;
}

