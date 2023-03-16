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

#include <stdio.h>          /* ssize_t             */
#include <stdlib.h>         /* atoi                */
#include <string.h>         /* memset              */
#include <dirent.h>         /* opendir             */
#include <unistd.h>         /* readlink            */
#include <regex.h>          /* reg{comp,exec,free} */
#include <proc/readproc.h>  /* openproc, readproc  */
#include <unordered_map>    /* unordered_map       */
#include <unordered_set>    /* unordered_set       */
#include <utility>          /* pair                */
#include <functional>       /* hash                */
#include <tuple>            /* tuple               */

#include "sock_cache.h"
#include "netlink_helpers.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

struct pair_hash {
    template <class T1, class T2>
    size_t operator()(const pair<T1, T2>& p) const
    {
        auto hash1 = hash<T1>{}(p.first);
        auto hash2 = hash<T2>{}(p.second);

        return hash1 ^ hash2;
    }
};

struct tuple_hash {
    template <class T1, class T2, class T3>
    size_t operator()(const tuple<T1, T2, T3>& p) const
    {
        auto hash1 = hash<T1>{}(get<0>(p));
        auto hash2 = hash<T1>{}(get<1>(p));
        auto hash3 = hash<T1>{}(get<2>(p));

        return hash1 ^ hash2 ^ hash3;
    }
};

/* type representing a port specific to a certain netowrk namespace
 *  @first  : resident device (namespace)
 *  @second : inode number    (namespace)
 *  @third  : port number
 *
 * see `man ioctl_ns` for more information
 */
typedef tuple<uint64_t, uint64_t, uint16_t> netns_port_t;

/* internal data structures                                             *
 *  pid_to_socks : set of socket inodes to which pid has access         *
 *  sock_to_pids : set of pids that have access to socket inodes        *
 *  fd_to_sock   : translation from <pid,fd> to socket inode            *
 *  inode_fd_ref : number of fd references a pid has to a socket inode  *
 *  sock_to_port : (netns_dev, netns_inode, port) associated to socket inode
 *  port_to_sock : socket inode associated to (netns_dev, netns_inode, port)
 *  tracked_pids : processes whose sockets were tracked since inception */
static unordered_map<uint32_t, unordered_set<uint32_t>>            pid_to_socks;
static unordered_map<uint32_t, unordered_set<uint32_t>>            sock_to_pids;
static unordered_map<pair<uint32_t, uint8_t>, uint32_t, pair_hash> fd_to_sock;
static unordered_map<pair<uint32_t, uint32_t>, uint8_t, pair_hash> inode_fd_ref;
static unordered_map<uint32_t, netns_port_t>                       sock_to_port;
static unordered_map<netns_port_t, uint32_t, tuple_hash>           port_to_sock;
static unordered_set<uint32_t>                                     tracked_pids;

/* runtine resources that need initialization -- see sc_init() */
static regex_t regex;       /* compiled regex to match "socket:[<inode>]" */

/* runtime statistics counters */
uint64_t symlink_miss = 0;      /* fd was closed too fast */
uint64_t dir_miss     = 0;      /* process ended too fast */

/******************************************************************************
 ********************************* PUBLIC API *********************************
 ******************************************************************************/

int32_t sc_init(void);
void    sc_open_fd(uint32_t pid, uint8_t fd);
void    sc_close_fd(uint32_t pid, uint8_t fd);
void    sc_proc_exit(uint32_t pid);
void    sc_proc_fork(uint32_t parent_pid, uint32_t child_pid);
void    sc_proc_exec(uint32_t pid);
void    sc_dump_state(void);

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
 ******************************************************************************/

/* _fd_to_inode - converts a "/proc/<pid>/fd/<fd>" path of a _socket_ to the
 *                inode of said socket; other types of fd are ignored
 *  @procfs_path : absolute path to fd, as specified in description
 *  @inode_p     : pointer to inode storage location
 *
 *  @return : 0 if everything went well; !0 on error or non-socket fd
 */
static int32_t _fd_to_inode(char *procfs_path, uint32_t *inode_p)
{
    char    symlink_val[128];
    ssize_t wb_link;
    int32_t ans;

    /* get symlink value                                                      *
     * NOTE: not unusual for socket to close or the process to exit before we *
     *       get a chance to properly identify it                             */
    wb_link = readlink(procfs_path, symlink_val, sizeof(symlink_val) - 1);
    if (wb_link == -1) {
        symlink_miss++;
        return -1;
    }
    symlink_val[wb_link] = '\0';

    /* check if fd is indeed a socket */
    ans = regexec(&regex, symlink_val, 0, NULL, 0);
    if (ans == REG_NOMATCH)
        return -1;
    RET(ans, -1, "error on regex match for %s (%d)", symlink_val, ans);

    /* extract socket inode from symlink */
    sscanf(symlink_val, "socket:[%u]", inode_p);

    return 0;
}

/* _fd_to_inode - wrapper over the implementation above
 *  @pid     : pid of the analyzed process
 *  @fd      : file descriptor of interest
 *  @inode_p : pointer to inode storage location
 */
static int32_t _fd_to_inode(uint32_t pid, uint8_t fd, uint32_t *inode_p)
{
    char procfs_path[128];

    /* compose absolute path to procfs fd symlink */
    snprintf(procfs_path, sizeof(procfs_path), "/proc/%u/fd/%hhu", pid, fd);

    /* invoke alternate version of this function to get the answer */
    return _fd_to_inode(procfs_path, inode_p);
}

/* _register_socket - register a new inode to pid via its fd
 *  @pid   : process that opened socket
 *  @fd    : file descriptor of socket
 *  @inode : inode of socket
 */
void _register_socket(uint32_t pid, uint8_t fd, uint32_t inode)
{
    /* add reference for <pid,fd> to inode for when dealing with close()    *
     * NOTE: an already existing entry means that we are trying to add the  *
     *       same socket twice; this can be harmful if we continue, but not *
     *       an unusual occurrence                                          */
    auto ans = fd_to_sock.insert({make_pair(pid, fd), inode});
    if (!ans.second)
        return;

    /* find or create socket set for given pid & insert inode */
    auto& sock_set = pid_to_socks[pid];
    sock_set.insert(inode);

    /* find or create pid set for given socket & insert pid */
    auto& pid_set = sock_to_pids[inode];
    pid_set.insert(pid);

    /* increment reference count to inode by given pid */
    inode_fd_ref[make_pair(pid, inode)]++;
}

/* _scan_proc_sockets - scan /proc/<pid>/fd/ to identify associated sockets
 *  @pid : process to analyze
 *
 *  @return : 0 if process still exists; !0 otherwise
 *
 * NOTE: if the function fails partway through, we do not revert changes to
 *       internal structures
 * TODO: implement revert changes on abnormal exit (very low priority)
 */
static int32_t _scan_proc_sockets(uint32_t pid)
{
    char           procfs_path[128];    /* "/proc/<pid>/fd/[...]"       */
    DIR            *d;                  /* opened directory             */
    struct dirent  *de;                 /* directory entry              */
    ssize_t        wb_path;             /* written bytes in procfs_path */
    uint32_t       inode;               /* socket inode value           */
    int32_t        ans;                 /* answer                       */

    /* compose procfs path */
    wb_path = snprintf(procfs_path, sizeof(procfs_path), "/proc/%u/fd/", pid);
    RET(wb_path >= sizeof(procfs_path), -1,
        "path truncated; increase buffer size");

    /* parse entries in directory                                   *
     * NOTE: possible but not usual for process to terminate early  *
     *       might warrant further investigation if it ever happens */
    d = opendir(procfs_path);
    if (!d) {
        dir_miss++;

        WAR("could not open %s", procfs_path);
        return -1;
    }

    errno = 0;
    while ((de = readdir(d))) {
        /* skip non-symlinks */
        if (de->d_type != DT_LNK)
            continue;

        /* compose full path to current direntry & get socket inode or skip */
        snprintf(&procfs_path[wb_path], sizeof(procfs_path) - wb_path, "%s",
            de->d_name);
        ans = _fd_to_inode(procfs_path, &inode);
        if (ans)
            continue;

        /* associate newly discovered socket inode to pid             *
         * NOTE: since lookup is O(1) anyway, just reuse socket_new() */
        _register_socket(pid, atoi(de->d_name), inode);

        /* reset errno in case next readdir fails with error */
        errno = 0;
    }

    /* error reading entry in fd/ is most likely due to early close() */
    if (errno == 2) {
        symlink_miss++;
    }

    /* cleanup */
    closedir(d);

    return 0;
}

/* _scan_all_procs - identify associated sockets for all processes
 *  @return : 0 if everything went well
 *
 * this is a costly operation and should only be called once, when a packet is
 * received via netfitler queue from a socket that was opened before we started
 * the firewall; chances are _very_ high that this will happen immeidately on a
 * normal machine (that has an open browser, for example)
 */
static int32_t _scan_all_procs(void)
{
    PROCTAB *proc;
    proc_t proc_info;

    /* clean proc info structure */
    memset(&proc_info, 0, sizeof(proc_info));

    /* get PROCTAB instance w/o extra info */
    proc = openproc(0);
    RET(!proc, -1, "");

    /* for all running processes */
    while (readproc(proc, &proc_info))
        _scan_proc_sockets(proc_info.tgid);

    /* clean up */
    closeproc(proc);

    return 0;
}

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* sc_init - initializes socket cache internal structures
 *  @return : 0 if everything went well
 */
int32_t sc_init(void)
{
    int32_t ans;

    /* compile regex for fd symlink value match to socket string */
    ans = regcomp(&regex, "socket:\\[[[:digit:]]*\\]", REG_NOSUB);
    RET(ans, ans, "unable to compile regex (%d)", ans);

    return 0;
}

/* sc_open_fd - process opened new fd (might be socket)
 *  @pid : process that opened fd
 *  @fd  : the openeed file descriptor
 */
void sc_open_fd(uint32_t pid, uint8_t fd)
{
    uint32_t inode;
    int32_t  ans;

    /* determine inode of newly opened id; if not socket, skip */
    ans = _fd_to_inode(pid, fd, &inode);
    if (ans)
        return;

    /* update internal structures with new info */
    _register_socket(pid, fd, inode);
}

/* sc_close_fd - process closed fd (might be socket)
 *  @pid : process that closed fd
 *  @fd  : the closed file descriptor
 */
void sc_close_fd(uint32_t pid, uint8_t fd)
{
    int32_t  ans;
    uint32_t inode;

    /* try to find previous <pid,fd>:inode associations for this instance   *
     * if missing, the fd was either not for a socket, or we didn't need to *
     * know about this socket until now (won't matter since it's closed)    */
    auto f2s_ans = fd_to_sock.find(make_pair(pid, fd));
    if (f2s_ans == fd_to_sock.end())
        return;
    inode = f2s_ans->second;

    /* descrease reference count for inode for this process     *
     * on counter reaching 0, remove <pid,fd>:inode association */
    if (--inode_fd_ref[make_pair(pid, inode)] == 0)
        fd_to_sock.erase(f2s_ans);

    /* find pid set for given socket & remove pid                         *
     * NOTE: remove pid_set if empty since we may not get a better chance */
    auto pid_set = sock_to_pids.find(inode);
    if (pid_set != sock_to_pids.end()) {
        auto ans = pid_set->second.erase(pid);
        ALERT(!ans, "pid %u not associated with inode %u", pid, inode);

        /* clean up empty set                                       *
         * NOTE: empty pid set means that the socket is effectively *
         *       inaccessible now and any claim to a port is void   */
        if (!pid_set->second.size()) {
            sock_to_pids.erase(pid_set);

            /* clean up port association (if any) */
            auto port_it = sock_to_port.find(inode);
            if (port_it != sock_to_port.end()) {
                port_to_sock.erase(port_it->second);
                sock_to_port.erase(port_it);
            }
        }
    } else
        WAR("no pid set exists for inode %u", inode);

    /* find socket set for given pid & remove inode             *
     * NOTE: sock_set will be removed for pid only when exiting */
    auto sock_set = pid_to_socks.find(pid);
    if (sock_set != pid_to_socks.end()) {
        auto ans = sock_set->second.erase(inode);
        ALERT(!ans, "inode %u not associated with pid %u", inode, pid);
    } else
        WAR("no socket set exists for pid %u", pid);
}

/* sc_proc_exit - process exits and all sockets are closed (for that process)
 *  @pid : process that exited
 */
void sc_proc_exit(uint32_t pid)
{
    /* find socket set for given pid */
    auto sock_set = pid_to_socks.find(pid);
    if (sock_set != pid_to_socks.end()) {
        /* for each socket inode associated to given pid */
        for (auto inode : sock_set->second) {
            /* find pid set for current socket & remove pid */
            auto pid_set = sock_to_pids.find(inode);
            if (pid_set != sock_to_pids.end()) {
                pid_set->second.erase(pid);

                /* clean up empty set                                       *
                 * NOTE: empty pid set means that the socket is effectively *
                 *       inaccessible now and any claim to a port is void   */
                if (!pid_set->second.size()) {
                    sock_to_pids.erase(pid_set);

                    /* clean up port association (if any) */
                    auto port_it = sock_to_port.find(inode);
                    if (port_it != sock_to_port.end()) {
                        port_to_sock.erase(port_it->second);
                        sock_to_port.erase(port_it);
                    }
                }
            } else
                WAR("no pid set exists for inode %u", inode);
        }

        /* clean up (possibly non-empty) set */
        pid_to_socks.erase(sock_set);
    }

    /* erase <pid,fd>:inode maps for current pid */
    erase_if(fd_to_sock, [pid](const auto &item) {
        auto const& [key, value] = item;
        return get<0>(key) == pid;
    });

    /* erase <pid,inode>:count maps for current pid */
    erase_if(inode_fd_ref, [pid](const auto &item) {
        auto const& [key, value] = item;
        return get<0>(key) == pid;
    });

    /* remove prpcess from tracked pids set (no surprise if not there) */
    tracked_pids.erase(pid);
}

/* sc_proc_fork - process forks and all socket descriptors are copied over
 *  @parent_pid : process that forked
 *  @child_pid  : new, child process
 */
void sc_proc_fork(uint32_t parent_pid, uint32_t child_pid)
{
    /* check if parent was tracked (results in fast path) */
    auto tracked_parent = tracked_pids.find(parent_pid);

    /* slow path - scan /proc/<parent_pid>/fd/ and add him to tracked set */
    if (tracked_parent == tracked_pids.end()) {
        int32_t ans = _scan_proc_sockets(parent_pid);

        /* even slower path - parent must have exited right after fork  *
         *                    must check /proc/<child_pid>/fd/ directly */
        if (unlikely(ans)) {
            _scan_proc_sockets(child_pid);
            goto proc_fork_out;
        }

        /* parent can now be considered tracked since inception */
        tracked_pids.insert(parent_pid);
    }

    /* fast path - copy parent's accessible sockets over to the child */
    pid_to_socks[child_pid] = pid_to_socks[parent_pid];

    for (auto& sock : pid_to_socks[child_pid])
        sock_to_pids[sock].insert(child_pid);

    for (auto& [key, value] : fd_to_sock)
        if (get<0>(key) == parent_pid) {
            fd_to_sock[make_pair(child_pid, get<1>(key))] = value;
            inode_fd_ref[make_pair(child_pid, value)] =
                inode_fd_ref[make_pair(parent_pid, value)];
        }

proc_fork_out:
    /* add new process to tracekd pids set */
    tracked_pids.insert(child_pid);
}

/* sc_proc_exec - process execs and we can't make assumptions about O_CLOEXEC
 *  @pid : process that exec-ed
 */
void sc_proc_exec(uint32_t pid)
{
    /* best option for now is to pretend the process died and reanalyze its *
     * /proc/<pid>/fd/ directory for open sockets                           */
    sc_proc_exit(pid);
    _scan_proc_sockets(pid);
}

/* sc_dump_state - dump internal state of data structures (for debug)
 */
void sc_dump_state(void)
{
    printf("=======================[ state dump ]=======================\n");

    /* for all monitored processes */
    for (auto& [pid_k, sock_set] : pid_to_socks) {
        printf(MAGENTA_B ">>> pid:   " UNSET_B "%5u (socks: %lu)\n" CLR,
            pid_k, sock_set.size());

        /* for all sockets available to current process */
        for (auto& inode : sock_set) {
            printf(CYAN_B " >> inode: " UNSET_B "%10u (refs: %lu)\n" CLR,
                inode, sock_to_pids[inode].size());
        }
    }

    /* print additional statistics */
    printf("\n\n");
    printf(BLUE_B "early fd close:     " UNSET_B "%10lu\n" CLR, symlink_miss);
    printf(BLUE_B "early process exit: " UNSET_B "%10lu\n" CLR, dir_miss);

    printf("========================[ cut here ]========================\n");
}

/* sc_get_pid - performs port -> socket_inode -> pid translation
 *  @protocol  : protocol employed by the socket
 *  @src_ip    : network order source ip        (can be 0)
 *  @dst_ip    : network order destination ip   (can be 0)
 *  @src_port  : network order source port      (must NOT be 0)
 *  @dst_port  : network order destination port (can be 0)
 *  @netns_dev : network namespace resident device
 *  @netns_ino : netowrk namespace inode
 *
 *  @return : pointer to set of pids that have access to given port
 *            or NULL on error or no match found
 *
 * arguments that can be 0 are used to filter entries in netlink socket
 * diagnostics request. only src_port will be used when mapping the inode in
 * the internal structures
 *
 * NOTE: see `man ioctl_ns` to understand where to get @netns_dev and @netns_ino
 *
 * NOTE: caller must perform transition to the correct network namespace
 *       _before_ calling this function; when taking the slow path, the creation
 *       of the netlink socket must be performed in the same namespace as the
 *       network socket that needs to be identified
 */
unordered_set<uint32_t> *sc_get_pid(uint8_t  protocol,
                                    uint32_t src_ip,
                                    uint32_t dst_ip,
                                    uint16_t src_port,
                                    uint16_t dst_port,
                                    uint64_t netns_dev,
                                    uint64_t netns_ino)
{
    int32_t  ans;       /* answer         */
    uint32_t inode;     /* socket inode   */

    /* sanity check; a src_port 0 will not break nl_sock_diag but will waste *
     * time with netlink socket diagnostics query that we can't use anyway   */
    RET(!src_port, NULL, "zero-valued src port was provided");

    /* fast path: look up socket inode based on namespace and port */
    auto inode_it = port_to_sock.find(
                        make_tuple(netns_dev, netns_ino, src_port));
    if (inode_it != port_to_sock.end()) {
        inode = inode_it->second;
    }
   /* slow path: find socket via netlink diagnostics */
    else {
        /* look up inode of socket with given filtering criteria *
         * NOTE: misses here can be common; make it less verbose *
         * TODO: might be interesting to add a counter here      */
        ans = nl_sock_diag(protocol, src_ip, dst_ip, src_port,
                dst_port, &inode);
        if (ans)
            return NULL;

        /* update internal structures */
        port_to_sock[make_tuple(netns_dev, netns_ino, src_port)] = inode;
        sock_to_port[inode] = make_tuple(netns_dev, netns_ino, src_port);
    }

    /* fast path: using inode, find the cached set of associated pids */
    auto pids_it = sock_to_pids.find(inode);
    if (pids_it != sock_to_pids.end()) {
        return &pids_it->second;
    }
    /* slow path: analyze the open file descriptors of all processes */
    else {
        _scan_all_procs();

        /* try finding the set of associated pids once again *
         * if this fails, we have a problem                  */
        pids_it = sock_to_pids.find(inode);
        RET(pids_it == sock_to_pids.end(), NULL,
            "could not find socket match in any process (inode: %u)", inode);
    }

    return NULL;
}

