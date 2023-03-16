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

#include <fcntl.h>          /* open            */
#include <unistd.h>         /* close           */
#include <sys/stat.h>       /* fstat           */

#include <unordered_map>    /* unordered_map   */
#include <string>           /* string          */

#include "netns_cache.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

/* internal data structures
 *  file_to_fd : map between magic namespace file names and file descriptors
 *  refcount   : number of references to each namespace file by existing rules
 *  fd_to_ns   : (netns_dev, netns_ino) associated to magic file
 */
static unordered_map<string, uint32_t>                   file_to_fd;
static unordered_map<string, size_t>                     refcount;
static unordered_map<uint32_t, pair<uint64_t, uint64_t>> fd_to_ns;

/******************************************************************************
 ********************************* PUBLIC API *********************************
 ******************************************************************************/

int32_t nnc_get_fd(char *netns_path);
int32_t nnc_retire_fd(char *netns_path);

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* nnc_get_fd - obtains file descriptor from magic network namespace file
 *  @netns_path : path to magic file (e.g.: /proc/<pid>/ns/net)
 *
 *  @return : file descriptor or -1 on error
 *
 * Should be called on firewall rule insertion.
 */
int32_t
nnc_get_fd(char *netns_path)
{
    auto        path_str = string(netns_path);  /* hastable key           */
    struct stat statbuf;                        /* magic file stat buffer */
    int32_t     fd;                             /* magic file descriptor  */
    int32_t     ans;                            /* answer                 */

    /* try to find the magic file in cache */
    auto entry = file_to_fd.find(path_str);
    if (entry != file_to_fd.end()) {
        refcount[path_str]++;
        return entry->second;
    }

    /* first time encountering this magic file                         *
     * NOTE: O_CLOEXEC is not really necessary, but better to be safe  *
     *       as long as there's an open file descriptor of a namespace *
     *       magic file, the namespace will not be deleted             */
    fd = open(netns_path, O_RDONLY | O_CLOEXEC);
    RET(fd == -1, -1, "unable to open netns magic file \"%s\" (%s)",
        netns_path, strerror(errno));

    /* stat magic file to find out the namespace device and inode *
     * these two uniquely identify the network namespace          *
     * NOTE: see `man ioctl_ns` for more details                  */
    ans = fstat(fd, &statbuf);
    GOTO(ans == -1, err_cleanup, "unable to stat netns magic file \"%s\" (%s)",
         netns_path, strerror(errno));

    /* update internal structures */
    file_to_fd[path_str] = fd;
    refcount[path_str]   = 1;
    fd_to_ns[fd]         = make_pair(statbuf.st_dev, statbuf.st_ino);

    return fd;

err_cleanup:

    return -1;
}

/* nnc_release_ns - retires cached namespace (if all references are gone)
 *  @netns_path : path to magic file (e.g.: /proc/<pid>/ns/net)
 *
 *  @return : 0 if everything went well; !0 otherwise
 *
 * Should be called on firewall rule deletion.
 */
int32_t
nnc_release_ns(char *netns_path)
{
    auto path_str = string(netns_path);

    /* check that magic file is indeed in cache */
    RET(!file_to_fd.contains(path_str) || !refcount.contains(path_str),
        -1, "netns cache does not contain \"%s\"", netns_path);

    /* decrement refcount; clean up if counter reaches 0 */
    if (--refcount[path_str] == 0) {
        close(file_to_fd[path_str]);

        refcount.erase(path_str);
        file_to_fd.erase(path_str);
    }

    return 0;
}

/* nnc_fd_to_ns - gets namespace dev & inode numbers from magic fd
 *  @fd : magic file descriptor of network namespace
 *
 *  @return : (netns_dev, netns_ino) on success; otherwise (-1, -1)
 */
pair<uint64_t, uint64_t>
nnc_fd_to_ns(uint32_t fd)
{
    RET(!fd_to_ns.contains(fd), make_pair(-1, -1), "unknown netns fd %u", fd);

    return fd_to_ns[fd];
}

