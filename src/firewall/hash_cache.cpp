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

#include <stdio.h>              /* fopen, fclose        */
#include <openssl/sha.h>        /* SHA256_DIGEST_LENGTH */
#include <openssl/evp.h>        /* EVP_*                */
#include <fcntl.h>              /* open                 */
#include <unistd.h>             /* close                */
#include <stdlib.h>             /* malloc               */
#include <sys/stat.h>           /* fstat                */
#include <sys/mman.h>           /* mmap, munmap         */
#include <libmount/libmount.h>  /* mnt_{table,fs}_*     */

#include <unordered_map>    /* unordered_map */
#include <unordered_set>    /* unordered_set */

#include "hash_cache.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

/* internal data structures
 *  path_to_hash : map between object path and pointer to its sha256 digest
 *  pid_to_objs  : map between pid and a set of its correspoding objects
 */
static unordered_map<string, uint8_t *>               path_to_hash;
static unordered_map<uint32_t, unordered_set<string>> pid_to_objs;

/* operational parameters */
uint8_t retain_maps;    /* keep privously detected but now unmapped objects */
uint8_t no_rescan;      /* prevent rescanning maps if set is non-empty      */

/******************************************************************************
 ********************************* PUBLIC API *********************************
 ******************************************************************************/

int32_t     hc_init(uint8_t _rm, uint8_t _pm);
uint8_t     *hc_get_sha256(char *path);
set<string> hc_get_maps(uint32_t pid);
void        hc_proc_exit(uint32_t pid);

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
 ******************************************************************************/

/* _compute_sha256 - computes hash of file on disk; updates internal structures
 *  @path : (preferably absolute) path to file on disk
 *
 *  @return : pointer to buffer containing the 32-byte digest or NULL on error
 */
uint8_t *_compute_sha256(char *path)
{
    EVP_MD_CTX *ctx;        /* sha256 contex         */
    int32_t     fd;         /* file descriptor       */
    struct stat fs;         /* file stat buffer      */
    uint8_t     *pa;        /* mmapped file address  */
    uint8_t     *md;        /* message digest buffer */
    uint8_t     *retval;    /* return value          */
    int32_t     ans;        /* answer                */

    /* until the hashing and caching are complete, return NULL after cleanup */
    retval = NULL;

    /* open target file */
    fd = open(path, O_RDONLY);
    RET(fd == -1, NULL, "unable to open file %s (%s)", path, strerror(errno));

    /* get file stats (interested only in its size) */
    ans = fstat(fd, &fs);
    GOTO(ans == -1, clean_fd, "unable to stat file %s (%s)",
        path, strerror(errno));

    /* map file in virtual memory */
    pa = (uint8_t *) mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    GOTO(pa == MAP_FAILED, clean_fd,
        "unable to mmap file %s (%s)", path, strerror(errno));

    /* allocate space on heap for hash                                   *
     * NOTE: must be manually freed when cache entry is removed (never?) */
    md = (uint8_t *) malloc(SHA256_DIGEST_LENGTH);
    GOTO(!md, clean_mmap, "unable to allocate space (%s)",
        strerror(errno));

    /* calculate sha256 of given file */
    ctx = EVP_MD_CTX_new();
    GOTO(!ctx, clean_mmap, "unable to create EVP context");

    ans = EVP_DigestInit(ctx, EVP_sha256());
    GOTO(ans != 1, clean_ctx, "unable to initialize SHA256 context");

    ans = EVP_DigestUpdate(ctx, pa, fs.st_size);
    GOTO(ans != 1, clean_ctx, "unable to update SHA256 context");

    ans = EVP_DigestFinal_ex(ctx, md, NULL);
    GOTO(ans != 1, clean_ctx, "unable to finalize hashing");

    /* initialize/update cache with the calculated digest for future queries */
    path_to_hash[string(path)] = md;

    /* perform cleanup */
    retval = md;

clean_ctx:
    EVP_MD_CTX_free(ctx);

clean_mmap:
    ans = munmap(pa, fs.st_size);
    ALERT(ans == -1, "problem unmapping file %s (%s)", path, strerror(errno));

clean_fd:
    ans = close(fd);
    ALERT(ans == -1, "problem closing file %s (%s)", path, strerror(errno));

    return retval;
}

/* get_rootfs_mp - get process rootfs mount point if running in different ns
 *  @pid        : target process id
 *  @root_mount : reference to process rootfs relative mount point string
 *
 *  @return :  0 if overlay rootfs mount point was found
 *             1 if it wasn't (but not due to an error)
 *            -1 on error
 *
 * NOTE: this function is implemented strictly for identifying the merged
 *       rootfs mountpoint of docker containers
 * TODO: consider adding support for chroot jails
 */
static int32_t
get_rootfs_mp(uint32_t pid, string &root_mount)
{
    char                mntinf_path[256];   /* patht to /proc/<pid>/mntinfo */
    const char          *fs_ops;            /* filesystem options string    */
    struct libmnt_table *table;             /* mount table abstraction      */
    struct libmnt_fs    *fs;                /* table entry filesystem       */
    struct libmnt_iter  *itr;               /* table iterator               */
    ssize_t             wb;                 /* number of written bytes      */
    int32_t             ans;                /* answer                       */
    int32_t             ret = -1;           /* return value                 */

    /* create path to mountinfo file */
    wb = snprintf(mntinf_path, sizeof(mntinf_path), "/proc/%u/mountinfo", pid);
    ALERT(wb == sizeof(mntinf_path), "consider increasing buffer size");

    /* allocate and initialize mount table from file contents */
    table = mnt_new_table_from_file(mntinf_path);
    RET(!table, -1, "unable to initialize mount table from %s", mntinf_path);

    /* allocate table entry iterator */
    itr = mnt_new_iter(MNT_ITER_FORWARD);
    GOTO(!itr, clean_table, "unable to allocate iterator");

    /* for each mount table entry             *
     * NOTE: the rootfs entry should be first */
    while (0 == mnt_table_next_fs(table, itr, &fs)) {
        /* ignore any entry whose target is not "/"       *
         * ignore any entry whose source is not "overlay" */
        if (strcmp(mnt_fs_get_target(fs), "/")
        ||  strcmp(mnt_fs_get_source(fs), "overlay"))
        {
            continue;
        }

        /* get filesystem options string to extract mountpoint */
        fs_ops = mnt_fs_get_options(fs);
        GOTO(!fs_ops, clean_iter, "unable to extract filesystem options");

        /* what we're interested in is the merged directory of the upper *
         * overlay; the mountpoint we identify here is bound to the diff *
         * directory in stead                                            */
        char *upper_start = (char *) strstr(fs_ops, "upperdir=");
        GOTO(!upper_start, clean_iter, "unable to find \"upper\" parameter");
        upper_start += strlen("upperdir=");

        char *upper_stop = (char *) strstr(upper_start, "/diff,");
        GOTO(!upper_stop, clean_iter, "unable to find end of \"upper\"");

        root_mount = string(upper_start, 0, upper_stop - upper_start)
                     + "/merged";

        /* success */
        ret = 0;
        goto clean_iter;
    }

    /* no mountpoint found to match our criteria; but that's ok */
    root_mount = "";
    ret = 1;

    /* cleanup */
clean_iter:
    mnt_free_iter(itr);

clean_table:
    mnt_free_table(table);

    return ret;
}

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* hc_init - initialize hash cache internal structures
 *  @return : 0 if everything went well
 */
int32_t hc_init(uint8_t _rm, uint8_t _nr)
{
    retain_maps = _rm;
    no_rescan   = _nr;

    return 0;
}

/* hc_get_sha256 - returns sha256 hash of file at given path
 *  @return : pointer to buffer containing 32-byte hash or NULL on error
 *
 * NOTE: caller must not modify received buffer
 */
uint8_t *hc_get_sha256(char *path)
{
    /* fast path: find the object in local cache */
    auto hash_it = path_to_hash.find(string(path));
    if (hash_it != path_to_hash.end())
        return hash_it->second;

    /* slow path: actually calculate the hash and store it for future use */
    return _compute_sha256(path);
}

/* hc_get_maps - returns set of maps with executable sections for given process
 *  @pid : target process id
 *
 *  @return : (ordered) set of paths to objects with .text section
 *
 *  NOTE: the set returned is a copy; caller can do whatever he wants with it
 */
set<string> hc_get_maps(uint32_t pid)
{
    static char   *buff = NULL;    /* buffer for contents of /proc/<pid>/maps */
    static size_t buff_sz = 0;     /* buffer size                             */
    size_t        trb;             /* total number of read bytes              */
    ssize_t       rb;              /* number of read bytes                    */
    ssize_t       wb;              /* number of written bytes                 */
    int32_t       ans;             /* answer                                  */
    int32_t       maps_fd;         /* /proc/<pid>/maps file descriptor        */
    char          *tit;            /* string token iterator                   */
    char          is_x;            /* 'x' if executable; '-' otherwise        */
    char          obj_path[256];   /* filesystem path to memory-mapped object */
    char          maps_path[256];  /* path to /proc/<pid>/maps                */
    string        root_mount;      /* namespace rootfs mountpoint             */
    unordered_set<string> lms;     /* local maps set                          */

    /* depending on maps retention policy, get reference to working set      *
     * updates to rs will not affect global context --> old maps don't count */
    unordered_set<string>& objs = retain_maps ? pid_to_objs[pid] : lms;

    /* ensure an initial buffer size of 1Mb (a bit large for stack) */
    if (unlikely(!buff)) {
        buff = (char *) malloc(1024 * 1024);
        GOTO(!buff, create_ordered_set, "unable to allocate buffer (%s)",
            strerror(errno));

        buff_sz = 1024 * 1024;
    }

    /* if map rescanning is disabled and we have a non-empty set, return it */
    if (no_rescan && objs.size())
        goto create_ordered_set;

    /* create path to maps file */
    wb = snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    ALERT(wb == sizeof(maps_path), "consider increasing buffer size");

    /* read /proc/<pid>/maps and permanently resize buffer (if needed)        *
     * NOTE: getline() is not an option since getdelim() can fail with SIGSEV *
     *       if the file is unliked mid-read (very likely for this file)      */
    maps_fd = open(maps_path, O_RDONLY);
    GOTO(maps_fd == -1, create_ordered_set, "unable to open %s (%s)",
        maps_path, strerror(errno));

    trb = 0;
    do {
        rb = read(maps_fd, buff + trb, buff_sz - trb);
        GOTO(rb == -1, create_ordered_set, "error reading from %s (%s)",
            maps_path, strerror(errno));

        trb += rb;
        if (trb == buff_sz) {
            buff = (char *) realloc(buff, buff_sz * 2);
            GOTO(!buff, create_ordered_set, "unable to double buffer size (%s)",
                strerror(errno));

            buff_sz *= 2;
        }
    } while (rb);

    /* do immeidate cleanup */
    ans = close(maps_fd);
    ALERT(ans == -1, "unable to close %s (%s)", maps_path, strerror(errno));

    /* this should be impossible... */
    GOTO(unlikely(!trb), create_ordered_set, "file %s was empty!?", maps_path);

    /* in case the process runs in a mount namespace, try finding prefix *
     * of its rootfs mount point according to our view of the entire     *
     * filesystem                                                        */
    ans = get_rootfs_mp(pid, root_mount);
    GOTO(ans == -1, create_ordered_set, "error getting rootfs mountpoint");

    /* replace final '\n' in /proc/<pid>/maps with '\0' for next step */
    buff[trb - 1] = '\0';

    /* tokenize file contents (split by '\n') -- parse line by line */
    tit = strtok(buff, "\n");
    while (tit) {
        /* extract relevant fields from line entry */
        sscanf(tit, "%*lx-%*lx %*c%*c%c%*c %*x %*hhx:%*hhx %*u %s\n",
            &is_x, obj_path);

        /* skip non-executable mapped sections           *
         * skip non-file-backed objects (e.g.: "[vdso]") *
         * skip if anonymous executable map              */
        if (is_x == '-' || obj_path[0] == '[' || !strlen(obj_path)) {
            /* transition to next token */
            tit = strtok(NULL, "\n");

            continue;
        }

        /* add object path to returned set */
        objs.insert(root_mount + string(obj_path));

        /* transition to next token */
        tit = strtok(NULL, "\n");
    }

create_ordered_set:
    /* copy the unordered set contents into an ordered one to maintain object *
     * order across processes (even if they are scrambled)                    *
     *                                                                        *
     * TODO: convert objs to set<string> across entire module?                *
     *       any performance cost? check this...                              */
    return set(objs.begin(), objs.end());
}

/* hc_proc_exit - process exits; free associated maps set
 *  @pid : process that terminated
 */
void hc_proc_exit(uint32_t pid)
{
    pid_to_objs.erase(pid);
}

