#include <unordered_map>    /* unordered_map          */
#include <stdio.h>          /* fopen, fclose, getline */
#include <openssl/sha.h>    /* SHA256_*               */
#include <fcntl.h>          /* open                   */
#include <unistd.h>         /* close                  */
#include <stdlib.h>         /* malloc                 */
#include <sys/stat.h>       /* fstat                  */
#include <sys/mman.h>       /* mmap, munmap           */

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

int32_t               hc_init(uint8_t _rm, uint8_t _pm);
uint8_t               *hc_get_sha256(char *path);
unordered_set<string> hc_get_maps(uint32_t pid);
void                  hc_proc_exit(uint32_t pid);

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
    SHA256_CTX  ctx;        /* sha256 context        */
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
    GOTO(ans == -1, _compute_sha256_clean_fd, "unable to stat file %s (%s)",
        path, strerror(errno));

    /* map file in virtual memory */
    pa = (uint8_t *) mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    GOTO(pa == MAP_FAILED, _compute_sha256_clean_fd,
        "unable to mmap file %s (%s)", path, strerror(errno));

    /* allocate space on heap for hash                                   *
     * NOTE: must be manually freed when cache entry is removed (never?) */
    md = (uint8_t *) malloc(SHA256_DIGEST_LENGTH);
    GOTO(!md, _compute_sha256_clean_mmap, "unable to allocate space (%s)",
        strerror(errno));

    /* calculate sha256 of given file */
    ans = SHA256_Init(&ctx);
    GOTO(!ans, _compute_sha256_clean_mmap, "unable to initialize context");

    ans = SHA256_Update(&ctx, pa, fs.st_size);
    GOTO(!ans, _compute_sha256_clean_mmap, "unable to update internal state");

    ans = SHA256_Final(md, &ctx);
    GOTO(!ans, _compute_sha256_clean_mmap, "unable to finalize hashing");

    /* initialize/update cache with the calculated digest for future queries */
    path_to_hash[string(path)] = md;

    /* perform cleanup */
    retval = md;

_compute_sha256_clean_mmap:
    ans = munmap(pa, fs.st_size);
    ALERT(ans == -1, "problem unmapping file %s (%s)", path, strerror(errno));

_compute_sha256_clean_fd:
    ans = close(fd);
    ALERT(ans == -1, "problem closing file %s (%s)", path, strerror(errno)); 

    return retval;
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
 *  @return : set of paths to objects with .text section
 *
 *  NOTE: the set returned is a copy; caller can do whatever he wants with it
 */
unordered_set<string> hc_get_maps(uint32_t pid)
{
    FILE    *maps_f;            /* file stream for /proc/<pid>/maps        */
    char    *linebuf;           /* buffer for line-by-line read            */
    size_t  linebuf_sz;         /* size of heap-allocated read buffer      */
    ssize_t rb;                 /* number of read bytes                    */
    ssize_t wb;                 /* number of written bytes                 */
    int32_t ans;                /* answer                                  */
    char    is_x;               /* 'x' if executable; '-' otherwise        */
    char    obj_path[256];      /* filesystem path to memory-mapped object */
    char    maps_path[256];     /* path to /proc/<pid>/maps                */
    unordered_set<string> lms;  /* local maps set                          */

    /* depending on maps retention policy, get reference to working set      *
     * updates to rs will not affect global context --> old maps don't count */
    unordered_set<string>& objs = retain_maps ? pid_to_objs[pid] : lms;

    /* if map rescanning is disabled and we have a non-empty set, return it */
    if (no_rescan && objs.size())
        return objs;

    /* create path to maps file */
    wb = snprintf(maps_path, sizeof(maps_path), "/proc/%hu/maps", pid);
    ALERT(wb == sizeof(maps_path), "consider increasing buffer size"); 

    /* read /proc/<pid>/maps line by line */
    maps_f     = fopen(maps_path, "r");
    linebuf    = (char *) malloc(512);
    linebuf_sz = 512;


    /* TODO: this method can cause segfaults if the process terminates
     *       early; try to replace with a single read() and tokenize string
     *
     * to recreate problem:
     *      $ nc fep.grid.pub.ro 22
     *      ENTER
     *
     *      repeat as many times as needed; will cause segfault sometime
     */
    while ((rb = getline(&linebuf, &linebuf_sz, maps_f)) != -1) {
        /* extract relevant fields from line entry */
        sscanf(linebuf, "%*lx-%*lx %*c%*c%c%*c %*x %*hhx:%*hhx %*u %s\n",
            &is_x, obj_path);
        
        /* skip non-executable mapped sections           *
         * skip non-file-backed objects (e.g.: "[vdso]") */
        if (is_x == '-' || obj_path[0] == '[')
            continue;

        /* add object path to return set */
        objs.insert(string(obj_path));
    }

    /* cleanup */
    free(linebuf);
    fclose(maps_f);

    return objs;
}

/* hc_proc_exit - process exits; free associated maps set
 *  @pid : process that terminated
 */
void hc_proc_exit(uint32_t pid)
{
    pid_to_objs.erase(pid);
}

