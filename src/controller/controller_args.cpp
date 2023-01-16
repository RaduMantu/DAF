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

#include <string.h>         /* strchr               */
#include <stdlib.h>         /* realpath, malloc     */
#include <fcntl.h>          /* open                 */
#include <unistd.h>         /* close, exit          */
#include <sys/mman.h>       /* mmap, munmap         */
#include <sys/stat.h>       /* stat                 */
#include <arpa/inet.h>      /* inet_pton, AF_INET   */
#include <netinet/in.h>     /* IPPROTO_*            */
#include <openssl/sha.h>    /* SHA256_DIGEST_LENGTH */
#include <openssl/evp.h>    /* EVP_*                */

#include <string>           /* string */
#include <set>              /* set    */

#include "controller_args.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** PARSER ARGUMENTS CONFIG ***************************
 ******************************************************************************/

/* argp API global variables */
const char *argp_program_version     = "version 1.0";
const char *argp_program_bug_address = "<andru.mantu@gmail.com>";

/* argument identifiers with no shorthand */
enum {
    ARG_SRCP = 600,         /* source port      */
    ARG_DSTP = 601,         /* destination port */
    ARG_AGGH = 602,         /* aggregate hash   */
    ARG_SNGH = 603,         /* single hash      */
};

/* command line arguments */
static struct argp_option options[] = {
    /* commands */
    { NULL, 0, NULL, 0, "Commands" },
    { "list",       'L', NULL,   0, "List existing rules",                  0 },
    { "append",     'A', NULL,   0, "Append rule at the end",               0 },
    { "insert",     'I', "NUM",  0, "Insert rule on position (0 is first)", 0 },
    { "delete",     'D', "NUM",  0, "Delete rule on position (0 is first)", 0 },
    { "print-hash", 'H', "PATH", 0, "prints the SHA256 digest of a file",   1 },

    /* meta */
    { NULL, 0, NULL, 0, "Modifiers" },
    { "not", '!', NULL, 0, "Negates next argument (appicable where \"[!]\")" },

    /* options */
    { NULL, 0, NULL, 0, "Options (for -I|-A)"},
    { "src-ip",    's',      "ADDR[/MASK]",    0, "[!] Source ip",                  0 },
    { "dst-ip",    'd',      "ADDR[/MASK]",    0, "[!] Destination ip",             0 },
    { "proto",     'p',      "{NUM|tcp|udp}",  0, "[!] Layer 4 protocol number",   10 },
    { "sport",     ARG_SRCP, "PORT",           0, "[!] Source port",               20 },
    { "dport",     ARG_DSTP, "PORT",           0, "[!] Destination port",          20 },
    { "sng-hash",  ARG_SNGH, "HEXSTR",         0, "[!] Hash of single object",     30 },
    { "agg-hash",  ARG_AGGH, "HEXSTR",         0, "[!] Aggregate multiple hashes", 30 },
    { "vrdct",     'v',      "{ACCEPT|DROP}",  0, "Verdict for matched criteria",  40 },
    { "chain",     'c',      "{INPUT|OUTPUT}", 0, "Where to apply command",        40 },
    { "sig-loc"  , 'l',      "{l3|l4}",        0, "Signature insertion location",  40 },

    /* end of list */
    { 0 },
};

/* argument parser prototype */
static error_t parse_opt(int, char *, struct argp_state *);

/* description of accepted non-option arguments */
static char args_doc[] = "";

/* program documentation */
static char doc[] = "Rule manager for application identity-based firewall.";

/* declaration of relevant structures */
struct argp    argp = {options, parse_opt, args_doc, doc };
struct ctl_msg cfg  = {
    .msg  = { 0 },
    .rule = { 0 },
};

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
 ******************************************************************************/

/* _compute_sha256 - computes hash of file on disk
 *  @path : (relative of absolute) path to file on disk
 *  @buff : message digest buffer (len = SHA256_DIGEST_LENGTH)
 *
 *  @return : 0 if everythin went well
 */
static int32_t _compute_sha256(char const *path, uint8_t *buff)
{
    EVP_MD_CTX *ctx;    /* sha256 contex         */
    int32_t     fd;     /* file descriptor      */
    struct stat fs;     /* file stat buffer     */
    uint8_t     *pa;    /* mmapped file address */
    int32_t     ans;    /* answer               */
    int32_t     ret;    /* return value         */

    /* until hashing is complete, assume error */
    ret = -1;

    /* open target file */
    fd = open(path, O_RDONLY);
    RET(fd == -1, ret, "unable to open file (%s)", strerror(errno));

    /* get file stats (interested only in its size) */
    ans = fstat(fd, &fs);
    GOTO(ans == -1, clean_fd, "unable to stat file (%s)",
        strerror(errno));

    /* map file in memory */
    pa = (uint8_t *) mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    GOTO(pa == MAP_FAILED, clean_fd, "unable to map file (%s)",
        strerror(errno));

    /* calculate sha256 of given file */
    ctx = EVP_MD_CTX_new();
    GOTO(!ctx, clean_mmap, "unable to create EVP context");

    ans = EVP_DigestInit(ctx, EVP_sha256());
    GOTO(ans != 1, clean_ctx, "unable to initialize SHA256 context");

    ans = EVP_DigestUpdate(ctx, pa, fs.st_size);
    GOTO(ans != 1, clean_ctx, "unable to update SHA256 context");

    ans = EVP_DigestFinal_ex(ctx, buff, NULL);
    GOTO(ans != 1, clean_ctx, "unable to finalize hashing");

    /* hashing finalized normally */
    ret = 0;

    /* perform cleanup */
clean_ctx:
    EVP_MD_CTX_free(ctx);

clean_mmap:
    ans = munmap(pa, fs.st_size);
    ALERT(ans == -1, "problem unmapping files (%s)", strerror(errno));

clean_fd:
    ans = close(fd);
    ALERT(ans == -1, "unable to close file (%s)", strerror(errno));

    return ret;
}

/* _display_hashes - processes all -H arguments and prints aggregate hash too
 *  @paths : ordered set of file absolute paths
 *
 *  @return : 0 if everything went well
 */
static int32_t _display_hashes(set<string>& paths)
{
    uint8_t    md_single[SHA256_DIGEST_LENGTH];
    uint8_t    md_aggregate[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx;        /* sha256 contex */
    int32_t    ans;         /* answer        */
    int32_t    ret = -1;    /* return value  */

    /* prepare sha256 context for aggregate hash */
    ctx = EVP_MD_CTX_new();
    RET(!ctx, -1, "unable to create EVP context");

    ans = EVP_DigestInit(ctx, EVP_sha256());
    GOTO(ans != 1, clean_ctx, "unable to initialize SHA256 context");

    /* for each absolute path (in order!) */
    for (auto& path_it : paths) {
        /* compute sha256 of file */
        ans = _compute_sha256(path_it.c_str(), md_single);
        GOTO(ans, clean_ctx, "unable to calculate sha256 of %s",
             path_it.c_str());

        /* print single hash entry */
        printf("%-52s -- ", path_it.c_str());
        print_hexstring(md_single, sizeof(md_single));
        printf("\n");

        /* update aggregate hash */
        ans = EVP_DigestUpdate(ctx, md_single, sizeof(md_single));
        GOTO(ans != 1, clean_ctx, "unable to update SHA256 context");

    }

    /* finalize aggregate hash calculation */
    ans = EVP_DigestFinal_ex(ctx, md_aggregate, NULL);
    GOTO(ans != 1, clean_ctx, "unable to finalize hashing");

    /* print aggregate hash */
    printf("============================================================"
           "============================================================"
           "\n%-52s -- ", "AGGREGATE HASH");
    print_hexstring(md_aggregate, sizeof(md_aggregate));
    printf("\n");

    /* success */
    ret = 0;

clean_ctx:
    EVP_MD_CTX_free(ctx);

    return 0;
}

/* _isnumber - checks if string is numeric
 *  @s : string
 *
 *  @return : 1 if the string represents a number; 0 otherwise
 */
static int32_t _isnumber(char *s)
{
    /* null string is not a number */
    if (!*s)
        return 0;

    for (; *s; ++s)
        if (*s < '0' || *s > '9')
            return 0;

    return 1;
}

/* _parse_cidr_addr - extracts IP and mask in network order from CIDR string
 *  @str  : CIDR string
 *  @addr : ptr to network order address
 *  @mask : ptr to network order mask
 *
 *  @return : 0 if everything went well
 *
 * NOTE: contents of str may be changed by this function
 */
static int32_t _parse_cidr_addr(char *str, uint32_t *addr, uint32_t *mask)
{
    char    *nm;    /* pointer to network mask in string */
    uint8_t prefix; /* network prefix in CIDR notation   */
    int32_t ans;    /* answer                            */

    /* check if network mask is present */
    nm = strchr(str, '/');
    if (nm) {
        /* separate ip address from network mask in arg string */
        *nm++ = '\0';

        /* extract network mask number from arg string */
        RET(!_isnumber(nm), EINVAL, "invalid network mask");
        sscanf(nm, "%lu", &prefix);
        RET(prefix < 0 || prefix > 32, EINVAL, "invalid network mask");
    }
    /* or assume that it's /32 */
    else
        prefix = 32;

    /* convert CIDR network mask to binary form (network order)             *
     * NOTE: there is a corner case where a (uint32_t) -1 shifted left (or  *
     *       right) by its size (i.e.: 32) will fail; that's why we need to *
     *       cast -1 to uint64_t so that all bits can overflow before       *
     *       recast-ing it to uint32_t. Note that shifting by 31 and then   *
     *       by 1 will achieve the expected result                          */
    *mask = htonl((uint64_t) (-1) << (32 - prefix));

    /* extract ip address & apply mask */
    ans = inet_pton(AF_INET, str, addr);
    RET(!ans, EINVAL, "invalid IPv4 address");
    RET(ans == -1, EINVAL, "invalid address family (%s)", strerror(errno));

    *addr &= *mask;

    return 0;
}

/* _parse_port_num - extracts port number in network order from string
 *  @str  : numeric string
 *  @port : ptr to network order port number
 *
 *  @return : 0 if everything went well
 */
static int32_t _parse_port_num(char *str, uint16_t *port)
{
    int64_t number;     /* store (posssibly negative) number */

    /* sanity check */
    RET(!_isnumber(str), EINVAL, "invalid port number");

    sscanf(str, "%ld", &number);
    RET(number < 0, EINVAL, "invalid port number");

    /* initialize port filed */
    *port = htons((uint16_t) number);

    return 0;
}

/* _is_hexfmt - checks if character represents a b16 representation of a nibble
 *  @c : character
 *
 *  @return : 1 if character is valid, 0 otherwise
 */
static int32_t _is_hexfmt(char c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'F')
        || (c >= 'a' && c <= 'f');
}

/* _read_hexstring - reads a hexstring from a char array into a buffer
 *  @str_buff : source string buffer
 *  @bin_buff : destination binary buffer
 *  @buff_len : length of string
 *
 *  @return : 0 if everything went ok
 *
 *  bin_buff must point to an already allocated memory region of size
 *  strlen(str_buff) / 2 or larger. string length must be even, meaning
 *  that str_buff must be be prepended with 0 if the ms nibble of the first
 *  byte is 0.
 */
static int32_t
_read_hexstring(char *str_buff, uint8_t *bin_buff, size_t buff_len)
{

    /* check that hexstring length is even */
    size_t str_len = strlen(str_buff);
    RET(str_len & 1, EINVAL, "must zero pad hexstring to even length");

    /* check that hexstring can fit (exactly) in buffer */
    RET(str_len / 2 > buff_len, EINVAL, "hexstring is too long");
    RET(str_len / 2 < buff_len, EINVAL, "hexstring is too small");

    /* iterate over hexstring */
    for (size_t i = 0; i < str_len; i += 2) {
        /* check that byte hexstring format is correct */
        RET(!_is_hexfmt(str_buff[i]) || !_is_hexfmt(str_buff[i+1]), EINVAL,
            "invalid hexstring format");

        /* convert string to binary */
        sscanf(&str_buff[i], "%02hhx", &bin_buff[i >> 1]);
    }

    return 0;
}

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* print_hexstring - prints a hexstring to stdout without newline
 *  @buff : pointer to buffer holding hexstring
 *  @len  : length of hexstring
 */
void print_hexstring(const uint8_t *buff, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        printf("%02hhx", buff[i]);
}

/* parse_opt - parses one argument and updates relevant structures
 *  @key   : argument id
 *  @arg   : pointer to actual argument
 *  @state : parsing state

 *  @return : 0 if everything ok
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    static uint16_t    invert = 0;      /* used when processing "-!"        */
    static set<string> paths;           /* ordered set of paths             */
    char               path[PATH_MAX];  /* real path buffer                 */
    char               *path_p;         /* return value from realpath       */
    int64_t            number;          /* store (possibly negative) number */
    int32_t            ans;             /* answer                           */

    switch (key) {
        /* list existing rules */
        case 'L':
            RET(cfg.msg.flags & CTL_HASH, EINVAL, "-L and -H not compatible");
            RET(cfg.msg.flags & CTL_REQ_MASK, EINVAL, "too many commands");

            cfg.msg.flags |= CTL_LIST;
            break;
        /* append rule */
        case 'A':
            RET(cfg.msg.flags & CTL_HASH, EINVAL, "-A and -H not compatible");
            RET(cfg.msg.flags & CTL_REQ_MASK, EINVAL, "too many commands");
            RET((cfg.msg.flags & CTL_INPUT)
             && (cfg.msg.flags & CTL_OUTPUT),
             EINVAL,
             "only LIST command works on both INPUT and OUTPUT simultaneously");

            cfg.msg.flags |= CTL_APPEND;
            break;
        /* insert rule */
        case 'I':
            RET(cfg.msg.flags & CTL_HASH, EINVAL, "-I and -H not compatible");
            RET(cfg.msg.flags & CTL_REQ_MASK, EINVAL, "too many commands");
            RET(!_isnumber(arg), EINVAL, "insert position is not numeric");
            RET((cfg.msg.flags & CTL_INPUT)
             && (cfg.msg.flags & CTL_OUTPUT),
             EINVAL,
             "only LIST command works on both INPUT and OUTPUT simultaneously");

            /* check if position is negative */
            sscanf(arg, "%ld", &number);
            RET(number < 0, EINVAL, "insert position can not be negative");

            cfg.msg.flags |= CTL_INSERT;
            cfg.msg.pos    = number;
            break;
        /* delete rule */
        case 'D':
            RET(cfg.msg.flags & CTL_HASH, EINVAL, "-D and -H not compatible");
            RET(cfg.msg.flags & CTL_REQ_MASK, EINVAL, "too many commands");
            RET(!_isnumber(arg), EINVAL, "delete position is not numeric");
            RET((cfg.msg.flags & CTL_INPUT)
             && (cfg.msg.flags & CTL_OUTPUT),
             EINVAL,
             "only LIST command works on both INPUT and OUTPUT simultaneously");

            /* check if position is negative */
            sscanf(arg, "%ld", &number);
            RET(number < 0, EINVAL, "delete position can not be negative");

            cfg.msg.flags |= CTL_DELETE;
            cfg.msg.pos    = number;
            break;
        /* get hash of file */
        case 'H':
            RET(cfg.msg.flags & CTL_REQ_MASK, EINVAL,
                "-H not compatible with firewall requests");
            cfg.msg.flags |= CTL_HASH;

            /* obtain real path from (possibly) relative */
            path_p = realpath(arg, path);
            RET(!path_p, EINVAL, "failed to resolve path %s (%s)", arg,
                strerror(errno));

            /* add path to set for later in-order hashing */
            paths.insert(string(path));

            break;
        /* source ip addr */
        case 's':
            RET(cfg.rule.flags & FLT_SRC_IP, EINVAL, "too many -s options");
            cfg.rule.flags |= FLT_SRC_IP;

            /* account for possible rule check inversion */
            if (invert) {
                cfg.rule.flags |= FLT_SRC_IP_INV;
                invert = 0;
            }

            /* parse CIDR address */
            ans = _parse_cidr_addr(arg, &cfg.rule.src_ip, &cfg.rule.src_ip_mask);
            RET(ans, ans, "failed to parse CIDR address");

            break;
        /* destination ip addr */
        case 'd':
            RET(cfg.rule.flags & FLT_DST_IP, EINVAL, "too many -d options");
            cfg.rule.flags |= FLT_DST_IP;

            /* account for possible rule check inversion */
            if (invert) {
                cfg.rule.flags |= FLT_DST_IP_INV;
                invert = 0;
            }

            /* parse CIDR address */
            ans = _parse_cidr_addr(arg, &cfg.rule.dst_ip, &cfg.rule.dst_ip_mask);
            RET(ans, ans, "failed to parse CIDR address");

            break;
        /* layer 4 protocol */
        case 'p':
            RET(cfg.rule.flags & FLT_L4_PROTO, EINVAL, "too many -p options");
            cfg.rule.flags |= FLT_L4_PROTO;

            /* account for possible rule check inversion */
            if (invert) {
                cfg.rule.flags |= FLT_L4_PROTO_INV;
                invert = 0;
            }

            /* protocol given in numeric format */
            if (_isnumber(arg)) {
                sscanf(arg, "%ld", &number);
                RET(number < 0, EINVAL, "l4 protocol can not be negative");

                cfg.rule.l4_proto = number;
                break;
            }

            /* protocol given in text format (only few implemented) */
            if (!strcmp(arg, "tcp")) {
                cfg.rule.l4_proto = IPPROTO_TCP;
                break;
            } else if (!strcmp(arg, "udp")) {
                cfg.rule.l4_proto = IPPROTO_UDP;
                break;
            }

            /* unknown protocol */
            RET(1, EINVAL, "unknown l4 protocol");
        /* source port */
        case ARG_SRCP:
            RET(cfg.rule.flags & FLT_SRC_PORT, EINVAL,
                "too many --sport options");
            cfg.rule.flags |= FLT_SRC_PORT;

            /* account for possible rule check inversion */
            if (invert) {
                cfg.rule.flags |= FLT_SRC_PORT_INV;
                invert = 0;
            }

            /* parse port number */
            ans = _parse_port_num(arg, &cfg.rule.src_port);
            RET(ans, ans, "failed to parse source port number");

            break;
        /* destination port */
        case ARG_DSTP:
            RET(cfg.rule.flags & FLT_DST_PORT, EINVAL,
                "too many --dport options");
            cfg.rule.flags |= FLT_DST_PORT;

            /* account for possible rule check inversion */
            if (invert) {
                cfg.rule.flags |= FLT_DST_PORT_INV;
                invert = 0;
            }

            /* parse port number */
            ans = _parse_port_num(arg, &cfg.rule.dst_port);
            RET(ans, ans, "failed to parse destination port number");

            break;
        /* aggregate hash */
        case ARG_AGGH:
            RET(cfg.rule.flags & FLT_HASH, EINVAL, "too many hash options");
            cfg.rule.flags |= (FLT_HASH | FLT_AGGREGATE_HASH);

            /* account for possible rule check inversion */
            if (invert) {
                cfg.rule.flags |= FLT_HASH_INV;
                invert = 0;
            }

            /* parse hexstring as sha256 md */
            ans = _read_hexstring(arg, cfg.rule.sha256_md,
                    sizeof(cfg.rule.sha256_md));
            RET(ans, ans, "failed to parse hexstring");

            break;
        /* single hash */
        case ARG_SNGH:
            RET(cfg.rule.flags & FLT_HASH, EINVAL, "too many hash options");
            cfg.rule.flags |= (FLT_HASH | FLT_SINGLE_HASH);

            /* account for possible rule check inversion */
            if (invert) {
                cfg.rule.flags |= FLT_HASH_INV;
                invert = 0;
            }

            /* parse hexstring as sha256 md */
            ans = _read_hexstring(arg, cfg.rule.sha256_md,
                    sizeof(cfg.rule.sha256_md));
            RET(ans, ans, "failed to parse hexstring");

            break;
        /* verdict */
        case 'v':
            RET(cfg.rule.verdict & VRD_MASK, EINVAL, "too many verdicts");

            /* extract verdict from arg string */
            if (!strcmp(arg, "ACCEPT"))
                cfg.rule.verdict |= VRD_ACCEPT;
            else if (!strcmp(arg, "DROP"))
                cfg.rule.verdict |= VRD_DROP;
            else
                RET(1, EINVAL, "unknown verdict");

            break;
        /* chain */
        case 'c':
            /* extract chain from arg string */
            if (!strcmp(arg, "INPUT")) {
                RET(cfg.msg.flags & CTL_INPUT, EINVAL,
                    "INPUT chain already specified");
                RET(cfg.msg.flags & CTL_OUTPUT
                 && cfg.msg.flags & (CTL_REQ_MASK & ~CTL_LIST),
                 EINVAL, "only LIST command works on both "
                         "INPUT and OUTPUT simultaneously");

                cfg.msg.flags |= CTL_INPUT;
            } else if (!strcmp(arg, "OUTPUT")) {
                RET(cfg.msg.flags & CTL_OUTPUT, EINVAL,
                    "INPUT chain already specified");
                RET(cfg.msg.flags & CTL_INPUT
                 && cfg.msg.flags & (CTL_REQ_MASK & ~CTL_LIST),
                 EINVAL, "only LIST command works on both "
                         "INPUT and OUTPUT simultaneously");

                cfg.msg.flags |= CTL_OUTPUT;
            } else
                RET(1, EINVAL, "unknown chain");

            break;
        /* signature location */
        case 'l':
            RET(cfg.rule.flags & (FLT_L3_SIG | FLT_L4_SIG), EINVAL,
                "signature location already specified");

            if (!strcmp(arg, "l3"))
                cfg.rule.flags |= FLT_L3_SIG;
            else if (!strcmp(arg, "l4"))
                cfg.rule.flags |= FLT_L4_SIG;
            else
                RET(1, EINVAL, "unknown signature location");

            break;
        /* next argument negation */
        case '!':
            invert = !invert;
            break;
        /* this is invoked after all arguments have been parsed */
        case ARGP_KEY_END:
            /* first, treat commands that can be handled locally */
            if (cfg.msg.flags & CTL_HASH) {
                ans = _display_hashes(paths);
                DIE(ans, "unable to display requested hashes");

                /* mothing more to do */
                exit(0);
            }

            /* from here, we sanitize requests for the firewall */
            RET(!(cfg.msg.flags & CTL_REQ_MASK), EINVAL,
                "no command specified");
            RET((cfg.msg.flags & (CTL_APPEND | CTL_INSERT))
                && !(cfg.rule.verdict & VRD_MASK),
                EINVAL, "no verdict specified");
            RET((cfg.msg.flags & (CTL_APPEND | CTL_INSERT | CTL_DELETE))
                && !(cfg.msg.flags & CHAIN_MASK),
                EINVAL, "no chain specified");

            /* if no chain is specified for -L, assume both */
            if ((cfg.msg.flags & CTL_LIST) && !(cfg.rule.verdict & CHAIN_MASK))
                cfg.rule.verdict |= (CTL_INPUT | CTL_OUTPUT);

            break;
        /* unknown argument */
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

