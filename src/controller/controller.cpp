#include <stdio.h>
#include <stdint.h>         /* [u]int*_t        */
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>     /* IPPROTO_*        */
#include <arpa/inet.h>      /* ntohs, inet_ntop */

#include <unordered_map>    /* unordered_map    */

#include "filter.h"
#include "controller_args.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

#define CTL_SOCK_NAME "/tmp/app_fw.socket"

static unordered_map<uint8_t, char const *> num2prot = {
    { IPPROTO_ICMP,    "icmp"    },
    { IPPROTO_IGMP,    "igmp"    },
    { IPPROTO_IPIP,    "ipip"    },
    { IPPROTO_TCP,     "tcp"     },
    { IPPROTO_EGP,     "egp"     },
    { IPPROTO_PUP,     "pup"     },
    { IPPROTO_UDP,     "udp"     },
    { IPPROTO_IDP,     "idp"     },
    { IPPROTO_TP,      "tp"      },
    { IPPROTO_DCCP,    "dccp"    },
    { IPPROTO_RSVP,    "rsvp"    },
    { IPPROTO_GRE,     "gre"     },
    { IPPROTO_ESP,     "esp"     },
    { IPPROTO_AH,      "ah"      },
    { IPPROTO_MTP,     "mtp"     },
    { IPPROTO_BEETPH,  "beetph"  },
    { IPPROTO_ENCAP,   "encap"   },
    { IPPROTO_PIM,     "pim"     },
    { IPPROTO_COMP,    "comp"    },
    { IPPROTO_SCTP,    "sctp"    },
    { IPPROTO_UDPLITE, "udplite" },
    { IPPROTO_MPLS,    "mpls"    },
    { IPPROTO_RAW,     "raw"     },
    { IPPROTO_MPTCP,   "mptcp"   },
};

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
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

/* print_header - prints header for rule table
 */
void print_header()
{
    printf("%5s %20s %20s %16s %9s %9s %9s %66s %7s \n", 
        "INDEX", "SRC IP", "DST IP", "L4 PROTO", "SRC PORT", "DST PORT",
        "HASH TYPE", "HASH VALUE", "VERDICT");
    printf("----- -------------------- -------------------- "
        "---------------- --------- --------- --------- "
        "------------------------------------------------------------------ "
        "------- \n");
}

/* print_rule - prints entry from rule table
 *  @idx  : index (order in which it was received)
 *  @rule : ptr to filtering criteria structure 
 */
void print_rule(size_t idx, struct flt_crit *rule)
{
    char ip_str[16];

    /* print rule index */
    printf("%5lu ", idx);

    /* print src ip */
    if (rule->flags & FLT_SRC_IP) {
        /* rule inversion mark (if any) */
        printf("%c ", (rule->flags & FLT_SRC_IP_INV) ? '!' : ' ');

        /* ip and netmask */
        inet_ntop(AF_INET, &rule->src_ip, ip_str, sizeof(ip_str));
        printf("%15s/%-2u ", ip_str,
            32 - __builtin_ctz(ntohl(rule->src_ip_mask)));
    } else
        printf("%20s ", "N/A");

    /* print dst ip */
    if (rule->flags & FLT_DST_IP) {
        /* rule inversion mark (if any) */
        printf("%c ", (rule->flags & FLT_DST_IP_INV) ? '!' : ' ');

        /* ip and netmask */
        inet_ntop(AF_INET, &rule->dst_ip, ip_str, sizeof(ip_str));
        printf("%15s/%-2u ", ip_str,
            32 - __builtin_ctz(ntohl(rule->dst_ip_mask)));
    } else
        printf("%20s ", "N/A");

    /* print layer 4 protocol */
    if (rule->flags & FLT_L4_PROTO) {
        /* rule inversion mark (if any) */
        printf("%c ", (rule->flags & FLT_DST_IP_INV) ? '!' : ' ');

        /* protocol */
        printf("%3u -- %-7s ", rule->l4_proto,
            (num2prot.contains(rule->l4_proto))
            ? num2prot[rule->l4_proto]
            : "UNKNOWN");
    } else
        printf("%16s ", "N/A");

    /* print src port */
    if (rule->flags & FLT_SRC_PORT) {
        /* rule inversion mark (if any) */
        printf("%c ", (rule->flags & FLT_DST_IP_INV) ? '!' : ' ');

        /* src port */
        printf("%7u ", ntohs(rule->src_port));
    } else
        printf("%9s ", "N/A");

    /* print dst port */
    if (rule->flags & FLT_DST_PORT) {
        /* rule inversion mark (if any) */
        printf("%c ", (rule->flags & FLT_DST_IP_INV) ? '!' : ' ');

        /* dst port */
        printf("%7u ", ntohs(rule->dst_port));
    } else
        printf("%9s ", "N/A");

    /* print sha256 md */
    if (rule->flags & FLT_HASH) {
        /* hash type */
        printf("%9s ", 
            (rule->flags & FLT_AGGREGATE_HASH)
            ? "aggregate"
            : "single");

        /* rule inversion mark (if any) */
        printf("%c ", (rule->flags & FLT_DST_IP_INV) ? '!' : ' ');

        /* message digest (32 bytes -> 64 chars) */
        print_hexstring(rule->sha256_md, sizeof(rule->sha256_md));
        printf(" ");
    } else
        printf("%9s %66s ", "N/A", "N/A");

    /* print verdict */
    printf("%7s ", (rule->verdict & VRD_ACCEPT) ? "ACCEPT" : "DROP");


    printf("\n");
}

/******************************************************************************
 ************************************ MAIN ************************************
 ******************************************************************************/

int32_t main(int32_t argc, char *argv[])
{
    struct sockaddr_un name;    /* unix socket name */
    int32_t ans;                /* asnswer */

    /* parse command line arguments */
    ans = argp_parse(&argp, argc, argv, 0, 0, &cfg);
    DIE(ans, "error parsing cli arguments");

    /* print rule */
    print_header();
    print_rule(0, &cfg.rule);

    return 0;
}

