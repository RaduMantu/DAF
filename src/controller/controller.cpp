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
 * Foobar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with app-fw. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>         /* [u]int*_t          */
#include <sys/socket.h>     /* socket             */
#include <sys/un.h>         /* sockaddr_un        */
#include <unistd.h>         /* read, write, close */
#include <netinet/in.h>     /* IPPROTO_*          */
#include <arpa/inet.h>      /* ntohs, inet_ntop   */

#include <unordered_map>    /* unordered_map      */

#include "filter.h"
#include "controller_args.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

#define CTL_SOCK_NAME "/tmp/app_fw.socket"

static unordered_map<uint8_t, char const * const> num2prot = {
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

/* print_header - prints header for rule table
 */
void print_header()
{
    printf("%5s %6s %20s %20s %16s %9s %9s %9s %66s %7s \n", 
        "INDEX", "OUTPUT", "SRC IP", "DST IP", "L4 PROTO", "SRC PORT",
        "DST PORT", "HASH TYPE", "HASH VALUE", "VERDICT");
    printf("----- ------ -------------------- -------------------- "
        "---------------- --------- --------- --------- "
        "------------------------------------------------------------------ "
        "------- \n");
}

/* print_rule - prints entry from rule table
 *  @idx   : index (order in which it was received)
 *  @chain : 0 if input, 1 if output
 *  @rule  : ptr to filtering criteria structure 
 */
void print_rule(size_t idx, uint8_t chain, struct flt_crit *rule)
{
    char ip_str[16];

    /* print rule index */
    printf("%5lu ", idx);

    /* print chain */
    printf("%6s ", chain ? "OUTPUT" : "INPUT");

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
    struct sockaddr_un name;        /* unix socket name          */
    struct ctl_msg     rm;          /* request / response buffer */
    ssize_t            rb, wb;      /* read / written bytes      */
    int32_t            dsock_fd;    /* unix data socket          */
    int32_t            ans;         /* asnswer                   */

    /* parse command line arguments */
    ans = argp_parse(&argp, argc, argv, 0, 0, &cfg);
    DIE(ans, "error parsing cli arguments");

    /* create socket */
    dsock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    DIE(dsock_fd == -1, "error opening AF_UNIX socket (%s)", strerror(errno));

    /* connect to named server socket */
    memset(&name, 0, sizeof(name));
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, CTL_SOCK_NAME, sizeof(name.sun_path) - 1);

    ans = connect(dsock_fd, (struct sockaddr *) &name, sizeof(name));
    DIE(ans == -1, "error connecting to named socket (%s)", strerror(errno));

    /* write request as generated by argp_parse() in cfg */
    wb = write(dsock_fd, &cfg, sizeof(cfg));
    GOTO(wb == -1, clean_data_socket, "error writing data to socket (%s)",
        strerror(errno));

    /* TODO: set socket timeout in case firewall encounters error */

    /* follow-up depending on request */
    switch (cfg.msg.flags & CTL_REQ_MASK) {
        /* list rules */
        case CTL_LIST:
            /* print header */
            print_header();

            /* receive rules, one by one */
            do {
                /* read response */
                rb = read(dsock_fd, &rm, sizeof(rm));
                GOTO(rb == -1, clean_data_socket,
                    "error reading data from socket (%s)", strerror(errno));

                /* break if CTL_END */
                if (rm.msg.flags & CTL_END)
                    break;

                /* print rule */
                print_rule(rm.msg.pos, !!(rm.msg.flags & CTL_OUTPUT), &rm.rule);
            } while (1);

            break;
        /* insert / append / delete -- receive (n)ack */
        case CTL_INSERT:
        case CTL_APPEND:
        case CTL_DELETE:
            /* response will not contain filtering criteria (for these ops) */
            rb = read(dsock_fd, &rm.msg, sizeof(rm.msg));
            GOTO(rb == -1, clean_data_socket,
                "error writing data to socket (%s)", strerror(errno));

            /* check server response */
            GOTO(rm.msg.flags & CTL_NACK, clean_data_socket,
                "firewall could not fulfill the request");
            GOTO(!(rm.msg.flags & CTL_ACK), clean_data_socket,
                "firewall could neither confirm nor deny that the request was "
                "processed");
            INFO("firewall successfully processed the request");

            break;
        /* impossible; could not have passed final parser check */
        default:
            break;
    }

clean_data_socket:
    ans = close(dsock_fd);
    ALERT(ans == -1, "error closing unix data socket (%s)", strerror(errno));

    return 0;
}

