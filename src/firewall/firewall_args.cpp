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

#include <string.h>             /* strncpy, strcmp  */
#include <termios.h>            /* tcgetattr        */
#include <linux/netfilter.h>    /* NF_{ACCEPT,DROP} */

#include "firewall_args.h"
#include "util.h"

/* argp API global variables */
const char *argp_program_version     = "version 1.0";
const char *argp_program_bug_address = "<andru.mantu@gmail.com>";

/* argument identifiers with no shorthand */
enum {
    ARG_QUEUE_IN   = 600,   /* input netfilter queue number   */
    ARG_QUEUE_OUT  = 601,   /* output netfilter queue number  */
    ARG_QUEUE_FWD  = 602,   /* forward netfilter queue number */
    ARG_POLICY_IN  = 700,   /* INPUT chain default policy     */
    ARG_POLICY_OUT = 701,   /* OUTPUT chain default policy    */
    ARG_POLICY_FWD = 702,   /* FORWARD chain default policy   */
};

/* command line arguments */
static struct argp_option options[] = {
    { NULL, 0, NULL, 0, "Core functionality" },
    { "ebpf-obj", 'e', "OBJ", 0,
      "eBPF object defining select syscall hooks" },
    { "queue-out", ARG_QUEUE_OUT, "NUM", 0,
      "netfilter queue number (default: 0)" },
    { "queue-in",  ARG_QUEUE_IN,  "NUM", 0,
      "netfilter queue number (default: 1)" },
    { "queue-fwd", ARG_QUEUE_FWD, "NUM", 0,
      "netfilter queue number (default: 2)" },
    { "pol-out", ARG_POLICY_OUT, "VERDICT", 0,
      "OUTPUT chain policy (default: ACCEPT)" },
    { "pol-in", ARG_POLICY_IN,  "VERDICT", 0,
      "INPUT chain policy (default: ACCEPT)" },
    { "pol-fwd", ARG_POLICY_FWD, "VERDICT", 0,
      "FORWARD chain policy (default: ACCEPT)" },
    { "sig-type", 't', "SIG_T", 0,
      "Type of signature (default: none)" },
    { "sig_proto", 'p', "SIG_P", 0,
      "Protocol to host the signature (default: ip)" },
    { "secret", 's', "FILE", 0,
      "Packet signing secret" },
    { "fwd-val", 'f', NULL, 0,
      "Validate signature on FORWARD chain (default: no)" },
    { "in-val", 'i', NULL, 0,
      "Validate signature on INPUT chain (default: no)" },

    { NULL, 0, NULL, 0, "Performance tuning" },
    { "proc-delay", 'd', "NUM", 0,
      "delay between receiving process exit event and handling it "
      "(default: 50ms) [μs]" },
    { "retain-maps", 'r', NULL, 0,
      "retain objects in set even after unmapping them (default: no)" },
    { "no-rescan", 'R', NULL, 0,
      "prevent rescanning maps if set is non-empty "
      "(default: no, implies: -r)" },
    { "parallel", 'm', NULL, 0,
      "use multiple threads for event processing (default: no)" },
    { "uniform-prio", 'u', NULL, 0,
      "enforce uniform priority for event processing (default: no)" },
    { "skip-ns-switch", 'S', NULL, 0,
      "skip same netns switches on consecutive rules (default: no)" },
    { "partial-read", 'P', NULL, 0,
      "read only first 80 bytes of each packet (default: no)" },
    { "batch-count", 'b', "NUM", 0,
      "max number of batched verdicts (default: 1)" },
    { "batch-timeout", 'B', "NUM", 0,
      "batch verdict transmission timeout (default: huge) [μs]" },
    { "max-nl-bufsz", 'n', "NUM", 0,
      "maximum netlink buffer size (default: 256M) [bytes]" },

    { 0 }
};

/* argument parser prototype */
static error_t parse_opt(int, char *, struct argp_state *);

/* description of accepted non-option arguments */
static char args_doc[] = "";

/* program documentation */
static char doc[] = "Network traffic filter that verifies identity of processes"
                    " having access to transmitting / receiving sockets"
                    "\v"
                    "* Without '-f', the FORWARD queue is not used\n"
                    "* The '-P' option is highly experimental!\n"
                    "\n"
                    "VERDICT={ACCEPT|DROP}\n"
                    "SIG_T={none,packet,app}\n"
                    "SIG_P={ip,tcp,udp}";

/* declaration of relevant structures */
struct argp   argp = { options, parse_opt, args_doc, doc };
struct config cfg  = {
    .secret_path      = NULL,
    .proc_delay       = 50'000,
    .queue_num_in     = 1,
    .queue_num_out    = 0,
    .queue_num_fwd    = 2,
    .policy_in        = NF_ACCEPT,
    .policy_out       = NF_ACCEPT,
    .policy_fwd       = NF_ACCEPT,
    .retain_maps      = 0,
    .no_rescan        = 0,
    .fwd_validate     = 0,
    .in_validate      = 0,
    .parallelize      = 0,
    .uniform_prio     = 0,
    .skip_ns_switch   = 0,
    .partial_read     = 0,
    .batch_max_count  = 1,
    .batch_timeout    = 3'600'000'000,
    .max_nl_bufsz     = 0x1000'0000,
    .sig_proto        = IPPROTO_IP,
    .sig_type         = SIG_NONE,
};

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* parse_opt - parses one argument and updates relevant structures
 *  @key   : argument id
 *  @arg   : pointer to actual argument
 *  @state : parsing state
 *
 *  @return : 0 if everything ok
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    switch (key) {
        /* ebpf object */
        case 'e':
            strncpy(cfg.ebpf_path, arg, 64);
            break;
        /* hmac secret */
        case 's':
            cfg.secret_path = strdup(arg);
            break;
        /* event processing delay */
        case 'd':
            sscanf(arg, "%lu", &cfg.proc_delay);

            /* convert from ms in us */
            cfg.proc_delay *= 1'000;

            break;
        /* netfilter input queue number */
        case ARG_QUEUE_IN:
            sscanf(arg, "%hu", &cfg.queue_num_in);
            break;
        /* netfilter output queue number */
        case ARG_QUEUE_OUT:
            sscanf(arg, "%hu", &cfg.queue_num_out);
            break;
        /* netfilter forward queue number */
        case ARG_QUEUE_FWD:
            sscanf(arg, "%hu", &cfg.queue_num_fwd);
            break;
        /* INPUT chain policy */
        case ARG_POLICY_IN:
            /* extract policy verdict from arg string */
            if (!strcmp(arg, "ACCEPT"))
                cfg.policy_in = NF_ACCEPT;
            else if (!strcmp(arg, "DROP"))
                cfg.policy_in = NF_DROP;
            else
               RET(1, EINVAL, "unknown INPUT policy");

            break;
        /* OUTPUT chain policy */
        case ARG_POLICY_OUT:
            /* extract policy verdict from arg string */
            if (!strcmp(arg, "ACCEPT"))
                cfg.policy_out = NF_ACCEPT;
            else if (!strcmp(arg, "DROP"))
                cfg.policy_out = NF_DROP;
            else
               RET(1, EINVAL, "unknown OUTPUT policy");

            break;
        /* FORWARD chain policy */
        case ARG_POLICY_FWD:
            /* extract policy verdict from arg string */
            if (!strcmp(arg, "ACCEPT"))
                cfg.policy_fwd = NF_ACCEPT;
            else if (!strcmp(arg, "DROP"))
                cfg.policy_fwd = NF_DROP;
            else
               RET(1, EINVAL, "unknown FORWARD policy");

            break;
        /* type of singature to include */
        case 't':
            if (!strcmp(arg, "none"))
                cfg.sig_type = SIG_NONE;
            else if (!strcmp(arg, "packet"))
                cfg.sig_type = SIG_PACKET;
            else if (!strcmp(arg, "app"))
                cfg.sig_type = SIG_APP;
            else
                RET(1, EINVAL, "unknown signature type");

            break;
        /* protocol to host signature */
        case 'p':
            if (!strcmp(arg, "ip"))
                cfg.sig_proto = IPPROTO_IP;
            else if (!strcmp(arg, "tcp"))
                cfg.sig_proto = IPPROTO_TCP;
            else if (!strcmp(arg, "udp"))
                cfg.sig_proto = IPPROTO_UDP;
            else
                RET(1, EINVAL, "unknown / unsupported protocol");

            break;
        /* validate signatures on forward chain */
        case 'f':
            cfg.fwd_validate = 1;
            break;
        /* validate signatures on input chain */
        case 'i':
            cfg.in_validate = 1;
            break;
        /* retain objects in set after unmapping them */
        case 'r':
            cfg.retain_maps = 1;
            break;
        /* prevent rescanning maps */
        case 'R':
            cfg.retain_maps = 1;
            cfg.no_rescan   = 1;
            break;
        /* parallelize event processing */
        case 'm':
            cfg.parallelize = 1;
            break;
        /* assign uniform priorities to events */
        case 'u':
            cfg.uniform_prio = 1;
            break;
        /* skip same netns switch on consecutive rule eval */
        case 'S':
            cfg.skip_ns_switch = 1;
            break;
        /* read only 80 bytes of each packet (dangerous!) */
        case 'P':
            cfg.partial_read = 1;
            break;
        /* maximum number packets batched for verdict transmission */
        case 'b':
            sscanf(arg, "%u", &cfg.batch_max_count);
            break;
        /* verdict transmission timeout for batch */
        case 'B':
            sscanf(arg, "%lu", &cfg.batch_timeout);
            break;
        /* maximum netlink socket recv buffer size */
        case 'n':
            sscanf(arg, "%u", &cfg.max_nl_bufsz);
            break;
        /* this is invoked after all arguments have been parsed */
        case ARGP_KEY_END:
            /* final sanity check */
            RET(cfg.queue_num_in == cfg.queue_num_out, EINVAL,
                "input and output queue numbers must be different");

            RET(cfg.sig_type != SIG_NONE && cfg.partial_read, EINVAL,
                "cannot sign packets while performing partial reads");

            RET(cfg.sig_type != SIG_NONE && cfg.batch_max_count > 1, EINVAL,
                "cannot sign packets while batching verdicts");
            RET(cfg.batch_max_count == 0, EINVAL,
                "invalid value for batch_max_count");

            break;
        /* unknown argument */
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

