#include <string.h>             /* strncpy, strcmp  */
#include <linux/netfilter.h>    /* NF_{ACCEPT,DROP} */

#include "firewall_args.h"
#include "util.h"

/* argp API global variables */
const char *argp_program_version     = "version 1.0";
const char *argp_program_bug_address = "<andru.mantu@gmail.com>";

/* argument identifiers with no shorthand */
enum {
    ARG_QUEUE_IN   = 600,   /* input netfilter queue number  */
    ARG_QUEUE_OUT  = 601,   /* output netfilter queue number */
    ARG_POLICY_IN  = 602,   /* INPUT chain default policy    */
    ARG_POLICY_OUT = 603,   /* OUTPUT chain default policy   */
};

/* command line arguments */
static struct argp_option options[] = {
    { NULL, 0, NULL, 0, "Core functionality" },
    { "ebpf-obj",   'e', "OBJ", 0,
      "eBPF object defining select syscall hooks" },
    { "proc-delay", 'd', "NUM", 0,
      "delay between receiving process exit event and handling it "
      "(default: 50ms) [μs]" },
    { "queue-out", ARG_QUEUE_OUT, "NUM", 0,
      "netfilter queue number (default: 0)" },
    { "queue-in",  ARG_QUEUE_IN,  "NUM", 0,
      "netfilter queue number (default: 1)" },
    { "policy-out", ARG_POLICY_OUT, "{ACCEPT|DROP}", 0,
      "OUTPUT chain policy (default: ACCEPT)" },
    { "policy-in",  ARG_POLICY_IN,  "{ACCEPT|DROP}", 0,
      "INPUT chain policy (default: ACCEPT)" },

    { NULL, 0, NULL, 0, "Performance tuning" },
    { "retain-maps", 'r', NULL, 0,
      "retain objects in set even after unmapping them (default: no)" },
    { "no-rescan",   'R', NULL, 0,
      "prevent rescanning maps if set is non-empty "
      "(default: no, implies: -r)" },
    { 0 }
};

/* argument parser prototype */
static error_t parse_opt(int, char *, struct argp_state *);

/* description of accepted non-option arguments */
static char args_doc[] = "";

/* program documentation */
static char doc[] = "Network traffic filter that verifies identity of processes"
                    " having access to transmitting / receiving sockets";

/* declaration of relevant structures */
struct argp   argp = { options, parse_opt, args_doc, doc };
struct config cfg  = {
    .proc_delay    = 50'000,
    .queue_num_in  = 1,
    .queue_num_out = 0,
    .policy_in     = NF_ACCEPT,
    .policy_out    = NF_ACCEPT,
    .retain_maps   = 0,
    .no_rescan     = 0,
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
        /* retain objects in set after unmapping them */
        case 'r':
            cfg.retain_maps = 1;
            break;
        /* prevent rescanning maps */
        case 'R':
            cfg.retain_maps = 1;
            cfg.no_rescan   = 1;
            break;
        /* this is invoked after all arguments have been parsed */
        case ARGP_KEY_END:
            /* final sanity check */
            RET(cfg.queue_num_in == cfg.queue_num_out, EINVAL,
                "input and output queue numbers must be different");

            break;
        /* unknown argument */
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

