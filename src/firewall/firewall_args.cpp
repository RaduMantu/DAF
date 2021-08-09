#include <string.h>     /* strncpy */

#include "firewall_args.h"
#include "util.h"


/* command line arguments */
static struct argp_option options[] = {
    { "ebpf-obj",  'e', "OBJ", 0,
      "eBPF object with select syscall hooks" },
    { "retain-maps", 'r', NULL, OPTION_ARG_OPTIONAL,
      "retain objects in set even after unmapping them (default: no)" },
    { "no-rescan",   'R', NULL, OPTION_ARG_OPTIONAL,
      "prevent rescanning maps if set is non-empty (default: no, implies: -r" },
    { "queue",       'q', "NUM", 0,
      "netfilter queue number (default: 0)" },
    { "proc-delay",  'd', "NUM", 0,
      "delay between process exit event rcv and handling it, in us "
      " (default: 50ms)" },
    { 0 }
};

/* argument parser prototype */
static error_t parse_opt(int, char *, struct argp_state *);

/* description of accepted non-option arguments */
static char args_doc[] = "";

/* program documentation */
static char doc[] = "app-fw -- network traffic filter based on originating"
                             " process memory mapped objects";

/* declaration of relevant structures */
struct argp   argp = { options, parse_opt, args_doc, doc };
struct config cfg  = {
    .proc_delay  = 50'000,
    .queue_num   = 0,
    .retain_maps = 0,
    .no_rescan   = 0,
};

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
        /* netfilter queue number */
        case 'q':
            sscanf(arg, "%hu", &cfg.queue_num);
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
        /* unknown argument */
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

