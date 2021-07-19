#include <string.h>     /* strncpy */

#include "cli_args.h"
#include "util.h"


/* command line argument */
static struct argp_option options[] = {
    { "ebpf-obj",  'e', "OBJ", 0,
      "eBPF object with select syscall hooks" },
    { "poll-maps", 'p', NULL,  OPTION_ARG_OPTIONAL,
      "Continuously poll /proc/<pid>/maps (default: no)" },
    { "queue",     'q', "NUM", 0,
      "netfilter queue number (default: 0)" },
    { 0 }
};

/* argument parser prototype */
static error_t parse_opt(int, char *, struct argp_state *);

/* descro[topm pf accepted non-option arguments */
static char args_doc[] = "";

/* program documentation */
static char doc[] = "app-fw -- network traffic filter based on originating"
                             " process memory mapped objects";

/* declaration of relevant structures */
struct argp   argp = { options, parse_opt, args_doc, doc };
struct config cfg  = {
    .queue_num = 0,
    .poll_maps = 0,
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
        /* netfilter queue number */
        case 'q':
            sscanf(arg, "%hu", &cfg.queue_num);
            break;
        /* enable /proc/<pid>/maps polling */
        case 'p':
            cfg.poll_maps = 1;
            break;
        /* unknown argument */
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

