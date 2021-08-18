#include <argp.h>
#include <stdint.h>

#ifndef _FIREWALL_ARGS_H
#define _FIREWALL_ARGS_H

/* structure holding cli arguments information */
struct config {
    char     ebpf_path[64];   /* path to ebpf object                    */
    uint64_t proc_delay;      /* delay in processing certain events     */
    uint16_t queue_num_in;    /* netfilter input queue number           */
    uint16_t queue_num_out;   /* netfilter output queue number          */
    uint16_t policy_in;       /* default INPUT chain policy             */
    uint16_t policy_out;      /* default OUTPUT chain policy            */
    uint8_t  retain_maps : 1; /* keep track of unmapped objects as well */
    uint8_t  no_rescan   : 1; /* prevent rescanning maps                */
};


extern struct argp   argp;
extern struct config cfg;

#endif

