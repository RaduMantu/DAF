#include <argp.h>
#include <stdint.h>

#ifndef _CLI_ARGS_H
#define _CLI_ARGS_H

/* structure holding cli arguments information */
struct config {
    char     ebpf_path[64]; /* path to ebpf object              */
    uint16_t queue_num;     /* netfilter queue number           */
    uint8_t  poll_maps : 1; /* do not cache objects for process */
};


extern struct argp   argp;
extern struct config cfg;

#endif

