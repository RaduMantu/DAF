#include <argp.h>
#include <stdint.h>

#ifndef _CLI_ARGS_H
#define _CLI_ARGS_H

/* structure holding cli arguments information */
struct config {
    char     ebpf_path[64];   /* path to ebpf object                    */
    uint16_t queue_num;       /* netfilter queue number                 */
    uint8_t  retain_maps : 1; /* keep track of unmapped objects as well */
    uint8_t  no_rescan   : 1; /* prevent rescanning maps                */
};


extern struct argp   argp;
extern struct config cfg;

#endif

