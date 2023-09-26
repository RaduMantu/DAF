#pragma once

#include <argp.h>       /* argp API  */
#include <stdint.h>     /* [u]int*_t */

#include "signer.h"     /* sign_t    */

/* structure holding cli arguments information */
struct config {
    char     ebpf_path[64];        /* path to ebpf object                    */
    char     *secret_path;         /* path to HMAC secret                    */
    uint64_t proc_delay;           /* delay in processing certain events     */
    uint16_t queue_num_in;         /* netfilter input queue number           */
    uint16_t queue_num_out;        /* netfilter output queue number          */
    uint16_t queue_num_fwd;        /* netfilter forward queue number         */
    uint16_t policy_in;            /* default INPUT chain policy             */
    uint16_t policy_out;           /* default OUTPUT chain policy            */
    uint16_t policy_fwd;           /* default FORWARD chain policy           */
    uint8_t  retain_maps      : 1; /* keep track of unmapped objects as well */
    uint8_t  no_rescan        : 1; /* prevent rescanning maps                */
    uint8_t  fwd_validate     : 1; /* validate signature on forward chain    */
    uint8_t  in_validate      : 1; /* validate signature on input chain      */
    uint8_t  parallelize      : 1; /* use multi-threaded version             */
    uint8_t  uniform_prio     : 1; /* assign uniform event priority          */
    uint8_t  skip_ns_switch   : 1; /* skip same netns switch on rule eval    */
    uint8_t  partial_read     : 1; /* read only 80 bytes of each packet      */
    uint32_t batch_max_count;      /* maximum number of batched packets      */
    uint64_t batch_timeout;        /* verdict transmission timeout for batch */
    uint8_t  sig_proto;            /* protocol to host the signature         */
    sign_t   sig_type;             /* type of appended signature             */
};

extern struct argp   argp;
extern struct config cfg;

