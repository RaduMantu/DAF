#include <stdint.h>

#ifndef _FILTER_H
#define _FILTER_H

/* flags */
enum {
    /* significance of hash */
    FLT_AGGREGATE_HASH = 1 <<  0,   /* check aggregate hash of all objects */
    FLT_SINGLE_HASH    = 1 <<  1,   /* check if object with hash exists    */

    /* enabled checks */
    FLT_SRC_IP         = 1 <<  2,
    FLT_DST_IP         = 1 <<  3,
    FLT_L4_PROTO       = 1 <<  4,
    FLT_SRC_PORT       = 1 <<  5,
    FLT_DST_PORT       = 1 <<  6,
    FLT_HASH           = 1 <<  7,

    /* criteria check inversion */
    FLT_SRC_IP_INV     = 1 <<  8,
    FLT_DST_IP_INV     = 1 <<  9,
    FLT_L4_PROTO_INV   = 1 << 10,
    FLT_SRC_PORT_INV   = 1 << 11,
    FLT_DST_PORT_INV   = 1 << 12,
    FLT_HASH_INV       = 1 << 13,
};

/* filtering criteria */
struct flt_crit {
    /* layer 3 */
    uint32_t src_ip;
    uint32_t src_ip_mask;
    uint32_t dst_ip;
    uint32_t dst_ip_mask;
    uint8_t  l4_proto;

    /* layer 4 */
    uint16_t src_port;
    uint16_t dst_port;

    /* process identity */
    uint8_t sha256_md[32];

    /* verdict */
    uint16_t verdict;

    /* meta */
    uint32_t flags;
};

int flt_handle_ctl(int32_t us_csock_fd);

#endif

