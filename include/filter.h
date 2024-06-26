#pragma once

#include <stdint.h> /* [u]int*_t */
#include <vector>   /* vector    */

/******************************************************************************
 ************************** MATCH RULE SPECIFICATION **************************
 ******************************************************************************/

/* match rule flags (16b) */
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

    /* signature insertion */
    FLT_L3_SIG         = 1 << 14,
    FLT_L4_SIG         = 1 << 15,
};


/* filtering criteria */
struct flt_crit {
    /* layer 3 */
    uint32_t src_ip;
    uint32_t src_ip_mask;
    uint32_t dst_ip;
    uint32_t dst_ip_mask;
    uint8_t  l4_proto;

    /* verdict */
    uint8_t verdict;

    /* layer 4 */
    uint16_t src_port;
    uint16_t dst_port;

    /* process identity */
    uint8_t sha256_md[32];

    /* network namespace */
    char     netns_file[256];
    uint32_t netns_fd;          /* to be populated by firewall */

    /* meta */
    uint32_t flags;
};

/******************************************************************************
 ***************** COMMUNICATION WITH RULE MANAGER COMPANION ******************
 ******************************************************************************/

/* controller communication flags (16b) */
enum {
    /* commands for firewall */
    CTL_LIST      = 1 <<  0,    /* list existing rules           */
    CTL_INSERT    = 1 <<  1,    /* insert rule at given position */
    CTL_APPEND    = 1 <<  2,    /* insert rule at end of chain   */
    CTL_DELETE    = 1 <<  3,    /* delete rule at given position */

    /* commands that companion app can handle itself */
    CTL_HASH      = 1 <<  4,    /* show hash of object(s)        */

    /* affected chains */
    CTL_INPUT     = 1 << 10,    /* affects INPUT chain  */
    CTL_OUTPUT    = 1 << 11,    /* affects OUTPUT chain */

    /* responses */
    CTL_NACK      = 1 << 13,    /* operation not acknowledged           */
    CTL_ACK       = 1 << 14,    /* operation acknowledged               */
    CTL_END       = 1 << 15,    /* end of variable length communication */
};
#define CTL_REQ_MASK  0x0f      /* mask for command flags */

/* verdicts / targets (8b) */
enum {
    VRD_ACCEPT = 1 << 0,
    VRD_DROP   = 1 << 1,
};
#define VRD_MASK   (VRD_ACCEPT | VRD_DROP)  /* mask for verdict flags */
#define CHAIN_MASK (CTL_INPUT | CTL_OUTPUT) /* mask for chain flags   */

/* controller utility request / response */
struct ctl_msg {
    struct {
        uint16_t flags;         /* see enum above           */
        uint32_t pos;           /* insert / delete position */
    } msg;                  /* request parameters           */
    struct flt_crit rule;   /* filtering rule (optional)    */
};

/******************************************************************************
 ************************ NETFILTER QUEUE INTERACTION *************************
 ******************************************************************************/

#define INPUT_CHAIN   0
#define OUTPUT_CHAIN  1

#define FORWARD_CHAIN 2

/******************************************************************************
 ********************************* PUBLIC API *********************************
 ******************************************************************************/

int32_t filter_init(uint8_t val_fwd, uint8_t val_in, uint8_t skip_ns_switch);
uint32_t get_verdict(void *pkt, uint32_t chain);
int32_t  flt_handle_ctl(int32_t us_dsock_fd);

/******************************************************************************
 **************************** TIME COUNTER EXPORTS ****************************
 ******************************************************************************/

extern uint64_t verd_hmac_verif_ctr;
extern uint64_t verd_field_extr_ctr;
extern uint64_t verd_hashes_clear_ctr;
extern uint64_t verd_netns_lookup_ctr;
extern uint64_t verd_netns_set_ctr;
extern uint64_t verd_pidset_lookup_ctr;
extern uint64_t verd_pidset_hashcalc_ctr;
extern uint64_t verd_hashes_resize_ctr;
extern uint64_t verd_hashes_lookup_ctr;
extern uint64_t verd_hash_calc_ctr;
extern uint64_t verd_hash_push_ctr;
extern uint64_t verd_hash_verif_ctr;

