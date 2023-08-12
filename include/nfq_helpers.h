#pragma once

#include <stdint.h>             /* [u]int*_t */
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* extra nfq handler parameters */
struct nfq_op_param {
    uint64_t proc_delay;    /* delay in processing certain events */
    uint16_t policy_in;     /* default INPUT chain policy         */
    uint16_t policy_out;    /* default OUTPUT chain policy        */
    uint16_t policy_fwd;    /* default FORWARD chain policy       */
};

/* API */
int32_t nfq_in_handler(struct nfq_q_handle *qh,
                       struct nfgenmsg     *nfmsg,
                       struct nfq_data     *nfd,
                       void                *data);
int32_t nfq_out_handler(struct nfq_q_handle *qh,
                        struct nfgenmsg     *nfmsg,
                        struct nfq_data     *nfd,
                        void                *data);
int32_t nfq_fwd_handler(struct nfq_q_handle *qh,
                        struct nfgenmsg     *nfmsg,
                        struct nfq_data     *nfd,
                        void                *data);

/******************************************************************************
 **************************** TIME COUNTER EXPORTS ****************************
 ******************************************************************************/

extern uint64_t nfqinh_extract_ctr;
extern uint64_t nfqinh_delayedev_ctr;
extern uint64_t nfqinh_verdict_ctr;
extern uint64_t nfqinh_report_ctr;

extern uint64_t nfqouth_extract_ctr;
extern uint64_t nfqouth_delayedev_ctr;
extern uint64_t nfqouth_verdict_ctr;
extern uint64_t nfqouth_report_ctr;

extern uint64_t nfqfwdh_extract_ctr;
extern uint64_t nfqfwdh_delayedev_ctr;
extern uint64_t nfqfwdh_verdict_ctr;
extern uint64_t nfqfwdh_report_ctr;

extern uint64_t nfqinh_packets_ctr;
extern uint64_t nfqouth_packets_ctr;
extern uint64_t nfqfwdh_packets_ctr;
