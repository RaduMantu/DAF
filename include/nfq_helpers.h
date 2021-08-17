#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#ifndef _NFQ_HELPERS_H
#define _NFQ_HELPERS_H

/* extra nfq handler parameters */
struct nfq_op_param {
    uint64_t proc_delay;    /* delay in processing certain events */
};


int nfq_out_handler(struct nfq_q_handle *qh,
                    struct nfgenmsg     *nfmsg,
                    struct nfq_data     *nfd,
                    void                *data);
int nfq_in_handler(struct nfq_q_handle *qh,
                   struct nfgenmsg     *nfmsg,
                   struct nfq_data     *nfd,
                   void                *data);

#endif

