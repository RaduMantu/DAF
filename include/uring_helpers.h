#pragma once

#include <liburing.h>       /* io_uring API           */
#include <netinet/in.h>     /* sockaddr_in, socklen_t */

/* request sources (for easy matching in completion queue) */
enum {
    NFQ_INPUT_READ,     /* read pkt from INPUT chain                 */
    NFQ_OUTPUT_READ,    /* read pkt from OUTPUT chain                */
    NFQ_FORWARD_READ,   /* read pkt from FORWARD chain               */
    BPF_RINGBUF_POLL,   /* poll eBPF ring buffer data availability   */
    NETLINK_PROC_READ,  /* read netlink proc event data              */
    CTL_ACCEPT,         /* accept incomming controller connection    */
};

struct io_uring *uring_init(uint32_t, uint32_t);
void uring_deinit(void);

int32_t uring_add_read_request(uint64_t, int32_t, void *, uint32_t);
int32_t uring_add_write_request(uint64_t, int32_t, void *, uint32_t);
int32_t uring_add_poll_request(uint64_t, int32_t, uint32_t);
int32_t uring_add_accept_request(uint64_t, int32_t, struct sockaddr_in *,
                                 socklen_t *);
int32_t uring_add_close_request(uint64_t, int32_t);

