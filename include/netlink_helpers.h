#pragma once

#include <stdint.h>             /* [u]int*_t                      */
#include <sys/socket.h>         /* AF_NETLINK, SOCK_DGRAM         */
#include <linux/netlink.h>      /* NETLINK_INET_DIAG              */
#include <linux/cn_proc.h>      /* proc_cn_mcast_op, PROC_EVENT_* */
#include <linux/connector.h>    /* CN_IDX_PROC, cn_msg            */

#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"

/* netlink datagram type (specialized for proc events) */
typedef struct __attribute__((aligned(NLMSG_ALIGNTO))) {
    struct nlmsghdr nl_hdr;             /* netlink header */
    struct __attribute__((packed)) {    /* netlink payload */
        struct cn_msg     cn_msg;
        struct proc_event proc_ev;
    };
} nldgram_t;

int32_t nl_socket(int socket_type, int netlink_family);
int32_t nl_proc_ev_connect(void);
int32_t nl_proc_ev_subscribe(int nl_fd, bool enable);
int32_t nl_proc_ev_handle(nldgram_t *msg);
void    nl_delayed_ev_handle(uint64_t delta_t);
int32_t nl_sock_diag(uint8_t protocol, uint32_t src_addr, uint32_t dst_addr,
                     uint16_t src_port, uint16_t dst_port, uint32_t *inode_p);

