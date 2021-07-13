#include <stdint.h>         /* [u]int*_t              */
#include <sys/socket.h>     /* AF_NETLINK, SOCK_DGRAM */
#include <linux/netlink.h>  /* NETLINK_INET_DIAG      */ 

#ifndef _NETLINK_HELPERS_H
#define _NETLINK_HELPERS_H

enum proc_events {
    PROC_EVENT_NONE     = 0x00000000,
    PROC_EVENT_FORK     = 0x00000001,
    PROC_EVENT_EXEC     = 0x00000002,
    PROC_EVENT_UID      = 0x00000004,
    PROC_EVENT_GID      = 0x00000040,
    PROC_EVENT_SID      = 0x00000080,
    PROC_EVENT_PTRACE   = 0x00000100,
    PROC_EVENT_COMM     = 0x00000200,
    PROC_EVENT_COREDUMP = 0x40000000,
    PROC_EVENT_EXIT     = 0x80000000,
};

int32_t nl_socket(int socket_type, int netlink_family);
int32_t nl_proc_ev_connect(void);
int32_t nl_proc_ev_subscribe(int nl_fd, bool enable);
int32_t nl_proc_ev_handle(int nl_fd);
int32_t nl_sock_diag(int32_t nl_fd, uint8_t protocol, uint32_t src_addr,
            uint32_t dst_addr, uint16_t src_port, uint16_t dst_port,
            uint32_t *inode_p);

#endif
