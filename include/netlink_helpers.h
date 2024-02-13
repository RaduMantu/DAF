#pragma once

#include <stdint.h>         /* [u]int*_t              */
#include <sys/socket.h>     /* AF_NETLINK, SOCK_DGRAM */
#include <linux/netlink.h>  /* NETLINK_INET_DIAG      */

int32_t nl_socket(int socket_type, int netlink_family);
int32_t nl_proc_ev_connect(void);
int32_t nl_proc_ev_subscribe(int nl_fd, bool enable);
int32_t nl_proc_ev_handle(int nl_fd);
void    nl_delayed_ev_handle(uint64_t delta_t);
int32_t nl_sock_diag(uint8_t protocol, uint32_t src_addr, uint32_t dst_addr,
                     uint16_t src_port, uint16_t dst_port, uint32_t *inode_p);

