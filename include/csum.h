#pragma once

#include <stdint.h>         /* [u]int*_t */
#include <netinet/ip.h>     /* iphdr     */

uint16_t csum_16b1c(uint64_t sum, uint16_t *buffer, size_t nbytes);
int ipv4_csum(struct iphdr *iph);

/* protocol specific checksum calculatiors array */
extern int (*layer4_csum[0x100])(struct iphdr *);

