/*
 * Copyright © 2021, Radu-Alexandru Mantu <andru.mantu@gmail.com>
 *
 * This file is part of ops-inject.
 *
 * ops-inject is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ops-inject is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ops-inject. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>         /* [u]int*_t        */
#include <netinet/ip.h>     /* iphdr            */
#include <netinet/tcp.h>    /* tcphdr           */
#include <netinet/udp.h>    /* udphdr           */

#include "util.h"
#include "csum.h"

/* disable warnings regarding designated initializers */
#pragma clang diagnostic ignored "-Wc99-designator"
#pragma clang diagnostic ignored "-Winitializer-overrides"

/* csum_16b1c - 16-bit 1's complement sum
 *  @sum    : initial partial sum (e.g.: tcp/udp pseudo headers)
 *  @buffer : buffer over which sum is computed
 *  @nwords : number of bytes in buffer (can be odd - rpad with zeros)
 *
 *  @return : checksum
 */
uint16_t csum_16b1c(uint64_t sum, uint16_t *buffer, size_t nbytes)
{
    /* sanity checks */
    RET(!buffer, 0, "buffer is NULL");

    /* calculate sum of all 16b words */
    for (; nbytes > 1; nbytes -= 2)
        sum += *buffer++;

    /* account for number of odd bytes */
    if (nbytes)
        sum += *((uint8_t *) buffer);

    /* fold partial checksum (account for carry) */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    /* return 1's complement of partial sum */
    return (uint16_t)(~sum);
}

/* ipv4_csum - calculates and sets IPv4 checksum
 *  @iph : start of ip header
 *
 *  @return : 0 if ok, !0 on failure
 *
 * NOTE: no need to zero out csum field before calling this function
 * NOTE: function array redirection is only for layer 4 protocols
 *       this function has to be calle dy the user as is
 */
int ipv4_csum(struct iphdr *iph)
{
    /* sanity check */
    RET(!iph, -1, "iph is NULL");

    /* zero out the csum field (as if to skip it) & compute checksum */
    iph->check = 0;
    iph->check = csum_16b1c(0, (uint16_t *) iph, iph->ihl * 4);

    return 0;
}

/* tcp_csum - calculats and sets TCP checksum
 *  @iph : start of ip header
 *
 *  @return : 0 if ok, !0 on failure
 *
 * NOTE: no need to zero out csum field before calling this function
 */
static int tcp_csum(struct iphdr *iph)
{
    uint64_t      sum = 0;   /* accumulator must hold csum overflow as well */
    uint16_t      tcp_len;   /* length of tcp header & paylaod (can be odd) */
    struct tcphdr *tcph; 

    /* sanity check */
    RET(!iph, -1, "iph is NULL");

    /* calculate tcp header & payload length */
    tcph = (struct tcphdr *)((uint8_t *) iph + iph->ihl * 4);
    tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;

    /* calculate partial pseudo header sum */
    sum += iph->saddr         & 0xffff;
    sum += (iph->saddr >> 16) & 0xffff;
    sum += iph->daddr         & 0xffff;
    sum += (iph->daddr >> 16) & 0xffff;
    sum += htons(tcp_len);
    sum += htons(iph->protocol);

    /* zero out csum field (as if to skip it) & compute checksum */
    tcph->check = 0;
    tcph->check = csum_16b1c(sum, (uint16_t *) tcph, tcp_len);

    return 0;
}

/* udp_csum - calculates and sets UDP checksum
 *  @iph : start of ip header
 *
 *  @return : 0 if ok, !0 on failure
 *
 * NOTE: no need to zero out csum field before calling this function
 */
static int udp_csum(struct iphdr *iph)
{
    uint64_t      sum = 0;   /* accumulator must hold csum overflow as well */
    uint16_t      udp_len;   /* length of udp header & payload (can be odd) */
    struct udphdr *udph; 

    /* sanity check */
    RET(!iph, -1, "iph is NULL");

    /* calcualte udp header & payload length                      *
     * NOTE: basing this measurement on iph->tot_len is incorrect *
     *       this is a mistake middleboxes make and drop udp ops  */
    udph = (struct udphdr *)((uint8_t *) iph + iph->ihl * 4);
    udp_len = ntohs(udph->len);

    /* calculate partial pseudo header sum */
    sum += iph->saddr         & 0xffff;
    sum += (iph->saddr >> 16) & 0xffff;
    sum += iph->daddr         & 0xffff;
    sum += (iph->daddr >> 16) & 0xffff;
    sum += htons(udp_len);
    sum += htons(iph->protocol);

    /* zero out csum field (as if to skip it) & compute checksum */
    udph->check = 0;
    udph->check = csum_16b1c(sum, (uint16_t *) udph , udp_len);

    /* udp 0 csum means "skip csum calculation" -> convert to 0xffff */
    if (!udph->check)
        udph->check = 0xffff;

    return 0;
}

/* dummy_icmp_csum - does nothing
 *  @return : 0
 *
 * icmp csum does not extend beyond its header and data; safe to ignore
 */
static int dummy_icmp_csum(struct iphdr *iph)
{
    return 0;
}

/* dummy_csum - dummy checksum for unhandled protocol
 *  @return : !0 (error)
 *
 * Asking for an unhandled protocol will cause this to return 1 (error) and
 * determine an unmodified pass of the packet. Even a protocol that does not
 * require a checksum should have a *_csum() function that only returns 0!
 */
static int dummy_csum(struct iphdr *iph)
{
    /* sanity check */
    RET(!iph, -1, "iph is NULL");
    RET(1, -1, "Bad layer 4 protocol (%hhd)", iph->protocol);
}


/* protocol specific checksum calculators array */
int (*layer4_csum[0x100])(struct iphdr *) = {
    [0x00 ... 0xff] = dummy_csum,

    [0x06] = tcp_csum,  /* Transmission Control Protocol */
    [0x11] = udp_csum,  /* User Datagram Protocol        */

    [0x01] = dummy_icmp_csum,
};

