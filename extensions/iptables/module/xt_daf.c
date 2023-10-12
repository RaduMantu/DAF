#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>               /* module_{init,exit}    */
#include <linux/skbuff.h>               /* skb related functions */
#include <linux/ip.h>                   /* iphdr                 */
#include <linux/tcp.h>                  /* tcphdr                */
#include <linux/udp.h>                  /* udphdr                */
#include <linux/netfilter/x_tables.h>   /* netfilter callbacks   */
#include <crypto/hash.h>                /* crypto API            */

#include "xt_daf.h"

/******************************************************************************
 ********************** MODULE SPECIFIC DATA STRUCTURES ***********************
 ******************************************************************************/

/* crypto structures */
static struct crypto_shash *cipher;
static struct shash_desc   *desc;

/* copy buffers for non-paged packet data */
static u8 ops_sec[40];
static u8 payload[0x10000];

/******************************************************************************
 ****************************** HELPER FUNCTIONS ******************************
 ******************************************************************************/

static char hexstr[65] = { [0 ... 64] = '\0' };

static int
to_hexstr(u8 *src, char *dst, size_t len)
{
    /* not our job to allocate buffers */
    if (!dst) {
        pr_err("no destination buffer allocated\n");
        return -1;
    }

    /* perform conversion */
    for (size_t i = 0; i < len; i++)
        snprintf(&dst[2 * i], 3, "%02hhx", src[i]);

    return 0;
}

/******************************************************************************
 ****************************** MODULE CALLBACKS ******************************
 ******************************************************************************/

/* xt_daf_match - performs packet match check
 *  @skb : socket buffer
 *  @par : parameters for match rule
 *
 *  @return : true if matched; false otherwise
 */
static bool
xt_daf_match(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct xt_daf_mtinfo *info = par->matchinfo;

    struct iphdr  *iph  = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;
    u8            digest[32];
    u32           payload_off;
    u32           payload_len;
    u8            *ops_sec_p;
    u8            *payload_p;
    int           ans;

    /* check that packet has IP options        *
     * NOTE: should at least have enough space *
     *       reserved for our option to exist  */
    if (iph->ihl < 14)
        return false;

    /* determine L4 payload length and offset based on supported protocols */
    switch (iph->protocol) {
        case IPPROTO_TCP:
            tcph        = tcp_hdr(skb);
            /* NOTE: avoid using tcp_hdr() if the options section is added *
             *       via Netfilter Queue; the reinjected packet does not   *
             *       recalculate @transport_header                         */
            tcph        = (struct tcphdr *) &((u8*) iph)[iph->ihl * 4];
            payload_off = iph->ihl * 4 + tcph->doff * 4;
            payload_len = ntohs(iph->tot_len) - payload_off;

            break;
        case IPPROTO_UDP:
            /* same reason for not using udp_hdr() as above */
            udph        = (struct udphdr *) &((u8*) iph)[iph->ihl * 4];
            payload_off = iph->ihl * 4 + sizeof(struct udphdr);
            payload_len = udph->len;

            break;
        default:    /* unsupported protocol */
            return false;
    }

    /* if relevant data is in nonlinear memory *
     * copy options section in local buffer    */
    ops_sec_p = skb_header_pointer(skb, 20, iph->ihl * 4 - 20, ops_sec);
    if (!ops_sec_p) {
        pr_err("unable to retrieve ptr to IP options section\n");
        par->hotdrop = true;
        return false;
    }

    /* check that the option codepoint and leght are correct *
     * NOTE: assuming that our option is the first           */
    if (ops_sec_p[0] != 0x5e && ops_sec_p[1] != 34)
        return false;

    /* if relevant data is in nonlinear memory *
     * copy payload in local buffer            */
    payload_p = skb_header_pointer(skb, payload_off, payload_len, payload);
    if (!payload_p) {
        pr_err("unable to retrieve ptr to L4 payload\n");
        par->hotdrop = true;
        return false;
    }

    /* set HMAC secret */
    ans = crypto_shash_setkey(cipher, info->secret, sizeof(info->secret));
    if (ans) {
        pr_err("unable to set secret\n");
        par->hotdrop = true;
        return false;
    }

    /* clean up request descriptor's operational state */
    memset(desc->__ctx, 0, crypto_shash_descsize(cipher));
    desc->tfm = cipher;

    /* perform synchronous HMAC on payload */
    ans = crypto_shash_init(desc);
    if (ans) {
        pr_err("unable to initialize hmac(sha256) context\n");
        par->hotdrop = true;
        return false;
    }

    ans = crypto_shash_update(desc, payload_p, payload_len);
    if (ans) {
        pr_err("unable to update digest with tcp payload\n");
        par->hotdrop = true;
        return false;
    }

    ans = crypto_shash_final(desc, digest);
    if (ans) {
        pr_err("unable to finalize hmac(sha256) operation\n");
        par->hotdrop = true;
        return false;
    }

    /* debugging */
    to_hexstr(&ops_sec_p[2], hexstr, 32);
    pr_info("reference hmac = \"%s\"\n", hexstr);
    to_hexstr(digest, hexstr, 32);
    pr_info("computed  hmac = \"%s\"\n", hexstr);

    /* check if computer hmac matches that in IP option */
    return memcmp(&ops_sec_p[2], digest, 32) == 0;
}

/* xt_daf_check - checks rule validity before insertion
 *  @par : parameters for match rule
 *
 *  @return : 0 if everything is ok; !0 otherwise
 */
static int
xt_daf_check(const struct xt_mtchk_param *par)
{
    struct xt_daf_mtinfo *info = par->matchinfo;

    /* don't trust userspace */
    if (!info->flags) {
        pr_err("no flags specified for inserted rule!\n");
        return 1;
    }

    return 0;
}

/* xtables module registration information */
static struct xt_match daf_mt_reg __read_mostly = {
    .name       = "daf",
    .revision   = 0,
    .family     = NFPROTO_IPV4,
    .matchsize  = sizeof(struct xt_daf_mtinfo),
    .match      = xt_daf_match,
    .checkentry = xt_daf_check,
    .me         = THIS_MODULE,
};

/******************************************************************************
 ************************ MODULE INIT & EXIT CALLBACKS ************************
 ******************************************************************************/

static int __init
daf_mt_init(void)
{
    int ans;

    /* allocate synchronous hash context */
    cipher = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(cipher)) {
        pr_err("unable to allocate cipher\n");
        return -1;
    }

    /* allocate request data structure */
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(cipher), GFP_KERNEL);
    if (!desc) {
        pr_err("out of memory\n");
        goto clean_cipher;
    }
    desc->tfm = cipher;

    /* register module with xtables core */
    ans = xt_register_match(&daf_mt_reg);
    if (ans) {
        pr_err("unable to register xtables module\n");
        goto clean_desc;
    }

    /* success */
    return 0;

clean_desc:
    kfree(desc);
clean_cipher:
    crypto_free_shash(cipher);

    /* failure */
    return -1;
}

static void __exit
daf_mt_exit(void)
{
    xt_unregister_match(&daf_mt_reg);
    kfree(desc);
    crypto_free_shash(cipher);
}

module_init(daf_mt_init);
module_exit(daf_mt_exit);

MODULE_DESCRIPTION("Xtables: IPv4 DAF signature option matching");
MODULE_AUTHOR("Radu Mantu <andru.mantu@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_daf");

