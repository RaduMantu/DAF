#include <fcntl.h>           /* open         */
#include <unistd.h>          /* read / close */
#include <string.h>          /* memcmp       */
#include <sys/stat.h>        /* fstat        */
#include <openssl/evp.h>     /* EVP_*        */
#include <netinet/in.h>      /* IPPROTO_*    */
#include <netinet/ip.h>      /* iphdr        */
#include <netinet/tcp.h>     /* tcphdr       */
#include <netinet/udp.h>     /* udphdr       */
#include <netinet/ip_icmp.h> /* icmphdr      */

#include "signer.h"
#include "util.h"

/* disable warnings regarding designated initializers */
#pragma clang diagnostic ignored "-Wc99-designator"
#pragma clang diagnostic ignored "-Winitializer-overrides"

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

static EVP_PKEY *key;       /* signer secret */

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
 ******************************************************************************/

/* update_hmac_udp - UDP-specific HMAC update function
 *  @data   : address of IP header
 *  @md_ctx : digest context
 *
 *  @return : 0 if everything went well; -1 otherwise
 *
 * NOTE: ignore potential UDP options
 */
static int32_t
update_hmac_udp(uint8_t *data, EVP_MD_CTX *md_ctx)
{
    int32_t       ans;    /* answer */
    struct iphdr  *iph  = (struct iphdr *) data;
    struct udphdr *udph = (struct udphdr *) &data[iph->ihl *4];

    /* update digest with immutable UDP fields */
    ans = EVP_DigestSignUpdate(md_ctx, &udph->len, sizeof(udph->len));
    RET(ans != 1, -1, "unable to update digest");

    /* update digest with payload */
    ans = EVP_DigestSignUpdate(md_ctx, &data[iph->ihl * 4 + sizeof(*udph)],
                udph->len - sizeof(*udph));
    RET(ans != 1, -1, "unable to update digest");

    return 0;
}

/* update_hmac_tcp - TCP-specific HMAC update function
 *  @data   : address of IP header
 *  @md_ctx : digest context
 *
 *  @return : 0 if everything went well; -1 otherwise
 */
static int32_t
update_hmac_tcp(uint8_t *data, EVP_MD_CTX *md_ctx)
{
    int32_t       ans;    /* answer */
    struct iphdr  *iph  = (struct iphdr *) data;
    struct tcphdr *tcph = (struct tcphdr *) &data[iph->ihl *4];

    /* update digest with immutable TCP fields *
     * TODO: add some flags as well            */
    ans = EVP_DigestSignUpdate(md_ctx, &tcph->seq, sizeof(tcph->seq));
    RET(ans != 1, -1, "unable to update digest");

    ans = EVP_DigestSignUpdate(md_ctx, &tcph->window, sizeof(tcph->window));
    RET(ans != 1, -1, "unable to update digest");

    ans = EVP_DigestSignUpdate(md_ctx, &tcph->urg_ptr, sizeof(tcph->urg_ptr));
    RET(ans != 1, -1, "unable to update digest");

    /* update digest with payload */
    ans = EVP_DigestSignUpdate(md_ctx, &data[(iph->ihl + tcph->doff) * 4],
                ntohs(iph->tot_len) - (iph->ihl + tcph->doff) * 4);

    return 0;
}

/* update_hmac_icmp - ICMP-specific HMAC update function
 *  @data   : address of IP header
 *  @md_ctx : digest_context
 *
 *  @return : 0 if everything went well; -1 otherwise
 */
static int32_t
update_hmac_icmp(uint8_t *data, EVP_MD_CTX *md_ctx)
{
    int32_t        ans;    /* answer */
    struct iphdr   *iph   = (struct iphdr *) data;
    struct icmphdr *icmph = (struct icmphdr *) &data[iph->ihl * 4];

    /* update digest with immutable ICMP fields              *
     * NOTE: not including type/code-specific rest of header */
    ans = EVP_DigestSignUpdate(md_ctx, &icmph->type, sizeof(icmph->type));
    RET(ans != 1, -1, "unable to update digest");

    ans = EVP_DigestSignUpdate(md_ctx, &icmph->code, sizeof(icmph->code));
    RET(ans != 1, -1, "unable to update digest");

    return 0;
}

/* update_hmac_dummy - catch-all HMAC update function
 *  @data : address of IP header
 *
 *  @return : 0 if everything went well; -1 otherwise
 */
static int32_t
update_hmac_dummy(uint8_t *data, EVP_MD_CTX *)
{
    struct iphdr *iph  = (struct iphdr *) data;

    WAR("unknown protocol: %hhu", iph->protocol);

    return 0;
}

/* vtable for protocol-specific HMAC update functions */
int32_t (*update_hmac_proto[0x100])(uint8_t *, EVP_MD_CTX *) = {
    [ 0x00 ... 0xff ] = update_hmac_dummy,

    [ IPPROTO_UDP  ] = update_hmac_udp,
    [ IPPROTO_TCP  ] = update_hmac_tcp,
    [ IPPROTO_ICMP ] = update_hmac_icmp,
};

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* signer_init - signer module initializer
 *  @key_path : path to HMAC secret (can be NULL)
 *
 *  @return : 0 if everything went well; -1 on error
 */
int32_t
signer_init(const char *key_path)
{
    struct stat stat_buf;   /* file stat buffer */
    uint8_t     *key_buf;   /* raw key buffer   */
    int32_t     fd;         /* key file fd      */
    int32_t     ans;        /* answer           */
    int32_t     ret = -1;   /* function ret val */
    ssize_t     rb;         /* read bytes       */

    /* TODO: add singature type argument           *
     *       check for NULL key_path based on that */

    /* alocate temporary key buffer and read raw key */
    fd = open(key_path, O_RDONLY);
    RET(fd == -1, -1, "unable to open %s (%s)", key_path, strerror(errno));

    ans = fstat(fd, &stat_buf);
    GOTO(ans == -1, clean_fd, "unable to stat file (%s)", strerror(errno));

    key_buf = (uint8_t *) malloc(stat_buf.st_size);
    GOTO(!key_buf, clean_fd, "unable to allocate buffer (%s)", strerror(errno));

    rb = read(fd, key_buf, stat_buf.st_size);
    GOTO(rb == -1, clean_buf, "unable to read file (%s)", strerror(errno));
    GOTO(rb != stat_buf.st_size, clean_buf, "unable to read entire file");

    /* initialize EVP_KEY from key buffer */
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key_buf,
                                       stat_buf.st_size);
    GOTO(!key, clean_buf, "unable to init EVP key");

    /* success */
    ret = 0;

    /* cleanup */
clean_buf:
    free(key_buf);

clean_fd:
    close(fd);

    return ret;
}

/* calc_hmac - calculates HMAC of immutable fields & payload
 *  @data    : address of IP header
 *  @sig_buf : address of signature buffer
 *
 *  @return : 0 if everything went well; -1 otherwise
 *
 * NOTE: this is also used for verification
 */
int32_t
calc_hmac(uint8_t *data, uint8_t *sig_buf)
{
    EVP_MD_CTX   *md_ctx;    /* digest context   */
    int32_t      ans;        /* answer           */
    int32_t      ret = -1;   /* function ret val */
    size_t       sig_sz;     /* signature size   */
    struct iphdr *iph = (struct iphdr *) data;

    /* sanity check */
    RET(!data, -1, "NULL packet buffer");
    RET(!sig_buf, -1, "NULL signature buffer");

    /* initialize digest context */
    md_ctx = EVP_MD_CTX_new();
    RET(!md_ctx, -1, "unable to create digest context");

    ans = EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, key);
    GOTO(ans != 1, clean_ctx, "unable to init digest context");

    /* update digest with IP-specific immutabile fields *
     * TODO: add bitfields */
    ans = EVP_DigestSignUpdate(md_ctx, &iph->id, sizeof(iph->id));
    GOTO(ans != 1, clean_ctx, "unable to update digest");

    ans = EVP_DigestSignUpdate(md_ctx, &iph->protocol, sizeof(iph->protocol));
    GOTO(ans != 1, clean_ctx, "unable to update digest");

    /* update digest with layer 4-specific fields & payload */
    ans = update_hmac_proto[iph->protocol](data, md_ctx);
    GOTO(ans, clean_ctx, "unable to update digest with L4 header & payload");

    /* finalize hashing */
    ans = EVP_DigestSignFinal(md_ctx, sig_buf, &sig_sz);
    GOTO(ans != 1, clean_ctx, "unable to finalize digest");
    GOTO(sig_sz != 32, clean_ctx, "unexpected digest size: %lu", sig_sz);

    /* success */
    ret = 0;

    /* cleanup */
clean_ctx:
    EVP_MD_CTX_free(md_ctx);

    return ret;
}

/* verify_hmac - verify HMAC of received packet
 *  @data        : address of IP header
 *  @ref_sig_buf : address of reference signature buffer
 *
 *  @return :  0 if HMAC did not match
 *             1 if HMAC matched
 *            -1 on error
 */
int32_t
verify_hmac(uint8_t *data, uint8_t *ref_sig_buf)
{
    uint8_t sig_buf[32];   /* sig buffer for verification */
    int32_t ans;           /* answer                      */

    /* sanity check */
    RET(!data, -1, "NULL packet buffer");
    RET(!ref_sig_buf, -1, "NULL reference signature buffer");

    /* calculate HMAC */
    ans = calc_hmac(data, sig_buf);
    RET(ans, -1, "unable to claculate HMAC for received packet");

    /* compare our HMAC with reference */
    return (memcmp(ref_sig_buf, sig_buf, 32) == 0);
}

