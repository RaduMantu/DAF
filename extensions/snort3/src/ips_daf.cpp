#include <string.h>         /* memset, strlen     */
#include <stdio.h>          /* sscanf             */
#include <netinet/in.h>     /* IPPROTO_*          */
#include <netinet/ip.h>     /* iphdr              */
#include <netinet/tcp.h>    /* tcphdr             */
#include <netinet/udp.h>    /* udphdr             */
#include <arpa/inet.h>      /* ntohs              */
#include <openssl/evp.h>    /* EVP hmac interface */
#include <openssl/err.h>    /* error reporting    */

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/ipv4_options.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "daf"

/* performance stats */
static THREAD_LOCAL ProfileStats dafPerfStats;

/* module config data extracted from rule */
struct DafData {
    uint8_t secret[32];
    bool    match_trigger;
};

/* rule based on this module */
class DafOption : public IpsOption
{
public:
    DafOption(const DafData& c) : IpsOption(s_name)
    { config = c; }

    DafData *get_data()
    { return &config; }

    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet *) override;

private:
    DafData config;
};

/* == - overrides rule equivalence check
 *  @ips : right hand side of == operation
 *
 *  @return : true if the two rules are identical
 */
bool DafOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const DafOption& rhs    = (const DafOption&) config;
    const DafData    *left  = &config;
    const DafData    *right = &rhs.config;

    if (left->match_trigger != right->match_trigger)
        return false;

    return memcmp(left->secret, right->secret, 32) == 0;
}

/* eval - checks if packet matches current rule's config
 *  @p : packet
 *
 *  @return : MATCH or NO_MATCH
 */
IpsOption::EvalStatus DafOption::eval(Cursor&, Packet *p)
{
    struct iphdr  *iph;         /* ip header              */
    struct tcphdr *tcph;        /* tcp header             */
    struct udphdr *udph;        /* udp header             */
    uint8_t       *pkt;         /* easy access to L3 hdr  */
    uint32_t      payload_len;  /* payload length         */
    uint32_t      payload_off;  /* payload offset         */
    uint8_t       md[32];       /* message digest         */
    size_t        md_len;       /* digest length          */
    EVP_PKEY      *key;         /* OpenSSL key            */
    EVP_MD_CTX    *ctx;         /* OpenSSL digest context */
    ssize_t       ans;          /* answer                 */

    /* possible return value array */
    IpsOption::EvalStatus ret[2] = { MATCH, NO_MATCH };
    RuleProfile profile(dafPerfStats);

    /* check L3 protocol */
    if (!p->is_ip4())
        return config.match_trigger ? NO_MATCH : MATCH;

    /* check if IP options section exists (and is large enough) */
    iph = (struct iphdr *) p->ptrs.ip_api.get_ip4h();
    pkt = (uint8_t *) iph;
    if (iph->ihl < 14)
        return config.match_trigger ? NO_MATCH : MATCH;

    /* check if IP option codepoint & length correspond *
     * NOTE: assuming the DAF option is first           */
    if (pkt[20] != 0x5e || pkt[21] != 34)
        return config.match_trigger ? NO_MATCH : MATCH;

    /* determine L4 payload length depending on supported protocols */
    switch (iph->protocol) {
        case IPPROTO_TCP:
            tcph = (struct tcphdr *) &pkt[iph->ihl * 4];
            payload_off = (iph->ihl + tcph->doff) * 4;
            payload_len = ntohs(iph->tot_len) - payload_off;

            break;
        case IPPROTO_UDP:
            /* should account for UDP options */
            udph = (struct udphdr *) &pkt[iph->ihl * 4];
            payload_off = iph->ihl * 4 + sizeof(struct udphdr);
            payload_len = udph->len;

            break;
        default:
            /* unsupported protocol */
            return config.match_trigger ? NO_MATCH : MATCH;
    }

    /* initialize OpenSSL key & digest context */
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, config.secret,
                                       sizeof(config.secret));

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "unable to create digest context\n");
        ERR_print_errors_fp(stderr);
        return NO_MATCH;
    }

    ans = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
    if (ans != 1) {
        fprintf(stderr, "unable to initialize digest context\n");
        ERR_print_errors_fp(stderr);
        return NO_MATCH;
    }

    /* update digest with obtained data */
    ans = EVP_DigestSignUpdate(ctx, &pkt[payload_off], payload_len);
    if (ans != 1) {
        fprintf(stderr, "unable to update digest\n");
        ERR_print_errors_fp(stderr);
        return NO_MATCH;
    }

    /* get amount of space required for digest */
    ans = EVP_DigestSignFinal(ctx, NULL, &md_len);
    if (ans != 1) {
        fprintf(stderr, "unable to determine signature size\n");
        ERR_print_errors_fp(stderr);
        return NO_MATCH;
    }

    if (md_len != sizeof(md)) {
        fprintf(stderr, "expected digest size mismatch: %lu\n", md_len);
        return NO_MATCH;
    }

    /* finalize hashing */
    ans = EVP_DigestSignFinal(ctx, md, &md_len);
    if (ans != 1) {
        fprintf(stderr, "unable to finalize signature\n");
        ERR_print_errors_fp(stderr);
        return NO_MATCH;
    }

    /* compare sigantures */
    ans = memcmp(&pkt[22], md, sizeof(md));
    return config.match_trigger ? ret[!!ans] : ret[!ans];
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

/* rule syntax */
static const Parameter s_params[] = {
    { "~secret", Parameter::PT_STRING, nullptr, nullptr,
      "hexstring of hmac secret" },

    { "match_trigger", Parameter::PT_BOOL, nullptr, "true",
      "trigger event on signature match if true / mismatch if false" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr },
};

#define s_help \
    "rule option to check for DAF packet signatures in IP options"

/* rule config parser */
class DafModule : public Module
{
public:
    DafModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char *, int, SnortConfig *)   override;
    bool set(const char *, Value &, SnortConfig *) override;

    ProfileStats *get_profile() const override
    { return &dafPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

    DafData data = { };
};

bool DafModule::begin(const char *, int, SnortConfig *)
{
    memset(data.secret, 0, sizeof(data.secret));
    data.match_trigger = true;
    return true;
}

bool DafModule::set(const char *, Value &v, SnortConfig *)
{
    size_t     len;     /* string argument length     */
    const char *arg;    /* string argument            */
    uint8_t    *sec_p;  /* iterator over secret bytes */

    if (v.is("~secret")) {
        arg   = v.get_string();
        len   = strlen(arg);
        sec_p = &data.secret[32 - (len + 1) / 2];

        /* corner case: first nibble of hexstring is omitted */
        if (len & 0x01)
            sscanf(arg, "%1hhx", sec_p++);

        /* parse each hexstring byte of remaining secret */
        for (size_t i = len & 0x01; i < len; i += 2)
            sscanf(&arg[i], "%2hhx", sec_p++);

    } else if (v.is("match_trigger")) {
        data.match_trigger = v.get_bool();
    } else {
        return false;
    }

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module *mod_ctor()
{
    return new DafModule;
}

static void mod_dtor(Module *m)
{
    delete m;
}

static IpsOption *dafopt_ctor(Module *p, OptTreeNode *)
{
    DafModule *m = (DafModule *) p;
    return new DafOption(m->data);
}

static void dafopt_dtor(IpsOption *p)
{
    delete p;
}

static const IpsApi daf_api = {
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor,
    },
    OPT_TYPE_DETECTION,
    1, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dafopt_ctor,
    dafopt_dtor,
    nullptr,
};

SO_PUBLIC const BaseApi *snort_plugins[] = {
    &daf_api.base,
    nullptr,
};
