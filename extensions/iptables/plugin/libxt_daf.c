#include <stdio.h>      /* printf         */
#include <stdint.h>     /* [u]int*_t      */
#include <xtables.h>    /* xtables_match  */
#include <getopt.h>     /* struct option  */
#include <string.h>     /* strlen, memset */

#include "xt_daf.h"

/******************************************************************************
 ************************* PLUGIN CALLBACK FUNCTIONS **************************
 ******************************************************************************/

/* daf_mt_help - prints out help message for this plugin
 */
static void
daf_mt_help(void)
{
    printf("DAF signature match options\n"
           "[!] --secret HEXSTR    Secret used in SHA256-HMAC calculation\n");
}

/* daf_mt_init - initializes rule data structure before parsing
 *  @match : contains pointer to our rule data struct 
 */
static void
daf_mt_init(struct xt_entry_match *match)
{
    struct xt_daf_mtinfo *info = (void *) match->data;

    memset(info, 0, sizeof(*info));
}

/* daf_mt_parse - parses cli options into data structure intended for kernel
 *  @c      : option id (see .val in daf_mt_opts)
 *  @argv   : argument array
 *  @invert : 1 if user specified "! " before the argument
 *  @flags  : for parser's discretionary use
 *  @entry  : ptr to an ipt_entry structure
 *  @match  : contains pointer to our rule data struct
 *
 *  @return : true if option was parsed, false otherwise
 */
static int
daf_mt_parse(int                   c,
             char                  **argv,
             int                   invert,
             unsigned int          *flags,
             const void            *entry,
             struct xt_entry_match **match)
{
    struct xt_daf_mtinfo *info = (void *) (*match)->data;

    size_t  len;    /* hexstring length           */
    uint8_t *sec_p; /* iterator over secret bytes */

    /* option-specific parsing */
    switch (c) {
        case '1':       /* --secret */
            /* check for multiple occurrences */
            if (*flags & XT_DAF_PKTHASH)
                xtables_error(PARAMETER_PROBLEM,
                    "xt_daf: specify exactly one \"--secret\"!");

            /* update perser & match criteria flags */
            *flags      |= XT_DAF_PKTHASH;
            info->flags |= XT_DAF_PKTHASH;
            info->flags |= invert ? XT_DAF_PKTHASH_INV : 0;

            /* initialize info->secret from hexstring */
            len = strlen(optarg);
            sec_p = &info->secret[32 - (len + 1) / 2];

            /* corner case: first nibble of hexstring is omitted */
            if (len & 0x01)
                sscanf(optarg, "%1hhx", sec_p++);

            /* parse each hexstring byte of remaining secret */
            for (size_t i = len & 0x01; i < len; i += 2)
                sscanf(&optarg[i], "%2hhx", sec_p++);

            return true;
    }

    return false;
}

/* daf_mt_print - prints rule info in freeform fashion
 *  @entry   : general ip structure (struct ipt_ip)
 *  @match   : contains pointer to our rule data struct
 *  @numeric : print stuff in human readable format (if applicable)
 */
static void
daf_mt_print(const void                  *entry,
             const struct xt_entry_match *match,
             int                         numeric)
{
    struct xt_daf_mtinfo *info = (void *) match->data;

    /* check for match rule reversal */
    if (info->flags & XT_DAF_PKTHASH_INV)
        printf("! ");

    /* print secret hexstring */
    for (size_t i = 0; i < sizeof(info->secret); i++)
        printf("%02hhx", info->secret[i]);
}

/* daf_mt_save - prints out arguments that generate this rule
 *  @entry : general ip structure (struct ipt_ip)
 *  @match : contains pointer to our rule data struct
 */
static void
daf_mt_save(const void                  *entry,
            const struct xt_entry_match *match)
{
    struct xt_daf_mtinfo *info = (void *) match->data;

    /* check for match rule reversal */
    if (info->flags & XT_DAF_PKTHASH_INV)
        printf("! ");

    /* print long option name (no shorthand) */
    printf("--secret ");

    /* print secret hexstring */
    for (size_t i = 0; i < sizeof(info->secret); i++)
        printf("%02hhx", info->secret[i]);
}

/* module specific options */
static const struct option daf_mt_opts[] = {
    { .name = "secret", .has_arg = required_argument, .val = '1' },
    { NULL },
};

/* plugin vtable (for iptables to interact with) */
static struct xtables_match daf_mt_reg = {
    .version       = XTABLES_VERSION,
    .name          = "daf",
    .revision      = 0,
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct xt_daf_mtinfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_daf_mtinfo)),

    .help        = daf_mt_help,
    .init        = daf_mt_init,
    .parse       = daf_mt_parse,
    .print       = daf_mt_print,
    .save        = daf_mt_save,
    .extra_opts  = daf_mt_opts,
};

/******************************************************************************
 ************************ LIBRARY MANAGEMENT ROUTINES *************************
 ******************************************************************************/

/* libxt_daf_init - registers plugin vtable on library load
 */
static void __attribute__((constructor))
libxt_daf_init(void)
{
    xtables_register_match(&daf_mt_reg);
}

