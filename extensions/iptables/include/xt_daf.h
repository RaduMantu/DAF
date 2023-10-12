#ifndef _XT_DAF_H
#define _XT_DAF_H

/* rule flag values */
enum {
    XT_DAF_PKTHASH     = 1 << 0,
    XT_DAF_PKTHASH_INV = 1 << 1,
};

/* rule match information */
struct xt_daf_mtinfo {
    __u8 secret[32];
    __u8 flags;
};

#endif /* _XT_DAF_H */

