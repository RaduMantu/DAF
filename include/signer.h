#pragma once

#include <stdint.h>     /* [u]int*_t    */

/* signature types */
enum sign_t {
    SIG_NONE,       /* no signature               */
    SIG_PACKET,     /* immutable fields & payload */
    SIG_APP,        /* aggregate object signature */
};

/* codepoint of IP signature option */
#define SIG_OP_CP 0x5e

/* public API */
int32_t signer_init(const char *, sign_t);
int32_t verify_hmac(uint8_t *, uint8_t *);

extern void *(*add_sig)(uint8_t *);

