#pragma once

#include <stdint.h>     /* [u]int*_t    */

int32_t signer_init(const char *key_path);
int32_t calc_hmac(uint8_t *, uint8_t *);
int32_t verify_hmac(uint8_t *, uint8_t *);

