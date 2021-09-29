#include <stdint.h>     /* [u]int*_t */

#ifndef _GPG_HELPERS_H
#define _GPG_HELPERS_H

int32_t gpg_init(char *_ep, char *_kh, char *_kfp, uint8_t _pem);
int32_t gpg_fini(void);

#endif  /* _GPG_HELPERS_H */
