#include <stdint.h>         /* [u]int*_t              */
#include <unordered_set>    /* unordered set          */
#include <string>           /* string                 */

#ifndef _HASH_CACHE_H
#define _HASH_CACHE_H

int32_t hc_init(uint8_t _rm, uint8_t _nr);
uint8_t *hc_get_sha256(char *path);
std::unordered_set<std::string> hc_get_maps(uint32_t pid);
void hc_proc_exit(uint32_t pid);

#endif
