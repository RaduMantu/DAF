#include <stdint.h>         /* [u]int*_t              */
#include <unordered_set>    /* unordered set          */
#include <string>           /* string                 */

#ifndef _HASH_CACHE_H
#define _HASH_CACHE_H

uint8_t *hc_get_sha256(char *path);
std::unordered_set<std::string> hc_get_maps(uint32_t pid);
void hc_proc_exit(uint32_t pid);

#endif

