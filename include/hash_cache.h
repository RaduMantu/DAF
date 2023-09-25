#pragma once

#include <stdint.h>         /* [u]int*_t     */
#include <set>              /* set           */
#include <unordered_set>    /* unordered_set */
#include <string>           /* string        */

int32_t               hc_init(uint8_t _rm, uint8_t _nr);
uint8_t               *hc_get_sha256(char *path);
void                  hc_proc_exit(uint32_t pid);

#ifdef DISABLE_ORDERING
std::unordered_set<std::string> hc_get_maps(uint32_t pid);
#else
std::set<std::string> hc_get_maps(uint32_t pid);
#endif /* DISABLE_ORDERING */

