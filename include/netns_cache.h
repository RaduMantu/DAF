#pragma once

#include <stdint.h>     /* [u]int*_t */
#include <utility>      /* pair      */

int32_t nnc_get_fd(char *netns_path);
int32_t nnc_release_ns(char *netns_path);
std::pair<uint64_t, uint64_t> nnc_fd_to_ns(uint32_t fd);


