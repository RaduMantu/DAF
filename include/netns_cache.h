#pragma once

#include <stdint.h>     /* [u]int*_t */

int32_t nnc_get_fd(char *netns_path);
int32_t nnc_release_ns(char *netns_path);

