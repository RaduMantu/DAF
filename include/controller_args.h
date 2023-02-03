#pragma once

#include <argp.h>
#include <stdint.h>

#include "filter.h"

extern struct argp    argp;
extern struct ctl_msg cfg;

void print_hexstring(const uint8_t *buff, size_t len);

