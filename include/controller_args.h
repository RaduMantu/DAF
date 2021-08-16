#include <argp.h>
#include <stdint.h>

#include "filter.h"

#ifndef _CONTROLLER_ARGS_H
#define _CONTROLLER_ARGS_H

extern struct argp    argp;
extern struct ctl_msg cfg;

void print_hexstring(const uint8_t *buff, size_t len);

#endif

