#include <stdint.h>     /* [u]int*_t */

#ifndef _SOCK_CACHE_H
#define _SCOK_CACHE_H

int32_t sc_init(void);
void    sc_open_fd(uint32_t pid, uint8_t fd);
void    sc_close_fd(uint32_t pid, uint8_t fd);
void    sc_proc_exit(uint32_t pid);
void    sc_proc_fork(uint32_t parent_pid, uint32_t child_pid);
void    sc_proc_exec(uint32_t pid);
void    sc_dump_state(void);

#endif

