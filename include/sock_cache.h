#pragma once

#include <stdint.h>         /* [u]int*_t */
#include <unordered_set>

int32_t sc_init(void);
void    sc_open_fd(uint32_t pid, uint8_t fd);
void    sc_close_fd(uint32_t pid, uint8_t fd);
void    sc_proc_exit(uint32_t pid);
void    sc_proc_fork(uint32_t parent_pid, uint32_t child_pid);
void    sc_proc_exec(uint32_t pid);
void    sc_dump_state(void);

std::unordered_set<uint32_t> *sc_get_pid(uint8_t  protocol, uint32_t src_ip,
        uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);

