#include <stdio.h>      /* size_t */
#include <stdint.h>     /* [u]int*_t */

#ifndef _EBPF_TYPES_H

/* event sample transmitted via ring buffer */
struct sample {
    /* [8 bytes] kernel / user space access mods */
    union {
        struct {
            int32_t pid;        /* userspace ProcessID */
            int32_t tid;        /* userspace ThreadID  */
        } us;
        uint64_t ks;
    };

    /* [4 bytes] encapsulate multiple event types */
    union {
        int32_t ret;    /* retvalue from sys_exit_* events */
        int32_t fd;     /* fd argument for sys_enter_close */
    };

    /* [4 bytes] syscall number */
    int32_t scn;

    /* [16 bytes] elements exceeding a power of 2 offset must be included in *
     *            a union with padding elements; eBPF ringbuff size must be  *
     *            multiple of PAGE_SIZE and power of 2                       */
    union {
        uint8_t  is_enter:1;    /* 1:sys_enter_* | 0:sys_exit_* */

        struct {                /* padding to 32 byte struct size */
            uint64_t r1;
            uint64_t r2;
        } reserved;
    };
};


int process_ebpf_sample(void *ctx, void *data, size_t len);
void ebpf_delayed_ev_handle(uint64_t delta_t);

#endif

