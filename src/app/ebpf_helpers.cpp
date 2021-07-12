#include <stdio.h>              /* snprintf */
#include <string.h>             /* memset */
#include <unistd.h>             /* readlink */
#include <sys/syscall.h>        /* SYS_* */

#include "sock_cache.h"
#include "ebpf_helpers.h"
#include "util.h"


int process_ebpf_sample(void *ctx, void *data, size_t len)
{
    struct sample *s;

    /* process sample */
    s = (struct sample *) data;

    switch (s->scn) {
        case SYS_socket:    /* 41 */
            /* update socket cache state */
            sc_open_fd(s->us.pid, s->ret);

            break;
        case SYS_close:     /* 3 */
            if (s->is_enter) {
                // DEBUG("eBPF: SYS_close(enter) pid:%-5d tid:%-5d fd:%-2d",
                //    s->us.pid, s->us.tid, s->fd);

                /* update socket cache state                               *
                 * NOTE: assume that this call always succeeds             *
                 * TODO: add a more robust implementation based on pid/tid */
                sc_close_fd(s->us.pid, s->fd);
            } else {
                // DEBUG("eBPF: SYS_close(exit)  pid:%-5d tid:%-5d ret:%-2d",
                //    s->us.pid, s->us.tid, s->ret);
            }
            break;
        default:
            WAR("unkown sample syscall number");
    }

    return 0;
}
