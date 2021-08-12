#include <stdio.h>              /* snprintf                            */
#include <string.h>             /* memset                              */
#include <unistd.h>             /* readlink                            */
#include <sys/syscall.h>        /* SYS_*                               */
#include <queue>                /* priority queue                      */
#include <utility>              /* pair, make_pair                     */

#include "sock_cache.h"         /* socket cache API                    */
#include "proc_events.h"        /* timestamped event struct definition */
#include "ebpf_helpers.h"
#include "util.h"

using namespace std;

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

/* internal data structures
 *  close_events - <pid, fd> of every close() call (to be processed later)
 */
static priority_queue<struct ts_event<pair<uint32_t, uint8_t>>> close_events;

/******************************************************************************
 ********************************* PUBLIC API *********************************
 ******************************************************************************/

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

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
                close_events.emplace(
                    make_pair<uint32_t, uint8_t>(s->us.pid, s->fd));
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

/* ebpf_delayed_ev_handle - handles delayed events
 *  @delta_t : minimum time difference in microsecs between emplacing the event
 *             and actually processing it
 */
void ebpf_delayed_ev_handle(uint64_t delta_t)
{
    struct timeval tv;
    uint64_t       ct;

    /* get current epoch time in microsecs */
    gettimeofday(&tv, NULL);
    ct = (uint64_t) (tv.tv_sec * 1e6 + tv.tv_usec);

    /* for each event, ordered by emplacement time */
    while (close_events.size()) {
        auto &ce = close_events.top();

        /* break if time since emplacement is lower than delta */
        if (ct - ce.ts < delta_t)
            break;

        /* process event (timeout already occurred) */
        sc_close_fd(get<0>(ce.ev_val), get<1>(ce.ev_val));

        /* pop element that was just processed from queue */
        close_events.pop();
    }
}
