/*
 * Copyright © 2021, Radu-Alexandru Mantu <andru.mantu@gmail.com>
 *
 * This file is part of app-fw.
 *
 * app-fw is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * app-fw is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with app-fw. If not, see <https://www.gnu.org/licenses/>.
 */

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

int32_t process_ebpf_sample(void *ctx, void *data, size_t len);
void    ebpf_delayed_ev_handle(uint64_t delta_t);

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

int32_t process_ebpf_sample(void *ctx, void *data, size_t len)
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
                /* update socket cache state                               *
                 * NOTE: assume that this call always succeeds             *
                 * TODO: add a more robust implementation based on pid/tid */
                close_events.emplace(
                    make_pair<uint32_t, uint8_t>(s->us.pid, s->fd));
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
    tscval_t ts;    /* cycles (or us) since system boot */

    /* get elapsed time since system boot in microsecs */
    rdtsc(ts.low, ts.high);
    ts.raw = ts.raw * 1'000'000 / BASE_FREQ;

    /* for each event, ordered by emplacement time */
    while (close_events.size()) {
        auto &ce = close_events.top();

        /* break if time since emplacement is lower than delta */
        if (ts.raw - ce.ts < delta_t)
            break;

        /* process event (timeout already occurred) */
        sc_close_fd(get<0>(ce.ev_val), get<1>(ce.ev_val));

        /* pop element that was just processed from queue */
        close_events.pop();
    }
}

