#pragma once

#include <stdint.h>     /* [u]int*_t */
#include "util.h"       /* rdtsc     */

/* ts_event - timestamped event-related values (e.g.: pid)
 *
 * timestamps are in microseconds
 * operator overload is for ordering oldest to newest by timestamp
 */
template<typename T>
struct ts_event {
    uint64_t ts;        /* timestamp           */
    T        ev_val;    /* event-related value */

    ts_event(T _ev_val) : ev_val(_ev_val)
    {
        /* the TimeStamp Counter (hopefully) holds the number of invariable *
         * base frequency cycles since system boot                          */
        tscval_t epoch_cycles;

        /* get cycle clount since boot */
        rdtsc(epoch_cycles.low, epoch_cycles.high);

        /* set timestamp to epoch time in us */
        ts = epoch_cycles.raw * 1'000'000 / BASE_FREQ;
    }

    bool operator < (const struct ts_event &x) const
    {
        return ts > x.ts;
    }
};

