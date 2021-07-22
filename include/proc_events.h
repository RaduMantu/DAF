#include <sys/time.h>   /* gettimeofday */
#include <stdint.h>     /* [u]int*_t */

#ifndef _PROC_EVENTS_H
#define _PROC_EVENTS_H

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
        struct timeval tv;

        /* set timestamp to epoch time in us */
        gettimeofday(&tv, NULL);
        ts = (uint64_t) (tv.tv_sec * 1e6 + tv.tv_usec);
    }

    bool operator < (const struct ts_event &x) const
    {
        return ts > x.ts;
    }
};

#endif

