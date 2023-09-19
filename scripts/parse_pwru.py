#!/usr/bin/python3

"""
This script parses the output of pwru and collects traces for each packet path
that is captured. These are translated into CFGs containing the reached trace
points and the average elapsed time in between them.
"""

import sys
import numpy as np

"""
Control Flow Grapth.

Key : [frozenset(str*)] list of tracepoints reached
Val : [list(int, np.array)] list of two elements:
            first  : number of hits on this path
            second : elapsed time(stamps) for each tracepoint in Key
"""
cfg = {}

def update_cfg(fn_trace, ts_trace):
    """ Updates control flow graph and cumulative relative timestamps

    Parameters
    ----------
    fn_trace : [list(str)] triggered tracepoint names
    ts_trace : [list(int)] relative timestamps for fn_trace

    NOTE: elapsed time for fn_trace[-1] cannot be calculated
          no timestamp available for its exit point
    """
    global cfg

    # possible on first packet match
    if len(fn_trace) == 0 or len(ts_trace) == 0:
        return

    # if an anomaly is encountered, split up the trace
    anomaly_idx = check_anomaly(fn_trace)
    if anomaly_idx != 0:
        ts_trace[anomaly_idx] = 0

        update_cfg(fn_trace[:anomaly_idx], ts_trace[:anomaly_idx])
        update_cfg(fn_trace[anomaly_idx:], ts_trace[anomaly_idx:])

        return

    # rotate timestamps and place them in a np.array
    #   ts_trace[n] is the elapsed time for fn_trace[n-1]
    #   fn_trace[-1] doesn't have an elapsed time
    ts_trace = ts_trace[1:] + ts_trace[:1]
    ts_trace = np.array(ts_trace)

    # create a tuple from fn_trace to use it as key
    fn_trace = tuple(fn_trace)

    # instantiate dict entry if this is first occurrence
    if fn_trace not in cfg:
        cfg[fn_trace] = [ 0, np.zeros(len(fn_trace)) ]

    # update number of path hits and relative timestamps
    cfg[fn_trace][0] += 1
    cfg[fn_trace][1] += ts_trace


def dump_cfg():
    """ Prints collected CFGs to stdout """

    # account for '^C' that's printed to stdout by terminal
    print('')

    for it in cfg:
        # compute relative timestamp averages
        cfg[it][1] /= cfg[it][0]

        # print number of hits & separator
        print('|===================[ %lu hits ]===================|' \
              % cfg[it][0])

        # print path w/ relative timestamps
        for itt in zip(it, cfg[it][1]):
            print(' %-30s -- %15.3f' % itt)
        print('\n')

def check_anomaly(fn_trace, threshold=3):
    """ Returns length of minimal trace (in case of anomaly)

    Parameters
    ----------
    fn_trace  : [list(str)] triggered tracepoint names
    threshold : [int] minimum sublist length (expect tracepoint duplicates
                within a normal trace)

    Returns
    -------
    0 if no anomaly was detected
    length of initial trace if anomaly was detected

    Details
    -------
    The anoomaly in question here is that sometimes, pwru can report non-zero
    relative timestamps for the first tracepoint triggered by a new packet.
    This can cause the inclusion of concatenations of multiple known paths
    as unique paths in our CFG.

    This function will try to find the largest sublist that is bound to the
    first element that will repeat in the remainder of the trace. Note that this
    approach can yeild incorrect results if there are 4 or more concatenations
    but this should not be a problem if update_cfg() calls check_anomaly()
    recursively. In other words, we split the 4x concatenation in 2x and 2x,
    then each 2x into 1x and 1x. Although messier, this compensates for
    threshold values that are too low.
    """

    # for each subset of fn_trace w/ bounded starting item
    # ordered by decreasing size, up to minimum threshold
    for i in range(len(fn_trace), threshold, -1):
        sublist = fn_trace[:i]

        # using a sublist-sized sliding window (excluding first element)
        # NOTE: the +1 is necessary for precisely x2 concatenation
        for j in range(i, len(fn_trace) - i + 1):
            # check for sublist match
            if fn_trace[j : j+i] == fn_trace[:i]:
                return i

    # no anomaly found
    return 0

def main():
    # instantiate trace variable
    fn_trace = []
    ts_trace = []

    # main while loop
    while True:
        try:
            line = sys.stdin.readline()
        except:     # Keyboard Interrupt
            update_cfg(fn_trace, ts_trace)

            break

        line = [ it for it in line.split(' ') if len(it) > 0 ]

        # skip lines that don't contain relevant entries
        if len(line) != 5 and not line[0].startswith('0x'):
            continue

        # extract function and relative timestamp
        # NOTE: could be the header
        try:
            function = line[3]
            rel_ts   = int(line[4])
        except:
            continue

        # new packet trace starts here
        if rel_ts == 0:
            # update cfg with previous trace
            update_cfg(fn_trace, ts_trace)

            # clear trace
            fn_trace = []
            ts_trace = []

        # push entry to trace
        fn_trace.append(function)
        ts_trace.append(rel_ts)

    # display collected data before exiting
    dump_cfg()

if __name__ == '__main__':
    main()

