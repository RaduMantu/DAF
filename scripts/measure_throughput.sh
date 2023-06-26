#!/bin/bash

# measure_throughput.sh - measure transport level throughput
#
# This does not include any headers. Only application data.

# usage - presented if sanity check fails
usage() {
    echo 'throughput_time.sh - measure throughput as a function of time'
    echo '    IFACE      : target interface               (required)'
    echo '    MTU        : MTU to be set on IFACE         (optional)'
    echo '    REST_TIME  : sleep time after setting MTU   (default:3)'
    echo ''
    echo '    IPERF_IP   : iperf server IP address        (required)'
    echo '    IPERF_PORT : iperf server port              (default:5201)'
    echo '    DURATION   : iperf run duration             (default:10'
    echo '    LOG_INTV   : iperf logging interval         (default:1)'
    echo '    WINDOW_SZ  : iperf window size              (default:128K)'
    echo ''
    echo '    FW_ENABLE  : enable firewall                (default:no)'
    echo '    FW_LOGFILE : firewall log file              (default:/dev/null)'
    echo '    FW_RULES   : number of rules to insert      (default:0)'
    echo '    NO_RESCAN  : prevent active va space rescan (default:no)'
    echo '    UNI_PRIO   : set uniform event priority     (default:no)'
    echo '    SKIP_NS_SW : skip useless netns switches    (default:no)'
    echo ''
    echo 'For each type of experiment, collect data by appending script output'
    echo 'to the same log file. From there on, process the log file however'
    echo 'you want.'
    echo ''
    echo 'Tip: check the maximum supported MTU for an interface before you'
    echo 'decide what MTU ranges to test for:'
    echo '    $ ip -c -d link list | grep maxmtu -B1'
    echo ''
    echo 'Tip: script needs to sleep for a bit after setting MTU, otherwise'
    echo 'iperf3 might not be able to connect to the server (no route to host)'
}

# cleanup - routine to be executed on EXIT signal trap
cleanup() {
    kill -s SIGKILL $(pidof app-fw) &>/dev/null
    rm -f /tmp/app_fw.socket
}

# default evnironment variable values
REST_TIME=${REST_TIME:-3}
IPERF_PORT=${IPERF_PORT:-5201}
DURATION=${DURATION:-10}
LOG_INTV=${LOG_INTV:-1}
WINDOW_SZ=${WINDOW_SZ:-128K}
FW_LOGFILE=${FW_LOGFILE:-/dev/null}
FW_RULES=${FW_RULES:-0}

# change "set" variables to actually sound parameters
if [ ! -z "${NO_RESCAN}" ]; then
    NO_RESCAN='-R'
fi

if [ ! -z "${UNI_PRIO}" ]; then
    UNI_PRIO='-u'
fi

if [ ! -z "${SKIP_NS_SW}" ]; then
    SKIP_NS_SW='-S'
fi

# sanity check
if [ -z "${IFACE}" ]; then
    printf 'Please specify the target interface\n\n'
    usage
    exit -1
fi

if [ -z "${IPERF_IP}" ]; then
    printf 'Please specify iperf server IP address\n\n'
    usage
    exit -1
fi

# set MTU on the target interface & wait for changes to take effect
# NOTE: not bothering to reset it to initial value after the experiment
if [ ! -z "${MTU}" ]; then
    ip link set ${IFACE} mtu ${MTU}
    printf '>>> MTU = %u\n' ${MTU}
    sleep ${REST_TIME}
fi

# set up firewall if requested by user
# NOTE: assumes that iptables rules have been configured already
if [ ! -z "${FW_ENABLE}" ]; then
    # register cleanup routine
    # NOTE: no sense doing this unless we activate the firewall
    trap cleanup EXIT

    # start firewall in background
    # NOTE: assuming that you're running this as root (EUID=0)
    ./bin/app-fw ${NO_RESCAN} ${UNI_PRIO} ${SKIP_NS_SW} -e bin/syscall_probe.o \
        &>>${FW_LOGFILE} &

    # append harcoded rules to firewall
    # NOTE: these rules must 1) specify object hashes to force a check (since
    #       this is pretty much the phenomenon we want to observe) and 2) ensure
    #       that all packets are evaluated against all existing rules)
    # NOTE: there is no problem in having the same rule N times; we don't have
    #       any rule minimization implemented in the firewall
    for ((i = 0; i < ${FW_RULES}; i++)); do
        ./bin/ctl-fw -A                             `# append rule          ` \
                     -c OUTPUT                      `# target chain         ` \
                     -v DROP                        `# verdict on match     ` \
                     -n /proc/$$/ns/net             `# process net namespace` \
                     --sng-hash $(sha256sum /usr/bin/curl | awk '{print $1}') \
                     &>>${FW_LOGFILE}
    done
    printf '>>> RULES = %u\n' ${FW_RULES}
fi

# start iperf client
iperf3 -c ${IPERF_IP} ${IPERF_PORT} \
       -t ${DURATION}               \
       -i ${LOG_INTV}               \
       -w ${WINDOW_SZ}

# print run delineator
printf '~%.0s' {1..80}
printf '\n'

