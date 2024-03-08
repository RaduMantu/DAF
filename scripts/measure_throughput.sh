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
    echo '    WINDOW_SZ  : iperf window size              (default:no)'
    echo '    IPERF_MSS  : iperf MSS                      (default:no)'
    echo '    IPERF_UDP  : iperf UDP parallel streams     (default:no)'
    echo '                 setting this value enables UDP'
    echo '                 otherwise, client is TCP'
    echo ''
    echo '    FW_ENABLE  : enable firewall                  (default:no)'
    echo '    FW_PKT_SIG : HMAC secret file; enable signing (default:no)'
    echo '    FW_LOGFILE : firewall log file                (default:/dev/null)'
    echo '    FW_RULES   : number of rules to insert        (default:0)'
    echo '    NO_RESCAN  : prevent active va space rescan   (default:no)'
    echo '    SKIP_NS_SW : skip useless netns switches      (default:no)'
    echo '    PART_CPY   : partial packet copy to u/s       (default:no)'
    echo '    BATCH_SZ   : maximum verdict batch size       (default:1)'
    echo '    BATCH_TO   : verdict transmission timeout     (default:3.6E9)'
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
FW_LOGFILE=${FW_LOGFILE:-/dev/null}
FW_RULES=${FW_RULES:-0}

# change "set" variables to actually sound parameters
if [ ! -z "${NO_RESCAN}" ]; then
    NO_RESCAN='-R'
fi

if [ ! -z "${SKIP_NS_SW}" ]; then
    SKIP_NS_SW='-S'
fi

if [ ! -z "${PART_CPY}" ]; then
    PART_CPY='-P'
fi

if [ ! -z "${BATCH_SZ}" ]; then
    BATCH_SZ="-b ${BATCH_SZ}"
fi

if [ ! -z "${BATCH_TO}" ]; then
    BATCH_TO="-B ${BATCH_TO}"
fi

# window size is optional!
if [[ ! -z "${WINDOW_SZ}" ]]; then
    WINDOW_SZ="-w ${WINDOW_SZ}"
fi

# ensure provided MSS is within iperf3 limits
if [[ ! -z "${IPERF_MSS}" && \
      ${IPERF_MSS} -ge 88 && \
      ${IPERF_MSS} -le 9216 ]]; then
    printf '>>> MSS = %u\n' ${IPERF_MSS}

    IPERF_MSS="-M ${IPERF_MSS}"
fi

# enable UDP client instead of TCP
if [[ ! -z "${IPERF_UDP}" && \
      ${IPERF_UDP} -gt 0 ]]; then
    IPERF_UDP="-u -b 0 -P ${IPERF_UDP}"
fi

# enable firewall packet signing
if [[ ! -z "${FW_PKT_SIG}" ]]; then
    FW_PKT_SIG="-t packet -s ${FW_PKT_SIG}"
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

# sync cached filesystem writes
# might be relevant for NFS; don't want writebacks during experiment
sync

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
    taskset -c 0-1                             \
    ./bin/app-fw                               \
        ${NO_RESCAN} ${SKIP_NS_SW} ${PART_CPY} \
        ${BATCH_SZ} ${BATCH_TO}                \
        -e bin/syscall_probe.o ${FW_PKT_SIG}   \
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

# start iperf3 client
# NOTE: may fail due to late routing table initialization after setting MTU
STATUS=1
ATTEMPTS=0
while [[ ${STATUS} -ne 0 ]]; do
    iperf3 -c ${IPERF_IP}%${IFACE} ${IPERF_PORT} \
           -t ${DURATION}                        \
           -i ${LOG_INTV}                        \
           -f k                                  \
           ${WINDOW_SZ}                          \
           ${IPERF_UDP}                          \
           ${IPERF_MSS}
    STATUS=$?

    # sleep some more if need be
    if [[ ${STATUS} -ne 0 ]]; then
        sleep 1
    fi

    # break out if 3 attempts have already been tried
    # NOTE: iperf3 might behave oddly when it comes to error codes sometimes
    ((ATTEMPTS++))
    if [[ ${ATTEMPTS} -eq 3 ]]; then
        printf '>>> iperf3 failed to start %d times\n' "${ATTEMPTS}"
        break
    fi
done

# print run delineator
printf '~%.0s' {1..80}
printf '\n'

