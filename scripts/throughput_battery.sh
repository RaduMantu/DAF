#!/bin/bash

# try to determine maximum MTU upper limit
if [ -z "${MAX_MTU}" ]; then
    if [ ! -z "${IFACE}" ]; then
        MAX_MTU=$(ip -d link show ${IFACE} \
                | grep -o 'maxmtu [0-9]*'  \
                | awk '{print $2}')
    else
        printf 'Please specify MAX_MTU or IFACE\n'
        exit -1
    fi
fi


tcp_battery() {
    for ((round = 0; round < 5; round++)); do
        for ((mtu = 100; mtu <= ${MAX_MTU}; mtu += 10)); do
            MTU=${mtu} \
            ./scripts/measure_throughput.sh 2>&1 | tee -a logs/baseline_nofw-${round}.log

            FW_ENABLE=1 FW_RULES=0 \
            ./scripts/measure_throughput.sh 2>&1 | tee -a logs/baseline_fw-${round}.log

            FW_ENABLE=1 FW_RULES=1 \
            ./scripts/measure_throughput.sh 2>&1 | tee -a logs/rule-1_fw-${round}.log

            FW_ENABLE=1 FW_RULES=1 NO_RESCAN=1 \
            ./scripts/measure_throughput.sh 2>&1 | tee -a logs/rule-1_fwR-${round}.log

            FW_ENABLE=1 FW_RULES=1 NO_RESCAN=1 SKIP_NS_SW=1 \
            ./scripts/measure_throughput.sh 2>&1 | tee -a logs/rule-1_fwRS-${round}.log

            FW_ENABLE=1 FW_RULES=1 NO_RESCAN=1 SKIP_NS_SW=1 UNI_PRIO=1 \
            ./scripts/measure_throughput.sh 2>&1 | tee -a logs/rule-1_fwRSu-${round}.log

            FW_ENABLE=1 FW_RULES=1 NO_RESCAN=1 SKIP_NS_SW=1 UNI_PRIO=1 PART_CPY=1 \
            ./scripts/measure_throughput.sh 2>&1 | tee -a logs/rule-1_fwRSuP-${round}.log
        done
    done
}

udp_battery() {
    for ((round = 0; round < 5; round++)); do
        for ((mtu = 100; mtu <= ${MAX_MTU}; mtu += 10)); do
            MTU=${mtu} FW_ENABLE=1 FW_RULES=0 IPERF_UDP=5 \
            ./scripts/measure_throughput.sh 2>&1          \
            | tee -a logs/udp_baseline_fw-${round}.log

            FW_ENABLE=1 FW_RULES=0 UNI_PRIO=1 IPERF_UDP=5 \
            ./scripts/measure_throughput.sh 2>&1          \
            | tee -a logs/udp_baseline_fwu-${round}.log

            FW_ENABLE=1 FW_RULES=0 UNI_PRIO=1 PART_CPY=1 IPERF_UDP=5 \
            ./scripts/measure_throughput.sh 2>&1                     \
            | tee -a logs/udp_baseline_fwuP-${round}.log

            FW_ENABLE=1 FW_RULES=1 NO_RESCAN=1 SKIP_NS_SW=1 UNI_PRIO=1 PART_CPY=1 IPERF_UDP=5 \
            ./scripts/measure_throughput.sh 2>&1                                              \
            | tee -a logs/udp_rule-1_fwRSuPU-${round}.log
        done
    done
}

pktsig_battery() {
    for ((round = 0; round < 5; round++)); do
        for ((mtu = 120; mtu <= ${MAX_MTU}; mtu += 10)); do
            MTU=${mtu} FW_ENABLE=1 FW_RULES=1 NO_RESCAN=1 SKIP_NS_SW=1 IPERF_MSS=$((mtu - 116)) \
            ./scripts/measure_throughput.sh 2>&1                                                \
            | tee -a logs/rule-1_fwRSuU_pktsig_mss-${round}.log
        done
    done
}

# input arg sanity check
if [ $# -ne 1 ]; then
    echo 'Usage: ./throughput_battery.sh {tcp|udp|sign}'
    exit -1
fi

# choose battery of tests based on user specification
case $1 in
    tcp)
        tcp_battery
        ;;
    udp)
        udp_battery
        ;;
    sign)
        pktsig_battery
        ;;
    *)
        echo 'Usage: ./throughput_battery.sh {tcp|udp|sign}'
        exit -1
esac

