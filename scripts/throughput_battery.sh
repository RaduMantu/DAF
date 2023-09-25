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

buffer_var() {
    for ((max_sz = 8; max_sz <= 32; max_sz++)); do
        max_sz_bytes=$((max_sz * 1024 * 1024))

        {
            # set network core upper limits
            # NOTE: defaults can be overwritten by tcp settings; these can't
            sysctl -w net.core.wmem_max=${max_sz_bytes}
            sysctl -w net.core.rmem_max=${max_sz_bytes}

            # set default & max tcp buffer sizes to current upper limit
            # NOTE: leave minimum buffer size unchanged (4K), just in case
            sysctl -w net.ipv4.tcp_wmem="4096 ${max_sz_bytes} ${max_sz_bytes}"
            sysctl -w net.ipv4.tcp_rmem="4096 ${max_sz_bytes} ${max_sz_bytes}"
        } | tee -a logs/buffy_rule-1_fwRSuPU-${max_sz_bytes}.log

        for ((mtu = 1000; mtu <= 9000; mtu += 1000)); do
            MTU=${mtu} FW_ENABLE=1 FW_RULES=1 NO_RESCAN=1 SKIP_NS_SW=1 UNI_PRIO=1 PART_CPY=1 \
            ./scripts/measure_throughput.sh 2>&1 | tee -a logs/buffy_rule-1_fwRSuPU-${max_sz_bytes}.log
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
    buffy)
        buffer_var
        ;;
    *)
        echo 'Usage: ./throughput_battery.sh {tcp|udp|sign|buffy}'
        exit -1
esac

