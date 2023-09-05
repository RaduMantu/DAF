#!/bin/bash

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

