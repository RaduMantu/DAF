#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* compilation:
 *  $ clang -D__KERNEL__ -D__BPF_TRACING__ -emit-llvm -O2 -c -o - \
 *    syscall_probe.c                                             \
 *    | llc -march=bpf -filetype=obj -o syscall_probe.o
 *
 * kernel sample used as example:
 *  https://github.com/torvalds/linux/blob/
 *  418baf2c28f3473039f2f7377760bd8f6897ae18/samples/bpf/syscall_tp_kern.c
 */

/* tracer callback arguments; check definition in this file:
 *  /sys/kernel/debug/tracing/events/syscalls/sys_exit_socket/format
 */
struct sys_exit_socket_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;

    int             syscall_nr;
    long            ret;
};


struct sample {
    int pid;    /* tgid in kernel               */
    int ret;    /* 32-bit, as seen in userspace */
};

struct ringbuf_map {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
}


BPF_PERF_OUTPUT(events);

/* trace_exit_socket - attaches to socket syscall exit tracepoint
 * for <args> definition see the following file:
 *  /sys/kernel/debug/tracing/events/syscalls/sys_exit_socket/format
 */
SEC("tracepoint/syscalls/sys_exit_socket")
int trace_exit_socket(struct sys_exit_socket_args *ctx)
{
    long tgid_pid = bpf_get_current_pid_tgid();

    


    return 0;
}


char _license[] SEC("license") = "GPL";
