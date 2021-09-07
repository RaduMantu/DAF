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
 * Foobar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with app-fw. If not, see <https://www.gnu.org/licenses/>.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "ebpf_helpers.h"     /* userspace communication types */


/* tracer callback arguments; check definition in files such as:
 *  /sys/kernel/debug/tracing/events/syscalls/sys_.../format
 */
struct sys_exit_args {
    /* inaccesible by direct means; don't care */
    uint16_t common_type;
    uint8_t  common_flags;
    uint8_t  common_preempt_count;
    int32_t  common_pid;

    /* relevant info */
    int32_t  syscall_nr;
    int64_t  ret;
};

struct sys_enter_close_args {
    /* inaccesible by direct means; don't care */
    uint16_t common_type;
    uint8_t  common_flags;
    uint8_t  common_preempt_count;
    int32_t  common_pid;

    /* relevant info */
    int32_t  syscall_nr;
    uint64_t fd;
};

/* ringbuffer map */
struct bpf_map_def SEC("maps") buffer = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 4096 * sizeof(struct sample),
};


/* trace_exit_socket - attaches to socket syscall exit tracepoint
 * for <args> definition see the following file:
 *  /sys/kernel/debug/tracing/events/syscalls/sys_exit_socket/format
 */
SEC("tracepoint/syscalls/sys_exit_socket")
int trace_exit_socket(struct sys_exit_args *ctx)
{
    /* since we only trace the exit of this syscall, ignore all failed calls */
    if (ctx->ret == -1)
        return 0;

    /* reserve sample-sized chunk in ringbuffer */
    struct sample *s = bpf_ringbuf_reserve(&buffer, sizeof(struct sample), 0);
    if (!s)
        return 1;

    /* initialize sample data */
    s->ks       = bpf_get_current_pid_tgid();
    s->scn      = ctx->syscall_nr;
    s->is_enter = 0;
    s->ret      = ctx->ret;

    /* submit sample to userspace */
    bpf_ringbuf_submit(s, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct sys_enter_close_args *ctx)
{
    /* reserve sample-sized chunk in ringbuffer */
    struct sample *s = bpf_ringbuf_reserve(&buffer, sizeof(struct sample), 0);
    if (!s)
        return 1;

    /* initialize sample data */
    s->ks       = bpf_get_current_pid_tgid();
    s->scn      = ctx->syscall_nr;
    s->is_enter = 1;
    s->fd       = ctx->fd;

    /* submit sample to userspace */
    bpf_ringbuf_submit(s, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int trace_exit_close(struct sys_exit_args *ctx)
{
    /* reserve sample-sized chunk in ringbuffer */
    struct sample *s = bpf_ringbuf_reserve(&buffer, sizeof(struct sample), 0);
    if (!s)
        return 1;

    /* initialize sample data */
    s->ks       = bpf_get_current_pid_tgid();
    s->scn      = ctx->syscall_nr;
    s->is_enter = 0;
    s->ret      = ctx->ret;

    /* submit sample to userspace */
    bpf_ringbuf_submit(s, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
