// SPDX-License-Identifier: GPL-2.0+
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include "net_bpf.h"

// Map to store connection details
BPF_HASH(connections, struct sock *, net_event_t);

// Ring buffer to send events to user space
BPF_RINGBUF_OUTPUT(net_events, 8 * 4096);

// Kprobe on tcp_v4_connect to trace new connections
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr) {
    if (uaddr->sa_family != AF_INET) {
        return 0;
    }

    net_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, TASK_COMM_LEN);

    struct sockaddr_in *addr_in = (struct sockaddr_in *)uaddr;
    event.daddr = addr_in->sin_addr.s_addr;
    event.dport = addr_in->sin_port;
    event.dport = bpf_ntohs(event.dport);

    connections.update(&sk, &event);

    return 0;
}

// Kprobe on tcp_sendmsg to trace data sending
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    net_event_t *event = connections.lookup(&sk);
    if (!event) {
        return 0; // Not a connection we are tracking
    }

    event->tx_bytes = size;

    net_event_t *submit_event = net_events.ringbuf_reserve(sizeof(net_event_t));
    if (!submit_event) {
        return 1;
    }

    bpf_probe_read_kernel(submit_event, sizeof(net_event_t), event);
    net_events.ringbuf_submit(submit_event, 0);

    return 0;
}

// Kprobe on tcp_close to clean up the map
int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk) {
    connections.delete(&sk);
    return 0;
}