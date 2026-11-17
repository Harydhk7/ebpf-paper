#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef struct policy_t {
	__u8 block_network;
	__u8 block_exec;
} policy_t;

typedef struct event_t {
	__u32 pid;
	__u32 violation_type;
	char comm[16];
} event_t;

const struct event_t *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct policy_t);
} policy_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int report_violation(__u32 pid, __u32 type)
{
	struct event_t *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		event->pid = pid;
		event->violation_type = type;
		bpf_get_current_comm(&event->comm, sizeof(event->comm));
		bpf_ringbuf_submit(event, 0);
	}
	bpf_send_signal(9);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct policy_t *policy = bpf_map_lookup_elem(&policy_map, &pid);

	if (policy && policy->block_network)
		return report_violation(pid, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct policy_t *policy = bpf_map_lookup_elem(&policy_map, &pid);

	if (policy && policy->block_exec)
		return report_violation(pid, 2);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
