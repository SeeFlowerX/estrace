#include "common.h"

struct soinfo_data_t {
    u32 pid;
    u32 tid;
    char comm[16];
    char buffer[1024];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} soinfo_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct soinfo_data_t);
    __uint(max_entries, 1);
} soinfo_data_buffer_heap SEC(".maps");

// soinfo过滤配置
struct soinfo_filter_t {
    u32 uid;
    u32 pid;
    u32 is_32bit;
    u32 read_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct soinfo_filter_t);
    __uint(max_entries, 1);
} soinfo_filter_map SEC(".maps");

SEC("uprobe/soinfo")
int probe_soinfo(struct pt_regs* ctx) {
    u32 filter_key = 0;
    struct soinfo_filter_t* filter = bpf_map_lookup_elem(&soinfo_filter_map, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid >> 32;
    if (filter->uid != 0 && filter->uid != uid) {
        return 0;
    }

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u32 tid = current_pid_tgid & 0xffffffff;
    if (filter->pid != 0 && filter->pid != pid) {
        return 0;
    }

    u32 zero = 0;
    struct soinfo_data_t* event = bpf_map_lookup_elem(&soinfo_data_buffer_heap, &zero);
    if (event == NULL) {
        return 0;
    }

    // 直接 bpf_probe_read_user 读取soinfo数据 解析工作交给前端

    event->pid = pid;
    event->tid = tid;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    long status = bpf_perf_event_output(ctx, &soinfo_events, BPF_F_CURRENT_CPU, event, sizeof(struct soinfo_data_t));

    return 0;
}