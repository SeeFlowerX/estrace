#ifndef ESTRACE_COMMON_H
#define ESTRACE_COMMON_H

#include <linux/bpf.h>
#include <bpf_helpers.h>

#define TASK_COMM_LEN 16

typedef signed char __s8;

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

struct sys_enter_args
{
    unsigned long long ignore;
    long id;
    unsigned long args[6];
};

struct sys_exit_args
{
    unsigned long long ignore;
    long id;
    long ret;
};

struct pt_regs {
    struct {
        u64 regs[31];
        u64 sp;
        u64 pc;
        u64 pstate;
    };
    u64 orig_x0;
    s32 syscallno;
    u32 unused2;
    u64 orig_addr_limit;
    u64 pmr_save;
    u64 stackframe[2];
    u64 lockdep_hardirqs;
    u64 exit_rcu;
};

char __license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

#endif