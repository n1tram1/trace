#!/usr/bin/python

from bcc import BPF

import sys

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct auth_thread {
    pid_t pid;
    pid_t subprocess_thread;

    u64 subprocess_start;
    u64 subprocess_end;

    bool subprocess_execved;

    bool success;
};

BPF_HASH(threads, pid_t, struct auth_thread);

static pid_t get_parent_pid_tgid(void)
{
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    if (!cur)
        return 0;


    parent = cur->parent;
    if (!parent)
        return 0;

    return ((u64)cur->tgid) << 32 | parent->pid;
}

static int is_comm_sshd(void)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    return strncmp(comm, "sshd", 4) == 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone)
{
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    pid_t child_pid = args->ret;
    struct auth_thread cur = {};

    if (!is_comm_sshd())
        return 1;

    /* Make sure we are in the parent */
    if (child_pid == 0)
        return 1;

    cur.pid = pid_tgid;
    cur.subprocess_thread = child_pid;
    cur.subprocess_start = bpf_ktime_get_ns();
    cur.subprocess_end = 0;
    cur.subprocess_execved = false;
    cur.success = true;

    threads.update(&pid_tgid, &cur);

    return 0;
}

static bool is_authkey_program()
{
    char authkey_program[] = "ssh-auth.sh";
    char comm[sizeof(authkey_program)];

    bpf_get_current_comm(&comm, sizeof(comm));

    for (size_t i = 0; i < sizeof(comm); i++) {
        if (comm[i] != authkey_program[i])
            return false;
    }

    return true;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    pid_t parent_pid_tgid = get_parent_pid_tgid();
    struct auth_thread *parent;

    if ((parent = threads.lookup(&parent_pid_tgid)) == NULL)
        return 1;

    if (!is_authkey_program())
        return 1;

    parent->subprocess_execved = true;

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_wait4)
{
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    pid_t waited_pid = args->ret;
    struct auth_thread *cur;

    if (!is_comm_sshd())
        return 1;

    if ((cur = threads.lookup(&pid_tgid)) == NULL)
        return 1;

    /* TODO: we should check the [int *options]
     * to make sure the subprocess is dead.
     */
    if (cur->subprocess_execved && waited_pid == cur->subprocess_thread) {
        cur->subprocess_end = bpf_ktime_get_ns();

        bpf_trace_printk("authkeycommand ran in %lu ms (execved %d)\\n",
                         (cur->subprocess_end - cur->subprocess_start) / 1000000, cur->subprocess_execved);
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_exit_group)
{
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    struct auth_thread *cur;

    if (!is_comm_sshd())
        return 1;

    if ((cur = threads.lookup(&pid_tgid)) == NULL)
        return 1;

    if (args->error_code == 255) {
        cur->success = false;
        bpf_trace_printk("authkeycommand failed to auth\\n");

        threads.delete(&pid_tgid);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_alarm)
{
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    struct auth_thread *cur;

    if (!is_comm_sshd())
        return 1;

    if ((cur = threads.lookup(&pid_tgid)) == NULL)
        return 1;

    if (cur->subprocess_execved && args->seconds == 0) {
        cur->success = true;
        bpf_trace_printk("authkeycommand success to auth\\n");

        threads.delete(&pid_tgid);
    }

    return 0;
}
"""

def main():
    bpf = BPF(text=bpf_source)

    print("Tracing...")

    while True:
        try:
            bpf.trace_print()
        except KeyboardInterrupt:
            sys.exit();

    return 0

if __name__ == "__main__":
    main()
