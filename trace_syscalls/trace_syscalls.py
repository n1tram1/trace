#!/usr/bin/python

from bcc import BPF

import sys

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/*
 * Diagram below shows the flow of the specific sshd thread being traced.
 *
 *                             execve   execute authkeys prog
 *                                !        comm != "sshd"
 *                                !      (subprocess thread)       if auth fails
 *                            +---!----------------------------X  +-------------->exit_group(255)
 * recv connection            |                                |  |
 *  comm == "sshd"            |                                |  |
 * (connection thread)   clone|                           wait4|  |
 *        |                   |                                |  |
 *        +-------------------+--------------------------------+--+------------>start ssh session in same thread
 *                                                                    alarm(0)
 */

struct connection_thread {
    pid_t pid;
    pid_t subprocess_thread;

    u64 subprocess_start;
    u64 subprocess_end;

    bool subprocess_execved;

    bool success;
};

BPF_HASH(threads, pid_t, struct connection_thread);

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

/**
 * Detect the first clone, for the authkeys prog subprocess.
 */
TRACEPOINT_PROBE(syscalls, sys_exit_clone)
{
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    pid_t child_pid = args->ret;
    struct connection_thread cur = {};

    if (!is_comm_sshd())
        return 1;

    /* Check we are in the parent */
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
    char authkey_program[] = "__AUTHKEYSCOMMAND__";
    char comm[sizeof(authkey_program)];

    bpf_get_current_comm(&comm, sizeof(comm));

    for (size_t i = 0; i < sizeof(comm); i++) {
        if (comm[i] != authkey_program[i])
            return false;
    }

    return true;
}

/**
 * Catch when the execve syscall finishes for the subprocess.
 * We must the new comm of the program because sshd
 * uses execve for other things. 
 */
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    pid_t parent_pid_tgid = get_parent_pid_tgid();
    struct connection_thread *parent;

    if ((parent = threads.lookup(&parent_pid_tgid)) == NULL)
        return 1;

    if (!is_authkey_program())
        return 1;

    parent->subprocess_execved = true;

    return 0;
}

/**
 * Catch when the parent waits for its subprocess.
 * Check that the subprocess has execved to make sure
 * it is our child which has executed the authkeys prog.
 */
TRACEPOINT_PROBE(syscalls, sys_exit_wait4)
{
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    pid_t waited_pid = args->ret;
    struct connection_thread *cur;

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

/**
 * Catch all exit_group calls because we know that sshd will kill its thread
 * with an exit(255) if a failure occurs.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_exit_group)
{
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    struct connection_thread *cur;

    if (!is_comm_sshd())
        return 1;

    if ((cur = threads.lookup(&pid_tgid)) == NULL)
        return 1;

    if (args->error_code == 255) {
    if (cur->subprocess_execved && args->error_code == 255) {
        cur->success = false;
        bpf_trace_printk("authkeycommand failed to auth\\n");

        threads.delete(&pid_tgid);
    }
    return 0;
}

/**
 * Before starting the auth sshd had set an alarm.
 * It disables that alarm once auth is successful.
 * Therefore if we catch an alarm(0), then the auth succeeded.
 * (We also check that the authkeys prog has ran)
 */
TRACEPOINT_PROBE(syscalls, sys_enter_alarm)
{
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    struct connection_thread *cur;

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
""".replace("__AUTHKEYSCOMMAND__", "ssh-auth.sh")

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
