#!/usr/bin/python

from bcc import BPF

import sys

import ctypes as ct

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define USERNAME_MAX 64

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
 *
 * For some reason, the authkeys prog is executed twice.
 */

struct connection_thread {
    char username[USERNAME_MAX];

    pid_t pid;
    pid_t subprocess_thread;

    u64 subprocess_start_time;
    u64 subprocess_end_time;

    bool subprocess_execved;

    bool auth_success;
};

BPF_HASH(threads, pid_t, struct connection_thread);

struct authentication {
    char username[USERNAME_MAX];
    int success;
};

BPF_PERF_OUTPUT(authentication_events);

struct authorizedkeys_command {
    char username[USERNAME_MAX];
    u64 start;
    u64 end;
};

BPF_PERF_OUTPUT(authorizedkeys_command_events);

static pid_t get_parent_pid_tgid(void)
{
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    if (!cur)
        return 0;


    parent = cur->parent;
    if (!parent)
        return 0;

    return ((u64)parent->tgid) << 32 | parent->pid;
}

static int is_comm_sshd(void)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    return strncmp(comm, "sshd", 4) == 0;
}

static int is_parent_comm_sshd(void)
{
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    char parent_comm[TASK_COMM_LEN];

    if (!cur)
        return 0;

    parent = cur->parent;
    if (!parent)
        return 0;

    bpf_probe_read_str(&parent_comm, sizeof(parent_comm), &parent->comm);

    return strncmp(parent_comm, "sshd", 4) == 0;
}

static u32 _get_pid()
{
    return bpf_get_current_pid_tgid() & 0xFFFFFFFF;
}

static u64 get_random_id(void)
{
    return ((u64)bpf_get_prandom_u32() << 32) | _get_pid();
}

/**
 * Detect the first clone, for the authkeys prog subprocess.
 *
 * Probe is hit when the connection thread uses clone (fork actually)
 * to launch a subprocess (the AuthorizedKeysCommand).
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

    cur.username[0] = '\\0';
    cur.pid = pid_tgid;
    cur.subprocess_thread = child_pid;
    cur.subprocess_start_time = bpf_ktime_get_ns();
    cur.subprocess_execved = false;
    cur.auth_success = true;

    threads.update(&pid_tgid, &cur);

    return 0;
}

static bool is_authkey_program()
{
    char authkey_program[] = "__AUTHKEYSCOMMAND__";
    char comm[sizeof(authkey_program)] = "";

    bpf_get_current_comm(&comm, sizeof(comm));

    /* Do the string comparison here to make the BPF checker happy. */
    for (size_t i = 0; i < sizeof(comm); i++) {
        if (comm[i] != authkey_program[i])
            return false;
    }

    return true;
}

/**
 * Catch the subprocess just before it uses execve, to get its argv.
 * In the argv there can be the username with which the AuthorizedKeysCommand
 * is called.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    pid_t parent_pid_tgid = get_parent_pid_tgid();
    struct connection_thread *parent;
    char *argv[10];

    if ((parent = threads.lookup(&parent_pid_tgid)) == NULL)
        return 1;

    if (!is_parent_comm_sshd()) {
        bpf_trace_printk("not parent sshd\\n");
        return 1;
    }

    /* TODO: properly get argv */
    bpf_probe_read(&argv, sizeof(argv), args->argv);

    bpf_probe_read(&parent->username, sizeof(parent->username), argv[1]);

    bpf_trace_printk("execve(file, %s\\n", parent->username);

    return 0;
}

/**
 * Catch when the execve syscall finishes for the subprocess.
 * We must check the new comm of the subprocess.
 * Be careful, sshd can call execve for other things.
 *
 * Catch when the subprocess has called exceve.
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

static void copy_username(char *dst, const char *src)
{
    for (size_t i = 0; i < USERNAME_MAX; i++) {
        dst[i] = src[i];
    }
}

/**
 * Catch when the parent waits for its subprocess.
 * Check that the subprocess has execved to make sure
 * it is our child which has executed the AuthorizedKeysCommand.
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
        cur->subprocess_end_time = bpf_ktime_get_ns();

        struct authorizedkeys_command cmd = {
            .username = "",
            .start = cur->subprocess_start_time,
            .end = cur->subprocess_end_time,
        };
        copy_username(cmd.username, cur->username);

        authorizedkeys_command_events.perf_submit(args, &cmd, sizeof(cmd));

        //bpf_trace_printk("authkeycommand ran in %lu ms (execved %d)\\n",
        //               (cur->subprocess_end - cur->subprocess_start) / 1000000, cur->subprocess_execved);
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

    if (cur->subprocess_execved && args->error_code == 255) {
        cur->auth_success = false;
        //bpf_trace_printk("authkeycommand failed to auth\\n");

        struct authentication auth = {
            .success = false,
        };
        copy_username(auth.username, cur->username);

        authentication_events.perf_submit(args, &auth, sizeof(auth));

        threads.delete(&pid_tgid);
    }
    return 0;
}

/**
 * Before starting the auth sshd had set an alarm.
 * It disables that alarm once auth is successful.
 * Therefore if we catch an alarm(0), then the auth succeeded.
 * (We also check that the authkeys prog has ran)
 *
 * Catch when auth finishes successfully.
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
        cur->auth_success = true;

        struct authentication auth = {
            .success = true,
        };
        copy_username(auth.username, cur->username);

        authentication_events.perf_submit(args, &auth, sizeof(auth));

        threads.delete(&pid_tgid);
    }

    return 0;
}
""".replace("__AUTHKEYSCOMMAND__", "ssh-auth.sh")

USERNAME_MAX = 64

class Authentication(ct.Structure):
    _fields_ = [
        ("username", ct.c_char * USERNAME_MAX),
        ("success", ct.c_int),
    ]

class AuthorizedKeysCommand(ct.Structure):
    _fields_ = [
        ("username", ct.c_char * USERNAME_MAX),
        ("start", ct.c_ulonglong),
        ("end", ct.c_ulonglong),
    ]

def authentication_cb(cpu, data, size):
    assert size >= ct.sizeof(Authentication)
    auth = ct.cast(data, ct.POINTER(Authentication)).contents

    print("[auth finished] username: {} success: {}".format(auth.username, auth.success))

def authorizedkeys_command_cb(cpu, data, size):
    assert size >= ct.sizeof(AuthorizedKeysCommand)
    cmd = ct.cast(data, ct.POINTER(AuthorizedKeysCommand)).contents

    print("[AuthorizedKeysCommand ran] username: {} duration: {} ms".format(cmd.username, (cmd.end - cmd.start) / 1000000))


def main():
    bpf = BPF(text=bpf_source)
    bpf["authentication_events"].open_perf_buffer(authentication_cb)
    bpf["authorizedkeys_command_events"].open_perf_buffer(authorizedkeys_command_cb)

    print("Tracing...")

    while True:
        try:
            bpf.perf_buffer_poll()
            # bpf.trace_print()
        except KeyboardInterrupt:
            sys.exit();

    return 0

if __name__ == "__main__":
    main()
