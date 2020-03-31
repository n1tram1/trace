#!/usr/bin/python

from bcc import BPF

import sys
import ctypes as ct

USERNAME_MAX = 30

class Session(ct.Structure):
    _fields_ = [
        ("username", ct.c_char * USERNAME_MAX),
        ("recv_bytes", ct.c_ulonglong),
        ("sent_bytes", ct.c_ulonglong),
        ("start", ct.c_ulonglong),
        ("end", ct.c_ulonglong),
        ("ssh", ct.c_void_p),
    ]


bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/compiler.h>

#include "sshd.h"

#define USERNAME_MAX 30

struct session {
    char username[USERNAME_MAX];
    size_t recv_bytes;
    u64 sent_bytes;
    u64 start;
    u64 end;
    struct ssh *ssh;
};

/**
 * The @sessions hashmap is used to store the struct session associated with
 * each thread running an ssh session.
 */
BPF_HASH(sessions, pid_t, struct session);

BPF_PERF_OUTPUT(session_events);

/**
 * Each sessions is handled by a single thread.
 * do_authenticated is called to start the ssh session
 * (which implies the user has successfully authed).
 *
 * At this probe, we store the new struct session into the @sessions hashmap.
 */
int trace_do_authenticated(struct pt_regs *ctx, struct ssh *ssh,
                           struct Authctxt *authctxt)
{
    pid_t pid = bpf_get_current_pid_tgid();
    struct session sess = {};

    bpf_probe_read_str(&sess.username, sizeof(sess.username),
                       authctxt->pw->pw_name);
    sess.recv_bytes = 0;
    sess.sent_bytes = 0;
    sess.start = bpf_ktime_get_ns();
    sess.end = 0;
    sess.ssh = ssh;

    sessions.insert(&pid, &sess);

    return 0;
}

/**
 * At this probe, the ssh session has ended so we gather our data and send it
 * back into the event buffer.
 * The session must be removed @sessions hashmap because the thread might get
 * reused for another session.
 */
int trace_do_cleanup(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid();

    struct session *sess  = sessions.lookup(&pid);
    if (!sess)
        return 1;

    sess->end = bpf_ktime_get_ns();
    session_events.perf_submit(ctx, sess, sizeof(*sess));

    sessions.delete(&pid);

    return 0;
}

/**
 * Checks whether @param[fd] is a socket of the @param[ssh] session.
 */
static int is_sshd_socket(u64 fd, struct ssh *ssh) {
    char comm[TASK_COMM_LEN] = "";
    u64 ssh_in_fd = ssh->state->connection_in;
    u64 ssh_out_fd = ssh->state->connection_out;

    bpf_get_current_comm(&comm, sizeof(comm));
    if (!(comm[0] == 's'
        && comm[1] == 's'
        && comm[2] == 'h'
        && comm[3] == 'd'
        && comm[4] == '\\0'))
        return 0;

    return fd == ssh_in_fd | fd == ssh_out_fd;
}

/**
 * Check each call to sys_read to count how much data is received
 * by each session.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    pid_t pid = bpf_get_current_pid_tgid();
    struct session *sess;

    sess = sessions.lookup(&pid);
    if (!sess)
        return 1;

    if (!is_sshd_socket(args->fd, sess->ssh))
        return 1;

    sess->recv_bytes += args->count;

    return 0;
}

/**
 * Check each call to sys_write to count how much data is sent by each session.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    pid_t pid = bpf_get_current_pid_tgid();
    struct session *sess;
    sess = sessions.lookup(&pid);
    if (!sess)
        return 1;

    if (!is_sshd_socket(args->fd, sess->ssh))
        return 1;

    sess->sent_bytes += args->count;

    return 0;
}

"""

def session_cb(cpu, data, size):
    assert size >= ct.sizeof(Session)
    sess = ct.cast(data, ct.POINTER(Session)).contents
    username = sess.username.decode("utf-8")
    time = (sess.end - sess.start) // 1000000
    recv = sess.recv_bytes
    sent = sess.sent_bytes

    print("| {:^20} | {:>10} | {:>10} | {:>20} |".format(username, recv, sent, time))

def main():
    bpf = BPF(text = bpf_source)
    bpf.attach_uprobe(name="/usr/bin/sshd", sym="do_authenticated", fn_name="trace_do_authenticated")
    bpf.attach_uprobe(name="/usr/bin/sshd", sym="do_cleanup", fn_name="trace_do_cleanup")
    bpf["session_events"].open_perf_buffer(session_cb);

    print("/-{:^20}---{:^10}---{:^10}---{:^20}-\\".format("-" * 20, "-" * 10, "-" * 10, "-" * 20))
    print("| {:^20} | {:^10} | {:^10} | {:^20} |".format("USERNAME", "RECV (B)", "SENT (B)", "TIME (ms)"))

    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("{:^20}---{:^10}---{:^10}---{:^20}-/".format("-" * 20, "-" * 10, "-" * 10, "-" * 20))
            sys.exit()

if __name__ == "__main__":
    main()
