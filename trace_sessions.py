#!/usr/bin/python

from bcc import BPF

import argparse
import sys
import json
import ctypes as ct

import bpf_event_logger

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

#include "sshd.h"

#define USERNAME_MAX 30

struct passwd {
   char   *pw_name;       /* username */
   char   *pw_passwd;     /* user password */
   uid_t   pw_uid;        /* user ID */
   gid_t   pw_gid;        /* group ID */
   char   *pw_gecos;      /* user information */
   char   *pw_dir;        /* home directory */
   char   *pw_shell;      /* shell program */
};

struct session {
    char username[USERNAME_MAX];
    size_t recv_bytes;
    u64 sent_bytes;
    u64 start;
    u64 end;
    struct ssh *ssh;
};
BPF_HASH(sessions, pid_t, struct session);

BPF_PERF_OUTPUT(session_events);

int trace_do_authenticated(struct pt_regs *ctx, struct ssh *ssh, struct Authctxt *authctxt)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct session sess = {};

    bpf_probe_read_str(&sess.username, sizeof(sess.username), authctxt->pw->pw_name);
    sess.recv_bytes = 0;
    sess.sent_bytes = 0;
    sess.start = bpf_ktime_get_ns();
    sess.end = 0;
    sess.ssh = ssh;

    sessions.insert(&pid, &sess);

    return 0;
}

int trace_do_cleanup(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct session *sess  = sessions.lookup(&pid);
    if (!sess)
        return 1;

    sess->end = bpf_ktime_get_ns();
    session_events.perf_submit(ctx, sess, sizeof(*sess));

    return 0;
}

struct sys_read_args {
    // from /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
    u64 __unused__;
    s32 __syscall_nr;
    u64 fd;
    unsigned char *buf;
    u64 count;
};

static int is_sshd_socket(u64 fd, struct ssh *ssh) {
    char comm[TASK_COMM_LEN] = "";
    u64 ssh_in_fd = ssh->state->connection_in;
    u64 ssh_out_fd = ssh->state->connection_out;

    bpf_get_current_comm(&comm, sizeof(comm));
    if (!(comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd' && comm[4] == '\\0'))
        return 0;

    return fd == ssh_in_fd | fd == ssh_out_fd;
}

int trace_sys_enter_read(struct sys_read_args *args)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct session *sess;

    sess = sessions.lookup(&pid);
    if (!sess)
        return 1;

    if (!is_sshd_socket(args->fd, sess->ssh))
        return 1;

    sess->recv_bytes += args->count;

    return 0;
}

int trace_sys_enter_write(struct sys_read_args *args)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32; struct session *sess;
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
    bpf.attach_tracepoint(tp="syscalls:sys_enter_read", fn_name="trace_sys_enter_read")
    bpf.attach_tracepoint(tp="syscalls:sys_enter_write", fn_name="trace_sys_enter_write")
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
