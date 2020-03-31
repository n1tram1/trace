#!/usr/bin/python

from bcc import BPF

import sys
import ctypes as ct

USERNAME_MAX = 30

class Authentication(ct.Structure):
    _fields_ = [
        ("username", ct.c_char * USERNAME_MAX),
        ("start", ct.c_ulonglong),
        ("end", ct.c_ulonglong),
        ("successful", ct.c_ulonglong),
    ]

bpf_source = """
#include <uapi/linux/ptrace.h>

#include "sshd.h"

#define USERNAME_MAX 30

struct authentication {
    char username[USERNAME_MAX];
    u64 start;
    u64 end;
    u64 successful;
};

/**
 * The @auths hashmap is used to store the struct auth associated to
 * a pubkey auth.
 */
BPF_HASH(auths, pid_t, struct authentication);

BPF_PERF_OUTPUT(auth_events);

int trace_user_key_allowed(struct pt_regs *ctx, struct ssh *ssh,
                           struct passwd * user_pwd) {
    pid_t pid = bpf_get_current_pid_tgid();
    struct authentication auth = {};

    bpf_probe_read_str(&auth.username, sizeof(auth.username),
                       user_pwd->pw_name),
    auth.start = bpf_ktime_get_ns();
    auth.end = 0;
    auth.successful = 0;

    auths.insert(&pid, &auth);

    return 0;
}

int trace_ret_user_key_allowed(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid();

    struct authentication *auth = auths.lookup(&pid);
    if (!auth)
        return 1;

    auth->end = bpf_ktime_get_ns();
    auth->successful = PT_REGS_RC(ctx);
    auth_events.perf_submit(ctx, auth, sizeof(*auth));

    auths.delete(&pid);

    return 0;
}
"""

def auth_cb(cpu, data, size):
    assert size >= ct.sizeof(Authentication)
    auth = ct.cast(data, ct.POINTER(Authentication)).contents
    success = bool(auth.successful)
    time = (auth.end - auth.start) // 1000000
    username = auth.username.decode("utf-8")

    print("| {:^20} | {:^10} | {:^12} |".format(username, success, time))

def main():
    bpf = BPF(text = bpf_source)
    bpf.attach_uprobe(name="/usr/bin/sshd", sym="user_key_allowed", fn_name="trace_user_key_allowed")
    bpf.attach_uretprobe(name="/usr/bin/sshd", sym="user_key_allowed", fn_name="trace_ret_user_key_allowed")
    bpf["auth_events"].open_perf_buffer(auth_cb);

    print("/-{:^20}---{:^10}---{:^12}-\\".format("-" * 20, "-" * 10, "-" * 12))
    print("| {:^20} | {:^10} | {:^12} |".format("USERNAME", "SUCCESS", "TIME TO AUTH"))

    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("{:^20}---{:^10}---{:^12}-/".format("-" * 20, "-" * 10, "-" * 12))
            sys.exit()

if __name__ == "__main__":
    main()
