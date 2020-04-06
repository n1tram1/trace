#!/usr/bin/python

from bcc import BPF

import sys

import ctypes as ct

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

    username = auth.username.decode()
    success = auth.success

    print(f"sshd_auth_finished{{username=\"{username}\", success={success}}}")


def authorizedkeyscommand_cb(cpu, data, size):
    assert size >= ct.sizeof(AuthorizedKeysCommand)
    cmd = ct.cast(data, ct.POINTER(AuthorizedKeysCommand)).contents

    username = cmd.username.decode()
    duration_ms = (cmd.end - cmd.start) / 1000000

    print(("sshd_authorizedkeyscommand_ran"
           f"{{username=\"{username}\", duration_ms={duration_ms}}}"))


def main():
    bpf = BPF(src_file="./trace_authorizedkeyscommands.c")
    bpf["authentication_events"].open_perf_buffer(authentication_cb)
    bpf["authorizedkeyscommand_events"]\
        .open_perf_buffer(authorizedkeyscommand_cb)

    print("Tracing...")

    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            sys.exit()

    return 0


if __name__ == "__main__":
    main()
