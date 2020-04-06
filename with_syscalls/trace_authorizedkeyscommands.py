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

    print("[auth finished] username: {} success: {}".format(str(auth.username), bool(auth.success)))

def authorizedkeys_command_cb(cpu, data, size):
    assert size >= ct.sizeof(AuthorizedKeysCommand)
    cmd = ct.cast(data, ct.POINTER(AuthorizedKeysCommand)).contents

    print("[AuthorizedKeysCommand ran] username: {} duration: {} ms".format(str(cmd.username), (cmd.end - cmd.start) / 1000000))


def main():
    bpf = BPF(src_file="./trace_authorizedkeyscommands.c")
    bpf["authentication_events"].open_perf_buffer(authentication_cb)
    bpf["authorizedkeys_command_events"].open_perf_buffer(authorizedkeys_command_cb)

    print("Tracing...")

    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            sys.exit();

    return 0

if __name__ == "__main__":
    main()
