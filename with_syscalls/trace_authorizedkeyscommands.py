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


def get_sshd_config_authorizedkeyscommand(config_path):
    with open(config_path) as f:
        for line in f.readlines():
            tokens = line.split()
            if len(tokens) > 1 and tokens[0] == "AuthorizedKeysCommand":
                return tokens[1::]

    return None


def get_sshd_config_authorizedkeyscommand_prog(config_path):
    authorizedkeyscommand = get_sshd_config_authorizedkeyscommand(config_path)
    if len(authorizedkeyscommand) < 1:
        return None

    prog_path = authorizedkeyscommand[0]
    prog = prog_path.split("/")[-1]

    return prog


def main():
    prog = get_sshd_config_authorizedkeyscommand_prog("/etc/ssh/sshd_config")
    if not prog:
        print("Couldn't find  AuthorizedKeysCommand in sshd_config")
        sys.exit()

    cflags = [
        f"-DAUTHORIZEDKEYSCOMMAND_PROG=\"{prog}\""
    ]

    bpf = BPF(src_file="./trace_authorizedkeyscommands.c", cflags=cflags)
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
