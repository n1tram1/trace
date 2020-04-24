#!/usr/bin/python

from bcc import BPF

import sys
import socket
import ipaddress
import ctypes as ct

g_sessions = {}

FILENAME_MAX = 255

class Id(ct.Structure):
    _fields_ = [
        ("src_addr", ct.c_uint),
        ("dst_addr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
    ]

    def __str__(self):
        src = ipaddress.ip_address(socket.ntohl(self.src_addr))
        dst = ipaddress.ip_address(socket.ntohl(self.dst_addr))
        sport = self.sport
        dport = socket.ntohs(self.dport)

        return f"{{src={src}, dst={dst}, sport={sport}, dport={dport}}}"


class Connection(ct.Structure):
    _fields_ = [
        ("priv_tgid", ct.c_uint),
        ("net_tgid", ct.c_uint),
        ("sent", ct.c_ulong),
        ("received", ct.c_ulong),
        ("id", Id),
        ("auth_successful", ct.c_int),
        ("start", ct.c_ulong),
        ("end", ct.c_ulong),
    ]

    def __str__(self):
        return f"{{id={self.id}, start={self.start}, end={self.end}, sent={self.sent}, received={self.received}, auth_successful={bool(self.auth_successful)}, priv={self.priv_tgid}, net={self.net_tgid}}}"


class Command(ct.Structure):
    _fields_ = [
        ("filename", ct.c_char * FILENAME_MAX),
        ("start", ct.c_ulonglong),
        ("end", ct.c_ulonglong),
        ("parent_tgid", ct.c_uint),
        ("current_tgid", ct.c_uint),
        ("id", Id),
    ]

    def __str__(self):
        _id = self.id
        filename = self.filename.decode()
        duration_ms = (self.end - self.start) / 1000000
        parent = self.parent_tgid
        current = self.current_tgid

        return f"{{id={_id}, filename=\"{filename}\", duration={duration_ms}, parent={parent}, current={current}}}"


def connection_cb(cpu, data, size):
    assert size >= ct.sizeof(Connection)
    conn = ct.cast(data, ct.POINTER(Connection)).contents

    print(f"connection{conn}")


def command_cb(cpu, data, size):
    assert size >= ct.sizeof(Command)
    cmd = ct.cast(data, ct.POINTER(Command)).contents

    print(f"command_ran{cmd}")


def main():
    bpf = BPF(src_file="./trace_sessions.c")
    bpf["command_events"].open_perf_buffer(command_cb)
    bpf["connection_events"].open_perf_buffer(connection_cb)

    print("Tracing...")

    while True:
        try:
            # bpf.trace_print()
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            sys.exit()

    return 0


if __name__ == "__main__":
    main()
