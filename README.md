# Trace sshd

A collection of BCC scripts to trace some events in OpenSSH's *sshd*.

The bpftrace scripts were just prototypes for the BCC scripts.

# Scripts

## trace_sessions
Collect stats of sessions as they end.

### Screenshots
```
/-----------------------------------------------------------------------\
|       USERNAME       |  RECV (B)  |  SENT (B)  |      TIME (ms)       |
|        martin        |    1343488 |    3342964 |                11171 |
|         root         |    4571136 |   16851732 |                10388 |
^C----------------------------------------------------------------------/
```
## trace_authorizedkeyscommand
Collect stats about the auth with the 'AuthorizedKeysCommand' program.

### Screenshots
```
/--------------------------------------------------\
|       USERNAME       |  SUCCESS   | TIME TO AUTH |
|        martin        |     1      |     2011     |
|        martin        |     1      |     9370     |
|         root         |     0      |     2008     |
^C-------------------------------------------------/
```

# Shortcomings
* Needs a non-stripped sshd
* Uses eBPF uprobes and structs definitions taken from the OpenSSH source code.
  This is a very unstable API to trace and is prone to breaking
  with every OpenSSH updates.

# Requirements
* sshd in (*/usr/bin/sshd*) that has not been stripped
* bcc
* python-bcc
