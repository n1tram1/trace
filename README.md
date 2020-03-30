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
## trace_auths
Collect stats about authentications.

### Screenshots
```
/--------------------------------------------------\
|       USERNAME       |  SUCCESS   | TIME TO AUTH |
|        martin        |     1      |     2011     |
|        martin        |     1      |     9370     |
|         root         |     0      |     2008     |
^C-------------------------------------------------/
```

# Requirements
* sshd in (*/usr/bin/sshd*) that has not been stripped
* bcc
* python-bcc
