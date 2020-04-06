# Trace sshd

A collection of BCC scripts to trace some events in OpenSSH's *sshd*.

The bpftrace scripts were just prototypes for the BCC scripts.

# Scripts

## with_syscalls
Scripts to trace sshd by only examining the syscalls it makes

### trace_authorizedkeyscommand
Trace each time the AuthorizedKeysCommand is ran, how much time it took and for which user it was done.
Also each time an authentication finishes, display who was the user and whether the auth succeeded.

#### Screenshots
```
sshd_authorizedkeyscommand_ran{username="martin", duration_ms=1010.226717}
sshd_authorizedkeyscommand_ran{username="martin", duration_ms=1007.266651}
sshd_auth_finished{username="martin", success=1}
```
As we can see from the screenshot above, the AuthorzedKeysCommand was ran twice
and the user 'martin' was authenticated successfully.

## with_symbols

Scripts to trace sshd that require sshd to not be stripped.
*Also make uses of unstable APIs.*

### trace_sessions
Collect stats of sessions as they end.

**WARNING**: For now the script is dependant on the fact that the
authkeyscommand is '/usr/local/bin/ssh-auth.sh %u'

#### Screenshots
```
/-----------------------------------------------------------------------\
|       USERNAME       |  RECV (B)  |  SENT (B)  |      TIME (ms)       |
|        martin        |    1343488 |    3342964 |                11171 |
|         root         |    4571136 |   16851732 |                10388 |
^C----------------------------------------------------------------------/
```

### trace_authorizedkeyscommand
Collect stats about the auth with the 'AuthorizedKeysCommand' program.

#### Screenshots
```
/--------------------------------------------------\
|       USERNAME       |  SUCCESS   | TIME TO AUTH |
|        martin        |     1      |     2011     |
|        martin        |     1      |     9370     |
|         root         |     0      |     2008     |
^C-------------------------------------------------/
```
#### Shortcomings
* Needs a non-stripped sshd
* sshd must be located in /usr/bin/sshd
* Uses eBPF uprobes and structs definitions taken from the OpenSSH source code.
  This is a very unstable API to trace and is prone to breaking
  with every OpenSSH update.

# How to run
Just do
```
sudo ./<script>.py
```


# Requirements
* sshd
* bcc
* python-bcc
