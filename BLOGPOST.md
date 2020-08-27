# Tracing sshd (hard mode)

## Introduction

TODO: write about why I did this

The data we wanted from the tracing:
- authentications
    - login of user
    - time & date
    - if it succeeded
- *ssh sessions*
    - start time
    - end time
    - commands that were ran inside
        - arguments to the command
        - return value
        - duration
        
### My first attempt
After knowing this I was really excited and eager to finally do something with eBPF (as I had only read about it).

My first step was to download OpenSSH's source code and find the functions that were of interest (which one did authentication, take care of commands, ...).
Once that was done I recompiled OpenSSH on my machine in order to have debug symbols.

Next I just wrote a small bpftrace PoC that got the data we wanted.
Happy that I had finished all this quickly I went to show my work.
That is when I learned that the whole point of using eBPF was its non-obstrusctivity, we could just run the script on an already running server and get the data we needed, without modifying the environment.

Another downside to my reliance on symbols was that I was using a header with the struct definitions from `sshd.h`.
If the definitions were modified and sshd updated, my script would be broken by looking at the wrong data.

### Second attempt

The solution to tracing `sshd` without its symbols is just to look at the syscalls it makes.
*(maybe there is another way but I haven't found it)*
I spent a day thinking about it and I was thinking that this idea was completely stupid and error prone and was going to give false data.

I had to dig much more into `sshd`'s source and after some time I started to release it was always the same pattern, there were lots calls to `fork`.

At first I really didn't get it until I learned about the privsep(TODO: link to something explaining privsep?) mechanism.

Consequently I realised that each child was performing a specific action.

If I could get a good understanding of how the children were interacting, when they were being created etc... I could get a good view of `sshd` from the outside by only looking at syscalls.

After a bit of time reading source code, monitoring sshd and lots of tinkering with `bpftrace` this is the diagram I came up with:
![](https://i.imgur.com/jBosi7i.png)

Once I had the diagram, it was just a matter of writing eBPF probes and tracking who was making the syscalls and who were the parents of the callees. 
By doing this I could easily trace sshd.
Writing the eBPF program was pretty trivial, the hardest part was understanding sshd.

You can find the source code in `with_syscalls/ssh_sessions/`

