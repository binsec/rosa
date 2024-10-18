# Analyzing the results

If ROSA claims it has detected a backdoor, it will place it in a special subdirectory of its output
directory (in our case, `rosa-out/backdoors`).

You will notice that the `backdoors` subdirectory contains other directories, with potentially
weird names:
```console
{container} $ ls rosa-out/backdoors/
0430a5dc3e14b0e1_cluster_000000  README.txt
```

By default, ROSA performs _deduplication_ based on the _detection signature_ of each backdoor. In
short, it groups backdoors together based on the detection reason. This removes a _lot_ of
otherwise duplicate examples (different ways of triggering the same behavior). We can look at any
one of the _actual suspicious inputs_ inside each subdirectory to draw conclusions about the entire
category of inputs described by the subdirectory.

We can use `od` to look at the contents of a suspicious input:
```console
{container} $ od -t cx1 rosa-out/backdoors/0430a5dc3e14b0e1_cluster_000000/e205ab0700d8b183
0000000   l   e   t   _   m   e   _   i   n  \0   i   l   j   g   v   w
         6c  65  74  5f  6d  65  5f  69  6e  00  69  6c  6a  67  76  77
0000020   r   w   l   u   z   s   l   z   v   m   o   h   r   i   z   x
         72  77  6c  75  7a  73  6c  7a  76  6d  6f  68  72  69  7a  78
0000040   x   h   y   w   p   y   j   u   o   g   u   y   j   u   j   d
         78  68  79  77  70  79  6a  75  6f  67  75  79  6a  75  6a  64
0000060   y   n   z   y   p   s   z   g   k   o   x   v   s   g   a   t
         79  6e  7a  79  70  73  7a  67  6b  6f  78  76  73  67  61  74
0000100   x   /
         78  2f
0000102
```

And there it is: `"let_me_in"`! ROSA has successfully produced an input triggering the backdoor.


## Exploring further

This is just a small example; in a real scenario, you wouldn't know what the backdoor looks like
(or if there even is one). In that case, you must examine _all_ of the subdirectories of
`backdoors/`, as some of them may be _false positives_ (i.e., reported as suspicious but not
actually involving a backdoor).

We propose the following method to help automate the investigation:
- For each subdirectory of `backdoors/`:
    1. Pick a _witness input_ out of the subdirectory, to be used to characterize the entire
       subdirectory (let's assume the input is `rosa-out/backdoors/X/Y`).
    2. Run `rosa-explain -o rosa-out Y` and inspect the parts starting with `"Syscalls: "`. These
       are the _discriminants_, meaning the system calls that are _different_ (either with regards
       to the suspect trace or its corresponding input family).
    3. Run the target program under `strace` by only filtering the system call numbers you saw
       previously.
    4. Look through the output of `strace` for suspicious system calls (or system call arguments).

Let's go through one _witness input_ example with `sudo`:

### Step 1 - Picking a witness input
We're picking `rosa-out/backdoors/0430a5dc3e14b0e1_cluster_000000/e205ab0700d8b183` as it's the
only one that exists. If there were more _backdoor categories_ (i.e., more subdirectories under
`rosa-out/backdoors/`), we would have to pick one input from each.

### Step 2 - Finding the discriminants
As discussed before, we will use `rosa-explain` to do this, looking at the _system call_
discriminants specifically:
```console
{container} $ rosa-explain -o rosa-out e205ab0700d8b183
...
Syscalls: 15, 32, 33, 56, 59, 61, 106, 111, 271, 273, 436
...
Syscalls:
```
The second one is empty, because there are no system calls present in the _cluster_ (input family)
that are **not** present in the _trace_.

### Step 3 - Running the target under strace
We'll only keep the system calls that are present in our discriminant list:
```console
{container} $ strace -f -e 15,32,33,56,59,61,106,111,271,273,436 -o trace.txt -- \
                 backdoored-sudo --stdin --reset-timestamp -- id < \
                 rosa-out/backdoors/0430a5dc3e14b0e1_cluster_000000/e205ab0700d8b183
Password: uid=0(root) gid=0(root) groups=0(root)
```

### Step 4 - Looking through strace's output
Let's see what the discriminants really look like:
```console
{container} $ cat trace.txt
18866 execve("/usr/bin/backdoored-sudo", ["backdoored-sudo", "--stdin", "--reset-timestamp", "--", "id"], 0x7ffc69b21c10 /* 11 vars */) = 0
18866 set_robust_list(0x7f468f9b7a20, 24) = 0
18866 setgid(0)                         = 0
18866 getpgrp()                         = 18863
18866 dup(0)                            = 11
18866 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f468f9b7a10) = 18867
18867 set_robust_list(0x7f468f9b7a20, 24) = 0
18866 ppoll([{fd=9, events=POLLIN}, {fd=3, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
18867 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f468f9b7a10) = 18868
18866 <... ppoll resumed>)              = 1 ([{fd=9, revents=POLLIN}])
18867 getpgrp()                         = 18867
18866 ppoll([{fd=9, events=POLLIN}, {fd=3, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
18868 set_robust_list(0x7f468f9b7a20, 24) = 0
18867 ppoll([{fd=6, events=POLLIN}, {fd=10, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
18868 dup(7)                            = 6
18868 close_range(7, 4294967295, 0)     = 0
18868 dup2(6, 7)                        = 7
18868 execve("/usr/bin/id", ["id"], 0x5652fad556f0 /* 13 vars */ <unfinished ...>
18867 <... ppoll resumed>)              = 1 ([{fd=6, revents=POLLIN|POLLHUP}])
18868 <... execve resumed>)             = 0
18867 ppoll([{fd=-1}, {fd=10, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
18868 set_robust_list(0x7f4bae314ae0, 24) = 0
18868 +++ exited with 0 +++
18867 <... ppoll resumed>)              = ? ERESTARTNOHAND (To be restarted if no handler)
18866 <... ppoll resumed>)              = 1 ([{fd=7, revents=POLLIN}])
18867 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18868, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---
18867 rt_sigreturn({mask=[]})           = -1 EINTR (Interrupted system call)
18866 ppoll([{fd=9, events=POLLIN}, {fd=3, events=POLLIN}, {fd=7, events=POLLIN}, {fd=6, events=POLLOUT}], 4, NULL, NULL, 8) = 1 ([{fd=6, revents=POLLOUT}])
18867 wait4(18868, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WNOHANG|WSTOPPED, NULL) = 18868
18866 ppoll([{fd=9, events=POLLIN}, {fd=3, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8) = 1 ([{fd=9, revents=POLLIN}])
18867 +++ exited with 1 +++
18866 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18867, si_uid=0, si_status=1, si_utime=0, si_stime=0} ---
18866 rt_sigreturn({mask=[]})           = 0
18866 ppoll([{fd=7, events=POLLIN}], 1, {tv_sec=0, tv_nsec=0}, NULL, 8) = 1 ([{fd=7, revents=POLLHUP}], left {tv_sec=0, tv_nsec=0})
18866 +++ exited with 0 +++
```

So we notice that a couple of `clone` system calls are executed, followed by an
`execve("/usr/bin/id" ...)` system call. There can only be one of three reasons why that point was
reached in `sudo`:
1. The fuzzer _guessed_ the correct password.
2. There is a backdoor allowing to bypass authentication, given a special password.
3. There is a backdoor spawing a shell and running the specified command triggered by some
   condition.

Obviously (1) is theoretically possible, but highly unlikely (in a realistic scenario, we can just
test it with a strong, long password). In order to decide if it's (2) or (3) (spoilers: it's (2)),
we would need to look further, using a debugger or a reverse-engineering/decompiling tool to reach
the source of the backdoor trigger. However, we have quickly pinpointed that there _must_ be a
backdoor in the program, since it behaves unexpectedly (the fuzzer seems to "guess" the password,
even though that shouldn't be possible).
