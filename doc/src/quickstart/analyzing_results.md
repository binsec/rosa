# Analyzing the results

If ROSA claims it has detected a backdoor, it will place it in a special subdirectory of its output
directory (in our case, `rosa-out/backdoors`).

You will notice that the `backdoors` subdirectory contains other directories, with potentially
weird names:
```console
{container} $ ls rosa-out/backdoors/
README.txt  ca0a23c55eb25b45_cluster_000000
```

By default, ROSA performs _deduplication_ based on the _detection signature_ of each backdoor. In
short, it groups backdoors together based on the detection reason. This removes a _lot_ of
otherwise duplicate examples (different ways of triggering the same behavior). We can look at any
one of the _actual suspicious inputs_ inside each subdirectory to draw conclusions about the entire
category of inputs described by the subdirectory.

We can use `od` to look at the contents of a suspicious input:
```console
{container} $ od -t cx1 rosa-out/backdoors/ca0a23c55eb25b45_cluster_000000/0be1d8daae577bb7
0000000   l   e   t   _   m   e   _   i   n  \0   n       x   v   p
           656c    5f74    656d    695f    006e    206e    7678    0070
0000017
```

And there it is: `"let_me_in"`! ROSA has successfully produced an input triggering the backdoor.

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
1. Picking `rosa-out/backdoors/ca0a23c55eb25b45_cluster_000000/0be1d8daae577bb7`.
2. ```console
   {container} $ rosa-explain -o rosa-out 0be1d8daae577bb7
   ...
   Syscalls: 15, 18, 32, 33, 56, 59, 61, 106, 111, 271, 273, 436
   ...
   Syscalls:
   ```
   The second one is empty, because there are no system calls present in the _cluster_ (input
   family) that are **not** present in the _trace_.
3. ```console
   {container} $ strace -f -e 15,18,32,33,56,59,61,106,111,271,273,436 -o trace.txt -- \
                     /root/aflpp/afl-qemu-trace -- \
                     /usr/bin/backdoored-sudo --stdin --reset-timestamp -- id < \
                     rosa-out/backdoors/ca0a23c55eb25b45_cluster_000000/0be1d8daae577bb7
   Password: uid=0(root) gid=0(root) groups=0(root)
   ```
   Notice how we had to use `/root/aflpp/afl-qemu-trace`; this is the emulator the binary was
   instrumented through during fuzzing, so if we want to understand the system calls produced by it
   we need to look at it in the same environment. If we just used `backdoored-sudo`, there are no
   guarantees that all of the discriminant system calls will be present.
4. ```console
   {container} $ cat trace.txt
   16285 execve("/root/aflpp/afl-qemu-trace", ["/root/aflpp/afl-qemu-trace", "--", "/usr/bin/backdoored-sudo", "--stdin", "--reset-timestamp", "--", "id"], 0x55f2cd0ad930 /* 12 vars */) = 0
   16285 set_robust_list(0x7f7151a7bee0, 24) = 0
   16286 set_robust_list(0x7f71516009a0, 24) = 0
   16286 --- SIGRT_1 {si_signo=SIGRT_1, si_code=SI_TKILL, si_pid=16285, si_uid=0} ---
   16286 rt_sigreturn({mask=0x7f71515ff8e8}) = 202
   16286 --- SIGRT_1 {si_signo=SIGRT_1, si_code=SI_TKILL, si_pid=16285, si_uid=0} ---
   16286 rt_sigreturn({mask=0x7f71515ff8e8}) = 202
   16286 --- SIGRT_1 {si_signo=SIGRT_1, si_code=SI_TKILL, si_pid=16285, si_uid=0} ---
   16286 rt_sigreturn({mask=0x7f71515ff8e8}) = 202
   16286 --- SIGRT_1 {si_signo=SIGRT_1, si_code=SI_TKILL, si_pid=16285, si_uid=0} ---
   16286 rt_sigreturn({mask=0x7f71515ff8e8}) = 202
   16286 --- SIGRT_1 {si_signo=SIGRT_1, si_code=SI_TKILL, si_pid=16285, si_uid=0} ---
   16286 rt_sigreturn({mask=~[ILL FPE KILL SEGV STOP RTMIN RT_1]} <unfinished ...>
   16285 setgid(0 <unfinished ...>
   16286 <... rt_sigreturn resumed>)       = 202
   16285 <... setgid resumed>)             = 0
   16285 getpgrp()                         = 16282
   16285 dup(0)                            = 11
   16285 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f7151a7bed0) = 16287
   16287 set_robust_list(0x7f7151a7bee0, 24) = 0
   16287 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f7151a7bed0) = 16288
   16288 set_robust_list(0x7f7151a7bee0, 24) = 0
   16285 ppoll([{fd=9, events=POLLIN}, {fd=3, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
   16287 getpgrp( <unfinished ...>
   16285 <... ppoll resumed>)              = 1 ([{fd=9, revents=POLLIN}])
   16287 <... getpgrp resumed>)            = 16287
   16285 ppoll([{fd=9, events=POLLIN}, {fd=3, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
   16288 dup(7)                            = 6
   16287 ppoll([{fd=6, events=POLLIN}, {fd=10, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
   16288 dup2(6, 7)                        = 7
   16288 execve("/usr/bin/id", ["id"], 0x55d5f54ac040 /* 13 vars */) = 0
   16287 <... ppoll resumed>)              = 1 ([{fd=6, revents=POLLIN|POLLHUP}])
   16287 ppoll([{fd=-1}, {fd=10, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
   16288 set_robust_list(0x7ff1e4879ae0, 24) = 0
   16285 <... ppoll resumed>)              = 1 ([{fd=7, revents=POLLIN}])
   16288 +++ exited with 0 +++
   16287 <... ppoll resumed>)              = ? ERESTARTNOHAND (To be restarted if no handler)
   16287 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=16288, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---
   16287 rt_sigreturn({mask=~[BUS SEGV]})  = -1 EINTR (Interrupted system call)
   16285 ppoll([{fd=9, events=POLLIN}, {fd=3, events=POLLIN}, {fd=7, events=POLLIN}, {fd=6, events=POLLOUT}], 4, NULL, NULL, 8) = 1 ([{fd=6, revents=POLLOUT}])
   16285 ppoll([{fd=9, events=POLLIN}, {fd=3, events=POLLIN}, {fd=7, events=POLLIN}], 3, NULL, NULL, 8 <unfinished ...>
   16287 wait4(16288, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WNOHANG|WSTOPPED, NULL) = 16288
   16285 <... ppoll resumed>)              = 1 ([{fd=9, revents=POLLIN}])
   16287 +++ exited with 1 +++
   16285 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=16287, si_uid=0, si_status=1, si_utime=0, si_stime=0} ---
   16285 rt_sigreturn({mask=~[BUS SEGV]})  = 1
   16285 ppoll([{fd=7, events=POLLIN}], 1, {tv_sec=0, tv_nsec=0}, NULL, 8) = 1 ([{fd=7, revents=POLLHUP}], left {tv_sec=0, tv_nsec=0})
   16286 +++ exited with 0 +++
   16285 +++ exited with 0 +++
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
