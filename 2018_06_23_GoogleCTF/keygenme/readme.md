# GoogleCTF 2018 - keygenme - 249pts
![Challenge description](/images/chall.png)

# TL;DR
For this challenge we were provided with a single file called `main`. The binary decrypts itself and then forks, the child decrypts the second stage and executes it, the parent rewrites the child code on the fly and the child performs verification of the flag with a modified MD5 and a transformation function.

# Long version
For this challenge we were provided with a single file called `main`.
```bash
user@re:~$ file main
main: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

Executing the binary we can see it reads two inputs and then exits.
```bash
user@re:~$ ./main
x
x
user@re:~$
```
Running `strace` we can get a rough idea of what the binary is doing. First it runs `ptrace` with `PTRACE_DETACH`, then it forks, then it appears to read and write to the child process via `process_vm_readv` and `process_vm_writev`. It also appears to be repeatedly getting and setting the registers of the child process with `PTRACE_GETREGS` and `PTRACE_SETREGS`.
```bash
user@re:~$ strace ./main
execve("./main", ["./main"], [/* 54 vars */]) = 0
mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7ffff7fea000
mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7ffff7fda000
ptrace(PTRACE_DETACH, 0, NULL, SIG_0)   = -1 ESRCH (No such process)
fork()                                  = 1354
mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7ffff7fca000
wait4(1354, a
a
[{WIFSTOPPED(s) && WSTOPSIG(s) == SIGTRAP}], 0, NULL) = 1354
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=1354, si_uid=900, si_status=SIGTRAP, si_utime=0, si_stime=0} ---
ptrace(PTRACE_CONT, 1354, NULL, SIG_0)  = 0
wait4(1354, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGTRAP}], 0, NULL) = 1354
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=1354, si_uid=900, si_status=SIGTRAP, si_utime=0, si_stime=0} ---
open("/proc/1354/maps", O_RDONLY)       = 3
read(3, "555555554000-555", 16)         = 16
close(3)                                = 0
ptrace(PTRACE_GETREGS, 1354, NULL, 0x7ffff7fca020) = 0
process_vm_readv(1354, [{"\314\353\376", 3}], 1, [{0x5555555547c5, 3}], 1, 0) = 3
process_vm_writev(1354, [{"^H\211", 3}], 1, [{0x5555555547c5, 3}], 1, 0) = 3
ptrace(PTRACE_SETREGS, 1354, NULL, 0x7ffff7fca020) = 0
ptrace(PTRACE_CONT, 1354, NULL, SIG_0)  = 0
wait4(1354, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGTRAP}], 0, NULL) = 1354
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=1354, si_uid=900, si_status=SIGTRAP, si_utime=0, si_stime=0} ---
ptrace(PTRACE_GETREGS, 1354, NULL, 0x7ffff7fca020) = 0
process_vm_writev(1354, [{"\314\353\376", 3}], 1, [{0x5555555547c5, 3}], 1, 0) = 3
process_vm_readv(1354, [{"\314\303", 2}], 1, [{0x555555554845, 2}], 1, 0) = 2
process_vm_writev(1354, [{"H\301", 2}], 1, [{0x555555554845, 2}], 1, 0) = 2
ptrace(PTRACE_SETREGS, 1354, NULL, 0x7ffff7fca020) = 0
ptrace(PTRACE_CONT, 1354, NULL, SIG_0)  = 0
wait4(1354, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGTRAP}], 0, NULL) = 1354
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=1354, si_uid=900, si_status=SIGTRAP, si_utime=0, si_stime=0} ---

...
```

Now lets see what's happening with the child using `strace -f`.

```
user@re:~$ strace -f ./main
execve("./main", ["./main"], [/* 54 vars */]) = 0
mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7ffff7fea000
mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7ffff7fda000
ptrace(PTRACE_DETACH, 0, NULL, SIG_0)   = -1 ESRCH (No such process)
fork()                                  = 1359
mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7ffff7fca000
wait4(1359, strace: Process 1359 attached
 <unfinished ...>
[pid  1359] mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7ffff7fca000
[pid  1359] read(0, x
"x\n", 5)           = 2
[pid  1359] read(0, x
"x\n", 32)          = 2
[pid  1359] prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0
[pid  1359] seccomp(SECCOMP_SET_MODE_STRICT, 1, NULL) = -1 EINVAL (Invalid argument)
[pid  1359] seccomp(SECCOMP_SET_MODE_FILTER, 0, {len = 8, filter = 0x7ffff7fdde7e}) = 0
[pid  1359] ptrace(PTRACE_TRACEME, 0, NULL, NULL) = -1 EPERM (Operation not permitted)
[pid  1359] memfd_create("hi", MFD_CLOEXEC) = 3
[pid  1359] write(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\7\0\0\0\0\0\0"..., 14488) = 14488
[pid  1359] fchmod(3, 0555)             = 0
[pid  1359] execve("/proc/self/fd/3", ["x\n", "x\n"], NULL) = 0
...
```
 
This shows the child setting up a seccomp filter, creating a memfd (fd = 3), writing what appears to be an ELF file to the memfd and then executing it with `execve`. 
Lets dump the seccomp filter with `seccomp-tools` to see what filter it's enforcing.

```
user@re:~$ seccomp-tools dump ./main
x
x
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x03 0x00 0x40000000  if (A >= 0x40000000) goto 0007
 0004: 0x15 0x01 0x00 0x0000005f  if (A == umask) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 ```

 This shows that the `umask` syscall will return `ERRNO(1)`, which means that the `umask` syscall will always return the value `1`. Interesting.


Now we can dive into some static reversing. 

Opening it up in IDA we immediately see some form of decryption loop. `sub_400189` mmaps a 65KB region of RWX memory, then we can see the code copies 17576 bytes from address `0x6001BC` in the .data section, to the mmapped memory, after which the mmapped memory is xored with the key `0x1122334455667788`.
![Decryption loop in IDA](/images/main_1.png)

I whipped up a quick IDA script to perform this xor statically so I could continue my analysis.

```python
start = 0x6001BC
key = 0x1122334455667788
length = 17576

print("[*] XOR start: {}".format(hex(start)))
for ptr in range(start, start+length, 8): 
    PatchQword(ptr, Qword(ptr) ^ key);

Message("[*] XOR done :)\n");
```

Browsing to `0x6001BC` and marking it as code we can now see the decrypted code. 

Most of this code looks like it has been handwritten and there are various self-modifying tricks to throw us off. For example the following piece of code actually calls `ptrace` and not `exit_group`, by changing the syscall number of its own code.
![Self modification with ptrace](/images/main_2.png)


Continuing to read through and following the (somewhat obfuscated) control flow we can see the aforementioned behaviour of setting up seccomp rules, creating and writing to a memfd, and eventually executing it. The two reads performed are passed to the `execve`d process as `argv[0]` and `argv[1]`. It appears that `sub_603EEE` does the decryption of the ELF file, however its control flow was too difficult to follow, so I just stepped over it when debugging and took it as a magic black box which decrypted the ELF. 

At `0x600442` the binary writes the decrypted file to the memfd, so it was at this point that I set a breakpoint with `gdb` and dumped 14488 bytes from the decrypted address, which gave me the second stage binary.

# Second stage
```
user@re:~$ file second_stage
second_stage: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1b6bb2a46a5e760d6de3fb5c4782e05c0a118f11, stripped
```

Opening this binary in IDA we could see some strange things going on. Specifically there appeared to be a few infinite loops, and code missing in several places, with `int 3`s replacing the missing code.

There was also some PLT trickery going on. The binary was patching its own PLT at runtime such that the PLT entry which looked to be pointing to the `exit` GOT entry actually ended up pointing to the `umask` GOT entry. This messed up some of IDAs disassembly/decompilation because what appeared to be unreachable code after the "exit" was actually perfectly reachable. To fix this I patched the PLT statically and nopped the runtime patch, which helped IDA make more sense of things. 

After giving this binary a quick skim I thought it would be more beneficial for my understanding to dump the data that was being sent back and forth between the parent and child binary, which we saw earlier in `strace`. Despite having the data already available via `strace`, in my tired and weary state I thought the best way to do this would be to write a kernel module, hook the `process_vm_readv` and `process_vm_writev` syscalls and output the data... so that is exactly what I did.

```c
#define _GNU_SOURCE
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/unistd_64.h>
#include <linux/semaphore.h>
#include <asm/cacheflush.h>
#include <asm/user_64.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <stdarg.h>
#include <asm/errno.h>

#define PTRACE_GETREGS 12
#define PTRACE_SETREGS 13
#define PTRACE_CONT    7
#define PTRACE_TRACEME 0
#define PTRACE_ATTACH  17

// Yeah sorry about this struct, was having header issues...
struct user_regs_struct_f
{
  unsigned long long int r15;
  unsigned long long int r14;
  unsigned long long int r13;
  unsigned long long int r12;
  unsigned long long int rbp;
  unsigned long long int rbx;
  unsigned long long int r11;
  unsigned long long int r10;
  unsigned long long int r9;
  unsigned long long int r8;
  unsigned long long int rax;
  unsigned long long int rcx;
  unsigned long long int rdx;
  unsigned long long int rsi;
  unsigned long long int rdi;
  unsigned long long int orig_rax;
  unsigned long long int rip;
  unsigned long long int cs;
  unsigned long long int eflags;
  unsigned long long int rsp;
  unsigned long long int ss;
  unsigned long long int fs_base;
  unsigned long long int gs_base;
  unsigned long long int ds;
  unsigned long long int es;
  unsigned long long int fs;
  unsigned long long int gs;
};

asmlinkage int (*original_ptrace)(int request, pid_t pid, void *addr, void *data);
asmlinkage int (*original_readv)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
asmlinkage int (*original_writev)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
asmlinkage int (*original_execve)(const char *filename, char *const argv[], char *const envp[]);

// sudo grep "sys_call_table" /boot/System.map-4.4.0-116-generic
long long int *syscall_table = (void*)0xffffffff81a00200;

// No ASLR plox
long long int bin_base = 0x0000555555554000;

asmlinkage int new_ptrace (int request, pid_t pid, void *addr, void *data) {
        if(request == PTRACE_CONT) {
                printk( "[*] PTRACE_CONT\n");
        }
        else if(request == PTRACE_TRACEME) {
                printk( "[*] PTRACE_TRACEME\n");
        }
        else if(request == PTRACE_ATTACH) {
                printk( "[*] PTRACE_ATTACH\n");
        }
        else if(request == PTRACE_GETREGS) {
                printk( "[*] PTRACE_GETREGS\n");
        }
        else if(request == PTRACE_SETREGS) {
                printk( "[*] PTRACE_SETREGS\n");

                struct user_regs_struct_f *p = (struct user_regs_struct_f *)data;

                printk( "[*] rax: %p\n", (void *)p->rax);
                printk( "[*] rbx: %p\n", (void *)p->rbx);
                printk( "[*] rcx: %p\n", (void *)p->rcx);
                printk( "[*] rdx: %p\n", (void *)p->rdx);
                printk( "[*] rsi: %p\n", (void *)p->rsi);
                printk( "[*] rdi: %p\n", (void *)p->rdi);
                printk( "[*] rbp: %p\n", (void *)p->rbp);
                printk( "[*] rsp: %p\n", (void *)p->rsp);
                printk( "[*] rip: %p\n", (void *)p->rip);
        }
        else {
                printk( "[*] PTRACE UNKNOWN: %d", request);
        }
    return original_ptrace(request, pid, addr, data);
}

asmlinkage int new_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
        int i;
        for(i = 0; i < liovcnt; i++) {
                printk("[*] Reading %d bytes from %p to %p: ", local_iov[i].iov_len, remote_iov[i].iov_base, local_iov[i].iov_base);
                int k = 0;
                for(k = 0; k < local_iov[i].iov_len; k++) {
                        printk("%02hhx", ((char *)local_iov[i].iov_base)[k]);
                }
                printk("\n");
        }

    return original_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

asmlinkage int new_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
        int i;
        for(i = 0; i < liovcnt; i++) {
                printk("[*] Writing %d bytes from %p to %p (%04x): ", local_iov[i].iov_len, local_iov[i].iov_base, remote_iov[i].iov_base, remote_iov[i].iov_base - bin_base);
                int k = 0;
                for(k = 0; k < local_iov[i].iov_len; k++) {
                        printk("%02hhx", ((char *)local_iov[i].iov_base)[k]);
                }
                printk("\n");

        }
    return original_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

int init_module()
{
        // Disable write protect
        write_cr0 (read_cr0 () & (~ 0x10000));
        original_ptrace = (void *)syscall_table[__NR_ptrace];
        original_readv = (void *)syscall_table[__NR_process_vm_readv];
        original_writev = (void *)syscall_table[__NR_process_vm_writev];

        syscall_table[__NR_ptrace] = &new_ptrace;
        syscall_table[__NR_process_vm_readv] = &new_readv;
        syscall_table[__NR_process_vm_writev] = &new_writev;

        // Disable read protect
        write_cr0 (read_cr0 () | 0x10000);


        printk( "[*] sys_call_table hooked\n");

        return 0;
}

void cleanup_module()
{
        // Restore original system calls
        printk("[*] Removing hooks\n");

        write_cr0 (read_cr0 () & (~ 0x10000));
        syscall_table[__NR_ptrace] = original_ptrace;

        syscall_table[__NR_process_vm_readv] = original_readv;
        syscall_table[__NR_process_vm_writev] = original_writev;

        write_cr0 (read_cr0 () | 0x10000);
}
```

Compiling and loading the kernel module and then running the `main` binary gives us the following:

```bash
user@re:~/hook$ make &>/dev/null
user@re:~/hook$ sudo insmod hook.ko
user@re:~/hook$ ../main
x
x
user@re:~/hook$ dmesg
[ 8475.670423] [*] sys_call_table hooked
[ 8484.887492] [*] PTRACE_ATTACH
[ 8487.582383] [*] PTRACE_TRACEME
[ 8487.586875] [*] PTRACE_CONT
[ 8487.588212] [*] PTRACE_GETREGS
[ 8487.588224] [*] Reading 3 bytes from 00005555555547c5 to 00007ffff7fca810: 000000
[ 8487.588233] [*] Writing 3 bytes from 00007ffff7fddf31 to 00005555555547c5 (07c5): 5e4889
[ 8487.588239] [*] PTRACE_SETREGS
[ 8487.588240] [*] rax: 000000000000001c
[ 8487.588241] [*] rbx:           (null)
[ 8487.588242] [*] rcx: 00007fffffffee90
[ 8487.588243] [*] rdx: 00007ffff7de7ab0
[ 8487.588244] [*] rsi: 0000000000000002
[ 8487.588245] [*] rdi: 00007ffff7ffe168
[ 8487.588245] [*] rbp:           (null)
[ 8487.588246] [*] rsp: 00007fffffffee70
[ 8487.588247] [*] rip: 00005555555547c5
[ 8487.588250] [*] PTRACE_CONT
[ 8487.588259] [*] PTRACE_GETREGS
[ 8487.588269] [*] Writing 3 bytes from 00007ffff7fca810 to 00005555555547c5 (07c5): ccebfe
[ 8487.588272] [*] Reading 2 bytes from 0000555555554845 to 00007ffff7fca810: cceb
[ 8487.588274] [*] Writing 2 bytes from 00007ffff7fde082 to 0000555555554845 (0845): 48c1
[ 8487.588276] [*] PTRACE_SETREGS
[ 8487.588277] [*] rax:           (null)
[ 8487.588278] [*] rbx:           (null)
[ 8487.588279] [*] rcx: 00000000000000a0
[ 8487.588280] [*] rdx: 00007fffffffee90
[ 8487.588280] [*] rsi:           (null)
[ 8487.588281] [*] rdi: 0000555555757070
[ 8487.588282] [*] rbp: 00007fffffffed50
[ 8487.588283] [*] rsp: 00007fffffffed50
[ 8487.588284] [*] rip: 0000555555554845
[ 8487.588285] [*] PTRACE_CONT
[ 8487.588290] [*] PTRACE_GETREGS
[ 8487.588294] [*] Writing 2 bytes from 00007ffff7fca810 to 0000555555554845 (0845): ccc3
[ 8487.588296] [*] Reading 2 bytes from 0000555555555c1b to 00007ffff7fca810: ccc3
[ 8487.588299] [*] Writing 2 bytes from 00007ffff7fddf0d to 0000555555555c1b (1c1b): 5d41
[ 8487.588304] [*] PTRACE_SETREGS
[ 8487.588305] [*] rax:           (null)
[ 8487.588306] [*] rbx:           (null)
[ 8487.588307] [*] rcx: 00000000000000a0
[ 8487.588308] [*] rdx: 00007fffffffee90
[ 8487.588309] [*] rsi:           (null)
[ 8487.588309] [*] rdi: 0000555555757070
[ 8487.588310] [*] rbp: 0000000000000001
[ 8487.588311] [*] rsp: 00007fffffffed70
[ 8487.588312] [*] rip: 0000555555555c1b
[ 8487.588313] [*] PTRACE_CONT
[ 8487.588331] [*] PTRACE_GETREGS
[ 8487.588335] [*] Writing 2 bytes from 00007ffff7fca810 to 0000555555555c1b (1c1b): ccc3
[ 8487.588338] [*] Reading 2 bytes from 0000555555555c1e to 00007ffff7fca810: ccc3
[ 8487.588340] [*] Writing 2 bytes from 00007ffff7fddf1f to 0000555555555c1e (1c1e): 415d
[ 8487.588342] [*] PTRACE_SETREGS
[ 8487.588343] [*] rax:           (null)
[ 8487.588344] [*] rbx:           (null)
[ 8487.588344] [*] rcx: 00000000000000a0
[ 8487.588345] [*] rdx: 00007fffffffee90
[ 8487.588346] [*] rsi:           (null)
[ 8487.588347] [*] rdi: 0000555555757070
[ 8487.588348] [*] rbp: 0000555555555bc0
[ 8487.588348] [*] rsp: 00007fffffffed80
[ 8487.588349] [*] rip: 0000555555555c1e
[ 8487.588351] [*] PTRACE_CONT
[ 8487.588361] [*] PTRACE_GETREGS
[ 8487.588369] [*] Writing 2 bytes from 00007ffff7fca810 to 0000555555555c1e (1c1e): ccc3
[ 8487.588372] [*] Reading 3 bytes from 0000555555555744 to 00007ffff7fca810: ccc3fe
[ 8487.588374] [*] Writing 3 bytes from 00007ffff7fde012 to 0000555555555744 (1744): 905dc3
[ 8487.588377] [*] PTRACE_SETREGS
[ 8487.588378] [*] rax: 00007fffffffecf0
[ 8487.588378] [*] rbx:           (null)
[ 8487.588379] [*] rcx: 00007ffff7262ed7
[ 8487.588380] [*] rdx: 0000000000000007
[ 8487.588381] [*] rsi: 00007ffff7531d10
[ 8487.588382] [*] rdi: 00007fffffffecf0
[ 8487.588382] [*] rbp: 00007fffffffec50
[ 8487.588383] [*] rsp: 00007fffffffec50
[ 8487.588384] [*] rip: 0000555555555744

...
```

The first write and read of each "block" look very repetitive and not very interesting. However the last write does appear to be interesting with different data every time. The data didn't appear to be ASCII or the flag encoded in any way, however each piece appeared to form valid x64 instructions. Then it hit me, the parent was rewriting the child code on the fly, every time the child hit an `int 3`, the parent would be notified and would replace the `int 3`s with real instructions.

At this point I spent a while trying to dump the whole patched binary from the kernel module after the final write, however I couldn't get the file IO to work correctly for some reason. So I resorted to a more hacky technique - I grepped all of the patches and offsets out from `dmesg`, and applied them manually via Python to the previously dumped second stage.

Now we finally had the complete second stage binary and could see what it was doing. 

Some of the functions initially looked pretty heavy.
![Decryption loop in IDA](/images/second_1.png)


However after spotting some MD5 constants it soon became clear that all the bad looking functions were actually MD5, which was nice.
```c
_DWORD *__fastcall sub_16FB(_DWORD *a1)
{
  _DWORD *result; // rax

  a1[2] = 0x67452301;
  a1[3] = 0xEFCDAB89;
  a1[4] = 0x98BADCFE;
  a1[5] = 0x10325476;
  *a1 = 0;
  result = a1;
  a1[1] = 0;
  return result;
}
```

There were also some slight modifications to the MD5 algorithm which were designed to make the MD5 wrong if you executed the second stage as a standalone binary. Specifically there were two calls to `umask`, which would return 1 (due to seccomp) when run within `main`, and return something else when run outside of `main`. If the `PWD` environment variable was set it would also xor an MD5 value with the address of the environment variable. `PWD` would usually be set if the binary was executed from a shell however it wouldn't be set if executed from `main`. 


It became clear that the binary was checking whether `MD5(argv[0]) == transform(argv[1])`, where `transform` was `sub_A0E` and was taking 32 hex digits and performing some transformation. If the results matched then the we had a valid key.

# Hooking `execve`
At this point all we had to do was find a way to get the same MD5 as the binary for a given `argv[0]` and reverse the transformation, which would give us `argv[1]` for a given `MD5(argv[0])`, and we were done. The second task proved significantly easier and my teammate quickly put together a script which reversed the transformation. Unfortunately, despite `LD_PRELOAD`ing the `umask` and unsetting `PWD` we couldn't get a correct hash from running the second stage binary standalone, so we realised we were going to have to dump it from normal execution of the second stage spawned by `main`. Debugging `main` was a challenge, so instead we planned to `LD_PRELOAD` the `strcmp` in the second stage, which compared the hash and the transformed `argv[1]`, and dump the first argument to get the hash. 

We quickly remembered that the second stage is spawned with a null environment and therefore our `LD_PRELOAD` wouldn't be present. In a flurry of questionable judgement (and forgetting `/etc/ld.so.preload`) we all decided that the best way to get around this was to hook `execve` and inject the `LD_PRELOAD` environment variable into the second stage, which made complete sense given we already had a kernel module with hooking functionality...

I tried to add the `execve` hook to my module code however I couldn't get it to work. While I was trying to fix this my teammate managed to come up with another novelty solution. He found https://github.com/kfiros/execmon, a process monitoring tool, which hooks `execve`, so he declared that he was simply going to patch that to inject the `LD_PRELOAD` environment variable. To our surprise the whole thing worked flawlessly and we were now successfully hooking `execve`, injecting `LD_PRELOAD` and hitting our proxy `strcmp`.

The patch to hook `execve('/proc/self/fd/3')` in `execmon` follows:
```c
diff --git a/kmod/syscalls.c b/kmod/syscalls.c
index b841594..76fa4fd 100644
--- a/kmod/syscalls.c
+++ b/kmod/syscalls.c
@@ -65,37 +65,20 @@ cleanup:
 static asmlinkage long new_sys_execve(const char __user * filename,
                                const char __user * const __user * argv,
                                const char __user * const __user * envp) {
-       size_t exec_line_size;
-       char * exec_str = NULL;
-       char ** p_argv = (char **) argv;
 
-       exec_line_size = (strlen(filename) + 1);
+    void* data = (void*)kmalloc(512, GFP_KERNEL);
+    copy_from_user(data, (void*)filename, 512);
 
-       /* Iterate through the execution arguments, to determine the final
-       size of the execution string. */
-       while (NULL != *p_argv) {
-               exec_line_size += (strlen(*p_argv) + 1);
-               (char **) p_argv++;     
-       }
-       
-       /* Allocate enough memory for the execution string */
-       exec_str = vmalloc(exec_line_size);
-       if (NULL != exec_str) {
-               snprintf(exec_str, exec_line_size, "%s", filename);
-
-               /* Iterate through the execution arguments */
-               p_argv = (char **) argv;
-               while (NULL != *p_argv) {
-                       /* Concatenate each argument with our execution line */
-                       snprintf(exec_str, exec_line_size,
-                                       "%s %s", exec_str, *p_argv);
-                       (char **) p_argv++;     
-               }
-
-               /* Send execution line to the user app */
-               COMM_nl_send_exec_msg(exec_str);
-       }
+       size_t exec_line_size = (strlen(data) + 1);
 
+    const long long int MAIN_EMPTY_SPACE = 0x604f30;
+    if (!strncmp(data, "/proc/self/fd/3", exec_line_size)) {
+        printk("[*] FD3 exec found :D\n");
+        
+        char data[] = "\x40\x4f\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LD_PRELOAD=/home/vagrant/hook/strcmp.so\x00";
+        copy_to_user(MAIN_EMPTY_SPACE, data, 56);
+        return orig_sys_execve_fn(filename, argv, (const char __user* const __user*)MAIN_EMPTY_SPACE);
+    }
 
        /* Finally, call the original sys_execve */
        return orig_sys_execve_fn(filename, argv, envp);
```

Now that we could get the correct MD5 from our proxy `strcmp` for a given `argv[0]`, and we had reversed the transformation, we just had to script the whole thing up and connect it to the network service provided.

```python
#!/usr/bin/env python2

from pwn import *


def prog():
    return remote('keygenme.ctfcompetition.com', 1337)

def untransform(data):
    data = unhex(data)
    out = [0] * 16
    for j in range(16):
        x = j ^ ord(data[j]) ^ (16*j)
        out[j] |= x & 0xF
        out[15-j] |= x & 0xF0
    return enhex(''.join(map(chr, out)))

def find_key(name):
    ret = ''
    with process('./main') as p:
        p.sendline(name + '0'*32)
        p.recvuntil('---') # StRcMp
        p.recvuntil('---') # str1
        p.recvuntil('--- ') # str 2 - our hash
        ret = p.recvuntil('NO!')[:-3]
    print ret
    ret = untransform(ret)
    print ret
    return ret

def main():
    with prog() as p:
        while True: # do rounds
            name = p.recvline().strip('\n')
            print name
            p.sendline(find_key(name))
            print p.recvuntil('OK\n')


if __name__ == "__main__":
    main()
```

Finally running this gave us the flag!
```bash
user@re:~$ sudo insmod execmon.ko
user@re:~$ python2 keygen.py
OPXnO
bd19551f05faa04c2fe2b631f0c26c25
dd88173c811f76ab37cbac4a2c7f02ba
OK

...

LGXJE
3b19ad4952baa02c6d88c045e9f10155
abe82f2af66f16eb55c1ea1e758c0f3a
OK

CTF{g1mm3_A11_T3h_keyZ}
```


# Conclusion
This was a really fun challenge with lots of detail. We definitely took many questionable turns along the road but we still managed to solve it in the end. Thanks GoogleCTF!