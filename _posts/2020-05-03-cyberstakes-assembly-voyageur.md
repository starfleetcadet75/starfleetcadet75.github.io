---
layout: post
title: "Cyberstakes CTF 2020: Assembly Voyageur"
categories: writeups
---

* **Category:** Misc
* **Points:** 300

## Challenge

It's time for an adventure. Begin your travels [here](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Cyberstakes/assembly-voyageur/AssemblyVoyageur.html)

#### Hints

- A good traveler knows that you should bring the right tools for the job: `sudo apt install gcc gcc-aarch64-linux-gnu gcc-mips-linux-gnu gcc-powerpc-linux-gnu gdb-multiarch qemu-user-static`
- Some assemblers support pseudo-instructions that aren't defined in the Instruction Set. Other assemblers may not support those pseudo-instructions, but do support the underlying instruction.

## Observations

The webpage for this challenge contains five textareas, each holding a snippet of assembly code for a different architecture.

![challenge](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Cyberstakes/assembly-voyageur/challenge.png)

Above each snippet is a set of initial conditions for the register state and a description that indicates the architecture type.
The register values that are output by executing one set of assembly are provided as inputs into the next one.
If we enter an incorrect solution into the challenge, the initial register values and assembly code are regenerated.

## Solution

The ideal solution to this challenge would have been to use [Keystone](https://github.com/keystone-engine/keystone) to compile the individual assembly and then feed its output into [Unicorn](https://github.com/unicorn-engine/unicorn) to emulate it and get a final result.
Unfortunately, even after regenerating the challenge multiple times, we run into issues.
Keystone would either fail to assemble certain instructions or Unicorn would fail while emulating the code.

This is not surprising given how unusual some of the assembly looks.
We will have to assemble these programs somewhat manually.
For the i386 and amd64 code, we can just use NASM:

```bash
nasm -f elf32 i386.asm -o i386.o
gcc i386.o -m32 -o i386.bin -static
```

For the other non-Intel code, we need to use the GCC toolchain for that specific architecture.
These can be installed with `sudo apt install gcc-{arch}-linux-gnu` just as the provided hint tells us.
The ARM assembly builds with no issues:

```bash
aarch64-linux-gnu-as aarch64.asm -o aarch64.o
aarch64-linux-gnu-gcc aarch64.o -o aarch64.bin -static
```

We do encounter some errors attempting to assemble the MIPS code.
The assembler complains about register names not being valid.
There are multiple names that can be used to refer to certain registers in MIPS assembly and apparently this assembler does not recognize all of them.
To solve this issue without modifying the actual code, we can add define statments at the top to provide the alternate register names:

```c
#define zero $0
#define AT   $1
#define v0   $2
#define v1   $3
#define a0   $4
#define a1   $5
#define a2   $6
#define a3   $7
#define s0   $16
#define s1   $17
#define s2   $18
#define s3   $19
#define s4   $20
#define s5   $21
#define s6   $22
#define s7   $23
#define t8   $24
#define t9   $25
#define jp   $25
#define k0   $26
#define k1   $27
#define gp   $28
#define sp   $29
#define fp   $30
#define s8   $30
#define ra   $31
```

We run into this same issue again with the PPC assembly.
With PPC however, the assembler supports an extra command line argument `-mregnames` which handles this for us:

```bash
powerpc-linux-gnu-as ppc.asm -mregnames -o ppc.o
powerpc-linux-gnu-gcc ppc.o -o ppc.bin -static
```

To automate this process, we can collect the above commands into a [Makefile](https://github.com/starfleetcadet75/writeups/blob/master/2020-Cyberstakes/assembly-voyageur/Makefile).

```
all: i368 amd64 aarch64 mips ppc

i386: i386.asm
	nasm -f elf32 i386.asm -o i386.o
	gcc i386.o -m32 -o i386.bin -static

amd64: amd64.asm
	nasm -f elf64 amd64.asm -o amd64.o
	gcc amd64.o -o amd64.bin -static

aarch64: aarch64.asm
	aarch64-linux-gnu-as aarch64.asm -o aarch64.o
	aarch64-linux-gnu-gcc aarch64.o -o aarch64.bin -static

mips: mips.S
	mips-linux-gnu-gcc mips.S -o mips.bin -static

ppc: ppc.asm
	powerpc-linux-gnu-as ppc.asm -mregnames -o ppc.o
	powerpc-linux-gnu-gcc ppc.o -o ppc.bin -static

clean:
	rm -rf *.o *.bin
```

We can also write a parser that will extract each snippet of assembly and write it to the source files.

```python
from bs4 import BeautifulSoup

with open("AssemblyVoyageur.html", "r") as f:
    page = f.read()

soup = BeautifulSoup(page, 'html.parser')
print(soup.prettify())

regstate = soup.body.find_all("ul")[0]
snippets = soup.body.find_all("textarea")
i386 = snippets[0]
amd64 = snippets[1]
aarch64 = snippets[2]
mips = snippets[3]
ppc = snippets[4]

# Create i386
with open("i386.asm", "w") as f:
    f.write("BITS 32\n")
    f.write("SECTION .text\n")
    f.write("global main\n")
    f.write("main:\n")

    # Add the initial register state
    for reg in regstate.find_all("li"):
        v, r = reg.contents[0].split()
        r = r[:-2].lower()
        f.write("mov " + r + ", " + v + "\n")

    for line in i386.contents:
        f.write(line)
    f.write("db 0xcc")

# Create amd64
with open("amd64.asm", "w") as f:
    f.write("BITS 64\n")
    f.write("SECTION .text\n")
    f.write("global main\n")
    f.write("main:\n")

    for line in amd64.contents:
        f.write(line)
    f.write("db 0xcc")

# Create aarch64
with open("aarch64.asm", "w") as f:
    f.write(".global main\n")
    f.write(".text\n")
    f.write("main:\n")

    for line in aarch64.contents:
        f.write(line)

# Create mips
with open("mips.S", "w") as f:
    f.write("#define zero $0\n")
    f.write("#define AT   $1\n")
    f.write("#define v0   $2\n")
    f.write("#define v1   $3\n")
    f.write("#define a0   $4\n")
    f.write("#define a1   $5\n")
    f.write("#define a2   $6\n")
    f.write("#define a3   $7\n")
    f.write("#define s0   $16\n")
    f.write("#define s1   $17\n")
    f.write("#define s2   $18\n")
    f.write("#define s3   $19\n")
    f.write("#define s4   $20\n")
    f.write("#define s5   $21\n")
    f.write("#define s6   $22\n")
    f.write("#define s7   $23\n")
    f.write("#define t8   $24\n")
    f.write("#define t9   $25\n")
    f.write("#define jp   $25\n")
    f.write("#define k0   $26\n")
    f.write("#define k1   $27\n")
    f.write("#define gp   $28\n")
    f.write("#define sp   $29\n")
    f.write("#define fp   $30\n")
    f.write("#define s8   $30\n")
    f.write("#define ra   $31\n")

    f.write(".global main\n")
    f.write(".text\n")
    f.write("main:\n")

    for line in mips.contents:
        f.write(line)

# Create ppc
with open("ppc.asm", "w") as f:
    f.write(".global main\n")
    f.write(".text\n")
    f.write("main:\n")

    for line in ppc.contents:
        f.write(line)
```

The full solution code can be found [here](https://github.com/starfleetcadet75/writeups/tree/master/2020-Cyberstakes/assembly-voyageur).

We can now easily create executables for each source file.
The last step is to run each program with the correct initial register values.
Instead of attempting to manually add new instructions to the beginning of each file, we can run each program with GDB and set the register values ourselves.

To debug the non-Intel programs, we can use QEMU's user-space emulation mode along with `gdb-multiarch`.
We compiled each program with the `-static` option, which means all of our programs are statically linked and should have no issues running in QEMU.
Each program can be debugged with the following:

```
qemu-{arch}-static -g 12345 ./{arch}.bin
gdb-multiarch ./{arch}.bin
```

The commands to enter in GDB, with the register values changed manually, are as follows:

```
// i386.bin
start
continue
info registers eax ebx ecx edx esi edi

// amd64.bin
start
set $rax = 0
set $rbx = 0xf
set $rcx = 0x18acfc96
set $rdx = 0xc052231
set $rsi = 0xc83cd
set $rdi = 0x91188000
continue
info registers rax rbx rcx rdx rsi rdi

// aarch64.bin
set architecture aarch64
set endian little
target remote localhost:12345
break main
continue
set $x1 = 0x16f5
set $x2 = 0x2dea
set $x3 = 0x15
set $x4 = 0
set $x5 = 0x16f500000
set $x6 = 0xb7a
continue
info registers x1 x2 x3 x4 x5 x6

// mips.bin
set architecture mips
set endian big
target remote localhost:12345
break main
continue
set $s1 = 0x9fe46ff7f1901bff & 0xffffffff
set $s2 = 0x2c0490ce5cce1c06 & 0xffffffff
set $s3 = 0x6000000000000000 & 0xffffffff
set $s4 = 0x6 & 0xffffffff
set $s5 = 0x34a5ffffea2b7f & 0xffffffff
set $s6 = 0x1b90080e6fe400 & 0xffffffff
continue
info registers s1 s2 s3 s4 s5 s6

// ppc.bin
set architecture powerpc:common
set endian big
target remote localhost:12345
break main
continue
set $r1 = 0
set $r2 = 0xffea29fe
set $r3 = 0
set $r4 = 0x4b800000
set $r5 = 0
set $r6 = 0
continue
info registers r1 r2 r3 r4 r5 r6
```

Running the PPC program gives us the final register values we need.

![ppc_running](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Cyberstakes/assembly-voyageur/running_ppc.PNG)

We can compute the final result from these registers and get the flag.

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Cyberstakes/assembly-voyageur/flag.PNG)
