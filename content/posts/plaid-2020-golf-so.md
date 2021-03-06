---
title: "Plaid CTF 2020: golf.so"
summary: "Upload a 64-bit ELF shared object of size at most 1024 bytes. It should spawn a shell when loaded using LD_PRELOAD"
date: 2020-04-20
categories:
  - "writeups"
tags:
  - "programming"
---

**Category:** Misc  
**Points:** 500  

## Challenge

![golf](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-PlaidCTF/golf.so/golf.png)

This challenge required the creation of a 64-bit ELF shared library that spawns a shell when loaded by a process.
Windows libraries typically contain a [DllMain](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain) function that is invoked whenever the libary is loaded by `LoadLibrary`.
The Linux equivalent is to mark a function as a special global constructor.
We can do this in GCC with `__attribute__((constructor))`.

```c
__attribute__((constructor)) void shell() {
    __asm__(
        "mov $231, %rax;"  // sys_exit_group
        "mov $42, %rdi;"   // int status
        "syscall;"
    );
}
```

This code will simply invoke the `exit_group` syscall with an argument of 42 whenever it gets loaded by the process.
We can compile it with `gcc golf.c -shared -s -nostdlib -nodefaultlibs -nostartfiles -o golf.so`, which will help save space.
To test that our function gets called, we run the library with `strace -E LD_PRELOAD=./golf.so /bin/true`.
The last line of the strace output prints `exit_group(42)`, which confirms that our code did indeed execute when loaded by `/bin/true`.

Despite stripping the binary, using only three assembly instructions, and avoiding the standard library, we still end up with an object of over 13k bytes in size.

## Custom ELF Binary

There is a good tutorial [here](https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html) on how to create a minimal 32-bit ELF executable.
Doing this requires us to ditch GCC completely and define our own ELF structures in assembly.

The first step is to update the 32-bit ELF structure to the 64-bit version.
Fortunately, someone has [already ported](https://blog.stalkr.net/2014/10/tiny-elf-3264-with-nasm.html) the code from the previous link.

You can read about the different ELF structures, including what fields changed, by running `man elf`.
The layout is as follows:

![elf](https://upload.wikimedia.org/wikipedia/commons/thumb/7/77/Elf-layout--en.svg/390px-Elf-layout--en.svg.png)

The ELF header appears at the start of the binary.
It contains the magic value that identifies this as an ELF file, the address of the entry point, the number of program headers that need to be parsed, and the offset to those program headers.
When an ELF is loaded by the kernel, every program header marked with type PT_LOAD is loaded into process memory.
The section header table and the section metadata is not needed for the program to actually run, so we will omit them to save space.

Adding shellcode from https://www.exploit-db.com/shellcodes/46907 to our file, we end up with the following initial code:

```asm
BITS 64

ehdr:                               ; Elf64_Ehdr
        db  0x7f, "ELF", 2, 1, 1, 0 ; e_ident
times 8 db  0
        dw  3                       ; e_type
        dw  0x3e                    ; e_machine
        dd  1                       ; e_version
        dq  shell                   ; e_entry
        dq  phdr - $$               ; e_phoff
        dq  0                       ; e_shoff
        dd  0                       ; e_flags
        dw  ehdrsize                ; e_ehsize
        dw  phdrsize                ; e_phentsize
        dw  1                       ; e_phnum
        dw  0                       ; e_shentsize
        dw  0                       ; e_shnum
        dw  0                       ; e_shstrndx
ehdrsize  equ  $ - ehdr

phdr:                               ; Elf64_Phdr
        dd  1                       ; p_type
        dd  5                       ; p_flags
        dq  0                       ; p_offset
        dq  $$                      ; p_vaddr
        dq  $$                      ; p_paddr
        dq  filesize                ; p_filesz
        dq  filesize                ; p_memsz
        dq  0x1000                  ; p_align
phdrsize  equ  $ - phdr

shell:
        xor  rsi,rsi
        push rsi
        mov  rdi,0x68732f2f6e69622f
        push rdi
        push rsp
        pop  rdi
        push 59
        pop  rax
        cdq
        syscall
filesize  equ  $ - $$
```

The Elf64_Ehdr is the ELF header and Elf64_Phdr is a single program header of type PT_LOAD.
Normally a program would contain at least two program headers; one for code and one for data.
However since this is not a requirement and we are trying to save space, we can condense the entire contents of the binary into the same segment.

Next we change the `e_type` field from 2 to 3, which indicates that this is a shared object and not an executable.
Since we manually laid out the ELF structures, we need NASM to output this as a flat binary:

```bash
nasm -f bin golf.asm -o golf.so
```

We are met with an interesting error when running this.
The `file` utility also gives an unexpected output.

![error](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-PlaidCTF/golf.so/error.png)

For some reason, `file` still thinks this is an executable despite the modified `e_type` field.
If we look back at the original GCC library we compiled, we notice that there is a program header of type PT_DYNAMIC.
It turns out that, in addition to requiring at least one PT_LOAD segment, [a shared library also requires a PT_DYNAMIC segment](https://michalmalik.github.io/elf-dynamic-segment-struggles).
In fact, the PT_DYNAMIC metadata is where we can indicate that a function is a global constructor by adding a DT_INIT entry.

Since segments can overlap, we can stick the PT_DYNAMIC segment inside of the already defined PT_LOAD one.
We just need to define a second program header and add the minimum required contents.

```asm
BITS 64

ehdr:                               ; Elf64_Ehdr
        db  0x7f, "ELF", 2, 1, 1, 0 ; e_ident
times 8 db  0
        dw  3                       ; e_type
        dw  0x3e                    ; e_machine
        dd  1                       ; e_version
        dq  shell                   ; e_entry
        dq  phdr - $$               ; e_phoff
        dq  0                       ; e_shoff
        dd  0                       ; e_flags
        dw  ehdrsize                ; e_ehsize
        dw  phdrsize                ; e_phentsize
        dw  2                       ; e_phnum
        dw  0                       ; e_shentsize
        dw  0                       ; e_shnum
        dw  0                       ; e_shstrndx
ehdrsize  equ  $ - ehdr

phdr:                               ; Elf64_Phdr
        dd  1                       ; p_type
        dd  7                       ; p_flags
        dq  0                       ; p_offset
        dq  $$                      ; p_vaddr
        dq  $$                      ; p_paddr
        dq  progsize                ; p_filesz
        dq  progsize                ; p_memsz
        dq  0x1000                  ; p_align
phdrsize  equ  $ - phdr
        ; PT_DYNAMIC segment
        dd  2                       ; p_type
        dd  7                       ; p_flags
        dq  dynamic                 ; p_offset
        dq  dynamic                 ; p_vaddr
        dq  dynamic                 ; p_paddr
        dq  dynsize                 ; p_filesz
        dq  dynsize                 ; p_memsz
        dq  0x1000                  ; p_align

shell:
        ; execve("/bin/sh", ["/bin/sh"])
        mov  rdi, 0x68732f6e69622f
        push rdi
        push rsp
        pop  rdi
        push 59
        pop  rax

        ; Adjust stack address for argv array
        push 0
        push rdi
        mov  rsi, rsp
        cdq
        syscall

dynamic:
  dt_init:
        dq  0xc, shell
  dt_strtab:
        dq  0x5, shell
  dt_symtab:
        dq  0x6, shell
dynsize  equ  $ - dynamic

progsize  equ  $ - $$
```

The most difficult part of this challenge was determining the minimum valid contents needed for populating the dynamic segment.
The global constructor table that we used earlier to execute our shellcode is the important DT_INIT entry.
Despite the fact that there is no symbol table in the binary, the interpreter still requires that DT_STRTAB and DT_SYMTAB entries be present.

Lastly, we had to make a minor change to the shellcode in order to get the server to accept the binary.
The original version worked but the server insisted that the second argument had to point to the `argv` array on the stack.
This program comes in at 255 bytes, which is small enough for the first flag.

## Optimization

In order to get the second flag, we need to remove even more bytes from our binary.
We can do this with some trial and error by removing fields and seeing if the program still functions.

* The `e_shentsize`, `e_shnum` and `e_shstrndx` can be removed entirely with no side-effects since there are no section headers or symbol table.
* We can remove half the contents of the PT_DYNAMIC program header without crashing the program.
* The PT_LOAD segment cannot be shortened since the interpreter spits out an error about the program header size being wrong.

The final thing we can do is split our shellcode up into multiple stages and fill in the empty gaps.

* The `e_shoff` and `e_flags` fields take up 12 empty bytes in the ELF header.
* The `p_paddr` and `p_filesz` fields in the loadable segment take up 16 bytes.

Using an [online disassembler](https://defuse.ca/online-x86-assembler.htm), we can count bytes as we try to minimize the shellcode.
We can fit the "/bin/sh" string followed by a short jump to stage 2 perfectly into the empty space in the ELF header.
Stage 2 fits into the 16 bytes in the program header.
Through these optimizations we have eliminated the entire code section and moved it into the headers to give us the following:

```asm
BITS 64

ehdr:                               ; Elf64_Ehdr
        db  0x7f, "ELF", 2, 1, 1, 0 ; e_ident
times 8 db  0
        dw  3                       ; e_type
        dw  0x3e                    ; e_machine
        dd  1                       ; e_version
        dq  stage1                  ; e_entry
        dq  phdr - $$               ; e_phoff
stage1: ; 12 bytes
        mov rdi, 0x68732f6e69622f  ; 10 bytes
        jmp stage2  ; 2 bytes

        dw  ehdrsize                ; e_ehsize
        dw  phdrsize                ; e_phentsize
        dw  2                       ; e_phnum
ehdrsize  equ  $ - ehdr

phdr:                               ; Elf64_Phdr
        dd  1                       ; p_type
        dd  7                       ; p_flags
        dq  0                       ; p_offset
        dq  $$                      ; p_vaddr
stage2: ; 16 bytes
        xor rax, rax  ; 3
        push rdi  ; 1
        push rsp  ; 1
        pop rdi   ; 1
        push 0    ; 1
        push rdi  ; 1
        mov rsi, rsp  ; 3
        mov al, 59  ; 2
        syscall  ; 2

        dq  progsize                ; p_memsz
        dq  0x1000                  ; p_align
phdrsize  equ  $ - phdr
        dd  2                       ; p_type
        dd  7                       ; p_flags
        dq  dynamic                 ; p_offset
        dq  dynamic                 ; p_vaddr

dynamic:
  dt_init:
        dq  0xc, stage1
  dt_strtab:
        dq  0x5, stage1
  dt_symtab:
        dq  0x6, stage1
dynsize  equ  $ - dynamic

progsize  equ  $ - $$
```

This produces a binary of 186 bytes.

![flags](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-PlaidCTF/golf.so/flags.png)
