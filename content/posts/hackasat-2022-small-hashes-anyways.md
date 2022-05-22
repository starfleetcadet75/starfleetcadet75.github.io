---
title: "Hack-A-Sat 2022: Small Hashes Anyways"
summary: "Micro hashes for micro blaze"
date: 2022-05-22
categories:
  - "writeups"
tags:
  - "reversing"
  - "microblaze"
---

**Category:** Reversing  
**Points:** 73  

## Challenge

> Micro hashes for micro blaze ¯\\_(ツ)_/¯
>
> [microblaze-linux.tar.bz2](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2022-Hack-A-Sat/small-hashes-anyways/microblaze-linux.tar.bz2)  
> [small_hashes_anyways](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2022-Hack-A-Sat/small-hashes-anyways/small_hashes_anyways)

## Observations

The challenge is a 32-bit program compiled for a MicroBlaze processor.

```none
small_hashes_anyways: ELF 32-bit MSB executable, Xilinx MicroBlaze 32-bit RISC, version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 3.2.0, stripped
```

We are also provided with a filesystem that includes the necessary shared libraries to run it using QEMU's usermode emulator.
It can be installed by running `apt-get install qemu-user qemu-user-static`.
The filesystem must be placed in `/opt/cross` in order for the symbolic links to work.

```none
mkdir /opt/cross
mv microblaze-linux /opt/cross
```

The program prompts the user for a 114 byte input.

```bash
$ qemu-microblaze -L /opt/cross/microblaze-linux small_hashes_anyways
small hashes anyways:
flag{AAAAAAAAAAAAAAAA}
wrong length wanted 114 got 22
```

If we supply it with an input of the correct length, it reports the first character that is incorrect and what the expected hash value was.

```bash
$ qemu-microblaze -L /opt/cross/microblaze-linux small_hashes_anyways
small hashes anyways:
flag{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}
mismatch 6 wanted 2607707657 got 817843024
```

We can use Binary Ninja with the [Microblaze](https://github.com/amtal/microblaze) architecture plugin to examine what the program is doing.
The `check_flag` function first checks that the input is 114 before entering the main loop.
It then iterates over each byte of the input, calling a function to calculate the hash of the current input byte given its position in the string.
The result of the hash is then compared against an entry in an array of 114 32-bit integers, which are the flag hash values.

![check_flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2022-Hack-A-Sat/small-hashes-anyways/check_flag.png)

The actual hash function uses the current position of the input byte to calculate a rolling result to include all of the previous input values.

![hash_function](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2022-Hack-A-Sat/small-hashes-anyways/hash_function.png)

## Solution

The hashes are reasonably small and we can assume that all of the flag characters are printable ASCII.
The challenge also tells us that our flag will begin with the string `flag{november314425india3:` which reduces the amount of characters to solve.
Most importantly, the program itself provides an oracle that reports exactly which byte is wrong.

We can write a simple bruteforce script that repeatedly runs the program with a new input.
If the program reports that the character at a specific index is wrong, we choose a random one from the list of possible values and try submitting the new input to see if the program advances.

```python
import sys
import string
import random
from pwn import *

# Create an initial flag that is 114 characters long with the known flag prefix
flag = b"flag{november314425india3:".ljust(113, b"a") + b"}"
flag = bytearray(flag)

while True:
    p = process(["qemu-microblaze", "-L", "/opt/cross/microblaze-linux", "small_hashes_anyways"])
    p.recvline()

    print(f"Trying {flag}")
    p.sendline(flag)
    resp = p.recvline()
    print(resp)

    # If there is an incorrect value, choose a new random value to try at that reported index
    if b"mismatch" in resp:
        data = resp.split()

        # The response uses indices starting at 1 not 0
        index = int(data[1]) - 1
        flag[index] = ord(random.choice(string.ascii_letters + string.digits + string.punctuation))
    else:
        print(f"The flag is: {flag}")
        sys.exit(0)

    p.close()
```

Running this script eventually solves for the flag:

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2022-Hack-A-Sat/small-hashes-anyways/flag.png)
