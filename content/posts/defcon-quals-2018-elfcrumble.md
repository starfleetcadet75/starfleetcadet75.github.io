---
title: "DEFCON CTF Quals 2018: ELF Crumble"
summary: "For this challenge we start off with a program which is aptly named `broken` as it segfaults when run."
date: 2018-05-18
categories:
  - "writeups"
tags:
  - "reversing"
  - "forensics"
---

**Category:** warmup  
**Points:** 102  
**Provided:**  

- [broken](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/broken)
- [fragment_1.dat](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/fragment_1.dat)
- [fragment_2.dat](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/fragment_2.dat)
- [fragment_3.dat](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/fragment_3.dat)
- [fragment_4.dat](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/fragment_4.dat)
- [fragment_5.dat](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/fragment_5.dat)
- [fragment_6.dat](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/fragment_6.dat)
- [fragment_7.dat](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/fragment_7.dat)
- [fragment_8.dat](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/fragment_8.dat)

## Observations

For this challenge we start off with a program which is aptly named `broken` as it segfaults when run. Opening it in Binary Ninja shows us why:

![original-binary](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/original-binary.png)

We notice there are 5 functions `main`, `f1`, `f2`, `f3`, and `recover_flag` which have all been replaced with X's.
We are given 8 fragments so its not a 1-1 match for each function. The fragment sizes are as follows:

```bash
 79 fragment_1.dat
 48 fragment_2.dat
175 fragment_3.dat
 42 fragment_4.dat
128 fragment_5.dat
 22 fragment_6.dat
283 fragment_7.dat
 30 fragment_8.dat
```

The total size of the fragments adds up to 807 bytes which is also the size of the missing region in the binary.

## Solution

The fragments contain the missing instructions for our binary and we need to put them back in the right places.
This challenge really showed off the great hex editing abilities of Binary Ninja.
I opened up each fragment and started creating user defined functions to disassemble them.
Then I compiled a list of each function fragments size and classified them based on whether they appeared to be function prologues, epilogues, or the main body itself.

```none
Fragment 1:
sub_0 = 3 (epilogue)
sub_3 = 69 (complete function)
sub_48 = 7 (prologue)

Fragment 2:
sub_0 = 16 (epilogue)
sub_11 = 31 (prologue)

Fragment 3:
sub_0 = 175 (body)

Fragment 4:
sub_0 = 42 (epilogue)

Fragment 5:
sub_0 = 109 (body and epilogue)
sub_6d = 19 (prologue)

Fragment 6:
sub_0 = 22 (body)

Fragment 7:
sub_0 = 283 (body)

Fragment 8:
sub_0 = 30 (prologue)
```

Then we can calculate the size of each missing function:

```none
main: 248
f1: 316
f2: 69
f3: 116
recover_flag: 58
```

Immediately we see that fragment 7 must be part of `f1()`.
We can also identify that `sub_3` from fragment 1 must be `f2()`.

`sub_0` from fragment 3 has the only interesting strings from any of the fragments and very much looks like a main function, so we can conclude that it is part of `main()`.
This means that we are still missing 73 bytes from `main()`.
`sub_11` from fragment 2 is 31 bytes and `sub_0` from fragment 4 is 42 bytes which together gives us the missing 73 bytes from `main()`.

Next, we see that `sub_6d` in fragment 5, fragment 6, and `sub_0` in fragment 2 adds up to give us the `recover_flag()` function.

Eventually we end up with the order of the fragments being 8, 7, 1, 5, 6, 2, 3, 4.
After moving the fragments into place using Binary Ninja, we have a [fixed binary](https://github.com/starfleetcadet75/writeups/raw/master/2018-DEFCON-CTF-Quals/broken_fixed) that prints the flag when run.

**Flag:** `welcOOOme`

## The Brute Force Option

Looking at other writeups online, it seems the common solution was to write a script that tried going through the possible permutations.
One of my teammates did quickly throw together the following script to do just that.
He let it run for quite a while and it did indeed yield the answer, however solving by hand was not that hard and proved to be more enjoyable.

```python
import itertools
import subprocess
import time
import os

def load(filename):
    with open(filename, "r") as f:
      return f.read()

# 0x5ad 8d3
with open('broken', 'r') as f:
    preamble = f.read(0x5ad)
    f.read(807) # junk
    postamble = f.read()

i = 0
for xs in itertools.permutations([1,2,3,4,5,6,7,8]):
    content = "".join(map(lambda x: load("fragment_{}.dat".format(x)), xs))
    filename = "./brokend/broken{}".format(i)
    with open(filename, "w") as f:
        f.write(preamble)
        f.write(content)
        f.write(postamble)
    os.chmod(filename, 0755)
    time.sleep(0.05)

    brok = subprocess.Popen([filename], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    i += 1
    response = brok.stdout.read()

    if not response:
        continue
    else:
        print response
```
