---
layout: post
title: "Cyberstakes CTF 2020: National Dex #65"
categories: writeups
---

* **Category:** Reverse Engineering
* **Points:** 100

## Challenge

We found the [encryptor](https://github.com/starfleetcadet75/writeups/raw/master/2020-Cyberstakes/national-dex-65/encrypt) but it won't decrypt [encrypted](https://github.com/starfleetcadet75/writeups/raw/master/2020-Cyberstakes/national-dex-65/encrypted)?

#### Hints

- I think they're using a cipher designed by Bruce Schneier.
- When reversing, it's useful to look for magic constants or use a tool like findcrypt (idapython version or Ghidra version).
- Make sure you're using CBC mode.

## Observations

Most modern encryption functions use identifiable constant values, usually to initialize their state before performing an operation.
[FindCrypt](https://github.com/d3v1l401/FindCrypt-Ghidra) uses a database of these constants to scan programs for their occurrence.
Running it on the `encrypt` program in Ghidra, we are shown the following results:

![findcrypt](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Cyberstakes/national-dex-65/findcrypt.png)

Bruce Schneier is the creator of Blowfish, so the results seem to confirm that this is the cipher in use.
The `bf_init` array at 0x493a60 is used in a function called `BF_set_key` so we navigate there.

![bfsetkey](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Cyberstakes/national-dex-65/bfsetkey.png)

We can see where the S and P boxes of the Blowfish cipher are created.
The key itself is probably passed in as an argument to this function from somewhere else.
Following the cross references takes us to the following location:

![bf_key](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Cyberstakes/national-dex-65/bf_key.png)

We can see that an array called `GLOBAL2` is used as an argument to the `BF_set_key` function.
This is the constant key value that the program uses to perform encryption but we still need to find the IV value.
If we look a little further below the `GLOBAL2` array, we notice another array called `GLOBAL1` which looks like a good candidate.

## Solution

We can write a short decryptor script using [PyCryptodome](https://www.pycryptodome.org/en/latest/) and copy the arrays from Ghidra.

```python
from Crypto.Cipher import Blowfish

bs = Blowfish.block_size
iv = b'\x71\x3a\xf2\x9a\x59\x36\x0b\xe4'
key = b'\xb0\x23\xc0\x4d\xcc\x55\x32\x41\xf6\x8a\xb3\xf7\x66\x91\x0c\x26'
ciphertext = b'\xd5\x35\x8e\xdd\x59\x3b\x4f\xe4\x13\x9b\x81\xde\xf6\xb7\xd7\x97\xd3\x93\x59\x9d\xc9\xa5\x46\x21\xde\x1c\xaa\xc9\x08\x26\x35\xf2'

cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
msg = cipher.decrypt(ciphertext)
print(msg)
```

**Flag:** `ACI{7845061bac2563882068e7f7061}`
