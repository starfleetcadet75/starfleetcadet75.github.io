---
title: "Flare-On CTF 2020 Challenge 9: crackinstaller"
summary: "What kind of crackme doesn't even ask for the password? We need to work on our COMmunication skills."
date: 2020-11-11
categories:
  - "writeups"
tags:
  - "reversing"
  - "windows-drivers"
---

## Challenge

> What kind of crackme doesn't even ask for the password?
> We need to work on our COMmunication skills.
>
> **Bug Notice:** Avoid a possible blue-screen by debugging this on a single core VM

## Observations

We are provided with a x86_64 PE executable that upsets Windows Defender.
[VirusTotal](https://www.virustotal.com/gui/file/b49f6cf962d78785f0d372e50183a6cf333a246e6d9debb7eb1e51af5995fd09/detection) already has plenty of detections for this program and it's behavior tab provides us some useful insight on the sample's functionality.

The program starts a new service called *cfs*, which probably executes the [cfs.dll](https://github.com/starfleetcadet75/writeups/blob/master/2020-Flareon-CTF/crackinstaller/cfs.sys) that was dropped into System32.
There is another embedded DLL called [credHelper.dll](https://github.com/starfleetcadet75/writeups/blob/master/2020-Flareon-CTF/crackinstaller/credHelper.dll) that gets dropped to `C:\Users\<USER>\AppData\Local\Microsoft\Credentials\credHelper.dll`.
It also accesses the registry key `HKCR\CLSID\{CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}`.

![vt_report](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/vt_report.PNG)

VirusTotal identifies the hash of cfs.dll [(da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24)](https://www.virustotal.com/gui/file/da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24/detection) as a device driver called *Capcom.sys*.

A quick search for Capcom leads to [this](http://www.fuzzysecurity.com/tutorials/28.html) blog post about the Capcom rootkit that includes a useful [Github](https://github.com/FuzzySecurity/Capcom-Rootkit) repository.

There is also an [article](https://www.theregister.com/2016/09/23/capcom_street_fighter_v/) that briefly describes its functionality:

> Capcom.sys completely blows this away on Windows: an application simply has to pass control codes 0xAA012044 and 0xAA013044 to the IOCTL, and a pointer to some instructions, and the driver will then jump to that block of code with full kernel permissions.

The Powershell PoC from FuzzySecurity hints at the functionality of the crackstaller program.
The script also includes a reference to the device name `Htsysm72FB`, which appeared in the VirusTotal report.

```powershell
# Some tricks here
# => cmp [rax-8], rcx
echo "`n[>] Allocating Capcom payload.."
[IntPtr]$Pointer = [CapCom]::VirtualAlloc([System.IntPtr]::Zero, (8 + $Shellcode.Length), 0x3000, 0x40)
$ExploitBuffer = [System.BitConverter]::GetBytes($Pointer.ToInt64()+8) + $Shellcode
[System.Runtime.InteropServices.Marshal]::Copy($ExploitBuffer, 0, $Pointer, (8 + $Shellcode.Length))
echo "[+] Payload size: $(8 + $Shellcode.Length)"
echo "[+] Payload address: $("{0:X}" -f $Pointer.ToInt64())"

$hDevice = [CapCom]::CreateFile("\\.\Htsysm72FB", [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)

if ($hDevice -eq -1) {
    echo "`n[!] Unable to get driver handle..`n"
    Return
} else {
    echo "`n[>] Driver information.."
    echo "[+] lpFileName: \\.\Htsysm72FB"
    echo "[+] Handle: $hDevice"
}

# IOCTL = 0xAA013044
#---
$InBuff = [System.BitConverter]::GetBytes($Pointer.ToInt64()+8)
$OutBuff = 0x1234
echo "`n[>] Sending buffer.."
echo "[+] Buffer length: $($InBuff.Length)"
echo "[+] IOCTL: 0xAA013044"
[CapCom]::DeviceIoControl($hDevice, 0xAA013044, $InBuff, $InBuff.Length, [ref]$OutBuff, 4, [ref]0, [System.IntPtr]::Zero) |Out-null
```

We already know a good deal about this program thanks to some basic OSINT work.
It drops a malicious Windows driver called cfs.dll to disk.
There is actually no need to spend time reversing this driver since we already know that its sole purpose is to execute some shellcode with full kernel permissions.

## Reversing Crackstaller.exe

The crackstaller.exe program performs steps similar to the above Powershell PoC.
It's purpose is to drop the embedded malicious driver and then execute some shellcode with elevated privileges.

It will eventually need to call `DeviceIoControl` in order to pass the shellcode to cfs.dll.
We can see that there is exactly one place where this happens and that the control code used is 0xAA013044.
The preceeding call to `VirtualAlloc` likely has something to do with setting up a buffer of shellcode.

![deviceiocontrol](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/deviceiocontrol.png)

To extract the contents of the shellcode buffer, we run the program until it reaches the call to `DeviceIoControl` and then dump the contents at that memory location.
Setting a breakpoint on `DeviceIoControl`, we can see the header of a PE executable appear in memory.

![dumping_shellcode](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/dumping_shellcode.png)

The program is yet another Windows driver.
The following diagram lays out the different components we are dealing with.

![diagram](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/diagram.png)

## Reversing Credhelper.dll

After running the program to completion with administrator rights, credHelper.dll gets dropped to the location originally mentioned in the VirusTotal report.
It is a COM server that implements a number of boilerplate functions such as `DllRegisterServer` and `DllGetClassObject`.

![credhelper_register](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/credhelper_register.PNG)

At the end of `DllRegisterServer` it creates new registry keys at `\\Registry\Machine\Software\Classes\CLSID\{CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}\Config\Flag` and `\\Registry\Machine\Software\Classes\CLSID\{CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}\Config\Password`.

![credhelper_register_keys](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/credhelper_register_keys.png)

It looks like the challenge wants us to enter the crackme password in the password registry key and it will then dump the flag to the other key.

A CLSID is a globally unique identifier that identifies the COM class object.
You can find an excellent presentation on how to reverse COM malware [here](https://github.com/strictlymike/presentations/blob/master/2020/2020.02.08_BSidesHuntsville/2020.02.08_Gophe_v1.5.pdf).
This challenge could have been solved by taking a deep dive into COM, but there is a simpler way.

The function at 0x18000153c uses `RegGetValueW` to access the stored password.
The rest of the function looks like state initialization code for [RC4](https://blog.talosintelligence.com/2014/06/an-introduction-to-recognizing-and.html).
The RC4 state structure is:

```c
struct rc4_state {
    uint8_t i;
    uint8_t j;
    uint8_t perm[0x100];
};
```

Retyping the second function argument, we can now follow where the substitution box is created.
This function only performs the initialization though, the actual xoring of data must occur elsewhere.

![rc4_init](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/rc4_init.png)

The following function at 0x1800016d8 generates the key stream and decodes the flag data.

![rc4_decode](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/rc4_decode.png)

The RC4 encrypted flag is:

```python
flag_ciphertext = [
    0x16, 0x56, 0xbc, 0x86, 0x9e, 0xe1, 0xd1, 0x02, 0x65, 0xc1, 0x69, 0x9f, 0x10, 0x0a, 0xac, 0xc1,
    0xf6, 0xe9, 0xfd, 0xb4, 0xcd, 0x22, 0x4a, 0x35, 0x9c, 0x12, 0x73, 0xbd, 0x2b, 0x10, 0x54, 0xb9,
    0x43, 0xd2, 0x13, 0x9a, 0x84, 0x65, 0xad, 0xb0, 0xbf, 0x5a, 0x81, 0x10
]
```

We still need to figure out the correct password in order to decrypt it.

## Reversing Driver.sys

The [driver.sys](https://github.com/starfleetcadet75/writeups/blob/master/2020-Flareon-CTF/crackinstaller/driver.sys?raw=true) program is fairly small.
It uses `CmRegisterCallbackEx` to register a callback function that is then called whenever a thread performs an operation on the registry.

![driverentry](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/driverentry.PNG)

Inside the callback function, the driver checks whether the triggering registry key started with a specific CLSID.
This is the same CLSID that appears in the credHelper.dll.
This driver functions as a filter driver that filters registry events and only performs an action when the given registry key has been accessed.

![callback_registry_check](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/callback_registry_check.PNG)

A [Yara scan](https://github.com/starfleetcadet75/binaryninja-yara) for cryptographic constants indicates that the driver can perform SHA-256 hashing and contains the code for a [ChaCha stream cipher](https://github.com/Ginurx/chacha20-c).

![yara_results](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/yara_results.png)

The matches indicate that the function at 0x1400034f0 performs state initialization for SHA-256 hashing.
We see that this function is called once and then followed by two related functions calls.
Searching for some simple C implementations on [Github](https://github.com/B-Con/crypto-algorithms/blob/master/sha256.h) provides us with the type signatures for these three functions.

![hashing](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/crackinstaller/hashing.png)

The key for the ChaCha20 cipher is the SHA-256 hash of 7 constant bytes of data.
If we try decrypting the password now, we will end up with junk.
It turns out that crackstaller.exe modifies those 7 bytes from `[0x23, 0x73, 0xb5, 0xc3, 0xf3, 0x16, 0xdc]` to `[0x42, 0x42, 0x41, 0x43, 0x41, 0x42, 0x41]` as the driver gets loaded.

## Solution

The RC4 encrypted flag is stored inside credHelper.dll.
The password to decrypt it is stored inside of driver.sys and also needs to be decrypted using ChaCha20.
The key for the ChaCha20 cipher is created by hashing 7 bytes from driver.sys.
These bytes are dynamically modified by crackstaller.exe as it loads the driver, adding an additional step to our analysis.

Putting all of these steps together yields the following solution:

```python
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import ARC4

# From driver.sys at 0x14000608c
# The original input values are modified dynamically as the driver is loaded
# [0x23, 0x73, 0xb5, 0xc3, 0xf3, 0x16, 0xdc] -> [0x42, 0x42, 0x41, 0x43, 0x41, 0x42, 0x41]
input_to_sha256 = [
    0x42, 0x42, 0x41, 0x43, 0x41, 0x42, 0x41
]

# From driver.sys at 0x140006078
input_to_chacha20 = [
    0x10, 0x31, 0xf0, 0x8b, 0x89, 0x4e, 0x73, 0xb5,
    0x30, 0x47, 0xad, 0x6e, 0x18, 0xa9, 0x5e
]

# From credHelper.dll at 0x18001a9f0
flag_ciphertext = [
    0x16, 0x56, 0xbc, 0x86, 0x9e, 0xe1, 0xd1, 0x02, 0x65, 0xc1, 0x69, 0x9f,
    0x10, 0x0a, 0xac, 0xc1, 0xf6, 0xe9, 0xfd, 0xb4, 0xcd, 0x22, 0x4a, 0x35,
    0x9c, 0x12, 0x73, 0xbd, 0x2b, 0x10, 0x54, 0xb9, 0x43, 0xd2, 0x13, 0x9a,
    0x84, 0x65, 0xad, 0xb0, 0xbf, 0x5a, 0x81, 0x10
]

h = SHA256.new()
h.update(bytes(input_to_sha256))
key = h.digest()
nonce = b"\x00" * 8
cipher = ChaCha20.new(key=key, nonce=nonce)

# Decrypt the password
password = cipher.decrypt(bytes(input_to_chacha20))
print("Password: " + str(password))

# Use the recovered password to decrypt the flag
cipher = ARC4.new(password)
flag = cipher.decrypt(bytes(flag_ciphertext))
print("Flag: " + str(flag))
```

**Flag:** `S0_m@ny_cl@sse$_in_th3_Reg1stry@flare-on.com`
