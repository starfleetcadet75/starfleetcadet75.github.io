---
title: "Flare-On CTF 2020 Challenge 2: garbage"
summary: "One of our team members developed a Flare-On challenge but accidentally deleted it. We recovered it using extreme digital forensic techniques but it seems to be corrupted."
date: 2020-09-19
categories:
  - "writeups"
tags:
  - "reversing"
---

## Challenge

> One of our team members developed a Flare-On challenge but accidentally deleted it.
> We recovered it using extreme digital forensic techniques but it seems to be corrupted.
> We would fix it but we are too busy solving today's most important information security threats affecting our global economy.
> You should be able to get it working again, reverse engineer it, and acquire the flag.

## Observations

The program `garbage` throws an error when we try to execute it.
Examining the program in Binary Ninja, we can see that the resource section has been cutoff and is missing part of the manifest.
We can also see from the section names that the program is packed with UPX.

![missing_rsrc](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/garbage/missing_rsrc.PNG)

## Repairing the Program

PE-Bear indicates that the resource section is supposed to be 0x400 bytes long.
We can use a hex editor to manually fix the manifest and then pad it out to the requested size of 0x400 bytes.

![fixed_rsrc](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/garbage/fixed_rsrc.png)

The application now displays a different error that the "side-by-side configuration is incorrect".
It turns out that the size of the manifest in the resource directory must match its actual size in bytes.
We can use CFF Explorer to change the size to equal the new length in bytes.

![fixed_size](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/garbage/fixed_size.png)

The program now runs without displaying an error message but still crashes.
At this point, CFF can now correctly unpack the program.
The import table for the unpacked program appears to indicate that it imports functions from two DLLs but it does not list their names.
Based on the imported function names, we can manually set the names to be kernel32.dll and shell32.dll.

![missing_imports](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/garbage/missing_imports.PNG)

The last obstacle we must address are the missing relocations.
The relocations should appear following the resource section but have been cut off.
This is simple to fix however since we can just tell the loader to ignore them.

![fixed_reloc](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/garbage/fixed_reloc.PNG)

Now that the [program has been repaired](https://github.com/starfleetcadet75/writeups/blob/master/2020-Flareon-CTF/garbage/garbage_fixed.exe), it drops a VBS script to the current directory that displays our flag:

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/garbage/flag.PNG)
