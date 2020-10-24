---
title: "Flare-On CTF 2020 Challenge 8: Aardvark"
summary: "Expect difficulty running this one. I suggest investigating why each error is occuring. Or not, whatever. You do you."
date: 2020-09-18
categories:
  - "writeups"
tags:
  - "reversing"
---

## Challenge

> Expect difficulty running this one.
> I suggest investigating why each error is occuring.
> Or not, whatever.
> You do you.

## Observations

We are given a PE executable that complains about the current version of WSL present on the computer.

![first_error](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/aardvark/first_error.PNG)

If we downgrade our WSL to version 1, we can run the program and see that it is a simple tic-tac-toe game against an AI that cannot be beaten.
There are strings such as "X wins!" and "O wins!" present in the program but Binary Ninja does not indicate any cross-references to them.

## Solution

In Process Hacker we notice that there is an unknown process called *6730.tmp* that is run at the same time as the game.
The path to the process shows that it is written to disk at `C:\Users\<USER>\AppData\Local\Temp\6730.tmp`.

![processhacker](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/aardvark/processhacker.png)

Opening [6730.tmp](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/aardvark/6730.tmp) in Binary Ninja, we can see that it is an ELF program that is most likely executed inside the WSL environment.
There are now cross-references present to the "O wins!" string.

![xrefs](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/aardvark/xrefs.png)

If we look at the memory pages in Process Hacker for this process and not ttt2.exe, we eventually locate the board state as it is stored in memory.

![board_state](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/aardvark/board_state.png)

Overwriting the board state with all O's makes the game think we have won and prints the flag.

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/aardvark/flag.png)
