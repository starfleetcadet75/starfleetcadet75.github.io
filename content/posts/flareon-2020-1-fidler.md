---
title: "Flare-On CTF 2020 Challenge 1: Fidler"
summary: "This is a simple game. Win it by any means necessary and the victory screen will reveal the flag."
date: 2020-09-18
categories:
  - "writeups"
tags:
  - "reversing"
---

## Challenge

> This is a simple game.
> Win it by any means necessary and the victory screen will reveal the flag.
> Enter the flag here on this site to score and move on to the next level.
> This challenge is written in Python and is distributed as a runnable EXE and matching source code for your convenience.
> You can run the source code directly on any Python platform with PyGame if you would prefer.

## Observations

We are provided with the source code for a small game in Python and with a runnable version of the program.

![password_prompt](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/fidler/password_prompt.PNG)

An incorrect password yields an excellant failure message:

![fail_screen](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/fidler/fail_screen.PNG)

## Reversing the Program

Since we are provided the source code, we can simply look at where the password is checked.
There is a function called `password_check` that checks whether the supplied password is "ghost":

```python
def password_check(input):
    altered_key = 'hiptu'
    key = ''.join([chr(ord(x) - 1) for x in altered_key])
    return input == key
```

We are next presented with a screen that forces us to play some sort of tedious coin game.

![coin_game](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/fidler/coin_game.PNG)

There is a function called `victory_screen` that makes a call to `decode_flag`.
It takes a single integer argument derived from the number of coins.
Since we already have the code, we can just iterate over every possible input and find the flag.

```python
def decode_flag(frob):
    last_value = frob
    encoded_flag = [
        1135, 1038, 1126, 1028, 1117, 1071, 1094, 1077, 1121, 1087, 1110, 1092,
        1072, 1095, 1090, 1027, 1127, 1040, 1137, 1030, 1127, 1099, 1062, 1101,
        1123, 1027, 1136, 1054
    ]
    decoded_flag = []

    for i in range(len(encoded_flag)):
        c = encoded_flag[i]
        val = (c - ((i % 2) * 1 + (i % 3) * 2)) ^ last_value
        decoded_flag.append(val)
        last_value = c

    return "".join([chr(x) for x in decoded_flag])

for i in range(1000):
    print(decode_flag(i))
```

Its pretty obvious from the output what the correct first letter should be:

```none
џdle_with_kitty@flare-on.com
ўdle_with_kitty@flare-on.com
ѝdle_with_kitty@flare-on.com
ќdle_with_kitty@flare-on.com
ћdle_with_kitty@flare-on.com
њdle_with_kitty@flare-on.com
љdle_with_kitty@flare-on.com
јdle_with_kitty@flare-on.com
їdle_with_kitty@flare-on.com
**іdle_with_kitty@flare-on.com**  <- flag
ѕdle_with_kitty@flare-on.com
єdle_with_kitty@flare-on.com
ѓdle_with_kitty@flare-on.com
ђdle_with_kitty@flare-on.com
ёdle_with_kitty@flare-on.com
ѐdle_with_kitty@flare-on.com
Яdle_with_kitty@flare-on.com
...
```
