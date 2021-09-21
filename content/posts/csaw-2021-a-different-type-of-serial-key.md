---
title: "CSAW 2021: A Different Type of Serial Key"
summary: "Attached are serial captures of two different uploads to an embedded device."
date: 2021-09-12
categories:
  - "writeups"
tags:
  - "forensics"
  - "ics"
---

**Category:** ICS  
**Points:** 489  
**Provided:**  

- [capture.sal](https://github.com/starfleetcadet75/writeups/blob/master/2021-CSAW/a-different-type-of-serial-key/capture.sal?raw=true)
- [key.sal](https://github.com/starfleetcadet75/writeups/blob/master/2021-CSAW/a-different-type-of-serial-key/key.sal?raw=true)

## Challenge

> Attached are serial captures of two different uploads to an embedded device.
> One of these uploads is a key and the other is a function block.
> Your goal is to decode the serial traffic, extract the key and function block, and use these to find the flag.
> The flag will be in format flag{}.

## Decoding the Serial Data

Both of the provided captures are regular zip files with a different extension.
By examining the binary files inside, we see a reference to Saleae which hints that these are supported by Saleae's [logic analyzer software](https://support.saleae.com/logic-software).

```none
$ xxd digital-0.bin
00000000: 3c53 414c 4541 453e 0100 0000 6400 0000  <SALEAE>....d...
00000010: 0100 0000 0060 e366 41b8 f539 a77b 0100  .....`.fA..9.{..
00000020: 0008 3a5a d592 8ee7 3f00 000c 0000 0000  ..:Z....?.......
00000030: 0000 0000 0000 0000 0000 0000 2006 0000  ............ ...
00000040: 0000 0000 2006 0000 0000 0000 1bb7 0000  .... ...........
00000050: 0000 0001 0000 0000 0000 0003 0000 0000  ................
00000060: 0000 0058 bf7f 0100 0000 0000 0000 0000  ...X............
```

Importing both files into Logic 2 displays the waveforms for both the key and capture.

The key data contains two channels.
Channel 0 is clearly a clock signal due to how uniform the peaks are and the fact that it seems to be driving the transfer of data in Channel 1. This implies that Channel 1 is sending data, meaning that we are dealing with a synchronous protocol that uses two wires.

![screenshot1](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2021-CSAW/a-different-type-of-serial-key/screenshot1.png)

[I2C](https://support.saleae.com/tutorials/learning-portal/learning-resources/learn-i2c) seems a likely candidate so we enable the built-in I2C analyzer, which displays the byte values being sent to the device.

![screenshot2](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2021-CSAW/a-different-type-of-serial-key/screenshot2.png)

The values are:

`59 57 72 31 79 CE 94 8D 15 D4 54 02 7C 5C A0 83 3D AC B7 2A 17 67 76 38 98 8F 69 E8 D0`

Unlike the key data, the other capture shows four different channels with two large spikes where the data was being transmitted.

![screenshot3](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2021-CSAW/a-different-type-of-serial-key/screenshot3.png)

By zooming into the first peak we can see that Channel 0 again appears to be the clock signal.
Channel 1 transitions from high to low at the same time as the data in Channel 3 starts, indicating that it likely is enabling the transmission of data.

![screenshot4](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2021-CSAW/a-different-type-of-serial-key/screenshot4.png)

Based on these observations, this transmission appears to be using SPI.
There are 4 wires in SPI: A clock line (SCLK), an enable line (EN/SS), a dedicated master-to-slave data line (MOSI), and a dedicated slave-to-master data line (MISO).

![screenshot5](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2021-CSAW/a-different-type-of-serial-key/screenshot5.png)

The data being sent over the wire are ASCII strings starting with the letter "S".
The values are:

```none
S00C00004C6F63616C204B6579BF
S221020018423B165105BDAAFF27DB3B5D223497EA549FDC4D27330808F7F95D95B0EC
S5030001FB

S0210000506F77657250432042696720456E6469616E2033322D42697420537475620E
S12304EC9421FFD093E1002C7C3F0B78907F000C909F000839200000913F001C4800012C7E
S123050C813F001C552907FE2F890000409E0058813F001C815F000C7D2A4A1489290000FF
S123052C7D2A07743D20100281090018813F001C7D284A14892900003929FFFD5529063EC7
S123054C7D2907747D494A787D280774813F001C815F00087D2A4A14550A063E9949000074
S123056C480000BC815F001C3D205555612955567D0A48967D49FE707D2940501D29000317
S123058C7D2950502F890000409E0058813F001C815F000C7D2A4A14892900007D2A077476
S12305AC3D20100281090018813F001C7D284A1489290000392900055529063E7D2907743F
S12305CC7D494A787D280774813F001C815F00087D2A4A14550A063E99490000480000408D
S12305EC813F001C815F000C7D2A4A14890900003D20100281490018813F001C7D2A4A145A
S123060C89490000813F001C80FF00087D274A147D0A5278554A063E99490000813F001CA1
S123062C39290001913F001C813F001C2F89001C409DFED0813F00083929001D3940000040
S11B064C9949000060000000397F003083EBFFFC7D615B784E80002060
S503000CF0
```

The first three lines are taken from the first part of the waveform and the larger block is from the second part.
Searching for some of the values leads to [this source code reference](https://github.com/eerimoq/bincopy/blob/master/tests/test_bincopy.py#L1065) that hints that we are dealing with S-Records.

## Reversing the S-Records

S-Records are a type of binary file format used by Motorola for transferring data between two systems.
As the name implies, each record starts with a capital "S".

The `srecord` package on Ubuntu provides utilities for converting them into different formats.
We can use `srec_cat` to output the first file as a C array.
The comment indicates that this is likely some type of key embedded on the device.

```none
$ srec_cat -Output -C-Array output data1.srec 
srec_cat: data1.srec: 4: warning: no execution start address record
/* Local Key */
const unsigned char output[] =
{
0x42, 0x3B, 0x16, 0x51, 0x05, 0xBD, 0xAA, 0xFF, 0x27, 0xDB, 0x3B, 0x5D,
0x22, 0x34, 0x97, 0xEA, 0x54, 0x9F, 0xDC, 0x4D, 0x27, 0x33, 0x08, 0x08,
0xF7, 0xF9, 0x5D, 0x95, 0xB0,
};
const unsigned long output_termination = 0x00000000;
const unsigned long output_start       = 0x00020018;
const unsigned long output_finish      = 0x00020035;
const unsigned long output_length      = 0x0000001D;

#define OUTPUT_TERMINATION 0x00000000
#define OUTPUT_START       0x00020018
#define OUTPUT_FINISH      0x00020035
#define OUTPUT_LENGTH      0x0000001D
```

The second data file contains a blob of 32-bit PowerPC code.

```none
$ srec_cat -Output -C-Array output data2.srec 
srec_cat: data2.srec: 15: warning: no execution start address record
/* PowerPC Big Endian 32-Bit Stub */
const unsigned char output[] =
{
0x94, 0x21, 0xFF, 0xD0, 0x93, 0xE1, 0x00, 0x2C, 0x7C, 0x3F, 0x0B, 0x78,
0x90, 0x7F, 0x00, 0x0C, 0x90, 0x9F, 0x00, 0x08, 0x39, 0x20, 0x00, 0x00,
0x91, 0x3F, 0x00, 0x1C, 0x48, 0x00, 0x01, 0x2C, 0x81, 0x3F, 0x00, 0x1C,
0x55, 0x29, 0x07, 0xFE, 0x2F, 0x89, 0x00, 0x00, 0x40, 0x9E, 0x00, 0x58,
0x81, 0x3F, 0x00, 0x1C, 0x81, 0x5F, 0x00, 0x0C, 0x7D, 0x2A, 0x4A, 0x14,
0x89, 0x29, 0x00, 0x00, 0x7D, 0x2A, 0x07, 0x74, 0x3D, 0x20, 0x10, 0x02,
0x81, 0x09, 0x00, 0x18, 0x81, 0x3F, 0x00, 0x1C, 0x7D, 0x28, 0x4A, 0x14,
0x89, 0x29, 0x00, 0x00, 0x39, 0x29, 0xFF, 0xFD, 0x55, 0x29, 0x06, 0x3E,
0x7D, 0x29, 0x07, 0x74, 0x7D, 0x49, 0x4A, 0x78, 0x7D, 0x28, 0x07, 0x74,
0x81, 0x3F, 0x00, 0x1C, 0x81, 0x5F, 0x00, 0x08, 0x7D, 0x2A, 0x4A, 0x14,
0x55, 0x0A, 0x06, 0x3E, 0x99, 0x49, 0x00, 0x00, 0x48, 0x00, 0x00, 0xBC,
0x81, 0x5F, 0x00, 0x1C, 0x3D, 0x20, 0x55, 0x55, 0x61, 0x29, 0x55, 0x56,
0x7D, 0x0A, 0x48, 0x96, 0x7D, 0x49, 0xFE, 0x70, 0x7D, 0x29, 0x40, 0x50,
0x1D, 0x29, 0x00, 0x03, 0x7D, 0x29, 0x50, 0x50, 0x2F, 0x89, 0x00, 0x00,
0x40, 0x9E, 0x00, 0x58, 0x81, 0x3F, 0x00, 0x1C, 0x81, 0x5F, 0x00, 0x0C,
0x7D, 0x2A, 0x4A, 0x14, 0x89, 0x29, 0x00, 0x00, 0x7D, 0x2A, 0x07, 0x74,
0x3D, 0x20, 0x10, 0x02, 0x81, 0x09, 0x00, 0x18, 0x81, 0x3F, 0x00, 0x1C,
0x7D, 0x28, 0x4A, 0x14, 0x89, 0x29, 0x00, 0x00, 0x39, 0x29, 0x00, 0x05,
0x55, 0x29, 0x06, 0x3E, 0x7D, 0x29, 0x07, 0x74, 0x7D, 0x49, 0x4A, 0x78,
0x7D, 0x28, 0x07, 0x74, 0x81, 0x3F, 0x00, 0x1C, 0x81, 0x5F, 0x00, 0x08,
0x7D, 0x2A, 0x4A, 0x14, 0x55, 0x0A, 0x06, 0x3E, 0x99, 0x49, 0x00, 0x00,
0x48, 0x00, 0x00, 0x40, 0x81, 0x3F, 0x00, 0x1C, 0x81, 0x5F, 0x00, 0x0C,
0x7D, 0x2A, 0x4A, 0x14, 0x89, 0x09, 0x00, 0x00, 0x3D, 0x20, 0x10, 0x02,
0x81, 0x49, 0x00, 0x18, 0x81, 0x3F, 0x00, 0x1C, 0x7D, 0x2A, 0x4A, 0x14,
0x89, 0x49, 0x00, 0x00, 0x81, 0x3F, 0x00, 0x1C, 0x80, 0xFF, 0x00, 0x08,
0x7D, 0x27, 0x4A, 0x14, 0x7D, 0x0A, 0x52, 0x78, 0x55, 0x4A, 0x06, 0x3E,
0x99, 0x49, 0x00, 0x00, 0x81, 0x3F, 0x00, 0x1C, 0x39, 0x29, 0x00, 0x01,
0x91, 0x3F, 0x00, 0x1C, 0x81, 0x3F, 0x00, 0x1C, 0x2F, 0x89, 0x00, 0x1C,
0x40, 0x9D, 0xFE, 0xD0, 0x81, 0x3F, 0x00, 0x08, 0x39, 0x29, 0x00, 0x1D,
0x39, 0x40, 0x00, 0x00, 0x99, 0x49, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
0x39, 0x7F, 0x00, 0x30, 0x83, 0xEB, 0xFF, 0xFC, 0x7D, 0x61, 0x5B, 0x78,
0x4E, 0x80, 0x00, 0x20,
};
const unsigned long output_termination = 0x00000000;
const unsigned long output_start       = 0x000004EC;
const unsigned long output_finish      = 0x00000664;
const unsigned long output_length      = 0x00000178;

#define OUTPUT_TERMINATION 0x00000000
#define OUTPUT_START       0x000004EC
#define OUTPUT_FINISH      0x00000664
#define OUTPUT_LENGTH      0x00000178
```

The code disassembles to a short function that combines the first provided argument with the embedded key located at address 0x10020018.

![screenshot6](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2021-CSAW/a-different-type-of-serial-key/screenshot6.png)

We can now write a script that uses the transmitted key as the first argument to obtain the flag.

```python
key = [
    0x59, 0x57, 0x72, 0x31, 0x79, 0xCE, 0x94, 0x8D,
    0x15, 0xD4, 0x54, 0x02, 0x7C, 0x5C, 0xA0, 0x83,
    0x3D, 0xAC, 0xB7, 0x2A, 0x17, 0x67, 0x76, 0x38,
    0x98, 0x8F, 0x69, 0xE8, 0x00
]
local_key = [
    0x42, 0x3B, 0x16, 0x51, 0x05, 0xBD, 0xAA, 0xFF,
    0x27, 0xDB, 0x3B, 0x5D, 0x22, 0x34, 0x97, 0xEA,
    0x54, 0x9F, 0xDC, 0x4D, 0x27, 0x33, 0x08, 0x08,
    0xF7, 0xF9, 0x5D, 0x95, 0xB0
]

def decode(arg1, arg2):
    for i in range(28):
        if (i & 1) == 0:
            arg2[i] = arg1[i] ^ (local_key[i] - 3)
        elif (i % 3) == 0:
            arg2[i] = arg1[i] ^ (local_key[i] + 5)
        else:
            arg2[i] = arg1[i] ^ local_key[i]

out = [0] * len(key)
decode(key, out)

flag = [ chr(int(c)) for c in out ]
print("".join(flag))
```

**Flag:** `flag{s3r14l_ch4ll3ng3_s0lv3r}`
