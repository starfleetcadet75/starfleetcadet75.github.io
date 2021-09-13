---
title: "CSAW 2021: ncore"
summary: "We have a very safe core with a very safe enclave."
date: 2021-09-12
categories:
  - "writeups"
tags:
  - "reversing"
  - "verilog"
---

**Category:** Reversing  
**Points:** 484  
**Provided:**  

- [ncore_tb.v](https://github.com/starfleetcadet75/writeups/blob/master/2021-CSAW/ncore/ncore_tb.v?raw=true)
- [server.py](https://github.com/starfleetcadet75/writeups/blob/master/2021-CSAW/ncore/server.py?raw=true)

## Challenge

> We have a very safe core with a very safe enclave.
>
> `nc rev.chal.csaw.io 5002`

## Observations

The challenge provides us with a Verilog file along with a short Python script that is used to run the service.

```python
import os
import shutil
import subprocess

def main():
    print("WELCOME")
    txt = input()
    print(txt)
    addr = os.environ.get("SOCAT_PEERADDR")
    if(os.path.exists(addr)):
        shutil.rmtree(addr)
    os.mkdir(addr)
    shutil.copy("flag.hex",f"{addr}/flag.hex")
    shutil.copy("nco",f"{addr}/nco")
    ramf = open(f"{addr}/ram.hex","w")
    ramf.write(txt)
    ramf.close()
    p = subprocess.Popen(["vvp","nco"],stdout=subprocess.PIPE,cwd=f"./{addr}")
    out = p.communicate()[0]
    print(out)
    shutil.rmtree(addr)
    return

if __name__ == "__main__":
    main()
```

The script runs a program named `nco` using the [Icarus Verilog runtime engine](https://www.systutorials.com/docs/linux/man/1-vvp/).
We can create this program by compiling the provided Verilog file with `iverilog -g2012 -o nco ncore_tb.v`.
The server script provides the program with the flag and writes the user's input to the initial contents of the simulated CPU's RAM.

The Verilog program simulates a simple CPU with two-byte instructions.
The first four bits is the opcode and the second byte is the address used by certain instructions.
The list of possible opcodes is defined at the top of the file:

```verilog
`define ADD  4'd0
`define SUB  4'd1
`define AND  4'd2
`define OR   4'd3
`define RES 4'd4
`define MOVF 4'd5
`define MOVT 4'd6
`define ENT  4'd7
`define EXT  4'd8 
`define JGT  4'd9
`define JEQ  4'd10
`define JMP  4'd11
`define INC  4'd12
`define MOVFS 4'd13
```

The module includes four 32-bit registers in addition to a `safe_rom` and `ram` memory regions.
The `safe_rom` is initialized with the flag and the user's input is stored in the `ram`.
There is also a 32-bit random key that is initialized from `/dev/urandom` and a flag indicating whether the CPU is running in a certain mode.

```verilog
module ncore_tb;
  reg [7:0] safe_rom [0:255];
  reg [7:0] ram [0:255];
  reg [31:0] regfile [0:3];
  reg [31:0] key [0:0];
  reg emode;
  wire [3:0] opcode;
```

The main execution loop continously reads the next opcode from `ram` and executes each instruction.
The MOVFS instruction looks interesting since it is the only one that touches `safe_rom`.
If the `emode` flag is set, MOVFS will read a single byte from `safe_rom` at the given address.

```verilog
`MOVFS: begin
  if(emode) begin
    regfile[ram[pc][5:4]] <= safe_rom[ram[pc+1]];
  end
  increment_pc();
end
```

To summarize the challenge, we are provided with a simulation of some custom CPU that will execute arbitrary code in RAM that is submitted to the server.
The flag is stored in a protected ROM region of memory and we will need to disable the protection flag in order to read it.

## Solution

In order to access the flag, we need to set `emode`.
Calling the ENT instruction will set it if the first 14-bits of the key match the value of register R0.

```verilog
`ENT: begin
  // $display("%d | %d",regfile[0],key[0][13:0]);
  if(key[0][13:0]==regfile[0]) begin
    emode <= 1;
    regfile[3] <= 0;
    $display("ENT");
  end else begin
    regfile[3] <= 1;
  end
  increment_pc();
end
```

The value of key is randomized each time the simulation is run.
However, only the first 14-bits of the key are actually used, which reduces the range of possible values.
We can also execute arbitrary code including performing control flow operations without any constraints.

Using the INC instruction (0xc), we can continously increment the R0 register and try executing ENT.
We can then use JEQ (0xa) to either continue the bruteforce attempt or breakout of it once the `emode` flag is changed.

Once we have disabled the read protections, we can execute a MOVFS instruction to read a single byte from `safe_rom` into register R0.
The program prints the contents of RAM when it finishes so we will write the flag character from R0 to memory using the MOVT instruction (0x6).

```none
// Brute force the 14-bit key and check if emode is set
2c 00  // Set R2 = 1 for JEQ to test against
0c 00  // INC R0
07 00  // ENT
ea 02  // JEQ R2, R3, 2

// Read 32 bytes from safe_rom into the ram addresses that get printed to the terminal
0d 00  // MOVFS R0, 0x0
06 ff  // MOVT R0, 0xff
0d 01  // MOVFS 0x1
06 fe  // MOVT R0, 0xfe
0d 02  // MOVFS 0x2
06 fd  // MOVT R0, 0xfd
...
```

The Verilog file includes a number of commented out display statements that are useful for debugging the custom code.
Submitting these hex strings to the server yields the flag:

```python
from pwn import *

ram = "2c 00 0c 00 07 00 ea 02 0d 00 06 ff 0d 01 06 fe 0d 02 06 fd 0d 03 06 fc 0d 04 06 fb 0d 05 06 fa 0d 06 06 f9 0d 07 06 f8 0d 08 06 f7 0d 09 06 f6 0d 0a 06 f5 0d 0b 06 f4 0d 0c 06 f3 0d 0d 06 f2 0d 0e 06 f1 0d 0f 06 f0 0d 10 06 ef 0d 11 06 ee 0d 12 06 ed 0d 13 06 ec 0d 14 06 eb 0d 15 06 ea 0d 16 06 e9 0d 17 06 e8 0d 18 06 e7 0d 19 06 e6 0d 1a 06 e5 0d 1b 06 e4 0d 1c 06 e3 0d 1d 06 e2 0d 1e 06 e1 0d 1f 06 e0"

r = remote("rev.chal.csaw.io", 5002)
print(r.recvuntil(b"WELCOME\n"))
r.sendline(ram)

r.recvuntil("ENT\\n")
flag = r.recvuntil("xx")
flag = flag.decode()[:-3].split()
flag = [ chr(int(c, 16)) for c in flag ]
print("".join(flag))
```

**Flag:** `flag{d0nT_mESs_wiTh_tHe_sChLAmi}`
