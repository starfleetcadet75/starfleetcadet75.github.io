---
layout: post
title: "Hack-A-Sat 2020: Sun? On my Sat?"
categories: writeups
---

* **Category:** Reverse Engineering / Exploitation
* **Points:** 324

## Challenge

We've uncovered a strange device listening on a port I've connected you to on our satellite. At one point one of our engineers captured the firmware from it but says he saw it get patched recently. We've tried to communicate with it a couple times, and it seems to expect a hex-encoded string of bytes, but all it has ever sent back is complaints about cookies, or something. See if you can pull any valuable information from the device and the cookies we bought to bribe the device are yours!

Provided File: [test.elf](https://github.com/starfleetcadet75/writeups/blob/master/2020-Hack-A-Sat/sun-on-my-sat/test.elf?raw=true)

## Observations

The challenge provides us with a 32-bit ELF program written for SPARC.
Ghidra's import summary shows that the program still contains debugging information including some of the source filenames.

```none
Program Name: test.elf
Processor: Sparc
Endian: Big
Address Size: 32
Executable Format: Executable and Linking Format (ELF)
ELF File Type: executable
ELF Original Image Base: 0x40000000
ELF Source File [0]: /opt/rtems/5/sparc-rtems5/leon3/lib/start.o
ELF Source File [1]: crtstuff.c
ELF Source File [2]: chal.c
ELF Source File [3]: io.c
ELF Source File [4]: crc.c
ELF Source File [5]: /tmp/ccnsQBw2.o
ELF Source File [6]: bspclean.c
... snip ...
```

Searching for the string “LEON” leads to the radiation-tolerant [LEON](https://en.wikipedia.org/wiki/LEON) microprocessor that implements the SPARC V8 ISA.
The end of the Wikipedia article mentions that [RTEMS](https://www.rtems.org/) is a RTOS that supports it.

## Debugging the Program

The RTEMS project includes plenty of documentation and we can browse through its source code.
Some further Googling turns up this [link](https://lists.rtems.org/pipermail/users/2014-September/028224.html) that indicates we might be able to run this program in QEMU.
It seems that the latest QEMU release has [source code](https://github.com/qemu/qemu/blob/master/hw/sparc/leon3.c) that references the LEON but it doesn't seem to run.

Following the instructions from the mailing list, we can download QEMU from source and checkout the v4.1.0 tagged release.
We then apply the provided patch file and build QEMU.
We are now able to run the application on our own system with `qemu-system-sparc -no-reboot -nographic -M leon3_generic -m 64M -kernel test.elf -gdb tcp::9000` and attach to it with GDB using `gdb-multiarch test.elf`.

![debugging](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Hack-A-Sat/sun-on-my-sat/debugging.PNG)

## Reversing the Protocol

Since debugging information is included in the program, locating the functions for the main application such as `readMsg()` and `msgHandler()` is straight forward.
The cross-references all lead us back to the `Init()` function, which implements the main program loop.

```cpp
void Init() {
  lastId = 0;
  puts("Configuration Server: Running");

  do {
    sleep(1);
    int msgLength = readMsg(msg, 64);
    msgHandler(msg, msgLength);
  } while (true);
}
```

First it calls `readMsg()` which reads 64 bytes into a global array called `msg` and returns the count of the total bytes read.
The first byte from the hex-encoded string indicates the total message size.

```cpp
int readMsg(char *msg, int length) {
  int input_length = (int) hexRead();
  if (length < input_length) {
    hangup("Message Too Long\n");
  }

  if (input_length < 2) {
    return 0;
  }

  for (int i = 0; input_length - 1 != i; i++) {
    msg[i] = hexRead();
  }

  return i;
}
```

The received message is then parsed by the `msgHandler()` function.
It is broken up into commands where the first byte indicates the command's length and the second byte indicates the command type.
The command types are:

| 0 | Header |
| 1 | GetInfo |
| 2 | Shutdown |
| 3 | getFlag |

The `getFlag()` function is a red haring that just prints "try harder" so we can safely ignore it.
Once a command has been parsed, the command length is added to the message pointer in order to move onto the next command in the buffer.

```cpp
char *msgHandler(char *msg, int msgLength) {
  bool headerReceived;
  char *msgPtr;
  
  if (0 < msgLength) {
    headerReceived = false;

    do {
      while (true) {
        msgPtr = msg;
        int cmdLength = getCmdLen(msgPtr);  // Get the byte at msg[0]
        int cmdType = getCmdType(msgPtr);   // Get the byte at msg[1]

        if (headerReceived == false && cmdType != 0) {
          hangup("Missing Header");
        }

        if (cmdType != 1)
            break;

        char *info = handleGetInfo(msgPtr);
        msgLength -= cmdLength;
        puts(info);

        msg = msgPtr + cmdLength;

        if (msgLength < 1)
            goto LAB_40001414;
      }

      if (cmdType < 2) {
        headerReceived = true;
        handleHeader(msgPtr);
      }
      else {
        if (cmdType == 2) {
          hangup("Shutdown Requested");
        }

        if (cmdType == 3) {
          getFlag(msgPtr);
        }

        hangup("Unexpected Message Section");
      }

      msgLength -= cmdLength;
      msg = msgPtr + cmdLength;
    } while (0 < msgLength);

LAB_40001414:
    msg = msgPtr + cmdLength;
  }

  puts("ACK");
  return msg;
}
```

### Header Command

The header check logic indicates that the first command received must be a header of command type 0 that gets parsed by the `handleHeader()` function.
We will need to send a valid header before it will accept any other commands.

```cpp
int handleHeader(char *msg) {
  bool valid = check_checksum(msg + 2);
  if (!valid) {
    hangup("Bad Checksum");
  }

  // Check the cookie value
  if (*(uint *)(msg + 4) == 0xf9b16b6c) {
    short msgId = getMsgId(msg);  // Reads two bytes from [msg+8]

    // Check the received message Id with the previous one
    if (lastId + 1 == msgId) {
      lastId = msgId;
      return 1;
    }
    hangup("Unexpected Msg Id");
  }
  hangup("Bad Cookie");
}
```

First the function computes a CRC8 checksum over the contents of the message starting at the first byte following the checksum value.
The byte preceeding the checksum is the checksum length and specifies how many bytes the checksum should be computed over.

```cpp
bool check_checksum(char *msg) {
  char msgChecksum = msg[1];  // Get the checksum from the msg
  char computedChecksum = crc8(msg + 2, msg[0]);  // Compute the checksum over msg[0] bytes
  return msgChecksum - computedChecksum;
}
```

If the checksum is valid, the function then checks that the next four bytes are equal to the `COOKIE` value of 0xf9b16b6c.
Lastly, the message Id is extracted and compared with the global variable `lastId + 1` to ensure that it is the next expected command.

The protocol for the header command (with the initial provided message length at the start) is as follows:

| Message Length (1) | Command Length (1) | Command Type (1) | Checksum Length (1) | CRC8 (1) | Cookie (4) | Message ID (2) | Next Command

### GetInfo Command

A command type of 1 is handled by the `handleGetInfo()` function.
`getStrIdx()` extracts the next byte from the message which is used as an index into a global array containing 3 different strings.
The third string is the flag.
`clipStrIdx()` performs a bounds-check on the index value before it accesses the array.

```cpp
char *handleGetInfo(char *msg) {
  int idx = getStrIdx(msg);
  int idx = clipStrIdx(idx);

  if ((idx - 1 < 3) && (CSWTCH.6[idx - 1] != NULL)) {
    return CSWTCH.6[idx - 1];
  }

  hangup("Invalid Config Option");
}
```

With the message protocol reversed, we can now craft messages that will print the version and serial strings from the `CSWTCH.6` array.

```python
# Create an empty message
msg = ["00"] * 60

# Header command
msg[1] = "0a"  # Command length
msg[2] = "00"  # Command type
msg[3] = "04"  # Checksum length
msg[4] = "45"  # Checksum
msg[5] = "f9"  # Cookie value
msg[6] = "b1"
msg[7] = "6b"
msg[8] = "6c"
msg[9] = "00"  # Message Id
msg[10] = "01"

# GetInfo command
msg[11] = "02"  # Command length
msg[12] = "01"  # Command type

# 1: Prints the program version
# 2: Prints the serial
# 3: Prints the flag
msg[13] = "02"

msg[0] = "0d"  # Set the total message length
msg = "".join(msg[:14])
print(msg)
```

![space_broker_msg](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Hack-A-Sat/sun-on-my-sat/space_broker_msg.PNG)

## Bypassing the Bounds Check

The function `clipStrIdx()`, which is called immediately prior to the array access, limits the index we can request to be 0, 1, or 2.
In order to access the flag, we need the index variable to be equal to 3.

There are two branch instructions inside `clipStrIdx()`.
The second one is an [_annulled_](https://stackoverflow.com/questions/604119/how-is-an-annulled-branch-different-from-a-regular-branch) branch that is indicated by the ",a" appended at the end of the mnemonic.
All branches in SPARC are delayed branches with the special case that if the branch is annulled, the instruction in the delay slot is ignored if the branch is not taken.
Ghidra does not seem to understand how annulment works and we can see that IDA produces a more accurate CFG.

![ghidra_bug](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Hack-A-Sat/sun-on-my-sat/ghidra_bug.PNG)

This branch tests whether the index is greater than the value of %g0, which holds a constant value of zero on SPARC.
If the index is greater than zero the function will move the index into the return value of %l7.
However, if the index is equal to zero, the `mov %i0, %l7` instruction will **not** be executed.
This means that the value returned from the function in %l7 will be equal to whatever its value was from before the function executed.
%l7 is an uninitialized variable when the index is equal to zero.

If we can control the value of %l7 and set it to 3, the program will print the flag.
Searching for all references to register %l7 throughout the program shows that the only application code that references it is inside the function `check_checksum()`.

![register_references](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Hack-A-Sat/sun-on-my-sat/register_references.PNG)

The result of the CRC8 calculation is passed through some useless shift operations.
%l7 is used as a temporary register to hold the value of the computed checksum and will retain that value when the function returns.

```asm
sll computedChecksum, 0x18, l7
srl l7, 0x18, l7
sub msgChecksum, l7, i0
```

If we set the message checksum field equal to 3, then %l7 will be set to 3.
We then need to make the actual index variable in our GetInfo command equal to 0 so that the program will use the uninitialized variable.
The final step is to make the checksum of the message actually equal to 3 so that it does not produce a bad checksum error.
To accomplish this, we can use CyberChef to determine how many null bytes we need to add to produce a CRC8 of 3.
Since the message buffer has a total size of 255 and the remaining unused bytes are initialized to zero, we can simply increase the checksum length field to include more null bytes.

![calc_crc](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Hack-A-Sat/sun-on-my-sat/calc_crc.PNG)

Sending the message `120a000d03f9b16b6c000102010000000000` to the server prints our flag.

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Hack-A-Sat/sun-on-my-sat/flag.PNG)
