---
layout: post
title: "Cyberstakes CTF 2018: Protocol"
author: starfleetcadet75
categories: writeup
tags: [cat/reversing, tool/binary-ninja, tool/wireshark]
---

* **Category:** Reverse Engineering
* **Points:** 150

<br />

Provided files:
- [challenge.pcap](https://github.com/starfleetcadet75/writeups/raw/master/2018-Cyberstakes/Protocol/challenge.pcap)
- [bserver](https://github.com/starfleetcadet75/writeups/raw/master/2018-Cyberstakes/Protocol/bserver)
- [libc.so](https://github.com/starfleetcadet75/writeups/raw/master/2018-Cyberstakes/Protocol/libc.so)

<br />

# Hints

- The provided packet capture is of communication between the client and server.
- Analyze the server to determine how the communication happens and what it means!
- The server is runnable, you can try communicating with it locally.

<br />

# Observations

We are provided with a server that implements a custom protocol and a packet capture of the protocol being used. 
Opening the server in Binary Ninja, we are drawn to a function called `RRQ_handler`. The rest of the `main` function appears to be boilerplate socket programming. 
A simple Google for `RRQ` points us to the Wikipedia page for [TFTP](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol). 
TFTP, as the name implies, is used for transferring files over a network and uses UDP as the transfer protocol. 
A TFTP server will listen on one specific port for an initial connection. 
Once a client has connected, the server chooses a random data transfer port to use for the remainder of the exchange.
Looking at the `RRQ_handler` function, we can see a call to `fork` and then subsequent calls to create a new socket within the new process. 
This appears to be consistant with TFTP.

### TFTP

1. Client sends a RRQ (read request) to the server at port number 69, containing the filename, transfer mode, and any other options.   
2. Server responds with a DATA packet to the RRQ. Packet is sent from a randomly allocated ephemeral port, and all future packets to the server should be directed to this port.   
3. Server sends numbered DATA packets to the client.   
4. Client replies with numbered ACK packets for all DATA packets.   

### Packet Capture

Turning our attention to the pcap file, we can see a lot of extra junk such as SSH packets. 
We know that TFTP uses UDP so if we filter by UDP packets, we can end up with this: 

![pcap](https://github.com/starfleetcadet75/writeups/raw/master/2018-Cyberstakes/Protocol/wireshark.png)


<br />

# Solution

The lengths of the packets, 262, shows up in calls to `malloc` inside the server program. This confirms that these are probably the right packets. 
The client is using port 46722 and the server is initially using 1234. The first message from the client is a 1 followed by the requested filename. 
The server, upon reciept of the RRQ, forks off the child process that then opens a new socket and the rest of the transmission uses port 47639. 
Each packet seems to start off with a sequence number that is used for ACKing data packets. 
For each message from the server, we can see the last four bytes contain some kind of data. The server is sending us the contents of the requested flag file, but only four bytes at a time. These bytes appear to be encoded in some manner.   
   
Looking back at the `RRQ_handler`, we can see a call to `rand` followed by the highlighted blocks:   

![server](https://github.com/starfleetcadet75/writeups/raw/master/2018-Cyberstakes/Protocol/binja.png)   

This is a loop that will execute 4 times, xoring the current flag character with a random byte value before sending these encoded characters to the client. 
If we look at the first block in the function, we can also see a call to `srand` with a seed value of 1. Since calls to `rand` will produce the same values given the same seed, we can now determine the exact sequence of random bytes and recover the contents of the flag.   

The [client.c](https://github.com/starfleetcadet75/writeups/raw/master/2018-Cyberstakes/Protocol/client.c) file provides an implementation of a client that can communicate with the given server program.  

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER "127.0.0.1"
#define PORT 1234
#define BUFLEN 262

char buf[BUFLEN];
struct sockaddr_in addr;
int addrlen = sizeof(addr);
int seqnum = 0;

void hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

void process_packet(int sockfd) {
	seqnum++;

	memset(buf, 0, BUFLEN);
	if (recvfrom(sockfd, buf, BUFLEN, 0, (struct sockaddr*) &addr, &addrlen) < 0) {
		fprintf(stderr, "recvfrom() failed\n");
		exit(1);
	}

	// Decrypt the message
	uint8_t key = (uint8_t) rand();
	printf("%x", key);
	// for (int i = 0; i< 4; i++) {
		// printf("%c", buf[258 + i] ^ key);
	// }

	memset(buf, 0, BUFLEN);
	buf[1] = 4;
	buf[3] = seqnum;

	if (sendto(sockfd, buf, BUFLEN, 0, (struct sockaddr*) &addr, addrlen) < 0) {
		fprintf(stderr, "sendto() failed\n");
		exit(1);
	}
}

int main(int argc, char* argv[]) {
	memset(buf, 0, BUFLEN);
	srand(1);  // Call `srand()` with the same seed as the server

	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		fprintf(stderr, "Failed to create socket\n");
		return 1;
	}

	memset((char*) &addr, 0, addrlen);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);

	if (inet_aton(SERVER, &addr.sin_addr) == 0) {
		fprintf(stderr, "inet_aton() failed\n");
		return 1;
	}

	printf("Sending initial Request to Read (RRQ)\n");
	buf[1] = 1;
	sprintf(&buf[2], "%s", "flag");

	if (sendto(sockfd, buf, BUFLEN, 0, (struct sockaddr*) &addr, addrlen) < 0) {
		fprintf(stderr, "sendto() failed\n");
		exit(1);
	}

	if (recvfrom(sockfd, buf, BUFLEN, 0, (struct sockaddr*) &addr, &addrlen) < 0) {
		fprintf(stderr, "recvfrom() failed\n");
		exit(1);
	}

	while (seqnum < 9) {
		process_packet(sockfd);
	}

	close(sockfd);
	return 0;
}
```

By creating a fake flag file with known contents and then running the client program, we can recover the random byte values. 
The following Scapy script then uses these values to iterate through the UDP packets in the pcap and decode the flag.  

```python
from scapy.all import *

pkts = rdpcap("./challenge.pcap")

# The random bytes determined from running the client program
key = bytearray(b'\x67\xc6\x69\x73\x51\xff\x4a\xec\x29')
index = 0
flag = ''

for pkt in pkts:
    # Only care about UDP packets
    if (pkt.haslayer(UDP)):
        chars = bytes(pkt[UDP].payload)[-4:]

        # Check if this payload has part of the flag
        if chars != '\x00\x00\x00\x00':
            for c in chars:
                flag += chr(ord(c) ^ key[index])

            index = index + 1

print(flag)
```

**Flag:** `ACI{1128d2e3744e402cd3cd594b30b}`
