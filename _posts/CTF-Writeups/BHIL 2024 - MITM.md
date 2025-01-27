---
title: "BHIL 2024 - Mitm"
classes: wide
header:
  teaser: /assets/images/ctf-writeups/utctf2020/logo.png
ribbon: green
description: "This challenge is asking for x64 shellcode to read the flag file, it's using some `seccomp rules` to limit us to only use `open/read/write/exit` syscalls (so we cannot spawn a shell).
We can write some assembly (painful) or we can use pwntools..."
categories:
  - CTF Writeups
---

> Challenge description:
>
> Mommy! I think I know how to make shellcodes




# MITM
This challenge contains two files:
* 1 - client.py
* 2 - mitm.pcapng
the `client.py` file is the client source code that communicate with the server, and the `mitm.pcapng` file is packets from the communication between them,
so we need to understand how to read that packets to reach the flag.

### client.py
In this file we can see that the client and the server do [Diffie Helman Key Swap](https://www.techtarget.com/searchsecurity/definition/Diffie-Hellman-key-exchange) before they start any communication, another thing that we can see is that the client and the server communicate under TCP, so that means they're going to do the [Three-Way Handshake](https://www.geeksforgeeks.org/tcp-3-way-handshake-process/) of TCP before any other communication.

#### client protocol:
In the funciton `recv_msg()` we can fing the communication protocol between the client and the server,
this protocol is very simple:
```
[4 bytes] - size
[{size} bytes] - msg
```
### mitm.pcapng
In this file we can see that [Three-Way Handshake](https://www.geeksforgeeks.org/tcp-3-way-handshake-process/) packets with the known flags:
- SYN
- SYN + ACK
- ACK
After that we can see the [Diffie Helman Key Swap](https://www.techtarget.com/searchsecurity/definition/Diffie-Hellman-key-exchange) packets.

## Update client.py
So now we update the function `recv_msg()` inside the `client.py` file and we will let it get its packets data from the `mitm.pcapng` file insted from the socket,
you can find the new functions inside the dummy_client.py string.

* Note: To run this script you must install [Python3.12](https://www.python.org/downloads/release/python-3120/)
