---
title: "VMProtect - From scratch!"
classes: wide
header:
  teaser: /assets/images/tutorials/VMProtect/VMProtect-logo.png
ribbon: blue
description: "The research shows how it was possible to gain unauthorized access to edit the devlink site's Firebase database and how it can be used to modify user data or gain access to other users' information and alter critical data."
categories:
  - Tutorials
---
## Intro - VMProtect
According to the official VMProtect website ([VMProtect Software](https://vmpsoft.com/)) VMProtect is designed to "secure your code against reverse engineering, analysis, and cracking. Use the advantage of code virtualization, which executes virtualized fragments of code on several virtual machines embedded into the protected application."

VMProtect is a virtualization-based software protection system. 
What makes it unique is its ability to generate custom virtual instruction sets for every build. 
This means that no two protected binaries are the same each one uses a completely different virtual architecture. 
Additionally, VMProtect can mix native and virtual instructions within a single function, making static analysis and devirtualization significantly more difficult.

- Note: In general, VMProtect is designed for both personal and commercial use, and you can find it in many games today. However, it can also be used in malware due to its strong protection. One of the main weaknesses of this protection is its impact on performance, as the bytecode handling can slow down execution, which can be frustrating for gamers and, in some cases, even hurt game sales.

## What does it mean software virtualization?
Software virtualization, in the context of code protection, is different from operating system or hardware virtualization. 
Instead of emulating an entire system or memory layout, software virtualization transforms CPU instructions into custom bytecode, which is then executed by a virtual machine embedded in the application. 
This virtual machine uses handler functions that interpret and execute each bytecode instruction, effectively hiding the original logic from disassemblers and reverse engineers.

### example
Let's take a look at this sample bytecode handler:
```c
#include <stdio.h>

uint8_t bytecode[] = {
    0x01, 3,    // PUSH 3
    0x01, 5,    // PUSH 5
    0x02,       // ADD
    0x03,       // PRINT
    0xFF        // HALT
};

int main() {
    int stack[16], sp = -1;
    for (int ip = 0; bytecode[ip] != 0xFF; ) {
        switch (code[ip++]) {
            case 0x01: stack[++sp] = code[ip++]; break;          // PUSH
            case 0x02: stack[sp-1] += stack[sp--]; break;        // ADD
            case 0x03: printf("%d\n", stack[sp--]); break;       // PRINT
            case 0xff: while(1){};                               // HALT
        }
    }
    return 0;
}
```
Now let’s break it down. This handler creates its own stack and stack pointer, then uses a switch statement to handle each bytecode instruction. Each opcode performs a specific function, like pushing a value / adding two values / printing the result.
In other words, it simulates a tiny virtual CPU!

## Analyzing a Real Handler
Now, we’re going to begin our first analysis mission. We’ll start with a simple binary that I compiled myself using the VMProtect demo version (just for learning purposes). You can download the binary [here](github.com/4f3rg4n). As we’ve learned, each build of VMProtect generates a unique virtualization protection, so I recommend using this specific binary. If you want to try compiling your own binaries with VMProtect, you can download the demo version installer from [here](https://vmpsoft.com/uploads/VMProtectDemo.exe).




