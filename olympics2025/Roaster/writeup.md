# Roaster writeup

```
I forgot my [**Roaster**](https://ctf.olympics.tech/tasks/Roaster_de24314c8950adf0f2803e77489fe95208b63b8b.txz) router credentials, Can you recover?

`nc 65.109.184.55 8080`
```

### Initial scouting

Since it is a firmware and not a direct binary I run standard linux utils against it like binwalk and file:

```bash
[master@PCNAME rstr]$ file firmware.bin
firmware.bin: data
[master@PCNAME rstr]$ binwalk -ev firmware.bin

Scan Time:     2025-09-27 21:18:05
Target File:   /mnt/c/coding/ctf_olyml/rstr/firmware.bin
MD5 Checksum:  d99f63a7451b8418e7ef330650d8bdc3
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
406512        0x633F0         CRC32 polynomial table, little endian
574456        0x8C3F8         Flattened device tree, size: 987 bytes, version: 17
1048576       0x100000        uImage header, header size: 64 bytes, header CRC: 0xFEF32325, created: 2025-09-23 20:14:54, image size: 4858710 bytes, Data Address: 0x80000000, Entry Point: 0x80000000, data CRC: 0x36E37F76, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: gzip, image name: "Linux ASIS"
1048640       0x100040        gzip compressed data, maximum compression, from Unix, last modified: 1970-01-01 00:00:00 (null date)

WARNING: Extractor.execute failed to run external extractor 'sasquatch -p 1 -le -d 'squashfs-root-0' '%e'': [Errno 2] No such file or directory: 'sasquatch', 'sasquatch -p 1 -le -d 'squashfs-root-0' '%e'' might
not be installed correctly

WARNING: Extractor.execute failed to run external extractor 'sasquatch -p 1 -be -d 'squashfs-root-0' '%e'': [Errno 2] No such file or directory: 'sasquatch', 'sasquatch -p 1 -be -d 'squashfs-root-0' '%e'' might
not be installed correctly
9437184       0x900000        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 1654188 bytes, 426 inodes, blocksize: 65536 bytes, created: 2025-09-24 22:42:35

[master@PCNAME rstr]$ ls
_firmware.bin.extracted  firmware.bin
[master@PCNAME rstr]$ cd _fr
-bash: cd: _fr: No such file or directory
[master@PCNAME rstr]$ cd _firmware.bin.extracted/
[master@PCNAME _firmware.bin.extracted]$ ls
100040  900000.squashfs  squashfs-root  squashfs-root-0
[master@PCNAME _firmware.bin.extracted]$ ls squashfs-root
bin  dev  etc  home  init  linuxrc  proc  sbin  sys  tmp  usr  var
[master@PCNAME _firmware.bin.extracted]$
```

We have a MIPS32 image of linux

`init` contains the following:
```bash
**#!/bin/sh

# Mount filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs none /tmp

# Create device nodes
mdev -s

# Set hostname
hostname ASIS-Router

# Start your application
echo "Starting system..."
/bin/cwmp &
/bin/httpd &
**
```

I decided to initially go for httpd, since it makes more sense, we are working with a webserver after all. 

### Static analysis 
#### Main
The webserver starts by a manual logging in with password:
<img width="883" height="625" alt="Pasted image 20250927214926" src="https://github.com/user-attachments/assets/e28abd73-fc3c-4250-a07b-4ba1b9ad4fde" />


After that it digests stuff with sha256 (we know that by the constants), and inits the network stack, forking the process for each new connection:

<img width="953" height="562" alt="Pasted image 20250927215311" src="https://github.com/user-attachments/assets/4426d307-6e9f-4d60-ba88-8b44b53d8e31" />


#### req_handler

It exploses the following  endpoints:
```
/gen141234/backup
/login
/logout
/index.html
/diag
/run_diag
```

Upon going to the actual webserver, and trying those, every one redirects to login, except for gen141234/backup, which fetches backup.bin - a file approximately 410 bytes with a header - `ASBP` and seeming random data. It is worth exploring how the backup is generated: sub_402390

#### sub_402390 - http backup generation

It turns out to be a wrapper which packs the info and appends the http header for the actual function: sub_403788

#### sub_403788 - real backup generation

In this one we can actually see that it fetches: admin_password, device_serial, wlan_psk, meaning that this config probably contains the info we need.

<img width="673" height="516" alt="Pasted image 20250927221008" src="https://github.com/user-attachments/assets/bf8cabb7-fe4e-4e11-aabf-5de600695482" />


#### Post processing of the fetched data

after that it mixes the length of the buffer around with 

```c
int __fastcall mix_int(unsigned int a1)
{
  return (a1 >> 12) + a1 + 13 + (a1 >> 14) + (a1 >> 25);
}
```

which adds some small value to the , and then mallocs this new value, presumably reserving space for some header.

Then it calls some function passing the previously parsed parameters, their size, new buffer and its size. 
```c
totalBufLen = bufLen + 1;
encodedSize = mix_int(bufLen + 1);
encodedBuf = alloc(encodedSize);
sub_404AF0(encodedBuf, &encodedSize, kvBuf, totalBufLen, 9);
```

#### sub_404AF0

Inside it I saw a call another function being called with a string "1.3.1", surrounded by proper error handling and messages like: "insufficient memory" or "stream error" hinting that this is some external library. 

Clicking through functions in hopes of finding any constants i stumble upon:

<img width="515" height="410" alt="Pasted image 20250928005929" src="https://github.com/user-attachments/assets/40ef7e1a-9fb6-448e-b8c9-cd712f699c33" />

Which reveals precious constants: `0, 0x43CBA687, 0xC7903CD4, 0x845B9A53, 0xCF270873, ...`

After googling which it becomes obvious that the library in question is zlib

#### Processing of the zlib compressed data

After compression it calls what looks like a padding function:

```c
  int __fastcall add_pkcs7_padding(
        int old_buf,
        unsigned int old_buf_size,
        unsigned int align,
        int *new_buf,
        _DWORD *new_buffer_size)
{
  int result; // $v0
  int v9; // $s1
  int v10; // $s6
  unsigned int v11; // $v0
  int v12; // $s2

  if ( !old_buf || !new_buf )
    return -1;
  result = -1;
  if ( !new_buffer_size )
    return result;
  result = -1;
  if ( align - 1 >= 0xFF )
    return result;
  if ( ~align < old_buf_size )
    return -1;
  v9 = align - old_buf_size % align;
  v10 = old_buf_size + v9;
  v11 = alloc(old_buf_size + v9);
  v12 = v11;
  if ( !v11 )
    return -2;
  if ( old_buf_size )
    memcpy(v11, old_buf, old_buf_size);
  memset(v12 + old_buf_size, v9, v9);
  result = 0;
  *new_buf = v12;
  *new_buffer_size = v10;
  return result;
}
```

This is a very heavy hint that encryption is coming very soon (probably AES)

#### The SHA256 and a bunch of random

After padding comes initialisation of the following string:

`sprintf(serialString, 256, "A:%s:S", deviceSerialPtr);`

Which is then hashed via sha256 (deduced from the state constants)

it sets 4 ints to equal the resulting hash (taking the lower 16 bytes of the hash)

```c
sha256_finalize(&shaState0, &digest0);
    hash_buf[0] = digest0;
    hash_buf[1] = digest1;
    hash_buf[2] = digest2;
    hash_buf[3] = digest3;
```

Then it generates 3 random ints, and follows it up with a `0x41353135`, putting it into another buffer. 


#### Key derivation and encryption

The results of a previous step are now passed inside of a function alongside an pointer. The function is AES key derivation (who would have guessed), we can clearly see the rcon vector constants along with the sbox. 

```c
int __fastcall generate_aes_key_from_sha256(_BYTE *expanded_key, char *input_key, _DWORD *iv)
{
  int v5; // $a0
  int v6; // $v1
  int result; // $v0

  aes_key_expansion(expanded_key, input_key);
  v5 = iv[1];
  v6 = iv[2];
  result = iv[3];
  *(expanded_key + 0x2C) = *iv;
  *(expanded_key + 0x2D) = v5;
  *(expanded_key + 0x2E) = v6;
  *(expanded_key + 0x2F) = result;
  return result;
}
```

It stores the iv vector after the expanded key and returns

#### Encryption

The encryption function is a standard AES-CBC, which unpacks the IV from the key array and encrypts the compressed data.

```c
// AES-128-CBC encryption function. IV stored at offset 176 of context. Encrypts data in-place using proper CBC chaining.
int __fastcall aes_encrypt_cbc(int aes_ctx, char *data_buf, unsigned int data_len)
{
  _DWORD *iv_dword_ptr; // $s0
  char *next_block_ptr; // $s4
  int loop_offset; // $s3
  char *current_block_ptr; // $s5
  char *plain_ptr; // $v0
  char *xor_src_ptr; // $a1
  char plain_byte; // $v1
  char xor_byte; // $a3
  int new_iv_word0; // $a1
  int new_iv_word1; // $a0
  int new_iv_word2; // $v1
  int new_iv_word3; // $v0

  iv_dword_ptr = (aes_ctx + 176);
  if ( data_len )
  {
    next_block_ptr = data_buf + 16;
    loop_offset = -16 - data_buf;
    current_block_ptr = (aes_ctx + 176);
    plain_ptr = data_buf;
    do
    {
      xor_src_ptr = current_block_ptr;
      current_block_ptr = plain_ptr;
      do
      {
        plain_byte = *plain_ptr++;
        xor_byte = *xor_src_ptr++;
        *(plain_ptr - 1) = plain_byte ^ xor_byte;
      }
      while ( plain_ptr != next_block_ptr );
      next_block_ptr += 16;
      aes_encrypt_block(current_block_ptr, aes_ctx);
      plain_ptr = next_block_ptr - 16;
    }
    while ( &next_block_ptr[loop_offset] < data_len );
  }
  else
  {
    current_block_ptr = (aes_ctx + 176);
  }
  new_iv_word0 = *current_block_ptr;
  new_iv_word1 = *(current_block_ptr + 1);
  new_iv_word2 = *(current_block_ptr + 2);
  new_iv_word3 = *(current_block_ptr + 3);
  *(aes_ctx + 176) = *current_block_ptr;
  *iv_dword_ptr = new_iv_word0;
  iv_dword_ptr[1] = new_iv_word1;
  iv_dword_ptr[2] = new_iv_word2;
  iv_dword_ptr[3] = new_iv_word3;
  return new_iv_word3;
}
```


#### Yet another SHA256

After the encryption we initiate another set of SHA256 states and hash the resulting ciphertext.

#### Writing to the file

Following all those steps, the program ends up *finally* packing the result in a file in the following way:

```c
sha256_finalize(&shaState0, &digest0);
    finalBuf = alloc(encryptedLen + 58); //allocs the buffer with the 58 bytes for the header
    iv_04 = iv_bytes[0];
    iv_48 = iv_bytes[1];
    finalWritePtr = (finalBuf + 26);
    *finalBuf = 0x41534250;                     // header == ASBP
    iv_8_12 = iv_bytes[2];
    *(finalBuf + 4) = random_data[0]; //put 8 bytes of random
    *(finalBuf + 8) = random_data[1];  
    *(finalBuf + 12) = more_funny_random;
    *(finalBuf + 14) = iv_04;
    *(finalBuf + 18) = iv_48;
    *(finalBuf + 22) = iv_8_12;
    do //
    {
      block0 = *digestPtr;
      digestPtr += 4;
      block1 = *(digestPtr - 3);
      block2 = *(digestPtr - 2);
      block3 = *(digestPtr - 1);
      *finalWritePtr = block0;
      finalWritePtr[1] = block1;
      finalWritePtr[2] = block2;
      finalWritePtr[3] = block3;
      finalWritePtr += 4;
    }
    while ( digestPtr != serialString );
    memcpy(finalBuf + 58, encryptedData, encryptedLen);
```

So the header format is:

```c
struct{
	uint32_t magic;
	uint8_t random[10];
	uint8_t iv[12];
	uint8_t hash_of_ciphertext[32];
	uint8_t ciphertext[1];
}
```

Note: the code ommitted the last 4 bytes of IV, since they were hardcoded before

With all that we are pretty much ready to write a decryptor!

#### Endianness

An attentive reader could have observed that near the magic `0x41534250` is a comment stating that its `ASBP`, however if you store it normally with LE as it is shown in the code, it should actually be `PBSA`, this was noticed by me quite early, but the same issue actually arises when it stores the last 4 bytes of IV (this cost me ~2 hours). 


#### The decryption

Well there's not much to be said, the key is the first 16 bytes of `A:<SERIAL>:S` hashed with sha256, the IV is fetched from the header + 4 bytes == `0x41353135`
in !Big Endian!. The serial could be observed on the website and is equal to -> `SN405CBA66B5`. After decrypting the payload we see a valid Zlib header: `78 DA`
And after successfully decrypting we finally have the backup:


```
hostname=ASISRouter
model=ASIS-2551
firmware=1.0.3
wan_proto=dhcp
wan_ip=203.0.113.5
admin_username=admin
wan_mask=255.255.255.0
wan_gw=203.0.113.1
dns1=8.8.8.8
dns2=8.8.4.4
admin_password=ea@Lae#cah4s
dhcp_lease=86400
dhcp_end=192.168.1.249
dhcp_start=192.168.1.100
lan_mask=255.255.255.0
device_serial=SN405CBA66B5
lan_ip=192.168.1.1
wlan_ssid=ASIS-WIFI-12e12
wlan_psk=ASIS{R0U73R_M4Y_R04S7_US_S0M3H0W_449bd7600f3716147a458b19}
wlan_mode=11n
wlan_channel=6
firewall=enabled
wlan_channel=6
vpn_enabled=false
ntp_server=time.example.com
syslog=enabled
syslog=enabled
leds=on
```

Which clearly shows the flag in it
