# Write up for SEKAI CTF x64_extension

## Initial analysis
It comes as a elf 64 executable and a flag.txt.enc, which implies that the program takes a flag.txt as input and produces an .enc version.

After opening it in IDA and locating the main function we see it loading 16 byte values which looked like hardcoded keys.


![image](https://github.com/user-attachments/assets/b22e23f5-53f7-4f7c-adfd-2297758e2e79)


Then it starts calling some functions, IDA handily tells us that the first of them takes string "flag.txt" as an argument, probably meaning that it or some other function later reads the content of the file. 
At this point it is worth starting the dynamic analysis

## Dynamic analysis

After running the debugger and checking function after functions return values in rax for pointers to our data.

![TRkJMd-DtZM](https://github.com/user-attachments/assets/cae6e0ca-24f6-47be-9b5a-e99a62fbdc21)

Locating the function which read the contents, it seems that theres only 1 funcion before the program starts processing the output, suggesting it is worth checking it out - sub_40450D.

![image](https://github.com/user-attachments/assets/2de0dd5b-7a62-4f47-8061-4d553fc27a44)


It does a call to another function - sub_404519

![image](https://github.com/user-attachments/assets/2e7324bf-baad-497c-8095-faea06729ae4)


Which has the block with a lot of aesenc in it. This is probably it.

First is starts out by putting the 16 byte long keys onto the stack, then calls a dummy function sub_4044F0 which does nothing, then fiddles around with data a bit more, until it calls  sub_4046F7. 

![image](https://github.com/user-attachments/assets/5e0b2efe-5cc6-4841-bcc7-2954d2dd11c0)


This function has aeskeygenassist instruction, which implies it is generating round keys, which it then stores. it does call sub_4048CC and sub_4048A7 which does some more xoring and shuffling, but in the end it stores all the keys in sequence in [rax], so by letting it finish and looking at the memory there, we are able to grab all the keys:

```
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
B7 73 C2 9F B3 76 C4 98 BB 7F CE 93 B7 72 C0 9C
B9 51 A8 CD AD 44 BE DA B5 5D A4 C1 A9 40 BA DE
8D 87 DF 4C 3E F1 1B D4 85 8E D5 47 32 FC 15 DB
9A E1 F1 74 37 A5 4F AE 82 F8 EB 6F 2B B8 51 B1
D6 56 17 BD E8 A7 0C 69 6D 29 D9 2E 5F D5 CC F5
55 E2 BA 92 62 47 F5 3C E0 BF 1E 53 CB 07 4F E2
A9 D2 8F A2 41 75 83 CB 2C 5C 5A E5 73 89 96 10
DA 45 2A 58 B8 02 DF 64 58 BD C1 37 93 BA 8E D5
87 CB 8C 7E C6 BE 0F B5 EA E2 55 50 99 6B C3 40
34 3A 04 51 8C 38 DB 35 D4 85 1A 02 47 3F 94 D7
A7 E9 82 DE 61 57 8D 6B 8B B5 D8 3B 12 DE 1B 7B
FD 27 AB 70 71 1F 70 45 A5 9A 6A 47 E2 A5 FE 90
C7 52 E2 46 A6 05 6F 2D 2D B0 B7 16 3F 6E AC 6D

```
Going back to the sub_404519, after it generates the keys it enters a loop:

![image](https://github.com/user-attachments/assets/dfe8f264-8550-4cd6-b8a3-7acddecd25bb)

It takes 16 bytes of read data, xors it with 2 xor keys, which are at the start 
```
XORKEY1 - 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
XORKEY2 - FF FE FD FC FB FA F9 F8 F7 F6 F5 F4 F3 F2 F1 F0
```
And then does 13 aesenc instruction with 13 round keys and at last does a aesenclast with the 14th key.
After which the encrypted block is stored back into memory, and to verify that it really is our block and no more encryptions are happening we can fill flag.txt with some blanc data, run the program normally once, and then put a breakpoint after the first iteration of this loop to check.
And sure enough, after opening the flag.txt.enc in the hex editor it checks up. 

![image](https://github.com/user-attachments/assets/48ea8f50-565d-479d-a998-fe8c21b05d61)

After storing the block, program updates XORKEY2 with the newly encoded block.


This is enough of debugging since from now we can write a decrypter, we have all the keys after all. I tried doing this with aesdec and aesdeclast instructions, however for some reason aesdeclast does not seem to revert aesenclast, or I am just stupid, so I decided to use my own AES implementation (lol).

to decrypt 16 bytes encrypted with AES, we need to reverse the process, so first we reverse AESENCLAST:


![image](https://github.com/user-attachments/assets/f26e4b79-e1c5-4736-888d-5a83eb4f2e85)


then we do 13 iterations of simple AES decryption:


![image](https://github.com/user-attachments/assets/077f95c0-fa60-441c-9814-58656464e5ef)


And then we xor it with our keys


![image](https://github.com/user-attachments/assets/5b2ac0d2-4fb2-46f1-bb92-79232c679289)


And do not forget that we have to update the XOR key after every iteration


![image](https://github.com/user-attachments/assets/7de7b65a-d05a-461a-9b3c-c94f6d832aa1)



And after running it sure enough we get the output:


![image](https://github.com/user-attachments/assets/5ce4829e-752d-438c-9f5d-3f586a885bae)








