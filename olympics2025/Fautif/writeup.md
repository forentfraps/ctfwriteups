### Initial scouting
Opening the binary in DIE reveals that its AARCH64 linux elf. 

<img width="852" height="548" alt="Pasted image 20250927184526" src="https://github.com/user-attachments/assets/c6923768-06fa-441a-ba40-7b557e839b8c" />


### Static analysis in IDA

Opening Ida and skimming the code, we can locate the main function: sub_A00. 

#### Main function

It initially loads some strings and calls a function, initial guess would be that this is some cipher initiation. 
```asm
STP             X29, X30, [SP,#var_50]!
ADRP            X0, #off_202B0@PAGE
ADRP            X1, #qword_1480@PAGE
MOV             X29, SP
MOV             W3, #2
LDR             X0, [X0,#off_202B0@PAGEOFF] ; unk_20328
STP             X19, X20, [SP,#0x50+var_40]
LDR             D31, [X1,#qword_1480@PAGEOFF]
STP             X21, X22, [SP,#0x50+var_30]
ADRP            X22, #qword_202D0@PAGE
ADD             X1, X22, #qword_202D0@PAGEOFF
STP             X23, X24, [SP,#0x50+var_20]
ADRL            X20, aAvozjkiwqfcdxb ; "AVOZJKIWQFCDXBRMNUTLHSPGYE"
ADD             X2, X20, #(aRfwka - 0x20090) ; "RFWKA"
ADD             X5, X20, #(unk_2015D - 0x20090)
ADD             X4, X0, #0x28 ; '('
ADD             X6, X0, #0x2C ; ','
STR             X6, [X22,#qword_202D0@PAGEOFF]
ADD             X19, X20, #(aNkrr - 0x20090) ; "Nkrr"
STUR            D31, [X0,#(qword_20344 - 0x20328)]
ADD             X20, X20, #(unk_2020A - 0x20090)
STR             W3, [X0,#(dword_2034C - 0x20328)]
ADD             X3, X0, #0x30 ; '0'
STP             X5, X4, [X1,#(qword_202D8 - 0x202D0)]
STP             X3, X2, [X1,#(qword_202E8 - 0x202D0)]
BL              sub_E08
```

I decided to check the strings, it turned out to be seven 26-wide uppercase strings, looking like scrambled alphabets. 
<img width="931" height="344" alt="Pasted image 20250927190050" src="https://github.com/user-attachments/assets/65894e73-e7ee-4b2e-98cb-e3665833ae27" />


Initial guess is that it uses these alphabets as permutation look up tables.

After initialisation function, it inputs user data with getdelim
```c
 if ( getdelim((char **)&qword_20320, (size_t *)algn_20318, -1, stdin) > 0 )
    sub_F40(qword_20320);
```
Then supposedly encrypts it with the sub_F40, after which it seeds the random with current unix timestamp, queries rand() twice, and takes the lower byte from them, occasionally negating it. With those 2 bytes it then xors it with the ciphertext and writes to stdout

```c
  v7 = time(0);
  srand(v7);
  v8 = rand();
  if ( v8 <= 0 )
    v9 = -(unsigned __int8)-(char)v8;
  else
    LOBYTE(v9) = v8;
  v16[0] = v9;
  v10 = rand();
  if ( v10 <= 0 )
    v10 = -(unsigned __int8)-(char)v10;
  v16[1] = v10;
  v11 = qword_20320;
  if ( v5 )
  {
    *v6 = v9 ^ *(_BYTE *)qword_20320;
    if ( v5 != 1 )
    {
      for ( i = 1; i != v5; ++i )
        v6[i] = v16[i & 1] ^ *(_BYTE *)(v11 + i);
    }
    v13 = v6;
    v6[v5] = 0;
    do
    {
      v14 = *v13++;
      printf("%02x", v14);
    }
    while ( v13 != &v6[v5] );
  }
```

This poses initial concerns, since we can't be sure that the time(0) returned the exact timestamp which the file has. 

#### sub_F40 (encryption function)

The main focus is  now on the evasive sub_F40 which I've postponed as much as possible. It is massive and there is not much point of including it here. First thing I did is fed the decompiled pseudo code to an LLM to rename the variables. 

And after a bit more cleaning and LLM probing, it become obvious that this is a modified Enigma machine with 6 rotors and a permutation layer before them.

It does a massive initialisation with somewhat non-trivial permutations which I decided to postpone for now, in search of an easier solution.
<img width="1124" height="621" alt="Pasted image 20250927191755" src="https://github.com/user-attachments/assets/6997ed7c-a64e-443a-b3dd-0da97d13e013" />


The key insight I got is that it is a stream cipher, meaning it encrypts char by char. In addition its input and output sets are ASCII printable chars,  this is true since the rotors only contained uppercase ascii chars.

Going back to the initiation routines before the encryption, if it would be deterministic then a bruteforce attack would be possible. 

A quick skim of sub_E08 makes it seem that it is the core initiation for the rotors, performing a plethora of permutations, the key insight being, again, deterministic ones.

Enough of static analysis has been done and now 2 options remain: reverse the algorithm from here statically or set up qemu to run it and see whats happening after it inits and encrypts. Option 2 is quite obvious.

### Dynamic analysis in QEMU 

Running the code with the breakpoint right after the encryption of the plaintext we are able to capture the output pre-xor: 
```
Input: ASIS{TEST}
output: GGRC{RTND}
```

Knowing that, we are able to derive the 2-byte XOR key from the payload we have in the secret.enc:

```py
with open("flag.enc", "r") as f:
    data = f.read()

bts = bytes.fromhex(data)

xor_key = [bts[0] ^ ord("G"), bts[1] ^ ord("G")]

dexorred = bytearray()
for i, bt in enumerate(bts):
    dexorred.append(bt ^ xor_key[i & 1])

print(dexorred.decode("utf-8"))
```

So the encrypted data turnes out to be:

`GGRC{Rot_Tjkyqf_dpzxvg_hha_k_iukaul_cfhghag_izvmg_ehkuexvhsgfkmlgcg_zbeyxmgi_ez_sfqnqcj_klg_brwjfpy_zozngimn!}`

### Solving with a bruteforcer

After that, I wrote a bruteforcer, which inputs the string into the program, captures the stdout, derives the 2-byte XOR key, gets the output of the enigma, and compare it with the target. The checking function looks like:

```py
def run_checker(cmd, candidate, timeout):
    """
    Runs the checker once, feeding the candidate via stdin.
    Returns (score, raw_stdout). Extracts the last number found in stdout.
    """
    try:
        completed = subprocess.run(
            cmd,
            input=candidate + "\xff",
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return -inf, f"[TIMEOUT] while checking {candidate!r}"

    out = completed.stdout.strip()
    bts = bytes.fromhex(out)
    xor_key = [bts[0] ^ ord("G"), bts[1] ^ ord("G")]
    dexorred = bytearray()
    for i, bt in enumerate(bts):
        dexorred.append(bt ^ xor_key[i & 1])
    to_check = dexorred.decode("utf-8")
    print(to_check)
    score = 0
    for c1, c2 in zip(list(to_check), list(target[0:len(to_check)])):
        if (c1 == c2):

            score += 1
        else:
            break
    return score, out
```


If the score increases for the string, then we lock the current char as correct and move on to the next one. 


When I run the full script, after 2-3 minutes we are able to get the flag

<img width="1631" height="324" alt="Pasted image 20250927195500" src="https://github.com/user-attachments/assets/6740ac51-0a4e-4cad-9f7e-dfcc410d1cfe" />


The flag is:

`ASIS{The_Enigma_cipher_was_a_system_created_using_electromechanical_machines_to_encrypt_and_decrypt_messages!}`
