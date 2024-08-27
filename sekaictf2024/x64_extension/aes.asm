global decrypt
global xor2blocks
global _KeyAdd
global _invShiftRows
global _Sbox
global _invMixColumn

section .text
mask_reverse: db 0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
_invShiftRows:
        movdqu xmm1, [rcx]
        mov rax, mask_reverse
        movdqu xmm2, [rax]
        pshufb xmm1, xmm2
        movdqu [rcx], xmm1
        ret
    _Sbox:
        mov rax, 15
        xor r10, r10
    _Sbox_back:
        cmp rax, 0
        jge _Sbox_Cycle
        ret
    _Sbox_Cycle:
        lea r9, [rcx + rax]
        mov r10b, [r9]
        lea r8, [rdx + r10]
        mov r8b, [r8]
        mov [r9], r8b
        dec rax
        jmp _Sbox_back
    _KeyAdd:
        movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        xorps xmm0, xmm1
        movdqu [rcx], xmm0
        ret

_invMixColumn:
        push r12
        push rbx
        push rdi

        xor rdi, rdi
        xor r12, r12
        xor r8, r8
        xor r9, r9
        xor r10, r10
        xor r11, r11
        mov r8b, [rcx]
        mov r9b, [rcx + 1]
        mov r10b, [rcx + 2]
        mov r11b, [rcx + 3]
        mov rbx, rcx
        ;;
        lea rcx, [rdx + 0xe * 256 + r8]
        xor r12b, [rcx]
        lea rcx, [rdx + 0xb * 256 + r9]
        xor r12b, [rcx]
        lea rcx, [rdx + 0xd * 256 + r10]
        xor r12b, [rcx]
        lea rcx, [rdx + 9 * 256 + r11]
        xor r12b, [rcx]
        mov dil, r12b
        ;;
        xor r12, r12
        lea rcx, [rdx + 9 * 256 + r8]
        xor r12b, [rcx]
        lea rcx, [rdx + 0xe * 256 + r9]
        xor r12b, [rcx]
        ror rdi, 8
        lea rcx, [rdx + 0xb * 256 + r10]
        xor r12b, [rcx]
        lea rcx, [rdx + 0xd * 256 + r11]
        xor r12b, [rcx]
        mov dil, r12b
        ;;
        xor r12, r12
        lea rcx, [rdx + 0xd * 256 + r8]
        xor r12b, [rcx]
        lea rcx, [rdx + 9 * 256 + r9]
        xor r12b, [rcx]
        ror rdi, 8
        lea rcx, [rdx + 0xe * 256 + r10]
        xor r12b, [rcx]
        lea rcx, [rdx + 0xb * 256 + r11]
        xor r12b, [rcx]
        mov dil, r12b
        ;;
        xor r12, r12
        lea rcx, [rdx + 0xb * 256 + r8]
        xor r12b, [rcx]
        lea rcx, [rdx + 0xd * 256 + r9]
        xor r12b, [rcx]
        ror rdi, 8
        lea rcx, [rdx + 9 * 256 + r10]
        xor r12b, [rcx]
        lea rcx, [rdx + 0xe * 256 + r11]
        xor r12b, [rcx]
        mov dil, r12b
        ;;
        rol rdi, 8*3
        mov [rbx], edi

        pop rdi
        pop rbx
        pop r12

        ret

xor2blocks:
  movdqa xmm0, [rdx]
  movdqa xmm1, [r8]
  pxor xmm0, xmm1
  movdqa xmm1, [r8 + 0x10]
  pxor xmm0, xmm1
  movdqu [rcx], xmm0
  ret

decrypt:
  ;THis fails for some reason idk why
  ;rdi - dest
  ;rsi enc
  ;rcx aeskeys
  ;rdx xor keys


  movdqa xmm0, [rdx]
  movdqa xmm1, [r8 + 0xD0]
  aesdeclast xmm0, xmm1
  movdqa xmm1, [r8 + 0xC0]
  aesdec xmm0, xmm1
  movdqa xmm1, [r8 + 0xB0]
  aesdec xmm0, xmm1
  movdqa xmm1, [r8 + 0xA0]
  aesdec xmm0, xmm1
  movdqa xmm1, [r8 + 0x90]
  aesdec xmm0, xmm1
movdqa xmm1, [r8 + 0x80]
  aesdec xmm0, xmm1
movdqa xmm1, [r8 + 0x70]
  aesdec xmm0, xmm1
movdqa xmm1, [r8 + 0x60]
  aesdec xmm0, xmm1
movdqa xmm1, [r8 + 0x50]
  aesdec xmm0, xmm1
movdqa xmm1, [r8 + 0x40]
  aesdec xmm0, xmm1
movdqa xmm1, [r8 + 0x30]
  aesdec xmm0, xmm1
movdqa xmm1, [r8 + 0x20]
  aesdec xmm0, xmm1
movdqa xmm1, [r8 + 0x10]
  aesdec xmm0, xmm1
movdqa xmm1, [r8]

  aesdec xmm0, xmm1
xorpart:
  movdqa xmm1, [r9]
  pxor xmm0, xmm1
  movdqa xmm1, [r9 + 0x10]
  pxor xmm0, xmm1
  movdqu [rcx], xmm0
  ret
