nasm -fwin64 -o aes.o aes.asm
gcc aes.o main.c -o main.exe
