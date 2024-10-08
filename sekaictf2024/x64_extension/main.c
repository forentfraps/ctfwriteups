#include "constants.c"
#include <stdio.h>
#include <string.h>
#include <windows.h>

unsigned char XORKEYS[] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                           0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

unsigned char AESKEYS[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
    0x1C, 0x1D, 0x1E, 0x1F, 0xB7, 0x73, 0xC2, 0x9F, 0xB3, 0x76, 0xC4, 0x98,
    0xBB, 0x7F, 0xCE, 0x93, 0xB7, 0x72, 0xC0, 0x9C, 0xB9, 0x51, 0xA8, 0xCD,
    0xAD, 0x44, 0xBE, 0xDA, 0xB5, 0x5D, 0xA4, 0xC1, 0xA9, 0x40, 0xBA, 0xDE,
    0x8D, 0x87, 0xDF, 0x4C, 0x3E, 0xF1, 0x1B, 0xD4, 0x85, 0x8E, 0xD5, 0x47,
    0x32, 0xFC, 0x15, 0xDB, 0x9A, 0xE1, 0xF1, 0x74, 0x37, 0xA5, 0x4F, 0xAE,
    0x82, 0xF8, 0xEB, 0x6F, 0x2B, 0xB8, 0x51, 0xB1, 0xD6, 0x56, 0x17, 0xBD,
    0xE8, 0xA7, 0x0C, 0x69, 0x6D, 0x29, 0xD9, 0x2E, 0x5F, 0xD5, 0xCC, 0xF5,
    0x55, 0xE2, 0xBA, 0x92, 0x62, 0x47, 0xF5, 0x3C, 0xE0, 0xBF, 0x1E, 0x53,
    0xCB, 0x07, 0x4F, 0xE2, 0xA9, 0xD2, 0x8F, 0xA2, 0x41, 0x75, 0x83, 0xCB,
    0x2C, 0x5C, 0x5A, 0xE5, 0x73, 0x89, 0x96, 0x10, 0xDA, 0x45, 0x2A, 0x58,
    0xB8, 0x02, 0xDF, 0x64, 0x58, 0xBD, 0xC1, 0x37, 0x93, 0xBA, 0x8E, 0xD5,
    0x87, 0xCB, 0x8C, 0x7E, 0xC6, 0xBE, 0x0F, 0xB5, 0xEA, 0xE2, 0x55, 0x50,
    0x99, 0x6B, 0xC3, 0x40, 0x34, 0x3A, 0x04, 0x51, 0x8C, 0x38, 0xDB, 0x35,
    0xD4, 0x85, 0x1A, 0x02, 0x47, 0x3F, 0x94, 0xD7, 0xA7, 0xE9, 0x82, 0xDE,
    0x61, 0x57, 0x8D, 0x6B, 0x8B, 0xB5, 0xD8, 0x3B, 0x12, 0xDE, 0x1B, 0x7B,
    0xFD, 0x27, 0xAB, 0x70, 0x71, 0x1F, 0x70, 0x45, 0xA5, 0x9A, 0x6A, 0x47,
    0xE2, 0xA5, 0xFE, 0x90, 0xC7, 0x52, 0xE2, 0x46, 0xA6, 0x05, 0x6F, 0x2D,
    0x2D, 0xB0, 0xB7, 0x16, 0x3F, 0x6E, 0xAC, 0x6D};
char dest[160] = {0};
unsigned char enc[] = {0x6F, 0xE5, 0xAC, 0x67, 0xDE, 0x10, 0x13, 0xF2,
                       0xA9, 0xC2, 0xDC, 0x35, 0x22, 0x9A, 0x1E, 0xC5};
unsigned char test[] = {0xD2, 0x8C, 0xCA, 0x0E, 0xAE, 0x20, 0xCC, 0xEE,
                        0xA6, 0x4E, 0x3E, 0xF6, 0x65, 0xE4, 0xC3, 0x12};
extern void _invShiftRows(unsigned char *[]);
extern void _Sbox(unsigned char *list, void *table);
extern void _KeyAdd(unsigned char *block, unsigned char *key);
extern void _invMixColumn(unsigned long *operand, void *table);

extern void xor2blocks(char *dest, unsigned char *enc, unsigned char *xorkeys);

int decblock(unsigned char *block) {

  _KeyAdd(block, AESKEYS + 0xD0);

  _invShiftRows(block);
  _Sbox(block, rsbox);

  for (int i = 0xc; i >= 0; --i) {
    _KeyAdd(block, AESKEYS + i * 0x10);
    for (int j = 0; j < 4; ++j) {
      _invMixColumn(block + j * sizeof(unsigned long), MultiplicationTable);
    }
    _invShiftRows(block);
    _Sbox(block, rsbox);
  }
  memset(dest, 16, 0);
  xor2blocks(dest, block, XORKEYS);

  printf("%s", dest);
}
int main() {
  HANDLE hFile;
  DWORD bytesRead;
  BOOL result;
  char *buffer;
  LPCSTR fileName = "REALFLAG";
  hFile = CreateFileA(fileName,              // File name
                      GENERIC_READ,          // Desired access
                      0,                     // Share mode
                      NULL,                  // Security attributes
                      OPEN_EXISTING,         // Creation disposition
                      FILE_ATTRIBUTE_NORMAL, // Flags and attributes
                      NULL                   // Template file
  );

  if (hFile == INVALID_HANDLE_VALUE) {
    printf("Failed to open file. Error: %d\n", GetLastError());
    return 1;
  }

  buffer = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 10000);
  if (buffer == NULL) {
    printf("Failed to allocate memory.\n");
    CloseHandle(hFile);
    return 1;
  }

  result = ReadFile(hFile, buffer, 1000, &bytesRead, NULL);
  if (!result) {
    printf("Failed to read file. Error: %d\n", GetLastError());
    HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(hFile);
    return 1;
  }

  printf("Read %d bytes from file:\n", bytesRead);

  for (int i = 0; i < 0xa0; i += 0x10) {
    memcpy(test, buffer + i, 16);
    decblock(buffer + i);
    memcpy(XORKEYS, test, 16);
  }

  HeapFree(GetProcessHeap(), 0, buffer);
  CloseHandle(hFile);

  return 0;
}
