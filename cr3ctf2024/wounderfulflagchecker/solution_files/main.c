#include <Windows.h>
#include <stdio.h>

#include "distormx.h"
typedef BOOL(WINAPI *VirtualProtect_t)(LPVOID lpAddress, SIZE_T dwSize,
                                       DWORD flNewProtect,
                                       PDWORD lpflOldProtect);
VirtualProtect_t originalVirtualProtect = NULL;

// Hook function
BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize,
                                 DWORD flNewProtect, PDWORD lpflOldProtect) {
  // Log the parameters
  printf("VirtualProtect called with parameters:\n");
  printf("Address: %p\n", lpAddress);
  printf("Size: %zu\n", dwSize);
  printf("New Protection: %x\n", flNewProtect);
  /*
  if (dwSize == 8192) {
    return 1;
  }
*/

  // Call the original VirtualProtect function
  BOOL result =
      originalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

  // Optionally, log the result
  printf("VirtualProtect result: %d\n", result);

  return result;
}

void *GetStackBase() {
  // Using the intrinsic to get the TEB address
  // On x64, the GS segment is used for the TEB
  NT_TIB *teb = (NT_TIB *)NtCurrentTeb();
  return teb->StackBase;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {

  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    printf("StackBase: %p \n", GetStackBase());

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    originalVirtualProtect =
        (VirtualProtect_t)GetProcAddress(kernel32, "VirtualProtect");
    distormx_hook(&originalVirtualProtect, HookedVirtualProtect);
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}
