# Intro

I haven't solved this chal during the ctf, instead I spent 6-7 hours scrolling throught disassembled code, in hopes of catching the goddamn checking routine, and eventually gave up.

After the ctf ended and I saw the [authors' write up and intended solution](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/rev/wonderful/solution) I was very impressed at what happened and decided to solve it using a new technology stack, which the author mentioned, but havent used.

His solution came down to manually determinning all of the possible arithmetic logic, and semi-statically solving it, which I thought was lame, since if the checks were more complex, he would've failed.


# My solution

## Initial overview

Opening the executable in detect it easy, the heart immidiatly drops and life is sucked out of the body:

![image](https://github.com/user-attachments/assets/ba82b902-11e4-4479-9427-821c2c87eaf2)

Well, that was enough to defeat me during the ctf, but now I am armed.



Lets see what the program does when we launch it:

```
[*] reprotecting stack through VirtualQuery&VirtualProtect...
[i] please enter the flag: cr3{test}
[i] hint: can you figure what am i calling?
[i] hell nah
```

Ok, so it is hinting that it is doing something is VirtualProtect and the stack, lets hook this function and see what's up.

## Poking around + static analysis

I will be using distormx hooking library to do the hooking. (All these source files are in this repo in the folder solution_files)

```c
typedef BOOL(WINAPI *VirtualProtect_t)(LPVOID lpAddress, SIZE_T dwSize,
                                       DWORD flNewProtect,
                                       PDWORD lpflOldProtect);
VirtualProtect_t originalVirtualProtect = NULL;


BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize,
                                 DWORD flNewProtect, PDWORD lpflOldProtect) {

  printf("VirtualProtect called with parameters:\n");
  printf("Address: %p\n", lpAddress);
  printf("Size: %zu\n", dwSize);
  printf("New Protection: %x\n", flNewProtect);
  /*
  if (dwSize == 8192) {
    return 1;
  }
*/

  BOOL result =
      originalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

  printf("VirtualProtect result: %d\n", result);

  return result;
}

```

and just for good measure its worth it to know where the stack is

```c
void *GetStackBase() {
  NT_TIB *teb = (NT_TIB *)NtCurrentTeb();
  return teb->StackBase;
}
```

To automatically hook the dll into the exe I like to use cff explorer's ImportAdder to add an import from the dll, so that it is automatically loaded when the exe starts.

Starting the patched and hooked exe again we see:
```
StackBase: 0000000019500000
VirtualProtect called with parameters:
Address: 00007ffc6e10c7c0
Size: 5
New Protection: 20
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 00007ffc6e090000
Size: 20
New Protection: 20
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 000000014003eaa8
Size: 60
New Protection: 40
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 000000014003edb8
Size: 720
New Protection: 40
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 000000014003edb8
Size: 680
New Protection: 40
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 0000000140000000
Size: 384
New Protection: 4
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 0000000140000000
Size: 384
New Protection: 2
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 000000014003edb8
Size: 680
New Protection: 40
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 000000014003edb8
Size: 720
New Protection: 80
VirtualProtect result: 1
VirtualProtect called with parameters:
Address: 000000014003eaa8
Size: 60
New Protection: 2
VirtualProtect result: 1
[*] reprotecting stack through VirtualQuery&VirtualProtect...
VirtualProtect called with parameters:
Address: 00000000194fe000
Size: 8192
New Protection: 40
VirtualProtect result: 1
[i] please enter the flag: cr3{test}
[i] hint: can you figure what am i calling?
[i] hell nah
```

The last protection is very large compared to the other (8192 bytes) and is located on the... stack!
The protection for it is also suspiciously 0x40 which stands for PAGE_EXECUTE_READWRITE.

So it is running shellcodes, which it presumably devirtualises one by one.

## Dynamic analysis

At this point we need to see what is it executing on the stack or to see whether it is even doing this. 
Lets block the last VirtualProtect call, which sets the stack to RWX, and view in IDA, where it fails, if it does.

![image](https://github.com/user-attachments/assets/4b31f220-5780-43fb-93fe-bb1bac001845)

And it tried to execute something from the stack, we can even see what

![image](https://github.com/user-attachments/assets/329e47c8-da3a-4226-b153-247bbb0a546a)

We can see it loading something from rcx, this is actually where our flag resides, you can see cr3{ to the left of it, then it loads peb and from it takes the IsBeingDebugged bit, does some math and finally compares it with a constant.

Alright, now to catch them all (all of the other shellcodes), we need to find a vm exit. For that to happen I enable instruction tracing and put a breakpoint where we found the shellcode. This wili take some time, since themida is virtualising a whole bunch of stuff and IDA is a prehistoric piece of software.

![image](https://github.com/user-attachments/assets/51ed38c0-79ea-45bb-9dce-9e5dd351bccd)

We find it, so allowing the VirtualProtect call and putting the breakpoint on the vmexit will allow us to see what is actually happening.

The vmexit triggers the following calls: themida stuff (which later calls VirtualProtect twice), kernel32_GetCurrentThread, advapi32_OpenThreadToken, kernel32_GetCurrentProcess, advapi32_OpenProcessToken,advapi32_AllocateAndInitializeSid, advapi32_FreeSid, kernel32_VirtualFree, shell32_IsUserAnAdmin, then another call to themida internals which performs a bunch of VirtualProtects, user input call, and then we see our shell codes:

![image](https://github.com/user-attachments/assets/448c399d-a2f2-4dbf-8317-5f3b7dfacb98)

and another one:


![image](https://github.com/user-attachments/assets/5f8406ef-6b28-4629-837a-cc6c95f796ea)


and another:

![image](https://github.com/user-attachments/assets/10280910-b627-4ccf-a5c3-eb761a723dee)

Ok, so we can now notice the trend: it grabs the char from rcx, does some math on it grabs stuff from memory, compares and returns 1 if success, 0 if failiure in eax.

## Pintool solution

We know that we are after code execution from the stack, and we know it start from mov cl, [rcx]

So lets create a pintool which upon locating this Basic Block (from now reffered to as BBL), which is on the stack, starts with mov cl, [rcx], find the right value of the chararcter, which satisfies the condition.

To do that we will need to make a TRACE_CALLBACK function, and for each BBL check its address and instructions.

```c
VOID TraceCallback(TRACE trace, VOID *v) {
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    ADDRINT bblAddress = BBL_Address(bbl);

    if (bblAddress >= 0x194fe000 && bblAddress <= (0x194fe000 + 8192)) {

      INS ret_ins;
      INS st_ins;
      int flag = 0;
      int counter = 0;
      for (INS ins = BBL_InsHead(bbl);
           INS_Valid(ins) && counter < 50 && flag != 3;
           ins = INS_Next(ins), counter++) {

        if ("mov cl, byte ptr [rcx]" == INS_Disassemble(ins)) {
          st_ins = ins;
          flag |= 2;
        }
        if (INS_IsRet(ins)) {
          flag |= 1;
          ret_ins = ins;
          break;
        }
      }
      if (flag != 3) {
        continue;
      }

      INS_InsertCall(st_ins, IPOINT_BEFORE, (AFUNPTR)starter, IARG_PTR,
                     st_ins, 
                     IARG_CONTEXT, IARG_END);
      INS_InsertCall(ret_ins, IPOINT_BEFORE, (AFUNPTR)ender, IARG_PTR,
                     ret_ins, 
                     IARG_CONTEXT, IARG_END);
    }
  }
}
```

Then we locate its first instruction and its last and we insert funtion calls which will do the char bruteforcing into them, passing the instruction and the current context.


The basic idea of the bruteforcing is that we 
 - locate the index of where the char resides relative the the flags starting prefix "cr3{"
 - save the current context, so that we can restore it later
 - let the execution go on
 - catch at the return
 - check eax
 - if its one, we found the char, we save it to the buffer and log that we did
 - if not, we increase the value we try to pass as a char, and restore the context to the start of the BBL and let it run again

```c
static CONTEXT ctx;
static UINT8 value = 0;
static int index = -4;

VOID starter(INS start_ins, CONTEXT *context) {

  UINT8 tmp = 0;
  ADDRINT rcx = PIN_GetContextReg(context, REG_RCX);
  if (index == -4) {
    while (tmp != '{') {
      PIN_SafeCopy(&tmp, (UINT8 *)rcx - index, sizeof(UINT8));
      index++;
    }
  }
  PIN_SaveContext(context, &ctx);
  PIN_SafeCopy((UINT8 *)rcx, &value, sizeof(value));
}

VOID ender(INS start_ins, CONTEXT *context) {
  ADDRINT rax = PIN_GetContextReg(context, REG_RAX);
  if (rax & 1) {
    fprintf(TraceFile, "letter found index %d -> %c\n", index, value);
    flag[index + 4] = value;
    index = -4;
  } else {
    value++;
    PIN_SaveContext(&ctx, context);
    PIN_ExecuteAt(context);
  }
}
```

Compiling pin is a massive headache, since I hate myself and do not use VisualStudio, but finally when we run the exe with our pintool:

we get:
```
[*] reprotecting stack through VirtualQuery&VirtualProtect...
[i] please enter the flag: cr3{
[i] hint: can you figure what am i calling?
[i] sounds about right
flag: cr3{0hw0www_YoU_4re_Th3_real_d34L!Ih0p3_y0u_werent_sc4red!!!!!!_hhmmpfrdkfegtsniczjyew6s3jiugm7mdev}
```

