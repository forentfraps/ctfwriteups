#include "pin.H"
#include <cstdio>

FILE *TraceFile;
static unsigned char flag[200];

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
                     st_ins, // Pass the BBL itself
                     IARG_CONTEXT, IARG_END);
      INS_InsertCall(ret_ins, IPOINT_BEFORE, (AFUNPTR)ender, IARG_PTR,
                     ret_ins, // Pass the BBL itself
                     IARG_CONTEXT, IARG_END);
    }
  }
}
VOID Fini(INT32 code, VOID *v) {
  fprintf(stdout, "flag: ");
  for (int i = 0; i < 200; ++i) {
    fprintf(stdout, "%c", flag[i]);
  }
}
int __declspec(dllexport) main(int argc, char *argv[]) {
  // Initialize pin
  if (PIN_Init(argc, argv)) {
    fprintf(stderr, "This pintool is made to solve a challenge from cr3 2024 "
                    "ctf - wonderfulFlagChecker\n");
    return 1;
  }

  // Open output file
  TraceFile = fopen("trace_output.txt", "w");
  if (!TraceFile) {
    fprintf(stderr, "Failed to open trace output file.\n");
    return 1;
  }

  TRACE_AddInstrumentFunction(TraceCallback, 0);
  PIN_AddFiniFunction(Fini, 0);

  PIN_StartProgram();

  fclose(TraceFile);
  return 0;
}
