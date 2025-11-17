#pragma once

#include <stdio.h>

#define CURRENT_PROCESS (HANDLE)(LONG_PTR)(-1)
#define CURRENT_THREAD (HANDLE)(LONG_PTR)(-2)

#ifdef _DEBUG
#define DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

VOID Delay(DWORD time);
UINT_PTR GetSyscallInst();
PUCHAR DecompressShellcode(PSIZE_T pShellcodeLength);
