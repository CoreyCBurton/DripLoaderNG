#pragma once

#include <Windows.h>

extern "C" {
UINT_PTR SyscallInst = 0;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntmmapi.h
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped,
	MemoryPhysicalContiguityInformation,
	MemoryBadInformation,
	MemoryBadInformationAllProcesses,
	MemoryImageExtensionInformation,
	MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

extern NTSYSCALLAPI NTSTATUS NtQueryVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
);

extern NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

extern NTSYSCALLAPI NTSTATUS NtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
);

}
