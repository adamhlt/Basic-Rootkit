#ifndef IAT_HOOK_H
#define IAT_HOOK_H

#include <Windows.h>

class IAT
{
public:
	static LPVOID Hook(LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction, LPCSTR lpTargetModuleName);
	static LPVOID Hook(LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction);

private:
	static LPVOID GetCurrentProcessModule();
	static LPVOID PatchImportTable(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction);
};

#endif
