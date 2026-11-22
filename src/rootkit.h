#ifndef ROOTKIT_H
#define ROOTKIT_H

#include <Windows.h>

/**
 * Initialize the configuration, install every hook and hide the DLL from the
 * module list. This function is meant to run on the dedicated thread created
 * from DllMain and terminates that thread once done.
 * \param lpParam : module handle of the DLL.
 */
DWORD WINAPI InitHook(LPVOID lpParam);

/**
 * Remove every hook and unload the DLL, then terminate the calling thread.
 * \param hModule : handle of the DLL to unload.
 */
void RemoveHookAndFreeLibrary(HMODULE hModule);

#endif
