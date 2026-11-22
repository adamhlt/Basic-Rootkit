#ifndef ROOTKIT_H
#define ROOTKIT_H

#include <Windows.h>

/**
 * Install the hooks. This function is meant to run on the dedicated thread
 * created from DllMain and terminates that thread once the hooks are set.
 * \param lpParam : unused.
 */
DWORD WINAPI InitHook(LPVOID lpParam);

/**
 * Remove the hooks and unload the DLL, then terminate the calling thread.
 * \param hModule : handle of the DLL to unload.
 */
void RemoveHookAndFreeLibrary(HMODULE hModule);

#endif
