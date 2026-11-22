<div align="center">

# Basic Rootkit

**POC ring 3 Windows rootkit in C++ (x86 / x64), hide processes, files, registry keys, services and the injected DLL**

![Language](https://img.shields.io/badge/C%2B%2B-16171C?logo=cplusplus)
![Platform](https://img.shields.io/badge/Windows-16171C)
![Arch](https://img.shields.io/badge/x86%20%7C%20x64-16171C)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-16171C)](LICENSE)

</div>

---

Basic Rootkit is a proof-of-concept ring 3 Windows rootkit that hides processes, files, registry keys and services from the running system, hides itself from the module list and protects its host process.

It is built as a DLL that patches the Import Address Table (IAT) of the host process, redirecting several `Nt*` and Win32 functions to filtered versions. Every entry whose name contains a hidden token is unlinked from the returned list, so the target becomes invisible to the tools that enumerate it. The same code base handles x86 and x64 applications.

## Features

**Hide processes**
- Unlink matching processes from `NtQuerySystemInformation` (`SystemProcessInformation`)

**Hide files**
- Unlink matching files from `NtQueryDirectoryFile` (`FileIdBothDirectoryInformation`)

**Hide registry keys and values**
- Skip matching keys and values from `NtEnumerateKey` and `NtEnumerateValueKey`

**Hide services**
- Remove matching services from `EnumServicesStatusExW`

**Hide the injected DLL**
- Unlink the DLL from the PEB loader lists so it disappears from `EnumProcessModules` and module snapshots

**Protect the host process**
- Strip `PROCESS_TERMINATE` in `NtOpenProcess` so the host process cannot be terminated from the outside

It has been tested with Task Manager (x64), Explorer (x64) and Process Hacker (x86) on Windows 10.

## Configuration

The identifier used to mark the entries to hide defaults to `$pwn`. It can be overridden at load time, in this order:

- The `ROOTKIT_TOKENS` environment variable (several tokens separated by `;`, `,` or newlines)
- A `rootkit.tokens` file placed next to the DLL (one token per line, `#` starts a comment)
- The `$pwn` default

Hiding can also be toggled at runtime through the exported functions:

```c
void EnableHiding();
void DisableHiding();
BOOL IsHidingEnabled();
```

## Demonstration

https://user-images.githubusercontent.com/48086737/165148200-de84195f-7db9-4cf7-8090-cfddc6e52872.mp4

https://user-images.githubusercontent.com/48086737/165148912-5030612b-e3a7-491b-b132-ccbe2fcb32fc.mp4

## Usage

This project produces a DLL that can be injected into any application you want to hook. Once loaded, every entry whose name contains a hidden token is removed from the hooks described above, and the DLL itself disappears from the module list.

The hidden token must be part of the name of the process, file, registry key/value or service you want to hide (for example a process whose executable is named `payload$pwn.exe`).

## Build

1. Open `Basic Rootkit.sln` in Visual Studio.
2. Build the project in Debug / Release (x86 / x64).

- **Output:** every configuration is already set up, the produced DLL is named `Basic Rootkit.dll`
- **Architecture:** the x86 and x64 builds work on both x86 and x64 applications

You can also easily carry this project to CMake.

> **Warning** <br>
> If you have any linking error when compiling make sure you include "Shlwapi.lib" to the project.

## Disclaimer

This project is provided for educational and research purposes only, to study how user-mode rootkits work. Use it only on systems you own or are explicitly authorized to test.

## License

This project is licensed under the [GNU GPLv3](LICENSE).
