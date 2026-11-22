<div align="center">

# Basic Rootkit

**POC ring 3 Windows rootkit in C++ (x86 / x64), hide processes and files**

![Language](https://img.shields.io/badge/C%2B%2B-16171C?logo=cplusplus)
![Platform](https://img.shields.io/badge/Windows-16171C)
![Arch](https://img.shields.io/badge/x86%20%7C%20x64-16171C)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-16171C)](LICENSE)

</div>

---

Basic Rootkit is a proof-of-concept ring 3 Windows rootkit that hides processes and files from the running system.

It is built as a DLL that patches the Import Address Table (IAT) of the host process, redirecting `NtQuerySystemInformation` and `NtQueryDirectoryFile` to filtered versions. Every entry whose name contains the `$pwn` identifier is unlinked from the returned list, so the hidden process or file becomes invisible to the tools that enumerate them. The same code base handles x86 and x64 applications.

## Features

**Hide processes**
- Unlink matching processes from `NtQuerySystemInformation` (`SystemProcessInformation`)

**Hide files**
- Unlink matching files from `NtQueryDirectoryFile` (`FileIdBothDirectoryInformation`)

It has been tested with Task Manager (x64), Explorer (x64) and Process Hacker (x86) on Windows 10.

## Demonstration

https://user-images.githubusercontent.com/48086737/165148200-de84195f-7db9-4cf7-8090-cfddc6e52872.mp4

https://user-images.githubusercontent.com/48086737/165148912-5030612b-e3a7-491b-b132-ccbe2fcb32fc.mp4

## Usage

This project produces a DLL that can be injected into any application you want to hook. Every process or file whose name contains the default `$pwn` identifier is hidden from the IAT hooks.

## Build

1. Open `Basic Rootkit.sln` in Visual Studio.
2. Build the project in Debug / Release (x86 / x64).

- **Output:** every configuration is already set up, the produced DLL is named `Basic Rootkit.dll`
- **Architecture:** the x86 and x64 builds work on both x86 and x64 applications

You can also easily carry this project to CMake.

> **Warning** <br>
> If you have any linking error when compiling make sure you include "Shlwapi.lib" to the project.

## License

This project is licensed under the [GNU GPLv3](LICENSE).
