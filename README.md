```
                       ____             _         ____              __  __   _ __ 
                      / __ )____ ______(_)____   / __ \____  ____  / /_/ /__(_) /_
                     / __  / __ `/ ___/ / ___/  / /_/ / __ \/ __ \/ __/ //_/ / __/
                    / /_/ / /_/ (__  ) / /__   / _, _/ /_/ / /_/ / /_/ ,< / / /_
                   /_____/\__,_/____/_/\___/  /_/ |_|\____/\____/\__/_/|_/_/\__/
                                                                     
                                                                     
                                POC Ring3 Windows Rootkit (x86 / x64)
                                      Hide processes and files
```

[![C++](https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/C%2B%2B) [![Windows](https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/Microsoft_Windows) [![x86](https://img.shields.io/badge/arch-x86-red.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/X86) [![x64](https://img.shields.io/badge/arch-x64-green.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/X64)

## :open_book: Project Overview :

This is project is a simple Windows ring 3 rootkit. It use my [IAT Hook library](https://github.com/adamhlt/IAT-Hooking) to perform hooking.

Rootkit functionnalities :

- Hide processes
- Hide files

Tested on :

- Task Manager (Windows 10 - x64)
- Explorer (Windows 10 - x64)
- Process Hacker (Windows 10 - x86)

It is working on x86 and x64 applications, you can easily add some new features using the library and using what I already did.

This project is a DLL and can be inject in every application you want to hook, the default prefix identifier is "$pwn".

## :rocket: Getting Started :

### Visual Studio :

1. Open the solution file (.sln).
2. Build the project in Debug / Release (x86 / x64)

### Other IDE using CMAKE :

You can easily carry this project on CMAKE.

> **Warning** <br>
> If you have any linking error when compiling make sure you include "Shlwapi.lib" to the project.

## :test_tube: Demonstration :

https://user-images.githubusercontent.com/48086737/165148200-de84195f-7db9-4cf7-8090-cfddc6e52872.mp4

https://user-images.githubusercontent.com/48086737/165148912-5030612b-e3a7-491b-b132-ccbe2fcb32fc.mp4
