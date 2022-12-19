#pragma once

#ifndef _LOADER_H_
#define _LOADER_H_

// Framework
#include "framework.h"

// General definitions

typedef LONG(NTAPI* fnNtFlushInstructionCache)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);

typedef BOOL(APIENTRY* fnDllMain)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

typedef struct {
	WORD unOffset : 12;
	WORD unType : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef struct _LOADER_DATA {
	// Addresses
	fnNtFlushInstructionCache m_pNtFlushInstructionCache;
	fnVirtualAlloc m_pVirtualAlloc;
	fnGetProcAddress m_pGetProcAddress;
	fnLoadLibraryA m_pLoadLibraryA;
	// Memory
	void* m_pMemoryAddress;
	size_t m_unMemorySize;
	char m_pLoaderPath[1024];
} LOADER_DATA, *PLOADER_DATA;

#endif // !_LOADER_H_
