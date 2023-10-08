
// Default
#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>

// Terminal
#include "Terminal.h"

// Detours
#include "Detours.h"

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

enum class PRODUCT_TYPE : unsigned char {
	UNKNOWN = 0,
	CODE_VIRTUALIZER = 1,
	THEMIDA = 2,
	THEMIDA64 = 3,
	WINLICENSE = 4,
	WINLICENSE64 = 5
};

typedef LONG(NTAPI* fnNtFlushInstructionCache)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);

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
	// Terminal Session Name
	TCHAR m_pSessionName[64];
} LOADER_DATA, *PLOADER_DATA;

bool g_bIsValidLaunch = false;
bool g_bStop = false;

size_t GetExportOffset(void* pMemory, const size_t unSize, const char* szExportName) {
	if (!pMemory) {
		return 0;
	}

	if (!unSize) {
		return 0;
	}

	if (unSize < sizeof(IMAGE_DOS_HEADER)) {
		return 0;
	}

	const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMemory);
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	if (unSize < pDH->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
		return 0;
	}

	const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pMemory) + pDH->e_lfanew);
	if (pNTHs->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	const PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
#ifdef _WIN64
	if (pFH->Machine != IMAGE_FILE_MACHINE_AMD64) {
		return 0;
	}

	const PIMAGE_OPTIONAL_HEADER64 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 0;
	}
#elif _WIN32
	if (pFH->Machine != IMAGE_FILE_MACHINE_I386) {
		return 0;
	}

	const PIMAGE_OPTIONAL_HEADER32 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return 0;
	}
#else
#error Unknown platform
#endif

	const PIMAGE_DATA_DIRECTORY pExportDD = &(pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	const PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(&(pNTHs->OptionalHeader)) + pFH->SizeOfOptionalHeader);
	for (DWORD i = 0; i < pFH->NumberOfSections; ++i) {
		if ((pExportDD->VirtualAddress >= pFirstSection[i].VirtualAddress) && (pExportDD->VirtualAddress < (pFirstSection[i].VirtualAddress + pFirstSection[i].Misc.VirtualSize))) {

			const DWORD unDelta = pFirstSection[i].VirtualAddress - pFirstSection[i].PointerToRawData;

			const PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pMemory) + pExportDD->VirtualAddress - unDelta);

			const PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(pMemory) + pExportDirectory->AddressOfFunctions - unDelta);
			const PWORD pOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<char*>(pMemory) + pExportDirectory->AddressOfNameOrdinals - unDelta);
			const PDWORD pNames = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(pMemory) + pExportDirectory->AddressOfNames - unDelta);

			const DWORD unNumberOfFunctions = pExportDirectory->NumberOfFunctions;
			const DWORD unNumberOfNames = pExportDirectory->NumberOfNames;
			for (DWORD j = 0; j < unNumberOfFunctions; ++j) {
				for (DWORD l = 0; l < unNumberOfNames; ++l) {
					if (pOrdinals[l] == j) {
						if (strcmp(szExportName, reinterpret_cast<char*>(pMemory) + pNames[l] - unDelta) == 0) {
							const DWORD unRVA = *reinterpret_cast<PDWORD>(&pFunctions[pOrdinals[l]]);
							for (DWORD k = 0; k < pFH->NumberOfSections; ++k) {
								if ((unRVA >= pFirstSection[k].VirtualAddress) && (unRVA < (pFirstSection[k].VirtualAddress + pFirstSection[k].SizeOfRawData))) {
									return unRVA - pFirstSection[k].VirtualAddress + pFirstSection[k].PointerToRawData;
								}
							}
						}
					}
				}
			}
		}
	}

	return 0;
}

bool InjectLibrary(Terminal::Console& Console, Terminal::Server& TerminalServer, const HANDLE hProcess, const HANDLE hProcessThread, void* pMemory, const size_t unSize, PLOADER_DATA pLoaderData) {
	if (!hProcess) {
		return false;
	}

	if (!pMemory) {
		return false;
	}

	if (!unSize) {
		return false;
	}

	if (unSize < sizeof(IMAGE_DOS_HEADER)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (File is too small)\n"));
		return false;
	}

	const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMemory);
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid DOS signature)\n"));
		return false;
	}

	if (unSize < pDH->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (File is too small)\n"));
		return false;
	}

	const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pMemory) + pDH->e_lfanew);
	if (pNTHs->Signature != IMAGE_NT_SIGNATURE) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid PE signature)\n"));
		return false;
	}

	const PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
#ifdef _WIN64
	if (pFH->Machine != IMAGE_FILE_MACHINE_AMD64) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid platform)\n"));
		return false;
	}

	const PIMAGE_OPTIONAL_HEADER64 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid optional PE signature)\n"));
		return false;
	}
#elif _WIN32
	if (pFH->Machine != IMAGE_FILE_MACHINE_I386) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid platform)\n"));
		return false;
	}

	const PIMAGE_OPTIONAL_HEADER32 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid optional PE signature)\n"));
		return false;
	}
#else
#error Unknown platform
#endif

	const size_t unLoaderOffset = GetExportOffset(pMemory, unSize, "?LibraryMain@@YGKPAX@Z");
	if (!unLoaderOffset) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Loader not found)\n"));
		return false;
	}

	void* pBuffer = VirtualAllocEx(hProcess, nullptr, unSize + sizeof(LOADER_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pBuffer) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to allocate memory)\n"));
		return false;
	}

	if (!WriteProcessMemory(hProcess, pBuffer, pMemory, unSize, nullptr)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to write memory)\n"));
		return false;
	}

	pLoaderData->m_pMemoryAddress = pBuffer;
	pLoaderData->m_unMemorySize = unSize;

	char szBuffer[sizeof(LOADER_DATA::m_pLoaderPath)];
	memset(szBuffer, 0, sizeof(szBuffer));
	if (!GetModuleFileNameA(nullptr, szBuffer, sizeof(szBuffer))) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Unknown path)\n"));
		return false;
	}

	char szDriveFile[sizeof(LOADER_DATA::m_pLoaderPath) / 2];
	memset(szDriveFile, 0, sizeof(szDriveFile));
	char szDirFile[sizeof(LOADER_DATA::m_pLoaderPath) / 2];
	memset(szDirFile, 0, sizeof(szDirFile));
	if (_splitpath_s(szBuffer, szDriveFile, sizeof(szDriveFile) - 1, szDirFile, sizeof(szDirFile) - 1, nullptr, 0, nullptr, 0)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Unknown path)\n"));
		return false;
	}

	memset(szBuffer, 0, sizeof(szBuffer));
	sprintf_s(szBuffer, "%s%s", szDriveFile, szDirFile);

	memcpy(pLoaderData->m_pLoaderPath, szBuffer, sizeof(LOADER_DATA::m_pLoaderPath));

	TCHAR szSessionName[64];
	if (!TerminalServer.GetSessionName(szSessionName)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to get session name\n"));
		return false;
	}

	memcpy(pLoaderData->m_pSessionName, szSessionName, sizeof(LOADER_DATA::m_pSessionName));

	if (!WriteProcessMemory(hProcess, reinterpret_cast<char*>(pBuffer) + unSize, pLoaderData, sizeof(LOADER_DATA), nullptr)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to write memory)\n"));
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<size_t>(pBuffer) + unLoaderOffset), reinterpret_cast<char*>(pBuffer) + unSize, CREATE_SUSPENDED, nullptr);
	if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid thread handle)\n"));
		return false;
	}

	ResumeThread(hThread);

	ResumeThread(hProcessThread);

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return true;
}

bool FileRead(Terminal::Console& Console, const TCHAR* szPath, PHANDLE phHeap, LPVOID* ppMemory, PDWORD punFileSize) {
	const HANDLE hFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `CreateFile` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	const DWORD unFileSize = GetFileSize(hFile, nullptr);
	if (!unFileSize || (unFileSize == INVALID_FILE_SIZE)) {
		CloseHandle(hFile);
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `GetFileSize` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	const HANDLE hHeap = GetProcessHeap();
	if (!hHeap || (hHeap == INVALID_HANDLE_VALUE)) {
		CloseHandle(hFile);
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `GetProcessHeap` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	void* pMemory = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, unFileSize);
	if (!pMemory) {
		CloseHandle(hFile);
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `HeapAlloc` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	DWORD unNumberOfBytesRead = 0;
	if (!ReadFile(hFile, pMemory, unFileSize, &unNumberOfBytesRead, nullptr) && (unFileSize != unNumberOfBytesRead)) {
		if (!HeapFree(hHeap, NULL, pMemory)) {
			CloseHandle(hFile);
			Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
			return false;
		}
		CloseHandle(hFile);
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `HeapAlloc` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	CloseHandle(hFile);

	if (phHeap) {
		*phHeap = hHeap;
	}

	if (ppMemory) {
		*ppMemory = pMemory;
	} else {
		if (!HeapFree(hHeap, NULL, pMemory)) {
			Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
			return false;
		}
	}

	if (punFileSize) {
		*punFileSize = unFileSize;
	}

	return true;
}

bool HackProcess(Terminal::Console& Console, Terminal::Server& TerminalServer, const HANDLE hProcess, const HANDLE hProcessThread) {
	if (!hProcess) {
		return false;
	}

	HMODULE hRemoteNTDLL = nullptr;
	HMODULE hRemoteKernel32 = nullptr;

	HMODULE hModules[1024];
	memset(hModules, 0, sizeof(hModules));

	DWORD unNeeded = 0;

	while (!hRemoteNTDLL || !hRemoteKernel32) {
		if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &unNeeded)) {
			const DWORD unEnd = unNeeded / sizeof(HMODULE);
			for (unsigned int i = 0; i < unEnd; ++i) {
				TCHAR szModuleName[MAX_PATH];
				memset(szModuleName, 0, sizeof(szModuleName));
				if (GetModuleBaseName(hProcess, hModules[i], szModuleName, MAX_PATH - 1)) {
					if ((_tccmp(szModuleName, _T("ntdll.dll")) == 0) && !hRemoteNTDLL) {
						hRemoteNTDLL = hModules[i];
						continue;
					}

					if ((_tccmp(szModuleName, _T("KERNEL32.DLL")) == 0) && !hRemoteKernel32) {
						hRemoteKernel32 = hModules[i];
						continue;
					}
				}
			}
		}

		if (!hRemoteNTDLL || !hRemoteKernel32) {
			ResumeThread(hProcessThread);
			SuspendThread(hProcessThread);
		}
	}

	Sleep(10000);

	LOADER_DATA LoaderData;
	memset(&LoaderData, 0, sizeof(LoaderData));

	LoaderData.m_pNtFlushInstructionCache = reinterpret_cast<fnNtFlushInstructionCache>(GetProcAddress(hRemoteNTDLL, "NtFlushInstructionCache"));
	LoaderData.m_pVirtualAlloc = reinterpret_cast<fnVirtualAlloc>(GetProcAddress(hRemoteKernel32, "VirtualAlloc"));
	LoaderData.m_pGetProcAddress = reinterpret_cast<fnGetProcAddress>(GetProcAddress(hRemoteKernel32, "GetProcAddress"));
	LoaderData.m_pLoadLibraryA = reinterpret_cast<fnLoadLibraryA>(GetProcAddress(hRemoteKernel32, "LoadLibraryA"));

	HANDLE hHeap = nullptr;
	LPVOID pMemory = nullptr;
	DWORD unFileSize = 0;

	if (!FileRead(Console, _T("Library.dll"), &hHeap, &pMemory, &unFileSize)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `FileRead` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	if (!InjectLibrary(Console, TerminalServer, hProcess, hProcessThread, pMemory, unFileSize, &LoaderData)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `InjectLibrary` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	Console.tprintf(Terminal::COLOR::COLOR_GREEN, _T("[+] Library injected!\n"));
	Console.tprintf(Terminal::COLOR::COLOR_GREEN, _T("[+]  > Base = 0x%08X\n"), reinterpret_cast<unsigned int>(LoaderData.m_pMemoryAddress));
	Console.tprintf(Terminal::COLOR::COLOR_GREEN, _T("[+]  > Size = 0x%08X\n"), LoaderData.m_unMemorySize);

	if (!HeapFree(hHeap, NULL, pMemory)) {
		Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

int _tmain(int nArgsCount, PTCHAR* pArgs, PTCHAR* pEnvVars) {
	if (nArgsCount < 1) {
		return -1;
	}

	Terminal::Window Window;
	if (Window.Open()) {
		Terminal::Screen Screen(&Window);
		Terminal::Console Console(&Screen);

		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_BLACK, 0x1B1B1B);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_DARK_BLUE, 0x2962FF);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_DARK_GREEN, 0x00C853);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_DARK_CYAN, 0x00B8D4);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_DARK_RED, 0xD50000);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_DARK_MAGENTA, 0xAA00FF);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_DARK_YELLOW, 0xFFD600);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_DARK_GRAY, 0x616161);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_GRAY, 0xEEEEEE);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_BLUE, 0x448AFF);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_GREEN, 0x69F0AE);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_CYAN, 0x18FFFF);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_RED, 0xFF5252);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_MAGENTA, 0xE040FB);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_YELLOW, 0xFFFF00);
		Screen.ChangeColorPalette(Terminal::COLOR::COLOR_WHITE, 0xFAFAFA);

		Console.tprintf(Terminal::COLOR::COLOR_WHITE, _T("OreansConsole [Version 2.0.0]\n\n"));

		TCHAR szMainFileName[16];
		memset(szMainFileName, 0, sizeof(szMainFileName));

		TCHAR szMainFileExtension[8];
		memset(szMainFileExtension, 0, sizeof(szMainFileExtension));

		if (_tsplitpath_s(pArgs[0], nullptr, 0, nullptr, 0, szMainFileName, sizeof(szMainFileName) / sizeof(TCHAR), szMainFileExtension, sizeof(szMainFileExtension) / sizeof(TCHAR)) != 0) {
			return -1;
		}

		TCHAR szMainFile[32];
		memset(szMainFile, 0, sizeof(szMainFile));

		if (_stprintf_p(szMainFile, sizeof(szMainFile) / sizeof(TCHAR), _T("%s%s"), szMainFileName, szMainFileExtension) == -1) {
			return -1;
		}

		if (nArgsCount < 2) {
			Console.tprintf(Terminal::COLOR::COLOR_YELLOW, _T("Usage: %s /[cv|th|wl] <args>\n"), szMainFile);
			return 0;
		}

		PRODUCT_TYPE unProductType = PRODUCT_TYPE::UNKNOWN;

		for (int i = 0; i < nArgsCount; ++i) {
			PTCHAR pArg = pArgs[i];
			if (!pArg) {
				return -1;
			}

			if (_tcscmp(pArg, _T("/help")) == 0) {
				Console.tprintf(Terminal::COLOR::COLOR_YELLOW, _T("Usage: %s /[cv|th|wl] <args>\n  /cv - Code Virtualizer\n  /th - Themida\n  /wl - WinLicense\n  <args> - Passes arguments.\n"), szMainFile);
				return 0;
			}

			if (_tcscmp(pArg, _T("/cv")) == 0) {
				unProductType = PRODUCT_TYPE::CODE_VIRTUALIZER;
				continue;
			}

			if (_tcscmp(pArg, _T("/th")) == 0) {
				unProductType = PRODUCT_TYPE::THEMIDA;
				continue;
			}

			if (_tcscmp(pArg, _T("/th64")) == 0) {
				unProductType = PRODUCT_TYPE::THEMIDA64;
				continue;
			}

			if (_tcscmp(pArg, _T("/wl")) == 0) {
				unProductType = PRODUCT_TYPE::WINLICENSE;
				continue;
			}

			if (_tcscmp(pArg, _T("/wl64")) == 0) {
				unProductType = PRODUCT_TYPE::WINLICENSE64;
				continue;
			}
		}

		if (unProductType == PRODUCT_TYPE::UNKNOWN) {
			//Console.tprintf(Terminal::COLOR::COLOR_YELLOW, _T("Usage: %s /[cv|cv64|th|th64|wl|wl64] <args to parse in product>\n"), szMainFile);
			Console.tprintf(Terminal::COLOR::COLOR_YELLOW, _T("Usage: %s /[cv|cv64|th|th64|wl|wl64]\n"), szMainFile);
			return -1;
		}

		HANDLE hToken = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `OpenProcessToken` (LastError = 0x%08X)\n"), GetLastError());
			return -1;
		}

		LUID luid;
		memset(&luid, 0, sizeof(luid));

		if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
			CloseHandle(hToken);
			Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `LookupPrivilegeValue` (LastError = 0x%08X)\n"), GetLastError());
			return -1;
		}

		TOKEN_PRIVILEGES tp;
		memset(&tp, 0, sizeof(tp));

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
			CloseHandle(hToken);
			Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `AdjustTokenPrivileges` (LastError = 0x%08X)\n"), GetLastError());
			return -1;
		}

		CloseHandle(hToken);

		STARTUPINFO si;
		memset(&si, 0, sizeof(si));

		si.cb = sizeof(STARTUPINFO);

		PROCESS_INFORMATION pi;
		memset(&pi, 0, sizeof(pi));

		if (unProductType == PRODUCT_TYPE::CODE_VIRTUALIZER) {
			if (!CreateProcess(_T("Virtualizer.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::THEMIDA) {
			if (!CreateProcess(_T("Themida.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::THEMIDA64) {
			if (!CreateProcess(_T("Themida64.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::WINLICENSE) {
			if (!CreateProcess(_T("WinLicense.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::WINLICENSE64) {
			if (!CreateProcess(_T("WinLicense64.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				Console.tprintf(Terminal::COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		Terminal::Server TerminalServer(&Screen);

		if (!HackProcess(Console, TerminalServer, pi.hProcess, pi.hThread)) {
			CloseHandle(pi.hThread);
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			return -1;
		}

		if (!TerminalServer.Open()) {
			CloseHandle(pi.hThread);
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			return -1;
		}

		TerminalServer.Launch();

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	return 0;
}
