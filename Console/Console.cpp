
// Default
#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>

// Custom
#include "ConsoleUtils.h"
#include "Detours.h"

// Namespaces
using namespace ConsoleUtils;
using namespace Detours;

// General definitions

bool g_bIsValidLaunch = false;
bool g_bStop = false;

enum class PRODUCT_TYPE : unsigned char {
	UNKNOWN = 0,
	CODE_VIRTUALIZER = 1,
	CODE_VIRTUALIZER64 = 2,
	THEMIDA = 3,
	THEMIDA64 = 4,
	WINLICENSE = 5,
	WINLICENSE64 = 6
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
} LOADER_DATA, *PLOADER_DATA;

typedef struct _CONSOLE_MESSAGE {
	char m_pMessage[1024];
	COLOR_PAIR m_ColorPair;
} CONSOLE_MESSAGE, *PCONSOLE_MESSAGE;


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

bool InjectLibrary(const HANDLE hProcess, const HANDLE hProcessThread, void* pMemory, const size_t unSize, PLOADER_DATA pLoaderData) {
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
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (File is too small)\n"));
		return false;
	}

	const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMemory);
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid DOS signature)\n"));
		return false;
	}

	if (unSize < pDH->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (File is too small)\n"));
		return false;
	}

	const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pMemory) + pDH->e_lfanew);
	if (pNTHs->Signature != IMAGE_NT_SIGNATURE) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid PE signature)\n"));
		return false;
	}

	const PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
#ifdef _WIN64
	if (pFH->Machine != IMAGE_FILE_MACHINE_AMD64) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid platform)\n"));
		return false;
	}

	const PIMAGE_OPTIONAL_HEADER64 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid optional PE signature)\n"));
		return false;
	}
#elif _WIN32
	if (pFH->Machine != IMAGE_FILE_MACHINE_I386) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid platform)\n"));
		return false;
	}

	const PIMAGE_OPTIONAL_HEADER32 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid optional PE signature)\n"));
		return false;
	}
#else
#error Unknown platform
#endif

	const size_t unLoaderOffset = GetExportOffset(pMemory, unSize, "?LibraryMain@@YGKPAX@Z");
	if (!unLoaderOffset) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Loader not found)\n"));
		return false;
	}

	void* pBuffer = VirtualAllocEx(hProcess, nullptr, unSize + sizeof(LOADER_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pBuffer) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to allocate memory)\n"));
		return false;
	}

	if (!WriteProcessMemory(hProcess, pBuffer, pMemory, unSize, nullptr)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to write memory)\n"));
		return false;
	}

	pLoaderData->m_pMemoryAddress = pBuffer;
	pLoaderData->m_unMemorySize = unSize;

	char szBuffer[sizeof(LOADER_DATA::m_pLoaderPath)];
	memset(szBuffer, 0, sizeof(szBuffer));
	if (!GetModuleFileNameA(nullptr, szBuffer, sizeof(szBuffer))) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unknown path)\n"));
		return false;
	}

	char szDriveFile[sizeof(LOADER_DATA::m_pLoaderPath) / 2];
	memset(szDriveFile, 0, sizeof(szDriveFile));
	char szDirFile[sizeof(LOADER_DATA::m_pLoaderPath) / 2];
	memset(szDirFile, 0, sizeof(szDirFile));
	if (_splitpath_s(szBuffer, szDriveFile, sizeof(szDriveFile) - 1, szDirFile, sizeof(szDirFile) - 1, nullptr, 0, nullptr, 0)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unknown path)\n"));
		return false;
	}

	memset(szBuffer, 0, sizeof(szBuffer));
	sprintf_s(szBuffer, "%s%s", szDriveFile, szDirFile);

	memcpy(pLoaderData->m_pLoaderPath, szBuffer, sizeof(LOADER_DATA::m_pLoaderPath));

	if (!WriteProcessMemory(hProcess, reinterpret_cast<char*>(pBuffer) + unSize, pLoaderData, sizeof(LOADER_DATA), nullptr)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to write memory)\n"));
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0x100000 /* 1 MiB */, reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<size_t>(pBuffer) + unLoaderOffset), reinterpret_cast<char*>(pBuffer) + unSize, CREATE_SUSPENDED, nullptr);
	if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid thread handle)\n"));
		return false;
	}

	ResumeThread(hThread);

	ResumeThread(hProcessThread);

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return true;
}

bool FileRead(const TCHAR* szPath, PHANDLE phHeap, LPVOID* ppMemory, PDWORD punFileSize) {
	const HANDLE hFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateFile` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	const DWORD unFileSize = GetFileSize(hFile, nullptr);
	if (!unFileSize || (unFileSize == INVALID_FILE_SIZE)) {
		CloseHandle(hFile);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `GetFileSize` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	const HANDLE hHeap = GetProcessHeap();
	if (!hHeap || (hHeap == INVALID_HANDLE_VALUE)) {
		CloseHandle(hFile);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `GetProcessHeap` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	void* pMemory = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, unFileSize);
	if (!pMemory) {
		CloseHandle(hFile);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapAlloc` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	DWORD unNumberOfBytesRead = 0;
	if (!ReadFile(hFile, pMemory, unFileSize, &unNumberOfBytesRead, nullptr) && (unFileSize != unNumberOfBytesRead)) {
		if (!HeapFree(hHeap, NULL, pMemory)) {
			CloseHandle(hFile);
			tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
			return false;
		}
		CloseHandle(hFile);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapAlloc` (LastError = 0x%08X)\n"), GetLastError());
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
			tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
			return false;
		}
	}

	if (punFileSize) {
		*punFileSize = unFileSize;
	}

	return true;
}

bool HackProcess(const HANDLE hProcess, const HANDLE hProcessThread) {
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
			Sleep(1);
			SuspendThread(hProcessThread);
		}
	}

	LOADER_DATA LoaderData;
	memset(&LoaderData, 0, sizeof(LoaderData));

	LoaderData.m_pNtFlushInstructionCache = reinterpret_cast<fnNtFlushInstructionCache>(GetProcAddress(hRemoteNTDLL, "NtFlushInstructionCache"));
	LoaderData.m_pVirtualAlloc = reinterpret_cast<fnVirtualAlloc>(GetProcAddress(hRemoteKernel32, "VirtualAlloc"));
	LoaderData.m_pGetProcAddress = reinterpret_cast<fnGetProcAddress>(GetProcAddress(hRemoteKernel32, "GetProcAddress"));
	LoaderData.m_pLoadLibraryA = reinterpret_cast<fnLoadLibraryA>(GetProcAddress(hRemoteKernel32, "LoadLibraryA"));

	HANDLE hHeap = nullptr;
	LPVOID pMemory = nullptr;
	DWORD unFileSize = 0;

	if (!FileRead(_T("Library.dll"), &hHeap, &pMemory, &unFileSize)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `FileRead` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	if (!InjectLibrary(hProcess, hProcessThread, pMemory, unFileSize, &LoaderData)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `InjectLibrary` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	tclrprintf(COLOR::COLOR_GREEN, _T("[+] Library injected!\n"));
	tclrprintf(COLOR::COLOR_GREEN, _T("[+]  > Base = 0x%08X\n"), reinterpret_cast<unsigned int>(LoaderData.m_pMemoryAddress));
	tclrprintf(COLOR::COLOR_GREEN, _T("[+]  > Size = 0x%08X\n"), LoaderData.m_unMemorySize);

	if (!HeapFree(hHeap, NULL, pMemory)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

bool ConnectToProcess() {

	tclrprintf(COLOR::COLOR_CYAN, _T("[i] Connecting to process... "));

	unsigned char unCount = 0;
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	while (!hPipe || (hPipe == INVALID_HANDLE_VALUE)) {
		if (unCount >= 30) {
			tclrprintf(COLOR::COLOR_RED, _T("[ FAIL ]\n"));
			return false;
		}
		++unCount;
		hPipe = CreateFile(_T("\\\\.\\pipe\\OreansCrack"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		Sleep(1000);
	}

	tclrprintf(COLOR::COLOR_GREEN, _T("[  OK  ]\n\n"));

	HANDLE hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	if (!hEvent || (hEvent == INVALID_HANDLE_VALUE)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateEvent` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	OVERLAPPED ol;
	memset(&ol, 0, sizeof(ol));

	ol.hEvent = hEvent;

	CONSOLE_MESSAGE Message;

	bool bContinue = true;
	while (bContinue && !g_bStop) {
		bContinue = false;
		memset(&Message, 0, sizeof(Message));
		DWORD unNumberOfBytesRead = 0;
		if (!ReadFile(hPipe, &Message, sizeof(Message), &unNumberOfBytesRead, &ol)) {
			switch (GetLastError()) {
				case ERROR_HANDLE_EOF: {
					break;
				}
				case ERROR_IO_PENDING: {
					bool bPending = true;
					while (bPending && !g_bStop) {
						bPending = false;
						if (!GetOverlappedResult(hPipe, &ol, &unNumberOfBytesRead, FALSE)) {
							switch (GetLastError()) {
								case ERROR_HANDLE_EOF: {
									break;
								}
								case ERROR_IO_INCOMPLETE: {
									bPending = true;
									bContinue = true;
									break;
								}
							}
						} else {
							if (unNumberOfBytesRead == sizeof(CONSOLE_MESSAGE)) {
								Message.m_pMessage[sizeof(Message.m_pMessage) - 1] = '\0';
								if (strnlen_s(Message.m_pMessage, sizeof(Message.m_pMessage)) > 0) {
									clrprintf(Message.m_ColorPair, "%s", Message.m_pMessage);
								}
								ResetEvent(ol.hEvent);
							}
						}
						Sleep(5);
					}
					break;
				}
				default: {
					break;
				}
			}
		} else {
			Message.m_pMessage[sizeof(Message.m_pMessage) - 1] = '\0';
			if (strnlen_s(Message.m_pMessage, sizeof(Message.m_pMessage)) > 0) {
				clrprintf(Message.m_ColorPair, "%s", Message.m_pMessage);
			}
			bContinue = true;
		}
		Sleep(5);
	}

	tclrprintf(COLOR::COLOR_WHITE, _T("\n"));

	CloseHandle(hEvent);
	CloseHandle(hPipe);

	return true;
}

int _tmain(int nArgsCount, PTCHAR* pArgs, PTCHAR* pEnvVars) {

	if (nArgsCount < 1) {
		return -1;
	}

	Terminal T(true, true);
	if (T.Open()) {
		T.ChangeColorPalette(COLOR::COLOR_BLACK, 0x1B1B1B);
		T.ChangeColorPalette(COLOR::COLOR_DARK_BLUE, 0x2962FF);
		T.ChangeColorPalette(COLOR::COLOR_DARK_GREEN, 0x00C853);
		T.ChangeColorPalette(COLOR::COLOR_DARK_CYAN, 0x00B8D4);
		T.ChangeColorPalette(COLOR::COLOR_DARK_RED, 0xD50000);
		T.ChangeColorPalette(COLOR::COLOR_DARK_MAGENTA, 0xAA00FF);
		T.ChangeColorPalette(COLOR::COLOR_DARK_YELLOW, 0xFFD600);
		T.ChangeColorPalette(COLOR::COLOR_DARK_GRAY, 0x616161);
		T.ChangeColorPalette(COLOR::COLOR_GRAY, 0xEEEEEE);
		T.ChangeColorPalette(COLOR::COLOR_BLUE, 0x448AFF);
		T.ChangeColorPalette(COLOR::COLOR_GREEN, 0x69F0AE);
		T.ChangeColorPalette(COLOR::COLOR_CYAN, 0x18FFFF);
		T.ChangeColorPalette(COLOR::COLOR_RED, 0xFF5252);
		T.ChangeColorPalette(COLOR::COLOR_MAGENTA, 0xE040FB);
		T.ChangeColorPalette(COLOR::COLOR_YELLOW, 0xFFFF00);
		T.ChangeColorPalette(COLOR::COLOR_WHITE, 0xFAFAFA);

		tclrprintf(COLOR::COLOR_WHITE, _T("OreansConsole [Version 1.0.1] (zeze839@gmail.com)\n\n"));

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
			tclrprintf(COLOR::COLOR_YELLOW, _T("Usage: %s /[cv|th|wl] <args>\n"), szMainFile);
			return 0;
		}

		PRODUCT_TYPE unProductType = PRODUCT_TYPE::UNKNOWN;

		for (int i = 0; i < nArgsCount; ++i) {
			PTCHAR pArg = pArgs[i];
			if (!pArg) {
				return -1;
			}

			if (_tcscmp(pArg, _T("/help")) == 0) {
				tclrprintf(COLOR::COLOR_YELLOW, _T("Usage: %s /[cv|th|wl] <args>\n  /cv - Code Virtualizer\n  /th - Themida\n  /wl - WinLicense\n  <args> - Passes arguments.\n"), szMainFile);
				return 0;
			}

			if (_tcscmp(pArg, _T("/cv")) == 0) {
				unProductType = PRODUCT_TYPE::CODE_VIRTUALIZER;
				continue;
			}

			if (_tcscmp(pArg, _T("/cv64")) == 0) {
				unProductType = PRODUCT_TYPE::CODE_VIRTUALIZER64;
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
			//tclrprintf(COLOR::COLOR_YELLOW, _T("Usage: %s /[cv|cv64|th|th64|wl|wl64] <args to parse in product>\n"), szMainFile);
			tclrprintf(COLOR::COLOR_YELLOW, _T("Usage: %s /[cv|cv64|th|th64|wl|wl64]\n"), szMainFile);
			return -1;
		}

		HANDLE hToken = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `OpenProcessToken` (LastError = 0x%08X)\n"), GetLastError());
			return -1;
		}

		LUID luid;
		memset(&luid, 0, sizeof(luid));

		if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
			CloseHandle(hToken);
			tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `LookupPrivilegeValue` (LastError = 0x%08X)\n"), GetLastError());
			return -1;
		}

		TOKEN_PRIVILEGES tp;
		memset(&tp, 0, sizeof(tp));

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
			CloseHandle(hToken);
			tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `AdjustTokenPrivileges` (LastError = 0x%08X)\n"), GetLastError());
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
				tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::CODE_VIRTUALIZER64) {
			if (!CreateProcess(_T("Virtualizer64.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::THEMIDA) {
			if (!CreateProcess(_T("Themida.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::THEMIDA64) {
			if (!CreateProcess(_T("Themida64.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::WINLICENSE) {
			if (!CreateProcess(_T("WinLicense.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (unProductType == PRODUCT_TYPE::WINLICENSE64) {
			if (!CreateProcess(_T("WinLicense64.exe"), nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
				tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateProcess` (LastError = 0x%08X)\n"), GetLastError());
				return -1;
			}
		}

		if (!HackProcess(pi.hProcess, pi.hThread)) {
			CloseHandle(pi.hThread);
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			return -1;
		}

		if (!ConnectToProcess()) {
			CloseHandle(pi.hThread);
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			return -1;
		}

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

	}
	return 0;
}
