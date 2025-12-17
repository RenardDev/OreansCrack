
#include "framework.h"

// Default
#include <Windows.h>
#include <Psapi.h>
#include <tchar.h>
#include <unordered_set>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <string>
#include <vector>

// Detours
#include "Detours/Detours.h"

// Terminal
#include "Terminal/Terminal.h"

// Log
#include "Log.h"

// HookManager
#include "HookManager.h"

// Types
using fnDbgPrint = ULONG(NTAPI*)(PCSTR Format, ...);

using fnRtlDosPathNameToNtPathName_U = BOOLEAN(NTAPI*)(PCWSTR DosName, PUNICODE_STRING NtName, PCWSTR* DosFilePath, PUNICODE_STRING NtFilePath);

using fnRtlFreeUnicodeString = void(NTAPI*)(PUNICODE_STRING UnicodeString);
using fnRtlFreeAnsiString = void(NTAPI*)(PANSI_STRING AnsiString);

using fnRtlInitUnicodeString = void(NTAPI*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
using fnRtlInitAnsiString = void(NTAPI*)(PANSI_STRING DestinationString, PCSZ SourceString);
using fnRtlUnicodeStringToAnsiString = NTSTATUS(NTAPI*)(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
using fnRtlAnsiStringToUnicodeString = NTSTATUS(NTAPI*)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);

using fnRtlAllocateHeap = PVOID(NTAPI*)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
using fnRtlFreeHeap = BOOLEAN(NTAPI*)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);

using fnNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
using fnNtFreeVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
using fnNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
using fnNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

using fnNtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
using fnNtFlushInstructionCache = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);

using fnLdrLoadDll = NTSTATUS(NTAPI*)(PWSTR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
using fnLdrGetDllHandle = NTSTATUS(NTAPI*)(PWORD pwPath, PVOID Unused, PUNICODE_STRING ModuleFileName, PHANDLE pHModule);
using fnLdrGetProcedureAddress = NTSTATUS(NTAPI*)(PVOID ModuleHandle, PANSI_STRING ProcedureName, ULONG Ordinal, PVOID* ProcedureAddress);

using fnDllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

using fnVM = void(__stdcall*)(unsigned char, unsigned int*);

typedef struct _LOADER_DATA {
	void* m_pImageAddress;

	HMODULE m_hNTDLL;

	fnDbgPrint m_pDbgPrint;

	fnRtlDosPathNameToNtPathName_U m_pRtlDosPathNameToNtPathName_U;
	fnRtlFreeUnicodeString m_pRtlFreeUnicodeString;
	fnRtlFreeAnsiString m_pRtlFreeAnsiString;
	fnRtlInitUnicodeString m_pRtlInitUnicodeString;
	fnRtlInitAnsiString m_pRtlInitAnsiString;
	fnRtlUnicodeStringToAnsiString m_pRtlUnicodeStringToAnsiString;
	fnRtlAnsiStringToUnicodeString m_pRtlAnsiStringToUnicodeString;
	fnRtlAllocateHeap m_pRtlAllocateHeap;
	fnRtlFreeHeap m_pRtlFreeHeap;
	fnNtAllocateVirtualMemory m_pNtAllocateVirtualMemory;
	fnNtFreeVirtualMemory m_pNtFreeVirtualMemory;
	fnNtReadVirtualMemory m_pNtReadVirtualMemory;
	fnNtWriteVirtualMemory m_pNtWriteVirtualMemory;
	fnNtProtectVirtualMemory m_pNtProtectVirtualMemory;
	fnNtFlushInstructionCache m_pNtFlushInstructionCache;
	fnLdrLoadDll m_pLdrLoadDll;
	fnLdrGetDllHandle m_pLdrGetDllHandle;
	fnLdrGetProcedureAddress m_pLdrGetProcedureAddress;

	TCHAR m_szTerminalSessionName[64];
} LOADER_DATA, *PLOADER_DATA;

// General definitions

#define OREANSCRACK_VERSION "4.0.0"

LOADER_DATA g_LoaderData;
HMODULE g_pSelf = nullptr;

DECLARE_INLINE_HOOK(
	NtMapViewOfSection,
	NTSTATUS,
	NTAPI,
	HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect
);

DECLARE_INLINE_HOOK(
	NtUnmapViewOfSection,
	NTSTATUS,
	NTAPI,
	HANDLE ProcessHandle, PVOID BaseAddress
);

DECLARE_INLINE_HOOK(
	LdrLoadDll,
	NTSTATUS,
	NTAPI,
	PWSTR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle
);

DECLARE_INLINE_HOOK(
	VirtualProtect,
	BOOL,
	WINAPI,
	LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect
);

DECLARE_INLINE_HOOK(
	VirtualAlloc,
	LPVOID,
	WINAPI,
	LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
);

DECLARE_INLINE_HOOK(
	VirtualFree,
	BOOL,
	WINAPI,
	LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType
);

DECLARE_INLINE_HOOK(
	GetForegroundWindow,
	HWND,
	WINAPI
);

DECLARE_INLINE_HOOK(
	GetActiveWindow,
	HWND,
	WINAPI
);

DECLARE_INLINE_HOOK(
	CreateRemoteThreadEx,
	HANDLE,
	WINAPI,
	HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId
);

// Code

fnVM pOriginalVM = nullptr;
void __stdcall VM_Hook(unsigned char unIndex, unsigned int* pData) {
	switch (unIndex) {
		case 0x01: { // Check executable headers
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x02: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x03: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x04: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x05: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x06: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x07: { // MAP list (Viewer - Dissambler)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x08: { // MAP list (Viewer - Dissambler)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x09: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x0A: { // First initialization
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x0B: { // Get VMs Names
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x0D: { // Get VMs Complexity
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x0E: { // Get VMs Speeds
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x0F: { // Get VMs Sizes
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x10: { // Get VMs
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x16: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x17: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x19: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x1B: { // Get protection macroses
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x1D: { // Unknown initialization
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x20: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x21: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x22: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x23: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x24: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x25: { // Macros processor
			unsigned int unMacroIndex = pData[0];
			unsigned int* pMacroResult = reinterpret_cast<unsigned int*>(pData[13]);

			switch (unMacroIndex) {
				case 0x3A: { // Checking Input and Output files
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x4C: { // Stealth...
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x4D: { // Stealth...
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x05: { // Reading Protection Macros
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x16: { // Reading Protection Macros
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x4F: { // Initializing VM machines
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x5D: { // Ansi Strings to Virtualize
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x68: { // Ansi Strings to Virtualize
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x5F: { // Ansi Strings to Virtualize
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x5E: { // Unicode Strings to Virtualize
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x69: { // Unicode Strings to Virtualize
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x60: { // Unicode Strings to Virtualize
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x2A: { // Virtual Machines Generation
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x15: { // Virtual Machines Generation
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x10: { // Virtual Machines Generation
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x12: { // Virtual Machines Generation
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x11: { // Virtual Machines Generation
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x14: { // Virtual Machines Generation
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x2C: { // Potecting Macros (Mutation & StrEncrypt)
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x2D: { // Potecting Macros (Mutation & StrEncrypt)
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x62: { // Potecting Macros (Mutation & StrEncrypt)
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x63: { // Potecting Macros (Mutation & StrEncrypt)
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x64: { // Potecting Macros (Virtualization)
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x08: { // Compressing Virtual Machines
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x2F: { // Compressing Virtual Machines
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x32: { // Compressing Virtual Machines
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x57: { // Finalizing Protection
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x44: { // Taggant
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x45: { // Taggant
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x43: { // Taggant
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x6D: { // Code Signing
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x6E: { // Code Signing
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x65: { // Called when Cancel pressed
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x4E: { // Rebuilding?
					pOriginalVM(unIndex, pData);
					return;
				}

				default: {
					pOriginalVM(unIndex, pData);

					LOG_DEBUG(_T("CALL MACRO (ID=0x%02X)\n"), unMacroIndex);
					LOG_DEBUG(_T(" DATA: 0x%08X (0x%08X)\n"), pMacroResult, *pMacroResult);

					return;
				}
			}

			return;
		}

		case 0x26: { // Get VMs
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x2F: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x32: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x33: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x34: { // Unknown (Called when loadinging file)
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x36: { // License Info
			pData[10] = reinterpret_cast<unsigned int>(L"RenardDev");
			return;
		}

		case 0x37: { // License Info
			//pData[10] = reinterpret_cast<unsigned int>(L"RenardDev (Developer License)");
			pData[10] = reinterpret_cast<unsigned int>(L"RenardDev (Cracked License)");
			return;
		}

		case 0x38: { // License Info
			pData[10] = reinterpret_cast<unsigned int>(L"1010-1983-8463-1184");
			return;
		}

		case 0x3C: { // Is Demo
			pData[7] = 0;
			return;
		}

		case 0x47: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		default: {
			pOriginalVM(unIndex, pData);

			LOG_DEBUG(_T("VM CALL (ID=0x%02X) from 0x%08X (RVA: 0x%08X)\n"), unIndex, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
			LOG_DEBUG(_T("  DATA: "));
			for (unsigned char i = 0; i < 14; ++i) {
				GetLog().GetClient().tprintf(Terminal::COLOR::COLOR_AUTO, _T("0x%08X "), pData[i]);
			}
			GetLog().GetClient().tprintf(Terminal::COLOR::COLOR_AUTO, _T("\n"));

			return;
		}
	}
	return;
}

Detours::Hook::RawHook RawVMHook;
bool __cdecl VMHook(Detours::Hook::PRAW_CONTEXT pCTX) {

	pOriginalVM = reinterpret_cast<fnVM>(RawVMHook.GetTrampoline());
	pCTX->Stack.push(VM_Hook);

	return true;
}

static bool IsAvailable() {
	return true;
}

static void* GetLdrLoadDllAddress() {
	HMODULE hNTDLL = GetModuleHandle(_T("ntdll.dll"));
	return hNTDLL ? GetProcAddress(hNTDLL, "LdrLoadDll") : nullptr;
}

static void* GetFromKernel32OrBase(const char* name) {
	HMODULE hK32 = GetModuleHandle(_T("kernel32.dll"));
	HMODULE hKBase = GetModuleHandle(_T("kernelbase.dll"));
	if (hK32) {
		if (auto p = GetProcAddress(hK32, name)) return p;
	}
	if (hKBase) {
		if (auto p = GetProcAddress(hKBase, name)) return p;
	}
	return nullptr;
}

static void* GetVirtualProtectAddress() { return GetFromKernel32OrBase("VirtualProtect"); }
static void* GetVirtualAllocAddress() { return GetFromKernel32OrBase("VirtualAlloc"); }
static void* GetVirtualFreeAddress() { return GetFromKernel32OrBase("VirtualFree"); }


static void* GetForegroundWindowAddress() {
	HMODULE hUser32 = GetModuleHandle(_T("user32.dll"));
	return hUser32 ? GetProcAddress(hUser32, "GetForegroundWindow") : nullptr;
}

static void* GetActiveWindowAddress() {
	HMODULE hUser32 = GetModuleHandle(_T("user32.dll"));
	return hUser32 ? GetProcAddress(hUser32, "GetActiveWindow") : nullptr;
}

static void* GetCreateRemoteThreadExAddress() {
	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	return hKernel32 ? GetProcAddress(hKernel32, "CreateRemoteThreadEx") : nullptr;
}

static const TCHAR* SectionInheritToString(ULONG v) {
	switch (v) {
	case 1:  return _T("ViewShare");
	case 2:  return _T("ViewUnmap");
	default: break;
	}
	static thread_local TCHAR b[32];
	_stprintf_s(b, _T("%lu"), v);
	return b;
}

static DWORD SafeGetProcessIdFromHandle(HANDLE h) {
	// Псевдо-дескриптор текущего процесса?
	if (h == GetCurrentProcess() || h == (HANDLE)(LONG_PTR)-1)
		return GetCurrentProcessId();
	DWORD pid = 0;
	__try { pid = GetProcessId(h); }
	__except (EXCEPTION_EXECUTE_HANDLER) { pid = 0; }
	return pid;
}

static void* GetNtMapViewOfSectionAddress() {
	HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
	return ntdll ? GetProcAddress(ntdll, "NtMapViewOfSection") : nullptr;
}

static void* GetNtUnmapViewOfSectionAddress() {
	HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
	return ntdll ? GetProcAddress(ntdll, "NtUnmapViewOfSection") : nullptr;
}


DEFINE_INLINE_HOOK(
	LdrLoadDll,
	IsAvailable,
	GetLdrLoadDllAddress,
	NTSTATUS,
	NTAPI,
	PWSTR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle
) {
	


	//LOG_INFO(_T("LdrLoadDll CALLED (ID=%lu) ModuleFileName=`%s` from 0x%08X (RVA: 0x%08X)\n"), GetCurrentThreadId(), ModuleFileName ? ModuleFileName->Buffer : L"", (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);

	static bool bOnce = false;

	void* pIsDemo = const_cast<void*>(Detours::Scan::FindSignature(g_pSelf, "\x55\x8B\xEC\x81\xC4\xBC\xFD\xFF\xFF\x8D")); // 55 8B EC 81 C4 BC FD FF FF 8D
	if (pIsDemo && !bOnce) {
		bOnce = true;

		MEMORY_BASIC_INFORMATION mbi{};

		unsigned char* pCallVM = reinterpret_cast<unsigned char*>(pIsDemo) + 0xF;
		pOriginalVM = reinterpret_cast<fnVM>(Detours::rddisasm::RdGetAddressFromRelOrDisp(pCallVM));
		if (pOriginalVM) {
			if (VirtualQuery(pOriginalVM, &mbi, sizeof(mbi))) {

				// Main Executable <-> SecureEngine <-> WinAPIs

				LOG_DEBUG(_T("SecureEngine\n"));
				LOG_DEBUG(_T("  BASE = 0x%08X\n"), reinterpret_cast<size_t>(mbi.BaseAddress));
				LOG_DEBUG(_T("  SIZE = 0x%08X\n"), mbi.RegionSize);
				//exit(1);
			}

			unsigned char* pMOV = reinterpret_cast<unsigned char*>(pIsDemo) + 0x1D;
			Detours::Memory::Protection Patch(pMOV, 1, false);
			if (Patch.Change(PAGE_EXECUTE_READWRITE)) {
				pMOV[0] = 0;
				Patch.Restore();
			}

			if (reinterpret_cast<unsigned char*>(pOriginalVM)[0] == 0xFF) {
				RawVMHook.Set(pOriginalVM);
				RawVMHook.Hook(VMHook, true);
				LOG_INFO(_T("Hooked VM CALL!\n"));
			}
		}
	}

	return g_HookLdrLoadDll.Call(PathToFile, Flags, ModuleFileName, ModuleHandle);
}

static const TCHAR* ProtToString(DWORD fl) {
	static thread_local TCHAR buf[128];
	buf[0] = 0;

	auto add = [](TCHAR* dst, size_t cap, const TCHAR* s) {
		if (dst[0]) _tcscat_s(dst, cap, _T("|"));
		_tcscat_s(dst, cap, s);
		};

	const DWORD base = (fl & 0xFF);
	switch (base) {
	case PAGE_NOACCESS:          add(buf, _countof(buf), _T("NOACCESS"));          break;
	case PAGE_READONLY:          add(buf, _countof(buf), _T("R"));                 break;
	case PAGE_READWRITE:         add(buf, _countof(buf), _T("RW"));                break;
	case PAGE_WRITECOPY:         add(buf, _countof(buf), _T("WC"));                break;
	case PAGE_EXECUTE:           add(buf, _countof(buf), _T("X"));                 break;
	case PAGE_EXECUTE_READ:      add(buf, _countof(buf), _T("XR"));                break;
	case PAGE_EXECUTE_READWRITE: add(buf, _countof(buf), _T("XRW"));               break;
	case PAGE_EXECUTE_WRITECOPY: add(buf, _countof(buf), _T("XWC"));               break;
	default: _stprintf_s(buf, _T("0x%08X"), fl);                                   break;
	}

	if (fl & PAGE_GUARD)        add(buf, _countof(buf), _T("GUARD"));
	if (fl & PAGE_NOCACHE)      add(buf, _countof(buf), _T("NOCACHE"));
	if (fl & PAGE_WRITECOMBINE) add(buf, _countof(buf), _T("WRITECOMB"));

	return buf;
}

static const TCHAR* AllocTypeToString(DWORD t) {
	static thread_local TCHAR buf[128];
	buf[0] = 0;
	auto add = [](TCHAR* dst, size_t cap, const TCHAR* s) {
		if (dst[0]) _tcscat_s(dst, cap, _T("|"));
		_tcscat_s(dst, cap, s);
		};

	if (t & MEM_COMMIT)        add(buf, _countof(buf), _T("COMMIT"));
	if (t & MEM_RESERVE)       add(buf, _countof(buf), _T("RESERVE"));
	if (t & MEM_RESET)         add(buf, _countof(buf), _T("RESET"));
	if (t & MEM_RESET_UNDO)    add(buf, _countof(buf), _T("RESET_UNDO"));
	if (t & MEM_LARGE_PAGES)   add(buf, _countof(buf), _T("LARGE_PAGES"));
	if (t & MEM_PHYSICAL)      add(buf, _countof(buf), _T("PHYSICAL"));
	if (t & MEM_TOP_DOWN)      add(buf, _countof(buf), _T("TOP_DOWN"));
	if (t & MEM_WRITE_WATCH)   add(buf, _countof(buf), _T("WRITE_WATCH"));

	if (!buf[0]) _stprintf_s(buf, _T("0x%08X"), t);
	return buf;
}

static const TCHAR* FreeTypeToString(DWORD t) {
	switch (t) {
	case MEM_DECOMMIT: return _T("DECOMMIT");
	case MEM_RELEASE:  return _T("RELEASE");
	default:           break;
	}
	static thread_local TCHAR buf[32];
	_stprintf_s(buf, _T("0x%08X"), t);
	return buf;
}

static bool IsExecProtect(DWORD fl) {
	const DWORD base = (fl & 0xFF);
	return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
		base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}


DEFINE_INLINE_HOOK(
	VirtualProtect,
	IsAvailable,
	GetVirtualProtectAddress,
	BOOL,
	WINAPI,
	LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect
) {
	static thread_local bool reenter = false;
	if (reenter) {
		return g_HookVirtualProtect.Call(lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}
	reenter = true;

	//LOG_INFO(_T("VirtualProtect CALLED (TID=%lu) addr=%p size=0x%IX new=%s (0x%08X) from 0x%08X (RVA: 0x%08X)\n"),
	//	GetCurrentThreadId(),
	//	lpAddress,
	//	(SIZE_T)dwSize,
	//	ProtToString(flNewProtect), flNewProtect,
	//	(unsigned int)_ReturnAddress(),
	//	(unsigned int)_ReturnAddress() - (unsigned int)g_pSelf
	//);

	static bool bOnce = false;

	void* pIsDemo = const_cast<void*>(Detours::Scan::FindSignature(g_pSelf, "\x55\x8B\xEC\x81\xC4\xBC\xFD\xFF\xFF\x8D")); // 55 8B EC 81 C4 BC FD FF FF 8D
	if (pIsDemo && !bOnce) {
		bOnce = true;

		MEMORY_BASIC_INFORMATION mbi{};

		unsigned char* pCallVM = reinterpret_cast<unsigned char*>(pIsDemo) + 0xF;
		pOriginalVM = reinterpret_cast<fnVM>(Detours::rddisasm::RdGetAddressFromRelOrDisp(pCallVM));
		if (pOriginalVM) {
			if (VirtualQuery(pOriginalVM, &mbi, sizeof(mbi))) {

				// Main Executable <-> SecureEngine <-> WinAPIs

				LOG_DEBUG(_T("SecureEngine\n"));
				LOG_DEBUG(_T("  BASE = 0x%08X\n"), reinterpret_cast<size_t>(mbi.BaseAddress));
				LOG_DEBUG(_T("  SIZE = 0x%08X\n"), mbi.RegionSize);
				//exit(1);
			}

			unsigned char* pMOV = reinterpret_cast<unsigned char*>(pIsDemo) + 0x1D;
			Detours::Memory::Protection Patch(pMOV, 1, false);
			if (Patch.Change(PAGE_EXECUTE_READWRITE)) {
				pMOV[0] = 0;
				Patch.Restore();
			}

			if (reinterpret_cast<unsigned char*>(pOriginalVM)[0] == 0xFF) {
				RawVMHook.Set(pOriginalVM);
				RawVMHook.Hook(VMHook, true);
				LOG_INFO(_T("Hooked VM CALL!\n"));
			}
		}
	}

	BOOL ok = g_HookVirtualProtect.Call(lpAddress, dwSize, flNewProtect, lpflOldProtect);

	if (ok) {
		DWORD oldProt = lpflOldProtect ? *lpflOldProtect : 0xFFFFFFFF;
		LOG_DEBUG(_T("  -> OK, old=%s (0x%08X)\n"), ProtToString(oldProt), oldProt);

		// Опциональный авто-дамп при установке исполняемой защиты
		static const SIZE_T MAX_DUMP_BYTES = (16ull * 1024 * 1024); // 16 MB safety cap
		if (IsExecProtect(flNewProtect) && lpAddress && dwSize) {
			SIZE_T toDump = dwSize > MAX_DUMP_BYTES ? MAX_DUMP_BYTES : dwSize;
			TCHAR name[128];
			_stprintf_s(name, _T("dump_exec_%p_%IX.bin"), lpAddress, (SIZE_T)toDump);
			//DumpRegion(name, lpAddress, (DWORD)toDump);
		}
	}
	else {
		LOG_WARNING(_T("  -> FAIL (GLE=%lu)\n"), GetLastError());
	}

	reenter = false;
	return ok;
}


DEFINE_INLINE_HOOK(
	GetForegroundWindow,
	IsAvailable,
	GetForegroundWindowAddress,
	HWND,
	WINAPI
) {
	LOG_INFO(_T("GetForegroundWindow CALLED (ID=%lu) from 0x%08X (RVA: 0x%08X)\n"), GetCurrentThreadId(), (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);

	static bool bOnce = false;

	void* pIsDemo = const_cast<void*>(Detours::Scan::FindSignature(g_pSelf, "\x55\x8B\xEC\x81\xC4\xBC\xFD\xFF\xFF\x8D")); // 55 8B EC 81 C4 BC FD FF FF 8D
	if (pIsDemo && !bOnce) {
		bOnce = true;

		MEMORY_BASIC_INFORMATION mbi{};

		unsigned char* pCallVM = reinterpret_cast<unsigned char*>(pIsDemo) + 0xF;
		pOriginalVM = reinterpret_cast<fnVM>(Detours::rddisasm::RdGetAddressFromRelOrDisp(pCallVM));
		if (pOriginalVM) {
			if (VirtualQuery(pOriginalVM, &mbi, sizeof(mbi))) {

				// Main Executable <-> SecureEngine <-> WinAPIs

				LOG_DEBUG(_T("SecureEngine\n"));
				LOG_DEBUG(_T("  BASE = 0x%08X\n"), reinterpret_cast<size_t>(mbi.BaseAddress));
				LOG_DEBUG(_T("  SIZE = 0x%08X\n"), mbi.RegionSize);
				//exit(1);
			}

			unsigned char* pMOV = reinterpret_cast<unsigned char*>(pIsDemo) + 0x1D;
			Detours::Memory::Protection Patch(pMOV, 1, false);
			if (Patch.Change(PAGE_EXECUTE_READWRITE)) {
				pMOV[0] = 0;
				Patch.Restore();
			}

			if (reinterpret_cast<unsigned char*>(pOriginalVM)[0] == 0xFF) {
				RawVMHook.Set(pOriginalVM);
				RawVMHook.Hook(VMHook, true);
				LOG_INFO(_T("Hooked VM CALL!\n"));
			}
		}
	}

	return nullptr; // Prevent x64dbg detection
}

DEFINE_INLINE_HOOK(
	GetActiveWindow,
	IsAvailable,
	GetActiveWindowAddress,
	HWND,
	WINAPI
) {
	LOG_INFO(_T("GetActiveWindow CALLED (ID=%lu) from 0x%08X (RVA: 0x%08X)\n"), GetCurrentThreadId(), (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);

	static bool bOnce = false;

	void* pIsDemo = const_cast<void*>(Detours::Scan::FindSignature(g_pSelf, "\x55\x8B\xEC\x81\xC4\xBC\xFD\xFF\xFF\x8D")); // 55 8B EC 81 C4 BC FD FF FF 8D
	if (pIsDemo && !bOnce) {
		bOnce = true;

		MEMORY_BASIC_INFORMATION mbi{};

		unsigned char* pCallVM = reinterpret_cast<unsigned char*>(pIsDemo) + 0xF;
		pOriginalVM = reinterpret_cast<fnVM>(Detours::rddisasm::RdGetAddressFromRelOrDisp(pCallVM));
		if (pOriginalVM) {
			if (VirtualQuery(pOriginalVM, &mbi, sizeof(mbi))) {

				// Main Executable <-> SecureEngine <-> WinAPIs

				LOG_DEBUG(_T("SecureEngine\n"));
				LOG_DEBUG(_T("  BASE = 0x%08X\n"), reinterpret_cast<size_t>(mbi.BaseAddress));
				LOG_DEBUG(_T("  SIZE = 0x%08X\n"), mbi.RegionSize);
				//exit(1);
			}

			unsigned char* pMOV = reinterpret_cast<unsigned char*>(pIsDemo) + 0x1D;
			Detours::Memory::Protection Patch(pMOV, 1, false);
			if (Patch.Change(PAGE_EXECUTE_READWRITE)) {
				pMOV[0] = 0;
				Patch.Restore();
			}

			if (reinterpret_cast<unsigned char*>(pOriginalVM)[0] == 0xFF) {
				RawVMHook.Set(pOriginalVM);
				RawVMHook.Hook(VMHook, true);
				LOG_INFO(_T("Hooked VM CALL!\n"));
			}
		}
	}

	return nullptr; // Prevent x64dbg detection
}

void DumpRegion(const TCHAR* szFileName, void* pData, DWORD unSize) {
	HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		LOG_WARNING(_T("CreateFile FAIL, GLE=%u\n"), GetLastError());
	} else {
		DWORD nWritten = 0;
		if (!WriteFile(hFile, pData, unSize, &nWritten, nullptr) || (nWritten != unSize)) {
			LOG_DEBUG(_T("WriteFile FAIL, GLE=%u\n"), GetLastError());
			DeleteFile(szFileName);
		} else {
			LOG_DEBUG(_T("DUMP '%s' OK (%u BYTES)\n"), szFileName, nWritten);
		}

		CloseHandle(hFile);
	}
}

DEFINE_INLINE_HOOK(
	CreateRemoteThreadEx,
	IsAvailable,
	GetCreateRemoteThreadExAddress,
	HANDLE,
	WINAPI,
	HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId
) {
	Detours::Exception::g_ExceptionListener.RefreshHandler();

	static bool bOnce = false;

	void* pIsDemo = const_cast<void*>(Detours::Scan::FindSignature(g_pSelf, "\x55\x8B\xEC\x81\xC4\xBC\xFD\xFF\xFF\x8D")); // 55 8B EC 81 C4 BC FD FF FF 8D
	if (pIsDemo && !bOnce) {
		bOnce = true;

		MEMORY_BASIC_INFORMATION mbi {};

		unsigned char* pCallVM = reinterpret_cast<unsigned char*>(pIsDemo) + 0xF;
		pOriginalVM = reinterpret_cast<fnVM>(Detours::rddisasm::RdGetAddressFromRelOrDisp(pCallVM));
		if (pOriginalVM) {
			if (VirtualQuery(pOriginalVM, &mbi, sizeof(mbi))) {

				// Main Executable <-> SecureEngine <-> WinAPIs

				LOG_DEBUG(_T("SecureEngine\n"));
				LOG_DEBUG(_T("  BASE = 0x%08X\n"), reinterpret_cast<size_t>(mbi.BaseAddress));
				LOG_DEBUG(_T("  SIZE = 0x%08X\n"), mbi.RegionSize);
				//exit(1);
			}

			unsigned char* pMOV = reinterpret_cast<unsigned char*>(pIsDemo) + 0x1D;
			Detours::Memory::Protection Patch(pMOV, 1, false);
			if (Patch.Change(PAGE_EXECUTE_READWRITE)) {
				pMOV[0] = 0;
				Patch.Restore();
			}

			if (reinterpret_cast<unsigned char*>(pOriginalVM)[0] == 0xFF) {
				RawVMHook.Set(pOriginalVM);
				RawVMHook.Hook(VMHook, true);
				LOG_INFO(_T("Hooked VM CALL!\n"));
			}
		}
	}

	const bool bHasSuspend = (dwCreationFlags & CREATE_SUSPENDED) != 0;

	HANDLE hThread = g_HookCreateRemoteThreadEx.Call(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, bHasSuspend ? dwCreationFlags : (dwCreationFlags | CREATE_SUSPENDED), lpAttributeList, lpThreadId);

	if (hThread && (hThread != INVALID_HANDLE_VALUE)) {
		LOG_INFO(_T("THREAD CREATED (ID=%lu) (lpStartAddress=0x%08X, lpParameter=0x%08X) from 0x%08X (RVA: 0x%08X)\n"), GetThreadId(hThread), reinterpret_cast<DWORD>(lpStartAddress), reinterpret_cast<DWORD>(lpParameter), (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);

		if (!bHasSuspend) {
			ResumeThread(hThread);
		}
	}

	return hThread;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			if (lpReserved) {
				g_LoaderData = *reinterpret_cast<PLOADER_DATA>(lpReserved);
				g_pSelf = GetModuleHandle(nullptr);

				if (!GetLog().GetClient().Open(g_LoaderData.m_szTerminalSessionName)) {
					return FALSE;
				}
			}

			LOG_INFO(_T("OreansCrack [Version " OREANSCRACK_VERSION "]\n\n"));

			if (!GetHookManager().HookAll()) {
				LOG_ERROR(_T("Impossible to hook all hooks.\n"));
				return FALSE;
			}

			LOG_INFO(_T("Loaded successful.\n"));
			break;
		}

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

	return TRUE;
}
