
#include "framework.h"

// Detours
#include "Detours/Detours.h"

// Terminal
#include "Terminal/Terminal.h"

// Log
#include "Log.h"

// HookManager
#include "HookManager.h"

using fnRtlDosPathNameToNtPathName_U = BOOLEAN(NTAPI*)(PCWSTR DosName, PUNICODE_STRING NtName, PCWSTR* DosFilePath, PUNICODE_STRING NtFilePath);
using fnRtlFreeUnicodeString = void(NTAPI*)(PUNICODE_STRING UnicodeString);
using fnRtlFreeAnsiString = void(NTAPI*)(PANSI_STRING AnsiString);
using fnNtCreateFile = NTSTATUS(NTAPI*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
using fnNtClose = NTSTATUS(NTAPI*)(HANDLE Handle);
using fnNtQueryInformationFile = NTSTATUS(NTAPI*)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
using fnRtlAllocateHeap = PVOID(NTAPI*)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
using fnRtlFreeHeap = BOOLEAN(NTAPI*)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
using fnNtReadFile = NTSTATUS(NTAPI*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
using fnNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
using fnNtFreeVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
using fnNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
using fnNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
using fnRtlInitUnicodeString = void(NTAPI*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
using fnRtlInitAnsiString = void(NTAPI*)(PANSI_STRING DestinationString, PCSZ SourceString);
using fnRtlUnicodeStringToAnsiString = NTSTATUS(NTAPI*)(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
using fnRtlAnsiStringToUnicodeString = NTSTATUS(NTAPI*)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
using fnLdrLoadDll = NTSTATUS(NTAPI*)(PWSTR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
using fnLdrGetDllHandle = NTSTATUS(NTAPI*)(PWORD pwPath, PVOID Unused, PUNICODE_STRING ModuleFileName, PHANDLE pHModule);
using fnLdrGetProcedureAddress = NTSTATUS(NTAPI*)(PVOID ModuleHandle, PANSI_STRING ProcedureName, ULONG Ordinal, PVOID* ProcedureAddress);
using fnNtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
using fnNtFlushInstructionCache = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
using fnDllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

using fnVM = void(__stdcall*)(unsigned char, unsigned int*);

typedef struct _LOADER_DATA {
	HMODULE m_hNTDLL;
	void* m_pImageAddress;
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

#define OREANSCRACK_VERSION "3.0.0"

LOADER_DATA g_LoaderData;
HMODULE g_pSelf = nullptr;

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

		case 0x1C: { // Unknown
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

				case 0x41: { // Unknown
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x17: { // Unknown
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x1C: { // Unknown
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x6B: { // Unknown
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x58: { // Unknown
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x59: { // Unknown
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x18: { // Unknown
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x1A: { // Unknown
					pOriginalVM(unIndex, pData);
					return;
				}

				case 0x1B: { // Unknown
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
					LOG_DEBUG(_T(" DATA: %08X (%08X)\n"), pMacroResult, *pMacroResult);

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

		case 0x35: { // Unknown
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

		case 0x46: { // Unknown
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x47: { // MAP list
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x12: { // Unknown
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x43: { // Unknown
			pOriginalVM(unIndex, pData);
			return;
		}

		case 0x30: { // Unknown
			pOriginalVM(unIndex, pData);
			return;
		}

		default: {
			pOriginalVM(unIndex, pData);

			LOG_DEBUG(_T("VM CALL (ID=0x%02X) from 0x%08X (RVA: 0x%08X)\n"), unIndex, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
			LOG_DEBUG(_T("  DATA: \n"));
			for (unsigned char i = 0; i < 14; ++i) {
				GetLog().GetClient().tprintf(Terminal::COLOR::COLOR_AUTO, _T("%08X "), pData[i]);
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

static void* GetCreateRemoteThreadExAddress() {
	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (!hKernel32) {
		return nullptr;
	}

	return GetProcAddress(hKernel32, "CreateRemoteThreadEx");
}

DEFINE_INLINE_HOOK(
	CreateRemoteThreadEx,
	IsAvailable,
	GetCreateRemoteThreadExAddress,
	HANDLE,
	WINAPI,
	HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId
) {
	static bool bOnce = false;

	void* pIsDemo = const_cast<void*>(Detours::Scan::FindSignature(g_pSelf, "\x55\x8B\xEC\x81\xC4\xBC\xFD\xFF\xFF\x8D")); // 55 8B EC 81 C4 BC FD FF FF 8D
	if (pIsDemo && !bOnce) {
		bOnce = true;
		unsigned char* pMOV = reinterpret_cast<unsigned char*>(pIsDemo) + 0x1D;
		Detours::Memory::Protection Patch(pMOV, 1, false);
		Patch.Change(PAGE_EXECUTE_READWRITE);
		pMOV[0] = 0;
		Patch.Restore();

		unsigned char* pCallVM = reinterpret_cast<unsigned char*>(pIsDemo) + 0x10;
		pOriginalVM = reinterpret_cast<fnVM>(reinterpret_cast<unsigned int>(pCallVM) + sizeof(unsigned int) + (*reinterpret_cast<unsigned int*>(pCallVM)));

		if (reinterpret_cast<unsigned char*>(pOriginalVM)[0] == 0xFF) {
			RawVMHook.Set(pOriginalVM);
			RawVMHook.Hook(VMHook, true);
			LOG_INFO(_T("[+] Hooked VM CALL!\n"));
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
