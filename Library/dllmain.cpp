
// Framework
#include "framework.h"

// Terminal
#include "Terminal.h"

// LibraryLoader
#include "LibraryLoader.h"

// Detours
#include "Detours.h"

// HookManager
#include "HookManager.h"

// STL
#include <unordered_map>
#include <memory>
#include <vector>
#include <array>

#pragma comment(lib, "dbghelp.lib")

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

typedef void(__stdcall* fnVM)(unsigned char, unsigned int*);

Terminal::Client TerminalClient;

DECLARE_INLINE_HOOK(
	CreateFileW,
	HANDLE,
	WINAPI,
	LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);

DECLARE_INLINE_HOOK(
	SendMessageW,
	LRESULT,
	WINAPI,
	HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam
);

DECLARE_INLINE_HOOK(
	VirtualAlloc,
	LPVOID,
	WINAPI,
	LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
);

DECLARE_INLINE_HOOK(
	VirtualProtect,
	BOOL,
	WINAPI,
	LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect
);

DECLARE_INLINE_HOOK(
	CreateRemoteThreadEx,
	HANDLE,
	WINAPI,
	HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId
);

bool bOnce = false;
bool bOnceDump = false;

bool SuspendOtherThreads() {
	auto pTEB = Detours::GetTEB();
	if (!pTEB) {
		return false;
	}

	DWORD unCurrentPID = pTEB->RealClientId.UniqueProcess;
	DWORD unCurrentTID = pTEB->RealClientId.UniqueThread;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnap || (hSnap == INVALID_HANDLE_VALUE)) {
		return false;
	}

	THREADENTRY32 te;
	memset(&te, 0, sizeof(THREADENTRY32));

	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnap, &te)) {
		do {
			if (te.th32OwnerProcessID != unCurrentPID) {
				continue;
			}

			if (te.th32ThreadID != unCurrentTID) {
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
					CloseHandle(hSnap);
					return false;
				}

				SuspendThread(hThread);

				CloseHandle(hThread);
			}

			memset(&te, 0, sizeof(THREADENTRY32));
			te.dwSize = sizeof(THREADENTRY32);

		} while (Thread32Next(hSnap, &te));
	}

	CloseHandle(hSnap);
	return true;
}

void ResumeOtherThreads() {
	auto pTEB = Detours::GetTEB();
	if (!pTEB) {
		return;
	}

	DWORD unCurrentPID = pTEB->RealClientId.UniqueProcess;
	DWORD unCurrentTID = pTEB->RealClientId.UniqueThread;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnap || (hSnap == INVALID_HANDLE_VALUE)) {
		return;
	}

	THREADENTRY32 te;
	memset(&te, 0, sizeof(THREADENTRY32));

	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnap, &te)) {
		do {
			if (te.th32OwnerProcessID != unCurrentPID) {
				continue;
			}

			if (te.th32ThreadID != unCurrentTID) {
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
					CloseHandle(hSnap);
					return;
				}

				ResumeThread(hThread);

				CloseHandle(hThread);
			}

			memset(&te, 0, sizeof(THREADENTRY32));
			te.dwSize = sizeof(THREADENTRY32);

		} while (Thread32Next(hSnap, &te));
	}

	CloseHandle(hSnap);
	return;
}

bool GetCalls(void** pBuffer, size_t* pMaxCount) {
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = GetCurrentThread();

	CONTEXT ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&ctx);

	STACKFRAME frame;
	memset(&frame, 0, sizeof(frame));

	frame.AddrPC.Offset = ctx.Eip;
	frame.AddrPC.Mode = AddrModeFlat;
	frame.AddrFrame.Offset = ctx.Ebp;
	frame.AddrFrame.Mode = AddrModeFlat;
	frame.AddrStack.Offset = ctx.Esp;
	frame.AddrStack.Mode = AddrModeFlat;

	size_t unCount = 0;
	const size_t unMaxCount = *pMaxCount;
	while ((unCount < unMaxCount) && StackWalk(IMAGE_FILE_MACHINE_I386, hProcess, hThread, &frame, &ctx, nullptr, SymFunctionTableAccess, SymGetModuleBase, nullptr)) {
		pBuffer[unCount] = reinterpret_cast<void*>(frame.AddrPC.Offset);
		++unCount;
	}

	*pMaxCount = unCount;

	return true;
}

PLOADER_DATA g_pLoaderData = nullptr;
HMODULE g_pSelf = nullptr;

DEFINE_INLINE_HOOK(
	CreateFileW, {
		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		if (!hKernel32) {
			return nullptr;
		}

		return GetProcAddress(hKernel32, "CreateFileW");
	},
	HANDLE,
	WINAPI,
	LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
) {
	//TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, "[+] CreateFileW_Hook(\"%ws\", ...) called from 0x%08X (RVA: 0x%08X)\n", lpFileName, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	//void* pCalls[256];
	//memset(pCalls, 0, sizeof(pCalls));
	//size_t unMax = 256;
	//GetCalls(pCalls, &unMax);

	//for (unsigned int i = 0; i < unMax; ++i) {
	//	TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, "[+]  Trace: 0x%08X (RVA: 0x%08X)\n", (unsigned int)pCalls[i], (unsigned int)pCalls[i] - (unsigned int)g_pSelf);
	//}

	return g_HookCreateFileW.Call(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

DEFINE_INLINE_HOOK(
	SendMessageW, {
		HMODULE hUser32 = GetModuleHandle(_T("user32.dll"));
		if (!hUser32) {
			return nullptr;
		}

		return GetProcAddress(hUser32, "SendMessageW");
	},
	LRESULT,
	WINAPI,
	HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam
) {
	switch (Msg) {
		case 0x14: { // Mouse
			return g_HookSendMessageW.Call(hWnd, Msg, wParam, lParam);
		}
		case 0x281: { // Window
			return g_HookSendMessageW.Call(hWnd, Msg, wParam, lParam);
		}
		case 0x282: { // Window
			return g_HookSendMessageW.Call(hWnd, Msg, wParam, lParam);
		}
		case 0x288: { // Window
			return g_HookSendMessageW.Call(hWnd, Msg, wParam, lParam);
		}
		case 0x317: { // Mouse
			return g_HookSendMessageW.Call(hWnd, Msg, wParam, lParam);
		}
		case 0x318: { // Mouse
			return g_HookSendMessageW.Call(hWnd, Msg, wParam, lParam);
		}
	}
	/*
	if ((Msg >= 0x0000) && (Msg <= 0x03FF) && wParam && lParam) {
		TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, "[+] SendMessageW_Hook(0x%08X, 0x%08X, 0x%08X, 0x%08X) from 0x%08X (0x%08X)\n", (UINT)hWnd, Msg, (UINT)wParam, (UINT)lParam, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	}
	if ((Msg >= 0x8000) && (Msg <= 0xBFFF) && wParam && lParam) {
		TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, "[+] SendMessageW_Hook(0x%08X, 0x%08X, 0x%08X, 0x%08X) from 0x%08X (0x%08X)\n", (UINT)hWnd, Msg, (UINT)wParam, (UINT)lParam, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	}
	if ((Msg >= 0xC000) && (Msg <= 0xFFFF) && wParam && lParam) {
		TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, "[+] SendMessageW_Hook(0x%08X, 0x%08X, 0x%08X, 0x%08X) from 0x%08X (0x%08X)\n", (UINT)hWnd, Msg, (UINT)wParam, (UINT)lParam, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	}
	*/
	return g_HookSendMessageW.Call(hWnd, Msg, wParam, lParam);
}

bool bMonitorMemory = false;

fnVM pVM = nullptr;
void __stdcall VM_Hook(unsigned char unIndex, unsigned int* pData) {
	switch (unIndex) {
		case 0x01: { // Check executable headers
			pVM(unIndex, pData);
			return;
		}
		case 0x02: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x03: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x04: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x05: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x06: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x07: { // MAP list (Viewer - Dissambler)
			pVM(unIndex, pData);
			return;
		}
		case 0x08: { // MAP list (Viewer - Dissambler)
			pVM(unIndex, pData);
			return;
		}
		case 0x09: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x0A: { // First initialization
			pVM(unIndex, pData);
			return;
		}
		case 0x0B: { // Get VMs Names
			pVM(unIndex, pData);
			return;
		}
		case 0x0D: { // Get VMs Complexity
			pVM(unIndex, pData);
			return;
		}
		case 0x0E: { // Get VMs Speeds
			pVM(unIndex, pData);
			return;
		}
		case 0x0F: { // Get VMs Sizes
			pVM(unIndex, pData);
			return;
		}
		case 0x10: { // Get VMs
			pVM(unIndex, pData);
			return;
		}
		case 0x16: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x17: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x19: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x1B: { // Get protection macroses
			pVM(unIndex, pData);
			return;
		}
		case 0x1C: { // Unknown
			pVM(unIndex, pData);
			return;
		}
		case 0x1D: { // Unknown initialization
			pVM(unIndex, pData);
			return;
		}
		case 0x20: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x21: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x22: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x23: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x24: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x25: { // Macroses processor
			unsigned int unMacroIndex = pData[0];
			unsigned int* pMacroResult = reinterpret_cast<unsigned int*>(pData[13]);
			switch (unMacroIndex) {
			case 0x3A: { // Checking Input and Output files
				pVM(unIndex, pData);
				return;
			}
			case 0x4C: { // Stealth...
				pVM(unIndex, pData);
				return;
			}
			case 0x4D: { // Stealth...
				pVM(unIndex, pData);
				return;
			}
			case 0x05: { // Reading Protection Macros
				pVM(unIndex, pData);
				return;
			}
			case 0x16: { // Reading Protection Macros
				pVM(unIndex, pData);
				return;
			}
			case 0x4F: { // Initializing VM machines
				pVM(unIndex, pData);
				return;
			}
			case 0x5D: { // Ansi Strings to Virtualize
				pVM(unIndex, pData);
				return;
			}
			case 0x68: { // Ansi Strings to Virtualize
				pVM(unIndex, pData);
				return;
			}
			case 0x5F: { // Ansi Strings to Virtualize
				pVM(unIndex, pData);
				return;
			}
			case 0x5E: { // Unicode Strings to Virtualize
				pVM(unIndex, pData);
				return;
			}
			case 0x69: { // Unicode Strings to Virtualize
				pVM(unIndex, pData);
				return;
			}
			case 0x60: { // Unicode Strings to Virtualize
				pVM(unIndex, pData);
				return;
			}
			case 0x2A: { // Virtual Machines Generation
				pVM(unIndex, pData);
				return;
			}
			case 0x15: { // Virtual Machines Generation
				pVM(unIndex, pData);
				return;
			}
			case 0x10: { // Virtual Machines Generation
				pVM(unIndex, pData);
				return;
			}
			case 0x12: { // Virtual Machines Generation
				pVM(unIndex, pData);
				return;
			}
			case 0x11: { // Virtual Machines Generation
				pVM(unIndex, pData);
				return;
			}
			case 0x14: { // Virtual Machines Generation
				pVM(unIndex, pData);
				return;
			}
			case 0x2C: { // Potecting Macros (Mutation & StrEncrypt)
				pVM(unIndex, pData);
				return;
			}
			case 0x2D: { // Potecting Macros (Mutation & StrEncrypt)
				pVM(unIndex, pData);
				return;
			}
			case 0x62: { // Potecting Macros (Mutation & StrEncrypt)
				pVM(unIndex, pData);
				return;
			}
			case 0x63: { // Potecting Macros (Mutation & StrEncrypt)
				pVM(unIndex, pData);
				return;
			}
			case 0x64: { // Potecting Macros (Virtualization)
				pVM(unIndex, pData);
				return;
			}
			case 0x08: { // Compressing Virtual Machines
				pVM(unIndex, pData);
				return;
			}
			case 0x2F: { // Compressing Virtual Machines
				pVM(unIndex, pData);
				return;
			}
			case 0x32: { // Compressing Virtual Machines
				pVM(unIndex, pData);
				return;
			}
			case 0x57: { // Finalizing Protection
				pVM(unIndex, pData);
				return;
			}
			case 0x44: { // Taggant
				pVM(unIndex, pData);
				return;
			}
			case 0x45: { // Taggant
				pVM(unIndex, pData);
				return;
			}
			case 0x43: { // Taggant
				pVM(unIndex, pData);
				return;
			}
			case 0x6D: { // Code Signing
				pVM(unIndex, pData);
				return;
			}
			case 0x6E: { // Code Signing
				pVM(unIndex, pData);
				return;
			}
			case 0x41: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x17: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x1C: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x6B: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x58: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x59: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x18: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x1A: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x1B: { // Unknown
				pVM(unIndex, pData);
				return;
			}
			case 0x65: { // Called when Cancel pressed
				pVM(unIndex, pData);
				return;
			}
			case 0x4E: { // Rebuilding?
				pVM(unIndex, pData);
				return;
			}

			default: {
				pVM(unIndex, pData);

				TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[+] CallMacro (ID=0x%02X)\n"), unMacroIndex);
				TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[+]  Data: %08X (%08X)\n"), pMacroResult, *pMacroResult);

				return;
			}
			}
			return;
		}
		case 0x26: { // Get VMs
			pVM(unIndex, pData);
			return;
		}
		case 0x2F: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x32: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x33: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x34: { // Unknown (Called when loadinging file)
			pVM(unIndex, pData);
			return;
		}
		case 0x35: { // Unknown
			pVM(unIndex, pData);
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
			pVM(unIndex, pData);
			return;
		}
		case 0x47: { // MAP list
			pVM(unIndex, pData);
			return;
		}
		case 0x12: { // Unknown
			pVM(unIndex, pData);
			return;
		}
		case 0x43: { // Unknown
			pVM(unIndex, pData);
			return;
		}
		case 0x30: { // Unknown
			pVM(unIndex, pData);
			return;
		}
		default: {
			pVM(unIndex, pData);

			TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[+] CallVM (ID=0x%02X) from 0x%08X (RVA: 0x%08X)\n"), unIndex, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
			TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[+]  Data: "));
			for (unsigned char i = 0; i < 14; ++i) {
				TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("%08X "), pData[i]);
			}
			TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("\n"));

			return;
		}
	}
	return;
}

Detours::Hook::RawHook RawVMHook;
bool __cdecl VMHook(Detours::Hook::PRAW_CONTEXT pCTX) {
	TerminalClient.tprintf(Terminal::COLOR::COLOR_GREEN, _T("[+] VM call!\n"));

	pVM = reinterpret_cast<fnVM>(RawVMHook.GetTrampoline());
	pCTX->Stack.push(VM_Hook);

	return true;
}

DEFINE_INLINE_HOOK(
	VirtualAlloc, {
		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		if (!hKernel32) {
			return nullptr;
		}

		return GetProcAddress(hKernel32, "VirtualAlloc");
	},
	LPVOID,
	WINAPI,
	LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
) {
	if (bMonitorMemory && (dwSize >= 0x1000)) {
		TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[+] Memory allocated! (lpAddress=0x%08X, dwSize=0x%08X, flAllocationType=0x%08X, flProtect=0x%08X)\n"), reinterpret_cast<DWORD>(lpAddress), dwSize, flAllocationType, flProtect);
	}

	return g_HookVirtualAlloc.Call(lpAddress, dwSize, flAllocationType, flProtect);
}

DEFINE_INLINE_HOOK(
	VirtualProtect, {
		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		if (!hKernel32) {
			return nullptr;
		}

		return GetProcAddress(hKernel32, "VirtualProtect");
	},
	BOOL,
	WINAPI,
	LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect
) {
	BOOL bRes = g_HookVirtualProtect.Call(lpAddress, dwSize, flNewProtect, lpflOldProtect);
	if (bMonitorMemory && (dwSize >= 0x1000)) {
		TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[+] Memory protected! (lpAddress=0x%08X, dwSize=0x%08X, flNewProtect=0x%08X)\n"), reinterpret_cast<DWORD>(lpAddress), dwSize, flNewProtect);
	}

	return bRes;
}

void DumpMemory() {
	FILE* pDumpFile = nullptr;
	if (_tfopen_s(&pDumpFile, _T("dump.txt"), _T("w+")) != 0) {
		TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("Error opening dump file for writing.\n"));
		return;
	}

	if (!pDumpFile) {
		TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("Error opening dump file for writing.\n"));
		return;
	}

	MEMORY_BASIC_INFORMATION mbi;
	memset(&mbi, 0, sizeof(mbi));

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	for (size_t unAddress = (size_t)sysInfo.lpMinimumApplicationAddress; unAddress < (size_t)sysInfo.lpMaximumApplicationAddress;) {
		if (!VirtualQuery((void*)unAddress, &mbi, sizeof(mbi))) {
			break;
		}

		// Check for any valid memory region
		if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
			TCHAR szFileName[128];
			memset(szFileName, 0, sizeof(szFileName));

			_sntprintf_s(szFileName, sizeof(szFileName) - 1, _T("0x%08X_memory_dump.bin"), unAddress);

			FILE* pFile = nullptr;
			if (_tfopen_s(&pFile, szFileName, _T("wb+")) == 0) {
				DWORD bytesRead;
				BYTE* buffer = new BYTE[mbi.RegionSize];

				if (ReadProcessMemory(GetCurrentProcess(), (LPVOID)unAddress, buffer, mbi.RegionSize, &bytesRead)) {
					fwrite(buffer, 1, bytesRead, pFile);
					TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[+] Addr: 0x%08X Size: 0x%08X to `%s`.\n"), unAddress, bytesRead, szFileName);
					if (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
						_ftprintf(pDumpFile, _T("0x%08X;C;%s\n"), unAddress, szFileName);
					} else {
						_ftprintf(pDumpFile, _T("0x%08X;D;%s\n"), unAddress, szFileName);
					}
				} else {
					TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[+] Addr: 0x%08X Size: 0x%08X to `FAIL`.\n"), unAddress, bytesRead);
				}

				delete[] buffer;
				fclose(pFile);
			}
		}

		unAddress += mbi.RegionSize;
	}

	fclose(pDumpFile);
}

DEFINE_INLINE_HOOK(
	CreateRemoteThreadEx, {
		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		if (!hKernel32) {
			return nullptr;
		}

		return GetProcAddress(hKernel32, "CreateRemoteThreadEx");
	},
	HANDLE,
	WINAPI,
	HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId
) {
	/*
	if (!bOnceDump) {
		bOnceDump = true;
		MEMORY_BASIC_INFORMATION mbi;
		memset(&mbi, 0, sizeof(mbi));
		if (VirtualQuery(reinterpret_cast<void*>(0x10000000), &mbi, sizeof(mbi))) {
			const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(0x10000000);
			const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(0x10000000) + pDH->e_lfanew);
			const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

			FILE* pFile = nullptr;
			if (fopen_s(&pFile, "./SecureEngine.dll", "wb+") != EINVAL) {
				SuspendOtherThreads();
				fwrite(reinterpret_cast<void*>(0x10000000), 1, pOH->SizeOfImage - 1, pFile);
				ResumeOtherThreads();
				fclose(pFile);
				TerminalClient.tprintf(Terminal::COLOR::COLOR_BLUE, "[+] SecureEngine dumped!\n");
			}
		}
	}
	*/

	void* pIsDemo = const_cast<void*>(Detours::Scan::FindSignature(g_pSelf, "\x55\x8B\xEC\x81\xC4\xBC\xFD\xFF\xFF\x8D")); // 55 8B EC 81 C4 BC FD FF FF 8D
	if (pIsDemo && !bOnce) {
		bOnce = true;
		unsigned char* pMOV = reinterpret_cast<unsigned char*>(pIsDemo) + 0x1D;
		Detours::Memory::Protection Patch(pMOV, 1, false);
		Patch.ChangeProtection(PAGE_EXECUTE_READWRITE);
		pMOV[0] = 0;
		Patch.RestoreProtection();

		unsigned char* pCallVM = reinterpret_cast<unsigned char*>(pIsDemo) + 0x10;
		pVM = reinterpret_cast<fnVM>(reinterpret_cast<unsigned int>(pCallVM) + sizeof(unsigned int) + (*reinterpret_cast<unsigned int*>(pCallVM)));

		if (reinterpret_cast<unsigned char*>(pVM)[0] == 0xFF) {
			RawVMHook.Set(pVM);
			RawVMHook.Hook(VMHook, true);
			TerminalClient.tprintf(Terminal::COLOR::COLOR_BLUE, _T("[+] Hooked VM call!\n"));

			//DumpMemory();

		}
	}

	HANDLE hThread = g_HookCreateRemoteThreadEx.Call(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
	TerminalClient.tprintf(Terminal::COLOR::COLOR_CYAN, _T("[+] Thread created! (ID=%lu) (lpStartAddress=0x%08X, lpParameter=0x%08X) from 0x%08X (RVA: 0x%08X)\n"), GetThreadId(hThread), reinterpret_cast<DWORD>(lpStartAddress), reinterpret_cast<DWORD>(lpParameter), (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	if (!(dwCreationFlags & CREATE_SUSPENDED)) {
		ResumeThread(hThread);
	}

	return hThread;
}

// NOTE: This is a buffer (structure) that is passed to CallVM and its address is located in the SecureEngine.
#pragma pack(push, 1)
typedef struct _OREANS_BUFFER {
	unsigned short m_unV1;
	char _Pad1[8];
	unsigned int m_unV2;
	char _Pad2[3];
	unsigned char m_unV3;
	char _Pad3[1];
	unsigned int m_unV4;
	char _Pad4[24];
	unsigned int m_unV5;
	char _Pad5[12];
	unsigned int m_unV6;
	char _Pad6[42];
	unsigned short m_unV7;
	unsigned short m_unV8;
	char _Pad7[40];
	unsigned int m_unV9;
	char _Pad8[8];
	unsigned int m_unV10;
	char _Pad9[17];
	unsigned int m_unV11;
	char _Pad10[20];
	unsigned int m_unV12;
	unsigned int m_unV13;
} OREANS_BUFFER, *POREANS_BUFFER;
#pragma pack(pop)

DWORD WINAPI MainRoutine(LPVOID lpThreadParameter) {
	if (!SuspendOtherThreads()) {
		return 0;
	}

	if (!TerminalClient.Open(g_pLoaderData->m_pSessionName)) {
		return 0;
	}

	g_pSelf = GetModuleHandle(nullptr);

	TerminalClient.tprintf(Terminal::COLOR::COLOR_WHITE, _T("OreansCrack [Version 2.1.0]\n\n"));
	TerminalClient.tprintf(Terminal::COLOR::COLOR_WHITE, _T("[OreansCrack] Loading... "));

	if (!g_HookManager.HookAll()) {
		TerminalClient.tprintf(Terminal::COLOR::COLOR_RED, _T("[ FAIL ]\n"));
		return 0;
	}

	TerminalClient.tprintf(Terminal::COLOR::COLOR_GREEN, _T("[  OK  ]\n"));

	bMonitorMemory = true;

	ResumeOtherThreads();
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	g_pLoaderData = reinterpret_cast<PLOADER_DATA>(lpReserved);
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			CreateThread(nullptr, NULL, MainRoutine, lpReserved, NULL, nullptr);
		}
		case DLL_THREAD_ATTACH: {
			break;
		}
		case DLL_THREAD_DETACH: {
			break;
		}
		case DLL_PROCESS_DETACH: {
			break;
		}
	}
	return TRUE;
}
