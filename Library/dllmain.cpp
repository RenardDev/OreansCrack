
// Framework
#include "framework.h"

// ConsoleAPI
#include "Console.h"

// LibraryLoader
#include "LibraryLoader.h"

// Detours
#include "Detours.h"

// Distorm(X)
#include "distorm.h"
#include "distormx.h"

// STL
#include <unordered_map>
#include <memory>
#include <vector>
#include <array>

// Namespaces
using namespace Detours;

#pragma comment(lib, "dbghelp.lib")

// General definitions
typedef LRESULT(WINAPI* fnSendMessageW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef BOOL(WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE(WINAPI* fnCreateRemoteThreadEx)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);
typedef void(__stdcall* fnVM)(unsigned char, unsigned int*);
typedef HANDLE(WINAPI* fnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

bool SuspendOtherThreads() {
	const PTEB pTEB = GetTEB();
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
	const PTEB pTEB = GetTEB();
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

fnCreateFileW CreateFileW_Original = nullptr;
HANDLE WINAPI CreateFileW_Hook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	//clrprintf(COLOR::COLOR_RED, "[+] CreateFileW_Hook(\"%ws\", ...) called from 0x%08X (RVA: 0x%08X)\n", lpFileName, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	//void* pCalls[256];
	//memset(pCalls, 0, sizeof(pCalls));
	//size_t unMax = 256;
	//GetCalls(pCalls, &unMax);

	//for (unsigned int i = 0; i < unMax; ++i) {
	//	clrprintf(COLOR::COLOR_RED, "[+]  Trace: 0x%08X (RVA: 0x%08X)\n", (unsigned int)pCalls[i], (unsigned int)pCalls[i] - (unsigned int)g_pSelf);
	//}

	return CreateFileW_Original(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

fnSendMessageW SendMessageW_Original = nullptr;
LRESULT WINAPI SendMessageW_Hook(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
	switch (Msg) {
		case 0x14: { // Mouse
			return SendMessageW_Original(hWnd, Msg, wParam, lParam);
		}
		case 0x281: { // Window
			return SendMessageW_Original(hWnd, Msg, wParam, lParam);
		}
		case 0x282: { // Window
			return SendMessageW_Original(hWnd, Msg, wParam, lParam);
		}
		case 0x288: { // Window
			return SendMessageW_Original(hWnd, Msg, wParam, lParam);
		}
		case 0x317: { // Mouse
			return SendMessageW_Original(hWnd, Msg, wParam, lParam);
		}
		case 0x318: { // Mouse
			return SendMessageW_Original(hWnd, Msg, wParam, lParam);
		}
	}
	/*
	if ((Msg >= 0x0000) && (Msg <= 0x03FF) && wParam && lParam) {
		clrprintf(COLOR::COLOR_RED, "[+] SendMessageW_Hook(0x%08X, 0x%08X, 0x%08X, 0x%08X) from 0x%08X (0x%08X)\n", (UINT)hWnd, Msg, (UINT)wParam, (UINT)lParam, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	}
	if ((Msg >= 0x8000) && (Msg <= 0xBFFF) && wParam && lParam) {
		clrprintf(COLOR::COLOR_RED, "[+] SendMessageW_Hook(0x%08X, 0x%08X, 0x%08X, 0x%08X) from 0x%08X (0x%08X)\n", (UINT)hWnd, Msg, (UINT)wParam, (UINT)lParam, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	}
	if ((Msg >= 0xC000) && (Msg <= 0xFFFF) && wParam && lParam) {
		clrprintf(COLOR::COLOR_RED, "[+] SendMessageW_Hook(0x%08X, 0x%08X, 0x%08X, 0x%08X) from 0x%08X (0x%08X)\n", (UINT)hWnd, Msg, (UINT)wParam, (UINT)lParam, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
	}
	*/
	return SendMessageW_Original(hWnd, Msg, wParam, lParam);
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
					//pVM(unIndex, pData);

					clrprintf(COLOR::COLOR_RED, "[+] CallMacro (ID=0x%02X)\n", unMacroIndex);
					clrprintf(COLOR::COLOR_RED, "[+]  Data: %08X (%08X)\n", pMacroResult, *pMacroResult);

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

			clrprintf(COLOR::COLOR_RED, "[+] CallVM (ID=0x%02X) from 0x%08X (RVA: 0x%08X)\n", unIndex, (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
			clrprintf(COLOR::COLOR_RED, "[+]  Data: ");
			for (unsigned char i = 0; i < 14; ++i) {
				clrprintf(COLOR::COLOR_RED, "%08X ", pData[i]);
			}
			clrprintf(COLOR::COLOR_RED, "\n");

			return;
		}
	}
	return;
}

fnVirtualProtect VirtualProtect_Original = nullptr;
BOOL WINAPI VirtualProtect_Hook(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
	BOOL bRes = VirtualProtect_Original(lpAddress, dwSize, flNewProtect, lpflOldProtect);
	//if (bMonitorMemory && (dwSize > 0x1000)) {
	//	clrprintf(COLOR::COLOR_RED, "[+] Memory protected! (lpAddress=0x%08X, dwSize=0x%08X, flNewProtect=0x%08X)\n", reinterpret_cast<DWORD>(lpAddress), dwSize, flNewProtect);
	//}
	return bRes;
}

bool bOnce = false;
bool bOnceDump = false;
fnCreateRemoteThreadEx CreateRemoteThreadEx_Original = nullptr;
HANDLE WINAPI CreateRemoteThreadEx_Hook(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId) {

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
				clrprintf(COLOR::COLOR_BLUE, "[+] SecureEngine dumped!\n");
			}
		}
	}
	*/

	void* pIsDemo = const_cast<void*>(Scan::FindSignature(g_pSelf, "\x55\x8B\xEC\x81\xC4\xBC\xFD\xFF\xFF\x8D")); // 55 8B EC 81 C4 BC FD FF FF 8D
	if (pIsDemo && !bOnce) {
		bOnce = true;
		unsigned char* pMOV = reinterpret_cast<unsigned char*>(pIsDemo) + 0x1D;
		Memory::ChangeProtection(pMOV, 1, PAGE_READWRITE);
		pMOV[0] = 0;
		Memory::RestoreProtection(pMOV);

		unsigned char* pCallVM = reinterpret_cast<unsigned char*>(pIsDemo) + 0x10;
		pVM = reinterpret_cast<fnVM>(reinterpret_cast<unsigned int>(pCallVM) + sizeof(unsigned int) + (*reinterpret_cast<unsigned int*>(pCallVM)));

		if (reinterpret_cast<unsigned char*>(pVM)[0] == 0xFF) {
			distormx_hook((void**)&pVM, VM_Hook);
			clrprintf(COLOR::COLOR_BLUE, "[+] Hooked VM call!\n");
		}
	}

	HANDLE hThread = CreateRemoteThreadEx_Original(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, (dwCreationFlags & CREATE_SUSPENDED) ? dwCreationFlags : (dwCreationFlags | CREATE_SUSPENDED), lpAttributeList, lpThreadId);
	clrprintf(COLOR::COLOR_CYAN, "[+] Thread created! (ID=%lu) (lpStartAddress=0x%08X, lpParameter=0x%08X) from 0x%08X (RVA: 0x%08X)\n", GetThreadId(hThread), reinterpret_cast<DWORD>(lpStartAddress), reinterpret_cast<DWORD>(lpParameter), (unsigned int)_ReturnAddress(), (unsigned int)_ReturnAddress() - (unsigned int)g_pSelf);
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

	if (!ConnectToConsole()) {
		return 0;
	}

	g_pSelf = GetModuleHandle(nullptr);

	clrprintf(COLOR::COLOR_WHITE, "OreansCrack [Version 1.0.0] (zeze839@gmail.com)\n\n");
	clrprintf(COLOR::COLOR_WHITE, "[OreansCrack] Loading... ");

	HMODULE hNTDLL = GetModuleHandle(_T("ntdll.dll"));
	if (!hNTDLL) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (!hKernel32) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	HMODULE hUser32 = GetModuleHandle(_T("user32.dll"));
	if (!hUser32) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	VirtualProtect_Original = reinterpret_cast<fnVirtualProtect>(GetProcAddress(hKernel32, "VirtualProtect"));
	if (!VirtualProtect_Original) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	if (!distormx_hook(reinterpret_cast<void**>(&VirtualProtect_Original), VirtualProtect_Hook)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	CreateRemoteThreadEx_Original = reinterpret_cast<fnCreateRemoteThreadEx>(GetProcAddress(hKernel32, "CreateRemoteThreadEx"));
	if (!CreateRemoteThreadEx_Original) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	if (!distormx_hook(reinterpret_cast<void**>(&CreateRemoteThreadEx_Original), CreateRemoteThreadEx_Hook)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	CreateFileW_Original = reinterpret_cast<fnCreateFileW>(GetProcAddress(hKernel32, "CreateFileW"));
	if (!CreateFileW_Original) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	if (!distormx_hook(reinterpret_cast<void**>(&CreateFileW_Original), CreateFileW_Hook)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	SendMessageW_Original = reinterpret_cast<fnSendMessageW>(GetProcAddress(hUser32, "SendMessageW"));
	if (!SendMessageW_Original) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	if (!distormx_hook(reinterpret_cast<void**>(&SendMessageW_Original), SendMessageW_Hook)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		return 0;
	}

	clrprintf(COLOR::COLOR_GREEN, "[  OK  ]\n");

	bMonitorMemory = true;

	ResumeOtherThreads();
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	g_pLoaderData = reinterpret_cast<PLOADER_DATA>(lpReserved);
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			CreateThread(nullptr, 0x100000 /* 1 MiB */, MainRoutine, lpReserved, NULL, nullptr);
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
