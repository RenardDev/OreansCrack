
// Default
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tchar.h>
#include <strsafe.h>
#include <dbghelp.h>

// C
#include <io.h>
#include <fcntl.h>
#include <conio.h>

// C++
#include <clocale>

// STL
#include <array>
#include <string>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <cwctype>
#include <cctype>

// Detours
#include "Detours/Detours.h"

// Terminal
#include "Terminal/Terminal.h"

// Types
using tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;
using tstring_optional = std::pair<bool, tstring>;

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

#define ProcessDebugObjectHandle static_cast<PROCESSINFOCLASS>(0x1E)
#define ProcessDebugFlags static_cast<PROCESSINFOCLASS>(0x1F)
#define SafeCloseHandle(x) if ((x) && (x != INVALID_HANDLE_VALUE)) { CloseHandle(x); }
#define FileStandardInformation static_cast<FILE_INFORMATION_CLASS>(5)

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtRemoveProcessDebug(IN HANDLE ProcessHandle, IN HANDLE DebugObjectHandle);

DEFINE_SECTION(".load", SECTION_READWRITE)

// [{
//     PID: (HANDLE, START ADDRESS)
// }]
std::unordered_map<DWORD, std::pair<HANDLE, LPVOID>> g_Processes;

// [{
//     PID: STUB ADDRESS
// }]
std::unordered_map<DWORD, LPVOID> g_Stub;

// [{
//     PID: [{
//         TID: CALLBACK ADDRESS
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<DWORD, LPVOID>> g_TLSReArm;

// [{
//     PID: [{
//         CALLBACK ADDRESS: ORIGINAL BYTES
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, BYTE>> g_TLSOriginalByte;

// [{
//     PID: [{
//         CALLBACK ADDRESS: MODULE BASE
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, LPVOID>> g_TLSCallBackOwner;

// [{
//     PID: [{
//         ENTRYPOINT: ORIGINAL BYTES
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, BYTE>> g_DLLEntryPointOriginalByte;

// [{
//     PID: [{
//         ENTRYPOINT: MODULE_BASE
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, LPVOID>> g_DLLEntryPointOwner;

// [{
//     PID: [{
//         TID: ENTRYPOINT
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<DWORD, LPVOID>> g_DLLEntryPointReArm;

// [{
//     PID: ORIGINAL BYTES
// }]
std::unordered_map<DWORD, BYTE> g_ProcessesOriginalEntryPointByte;

// [{
//     PID: [{
//         TID: (HANDLE, START ADDRESS)
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<DWORD, std::pair<HANDLE, LPVOID>>> g_Threads;

// [{
//     PID: [{
//         BASE ADDRESS: FULL MODULE PATH
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, tstring_optional>> g_Modules;

// [{
//     PID: [
//         HANDLE
//     ]
// }]
std::unordered_map<DWORD, HANDLE> g_ProcessSuspendedMainThreads;

// [{
//     PID: [
//         HANDLE
//     ]
// }]
std::unordered_map<DWORD, HANDLE> g_ProcessInjectionThreads;

// TerminalServer
std::unique_ptr<Terminal::Server> g_pTerminalServer;

bool g_bContinueDebugging = true;
bool g_bGlobalDisableThreadLibraryCalls = false;

bool IsRunningAsAdmin() {
	SID_IDENTIFIER_AUTHORITY NT_AUTHORITY = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup = nullptr;
	if (!AllocateAndInitializeSid(&NT_AUTHORITY, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
		_tprintf_s(_T("ERROR: AllocateAndInitializeSid (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	BOOL bIsAdmin = FALSE;
	if (!CheckTokenMembership(NULL, AdministratorsGroup, &bIsAdmin)) {
		_tprintf_s(_T("ERROR: CheckTokenMembership (Error = 0x%08X)\n"), GetLastError());
		FreeSid(AdministratorsGroup);
		return false;
	}

	return bIsAdmin;
}

bool ReLaunchAsAdmin(bool bAllowCancel = false) {
	TCHAR szPath[MAX_PATH];
	if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
		return false;
	}

	LPCTSTR szCommandLine = GetCommandLine();
	LPCTSTR szArguments = _tcschr(szCommandLine, _T(' '));
	if (!szArguments) {
		_tprintf_s(_T("ERROR: _tcsstr\n"));
		return false;
	}

	SHELLEXECUTEINFO sei {};
	sei.cbSize = sizeof(sei);
	sei.lpVerb = _T("runas");
	sei.lpFile = szPath;
	sei.lpParameters = szArguments;
	sei.nShow = SW_NORMAL;

	if (!ShellExecuteEx(&sei)) {
		if (bAllowCancel && (GetLastError() == ERROR_CANCELLED)) {
			return true;
		}

		_tprintf_s(_T("ERROR: ShellExecuteEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

bool EnableDebugPrivilege(HANDLE hProcess, bool bEnable) {
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		_tprintf_s(_T("ERROR: OpenProcessToken (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	LUID luid {};
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		_tprintf_s(_T("ERROR: LookupPrivilegeValue (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hToken);
		return false;
	}

	TOKEN_PRIVILEGES tp {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
		_tprintf_s(_T("ERROR: AdjustTokenPrivileges (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return true;
}

tstring_optional GetProcessPath(HANDLE hProcess) {
	TCHAR szProcessPath[MAX_PATH + 1] {};
	if (!GetProcessImageFileName(hProcess, szProcessPath, _countof(szProcessPath))) {
		_tprintf_s(_T("ERROR: GetProcessImageFileName (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	TCHAR szTemp[MAX_PATH * 2] {};
	if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {
		TCHAR szName[MAX_PATH] {};
		TCHAR szDrive[3] = _T(" :");
		bool bFound = false;
		PTCHAR p = szTemp;

		do {
			*szDrive = *p;

			if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
				const size_t unNameLength = _tcslen(szName);

				bFound = (_tcsnicmp(szProcessPath, szName, unNameLength) == 0) && (*(szProcessPath + unNameLength) == _T('\\'));
				if (bFound) {
					TCHAR szTempFile[MAX_PATH];
					StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, szProcessPath + unNameLength);
					StringCchCopyN(szProcessPath, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
				}
			}

			while (*p++);
		} while (!bFound && *p);
	}

	return { true, szProcessPath };
}

tstring_optional GetProcessDirectory(HANDLE hProcess) {
	auto ProcessPath = GetProcessPath(hProcess);
	if (!ProcessPath.first) {
		return { false, _T("") };
	}

	TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {};
	errno_t err = _tsplitpath_s(ProcessPath.second.c_str(), szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), nullptr, 0, nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szProcessDirectory[MAX_PATH] {};
	if (_stprintf_s(szProcessDirectory, _countof(szProcessDirectory), _T("%s%s"), szDrive, szDirectory) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	return { true, szProcessDirectory };
}

tstring_optional GetProcessName(HANDLE hProcess) {
	auto ProcessPath = GetProcessPath(hProcess);
	if (!ProcessPath.first) {
		return { false, _T("") };
	}

	TCHAR szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
	errno_t err = _tsplitpath_s(ProcessPath.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt));
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szProcessName[MAX_PATH] {};
	if (_stprintf_s(szProcessName, _countof(szProcessName), _T("%s%s"), szName, szExt) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	tstring ProcessName = szProcessName;

	std::transform(ProcessName.begin(), ProcessName.end(), ProcessName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	return { true, ProcessName };
}

tstring_optional GetFilePath(HANDLE hFile) {
	HANDLE hFileMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 1, nullptr);
	if (!hFileMap || (hFileMap == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
	if (!pMem) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hFileMap);
		return { false, _T("") };
	}

	TCHAR szFilePath[MAX_PATH + 1] {};
	if (!GetMappedFileName(GetCurrentProcess(), pMem, szFilePath, _countof(szFilePath))) {
		_tprintf_s(_T("ERROR: GetMappedFileName (Error = 0x%08X)\n"), GetLastError());
		UnmapViewOfFile(pMem);
		CloseHandle(hFileMap);
		return { false, _T("") };
	}

	UnmapViewOfFile(pMem);
	CloseHandle(hFileMap);

	TCHAR szTemp[MAX_PATH * 2] {};
	if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {
		TCHAR szName[MAX_PATH] {};
		TCHAR szDrive[3] = _T(" :");
		bool bFound = false;
		PTCHAR p = szTemp;

		do {
			*szDrive = *p;

			if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
				const size_t unNameLength = _tcslen(szName);

				bFound = (_tcsnicmp(szFilePath, szName, unNameLength) == 0) && (*(szFilePath + unNameLength) == _T('\\'));
				if (bFound) {
					TCHAR szTempFile[MAX_PATH];
					StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, szFilePath + unNameLength);
					StringCchCopyN(szFilePath, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
				}
			}

			while (*p++);
		} while (!bFound && *p);
	}

	return { true, szFilePath };
}

tstring_optional GetFileDirectory(HANDLE hFile) {
	auto FilePath = GetFilePath(hFile);
	if (!FilePath.first) {
		return { false, _T("") };
	}

	TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {};
	errno_t err = _tsplitpath_s(FilePath.second.c_str(), szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), nullptr, 0, nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szFileDirectory[MAX_PATH] {};
	if (_stprintf_s(szFileDirectory, _countof(szFileDirectory), _T("%s%s"), szDrive, szDirectory) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	return { true, szFileDirectory };
}

tstring_optional GetFileName(HANDLE hFile) {
	auto FilePath = GetFilePath(hFile);
	if (!FilePath.first) {
		return { false, _T("") };
	}

	TCHAR szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
	errno_t err = _tsplitpath_s(FilePath.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt));
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szFileName[MAX_PATH] {};
	if (_stprintf_s(szFileName, _countof(szFileName), _T("%s%s"), szName, szExt) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	tstring FileName = szFileName;

	std::transform(FileName.begin(), FileName.end(), FileName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	return { true, FileName };
}

bool CreateStandardProcess(const TCHAR* szFileName, PTCHAR szCommandLine, PROCESS_INFORMATION& pi) {
	STARTUPINFO si {};
	si.cb = sizeof(si);

	if (!CreateProcess(szFileName, szCommandLine, nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
		_tprintf_s(_T("ERROR: CreateProcess (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

bool CreateProcessWithParent(const TCHAR* szFileName, PTCHAR szCommandLine, HANDLE hParentProcess, PROCESS_INFORMATION& pi) {
	STARTUPINFOEX si {};
	si.StartupInfo.cb = sizeof(si);

	/* FIXME: Changing parent is unstable and currently impossible to redirect stdin/stdout in right way
	SIZE_T attrSize = 0;
	InitializeProcThreadAttributeList(nullptr, 2, 0, &attrSize);
	si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attrSize));
	if (!si.lpAttributeList ||
		!InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &attrSize) ||
		!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), nullptr, nullptr)) {
		_tprintf_s(_T("ERROR: Failed to set up process attributes (Error = 0x%08X)\n"), GetLastError());
		HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
		return false;
	}
	*/

	if (!CreateProcess(szFileName, szCommandLine, nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi)) {
		_tprintf_s(_T("ERROR: CreateProcess (Error = 0x%08X)\n"), GetLastError());
		//DeleteProcThreadAttributeList(si.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
		return false;
	}

	//DeleteProcThreadAttributeList(si.lpAttributeList);
	//HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
	return true;
}

bool CreateDebugProcess(const TCHAR* szFileName, PTCHAR szCommandLine, HANDLE hJob, PPROCESS_INFORMATION pProcessInfo) {
	if (!szFileName) {
		return false;
	}

	PROCESS_BASIC_INFORMATION pbi {};
	if (!NT_SUCCESS(NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr))) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	HANDLE hParentProcess = nullptr;

	DWORD unParentPID = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pbi.Reserved3));
	if (unParentPID) {
		hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unParentPID);
		if (hParentProcess == INVALID_HANDLE_VALUE) {
			hParentProcess = nullptr;
		}
	}

	auto ProcessName = GetProcessName(hParentProcess);
	if (ProcessName.second == _T("wininit.exe")) {
		_tprintf_s(_T("ERROR: Parent process is `wininit.exe`!\n"));
		return false;
	}

	if (hParentProcess && ProcessName.first && ((ProcessName.second == _T("services.exe")) || (ProcessName.second == _T("explorer.exe")))) {
		CloseHandle(hParentProcess);
		hParentProcess = nullptr;
	}

	PROCESS_INFORMATION pi {};
	if (!hParentProcess) {
		if (!CreateStandardProcess(szFileName, szCommandLine, pi)) {
			return false;
		}
	} else {
		if (!CreateProcessWithParent(szFileName, szCommandLine, hParentProcess, pi)) {
			return false;
		}

		CloseHandle(hParentProcess);
	}

	if (!pi.hProcess || !pi.hThread) {
		return false;
	}

	if (hJob && (hJob != INVALID_HANDLE_VALUE)) {
		if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
			_tprintf_s(_T("ERROR: AssignProcessToJobObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return false;
		}
	}

	if (SuspendThread(pi.hThread) != 1) {
		_tprintf_s(_T("ERROR: SuspendThread (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	if (!NT_SUCCESS(NtResumeProcess(pi.hProcess))) {
		_tprintf_s(_T("ERROR: NtResumeProcess (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	if (pProcessInfo) {
		*pProcessInfo = pi;
	}

	return true;
}

HANDLE GetDebugProcess(DWORD unProcessID, LPVOID* ppStartAddress = nullptr) {
	auto Process = g_Processes.find(unProcessID);
	if (Process == g_Processes.end()) {
		return nullptr;
	}

	if (ppStartAddress) {
		*ppStartAddress = Process->second.second;
	}

	return Process->second.first;
}

HANDLE GetDebugThread(DWORD unProcessID, DWORD unThreadID, LPVOID* ppStartAddress = nullptr) {
	auto ProcessThreads = g_Threads.find(unProcessID);
	if (ProcessThreads == g_Threads.end()) {
		return nullptr;
	}

	auto Thread = ProcessThreads->second.find(unThreadID);
	if (Thread == ProcessThreads->second.end()) {
		return nullptr;
	}

	if (ppStartAddress) {
		*ppStartAddress = Thread->second.second;
	}

	return Thread->second.first;
}

tstring_optional GetDebugModulePath(DWORD unProcessID, LPVOID pImageBase) {
	auto ProcessModules = g_Modules.find(unProcessID);
	if (ProcessModules == g_Modules.end()) {
		return { false, _T("") };
	}

	auto Module = ProcessModules->second.find(pImageBase);
	if (Module == ProcessModules->second.end()) {
		return { false, _T("") };
	}

	if (!Module->second.first) {
		return { false, _T("") };
	}

	return Module->second;
}

tstring_optional GetDebugModuleDirectory(DWORD unProcessID, LPVOID pImageBase) {
	auto ProcessModules = g_Modules.find(unProcessID);
	if (ProcessModules == g_Modules.end()) {
		return { false, _T("") };
	}

	auto Module = ProcessModules->second.find(pImageBase);
	if (Module == ProcessModules->second.end()) {
		return { false, _T("") };
	}

	if (!Module->second.first) {
		return { false, _T("") };
	}

	TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {};
	errno_t err = _tsplitpath_s(Module->second.second.c_str(), szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), nullptr, 0, nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szFileDirectory[MAX_PATH] {};
	if (_stprintf_s(szFileDirectory, _countof(szFileDirectory), _T("%s%s"), szDrive, szDirectory) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	return { true, szFileDirectory };
}

tstring_optional GetDebugModuleName(DWORD unProcessID, LPVOID pImageBase) {
	auto ProcessModules = g_Modules.find(unProcessID);
	if (ProcessModules == g_Modules.end()) {
		return { false, _T("") };
	}

	auto Module = ProcessModules->second.find(pImageBase);
	if (Module == ProcessModules->second.end()) {
		return { false, _T("") };
	}

	if (!Module->second.first) {
		return { false, _T("") };
	}

	TCHAR szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
	errno_t err = _tsplitpath_s(Module->second.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt));
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szFileName[MAX_PATH] {};
	if (_stprintf_s(szFileName, _countof(szFileName), _T("%s%s"), szName, szExt) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	tstring FileName = szFileName;

	std::transform(FileName.begin(), FileName.end(), FileName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	return { true, FileName };
}

LPVOID GetDebugModuleAddress(DWORD unProcessID, tstring ModuleName) {
	auto ProcessModules = g_Modules.find(unProcessID);
	if (ProcessModules == g_Modules.end()) {
		return nullptr;
	}

	tstring LowerModuleName = ModuleName;
	std::transform(LowerModuleName.begin(), LowerModuleName.end(), LowerModuleName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	for (const auto& Module : ProcessModules->second) {
		if (!Module.second.first) {
			continue;
		}

		TCHAR szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
		if (_tsplitpath_s(Module.second.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt)) != 0) {
			continue;
		}

		TCHAR szFileName[MAX_PATH] {};
		if (_stprintf_s(szFileName, _countof(szFileName), _T("%s%s"), szName, szExt) < 0) {
			continue;
		}

		tstring CurrentModuleName = szFileName;
		std::transform(CurrentModuleName.begin(), CurrentModuleName.end(), CurrentModuleName.begin(), [](TCHAR c) {
#ifdef _UNICODE
			return std::towlower(c);
#else
			return std::tolower(static_cast<unsigned char>(c));
#endif
		});

		if (CurrentModuleName == LowerModuleName) {
			return Module.first;
		}
	}

	return nullptr;
}

LPVOID EnsureStub(DWORD unProcessID, HANDLE hProcess) {
	auto it = g_Stub.find(unProcessID);
	if (it != g_Stub.end()) {
		return it->second;
	}

#ifdef _WIN64
	BYTE pStub[] = {
		0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0xC3                          // ret
	};
#else
	BYTE pStub[] = {
		0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0xC2, 0x0C, 0x00              // ret 0x0C   ; DllMain/TLS __stdcall: 3 args = 12 bytes
	};
#endif

	LPVOID pMemory = VirtualAllocEx(hProcess, nullptr, sizeof(pStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMemory) {
		return nullptr;
	}

	SIZE_T unWritten = 0;
	if (!WriteProcessMemory(hProcess, pMemory, pStub, sizeof(pStub), &unWritten) || (unWritten != sizeof(pStub))) {
		VirtualFreeEx(hProcess, pMemory, 0, MEM_RELEASE);
		return nullptr;
	}

	FlushInstructionCache(hProcess, pMemory, sizeof(pStub));

	g_Stub[unProcessID] = pMemory;

	return pMemory;
}

bool EnumTLSCallBacks(HANDLE hProcess, LPVOID lpBaseOfImage, std::vector<LPVOID>& vecCallBacks) {
	IMAGE_DOS_HEADER dh {};
	SIZE_T unReadden = 0;
	if (!ReadProcessMemory(hProcess, lpBaseOfImage, &dh, sizeof(dh), &unReadden) || (unReadden != sizeof(dh))) {
		return false;
	}

	if (dh.e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	IMAGE_NT_HEADERS nths {};
	unReadden = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<BYTE*>(lpBaseOfImage) + dh.e_lfanew, &nths, sizeof(nths), &unReadden) || (unReadden != sizeof(nths))) {
		return false;
	}

	if (nths.Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	const auto& TLSDD = nths.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (!TLSDD.VirtualAddress || !TLSDD.Size) {
		return false;
	}

#ifdef _WIN64
	IMAGE_TLS_DIRECTORY64 TLSDirectory {};
#else
	IMAGE_TLS_DIRECTORY32 TLSDirectory {};
#endif
	unReadden = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<BYTE*>(lpBaseOfImage) + TLSDD.VirtualAddress, &TLSDirectory, sizeof(TLSDirectory), &unReadden) || (unReadden != sizeof(TLSDirectory))) {
		return false;
	}

	if (!TLSDirectory.AddressOfCallBacks) {
		return false;
	}

	LPVOID pArray = reinterpret_cast<LPVOID>(TLSDirectory.AddressOfCallBacks);
	while (true) {
		LPVOID pCallBack = nullptr;
		unReadden = 0;
		if (!ReadProcessMemory(hProcess, pArray, &pCallBack, sizeof(pCallBack), &unReadden) || (unReadden != sizeof(pCallBack))) {
			break;
		}

		if (!pCallBack) {
			break;
		}

		vecCallBacks.push_back(pCallBack);

		pArray = reinterpret_cast<PBYTE>(pArray) + sizeof(LPVOID);
	}

	if (vecCallBacks.empty()) {
		return false;
	}

	return true;
}

bool WriteByte(HANDLE hProcess, LPVOID pAddress, BYTE unValue, BYTE* pPreviousByte = nullptr) {
	BYTE unOldByte = 0;
	SIZE_T unReadden = 0;
	if (!ReadProcessMemory(hProcess, pAddress, &unOldByte, 1, &unReadden) || (unReadden != 1)) {
		return false;
	}

	if (pPreviousByte) {
		*pPreviousByte = unOldByte;
	}

	MEMORY_BASIC_INFORMATION mbi {};
	if (!VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi))) {
		return false;
	}

	DWORD unOldProtection = 0;
	if (!VirtualProtectEx(hProcess, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
		return false;
	}

	SIZE_T unWritten = 0;
	if (!WriteProcessMemory(hProcess, pAddress, &unValue, 1, &unWritten) || (unWritten != 1)) {
		FlushInstructionCache(hProcess, pAddress, 1);

		DWORD unDummy = 0;
		VirtualProtectEx(hProcess, mbi.BaseAddress, 1, unOldProtection, &unDummy);

		return false;
	}
	
	FlushInstructionCache(hProcess, pAddress, 1);

	DWORD unDummy = 0;
	VirtualProtectEx(hProcess, mbi.BaseAddress, 1, unOldProtection, &unDummy);
	return true;
}

bool RestoreByte(HANDLE hProcess, LPVOID pAddress, BYTE unOriginal) {
	MEMORY_BASIC_INFORMATION mbi {};
	if (!VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi))) {
		return false;
	}

	DWORD unOldProtection = 0;
	if (!VirtualProtectEx(hProcess, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
		return false;
	}

	SIZE_T unWritten = 0;
	if (!WriteProcessMemory(hProcess, pAddress, &unOriginal, 1, &unWritten) || (unWritten != 1)) {
		FlushInstructionCache(hProcess, pAddress, 1);

		DWORD unDummy = 0;
		VirtualProtectEx(hProcess, mbi.BaseAddress, 1, unOldProtection, &unDummy);

		return false;
	}

	FlushInstructionCache(hProcess, pAddress, 1);

	DWORD unDummy = 0;
	VirtualProtectEx(hProcess, mbi.BaseAddress, 1, unOldProtection, &unDummy);
	return true;
}

bool SetTLSBreakPointsForModule(DWORD unProcessID, HANDLE hProcess, LPVOID pModuleBase) {
	std::vector<LPVOID> vecCallBacks;
	if (!EnumTLSCallBacks(hProcess, pModuleBase, vecCallBacks)) {
		return true;
	}

	for (auto& pCallBack : vecCallBacks) {
		if (g_TLSOriginalByte[unProcessID].count(pCallBack)) {
			continue;
		}

		BYTE unOriginal = 0;
		if (!WriteByte(hProcess, pCallBack, 0xCC, &unOriginal)) {
			continue;
		}

		g_TLSOriginalByte[unProcessID][pCallBack] = unOriginal;
		g_TLSCallBackOwner[unProcessID][pCallBack] = pModuleBase;
	}

	return true;
}

bool SetDLLEntryBreakPointForModule(DWORD unProcessID, HANDLE hProcess, LPVOID pMmoduleBase) {
	IMAGE_DOS_HEADER dh {};
	SIZE_T unReadden = 0;
	if (!ReadProcessMemory(hProcess, pMmoduleBase, &dh, sizeof(dh), &unReadden) || (unReadden != sizeof(dh))) {
		return false;
	}

	if (dh.e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	IMAGE_NT_HEADERS nths {};
	unReadden = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<BYTE*>(pMmoduleBase) + dh.e_lfanew, &nths, sizeof(nths), &unReadden) || (unReadden != sizeof(nths))) {
		return false;
	}

	if (nths.Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	if (!(nths.FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		return true;
	}

	DWORD unEntryPoint = nths.OptionalHeader.AddressOfEntryPoint;
	if (!unEntryPoint) {
		return true;
	}

	LPVOID pEntryPoint = reinterpret_cast<BYTE*>(pMmoduleBase) + unEntryPoint;

	if (g_DLLEntryPointOriginalByte[unProcessID].count(pEntryPoint)) {
		return true;
	}

	BYTE unOriginal = 0;
	if (!WriteByte(hProcess, pEntryPoint, 0xCC, &unOriginal)) {
		return false;
	}

	g_DLLEntryPointOriginalByte[unProcessID][pEntryPoint] = unOriginal;
	g_DLLEntryPointOwner[unProcessID][pEntryPoint] = pMmoduleBase;

	return true;
}

static void RestoreAllProcessBreakPoints(DWORD unProcessID) {
	LPVOID pStartAddress = nullptr;
	auto Process = GetDebugProcess(unProcessID, &pStartAddress);
	if (!Process) {
		return;
	}

	auto itEntryPointOriginalByte = g_ProcessesOriginalEntryPointByte.find(unProcessID);
	if (itEntryPointOriginalByte != g_ProcessesOriginalEntryPointByte.end()) {
		MEMORY_BASIC_INFORMATION mbi {};
		if (VirtualQueryEx(Process, pStartAddress, &mbi, sizeof(mbi))) {
			DWORD unOldProtection = 0;
			if (VirtualProtectEx(Process, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
				SIZE_T unWritten = 0;
				WriteProcessMemory(Process, pStartAddress, &itEntryPointOriginalByte->second, 1, &unWritten);
				FlushInstructionCache(Process, pStartAddress, 1);
				DWORD unDummy = 0;
				VirtualProtectEx(Process, mbi.BaseAddress, 1, unOldProtection, &unDummy);
			}
		}

		g_ProcessesOriginalEntryPointByte.erase(itEntryPointOriginalByte);
	}

	auto itTLSOriginalByte = g_TLSOriginalByte.find(unProcessID);
	if (itTLSOriginalByte != g_TLSOriginalByte.end()) {
		for (const auto& rec : itTLSOriginalByte->second) {
			if (!rec.first) {
				continue;
			}

			MEMORY_BASIC_INFORMATION mbi {};
			if (VirtualQueryEx(Process, rec.first, &mbi, sizeof(mbi))) {
				DWORD unOldProtection = 0;
				if (VirtualProtectEx(Process, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
					SIZE_T unWritten = 0;
					WriteProcessMemory(Process, rec.first, &rec.second, 1, &unWritten);
					FlushInstructionCache(Process, rec.first, 1);
					DWORD unDummy = 0;
					VirtualProtectEx(Process, mbi.BaseAddress, 1, unOldProtection, &unDummy);
				}
			}
		}

		g_TLSOriginalByte.erase(itTLSOriginalByte);
		g_TLSCallBackOwner.erase(unProcessID);
	}

	g_TLSReArm.erase(unProcessID);

	if (g_Stub.count(unProcessID)) {
		VirtualFreeEx(Process, g_Stub[unProcessID], 0, MEM_RELEASE);
		g_Stub.erase(unProcessID);
	}

	auto itDLLOriginalByte = g_DLLEntryPointOriginalByte.find(unProcessID);
	if (itDLLOriginalByte != g_DLLEntryPointOriginalByte.end()) {
		for (const auto& rec : itDLLOriginalByte->second) {
			if (!rec.first) {
				continue;
			}

			MEMORY_BASIC_INFORMATION mbi {};
			if (VirtualQueryEx(Process, rec.first, &mbi, sizeof(mbi))) {
				DWORD unOldProtection = 0;
				if (VirtualProtectEx(Process, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
					SIZE_T unWritten = 0;
					WriteProcessMemory(Process, rec.first, &rec.second, 1, &unWritten);
					FlushInstructionCache(Process, rec.first, 1);
					DWORD unDummy = 0;
					VirtualProtectEx(Process, mbi.BaseAddress, 1, unOldProtection, &unDummy);
				}
			}
		}

		g_DLLEntryPointOriginalByte.erase(itDLLOriginalByte);
		g_DLLEntryPointOwner.erase(unProcessID);
	}

	g_DLLEntryPointReArm.erase(unProcessID);
}

tstring_optional GetProcessOreansCrackLibraryName(HANDLE hProcess) {
#ifdef _WIN64
	return { true, _T("oc.dll") };
#else
	return { true, _T("oc32.dll") };
#endif
}

bool GetRemoteModuleHandle(HANDLE hProcess, const TCHAR* szModuleName, HMODULE* phModule) {
	if (!hProcess || (hProcess == INVALID_HANDLE_VALUE) || !szModuleName) {
		return false;
	}

	const size_t unModuleNameLength = _tcsclen(szModuleName);

	HMODULE hModules[1024] {};
	DWORD cbNeeded = 0;

	if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
		for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
			TCHAR szName[MAX_PATH] {};
			if (GetModuleFileNameEx(hProcess, hModules[i], szName, MAX_PATH)) {
				if (_tcsicmp(szName + _tcsclen(szName) - unModuleNameLength, szModuleName) == 0) {

					if (phModule) {
						*phModule = hModules[i];
					}

					return true;
				}
			}
		}
	}

	return false;
}

template<typename T>
bool GetRemoteProcAddress(HANDLE hProcess, const TCHAR* szModuleName, const char* szProcName, T* pFunc) {
	if (!hProcess || (hProcess == INVALID_HANDLE_VALUE) || !szModuleName || !szProcName) {
		return false;
	}

	HMODULE hModule = GetModuleHandle(szModuleName);
	if (!hModule) {
		return false;
	}

	HMODULE hRemoteModule = nullptr;
	if (!GetRemoteModuleHandle(hProcess, szModuleName, &hRemoteModule)) {
		return false;
	}

	T pLocalProcAddress = reinterpret_cast<T>(GetProcAddress(hModule, szProcName));
	if (!pLocalProcAddress) {
		return false;
	}

	const uintptr_t unOffset = reinterpret_cast<uintptr_t>(pLocalProcAddress) - reinterpret_cast<uintptr_t>(hModule);

	if (pFunc) {
		*pFunc = reinterpret_cast<T>(reinterpret_cast<uintptr_t>(hRemoteModule) + unOffset);
	}

	return true;
}

bool FillLoaderData(HANDLE hProcess, PLOADER_DATA pLoaderData) {
	if (!hProcess || (hProcess == INVALID_HANDLE_VALUE) || !pLoaderData) {
		return false;
	}

	if (!GetRemoteModuleHandle(hProcess, _T("ntdll.dll"), &pLoaderData->m_hNTDLL)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlDosPathNameToNtPathName_U", &pLoaderData->m_pRtlDosPathNameToNtPathName_U)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlFreeUnicodeString", &pLoaderData->m_pRtlFreeUnicodeString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlFreeAnsiString", &pLoaderData->m_pRtlFreeAnsiString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlInitUnicodeString", &pLoaderData->m_pRtlInitUnicodeString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlInitAnsiString", &pLoaderData->m_pRtlInitAnsiString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlUnicodeStringToAnsiString", &pLoaderData->m_pRtlUnicodeStringToAnsiString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlAnsiStringToUnicodeString", &pLoaderData->m_pRtlAnsiStringToUnicodeString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlAllocateHeap", &pLoaderData->m_pRtlAllocateHeap)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlFreeHeap", &pLoaderData->m_pRtlFreeHeap)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtAllocateVirtualMemory", &pLoaderData->m_pNtAllocateVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtFreeVirtualMemory", &pLoaderData->m_pNtFreeVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtReadVirtualMemory", &pLoaderData->m_pNtReadVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtWriteVirtualMemory", &pLoaderData->m_pNtWriteVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtProtectVirtualMemory", &pLoaderData->m_pNtProtectVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtFlushInstructionCache", &pLoaderData->m_pNtFlushInstructionCache)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "LdrLoadDll", &pLoaderData->m_pLdrLoadDll)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "LdrGetDllHandle", &pLoaderData->m_pLdrGetDllHandle)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "LdrGetProcedureAddress", &pLoaderData->m_pLdrGetProcedureAddress)) {
		return false;
	}

	if (!g_pTerminalServer->GetSessionName(pLoaderData->m_szTerminalSessionName)) {
		return false;
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool MapImage(PLOADER_DATA pLD) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);

	PVOID pDesiredBase = reinterpret_cast<PVOID>(pNTHs->OptionalHeader.ImageBase);
	SIZE_T unSizeOfImage = pNTHs->OptionalHeader.SizeOfImage;

	if (!NT_SUCCESS(pLD->m_pNtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, 0, &unSizeOfImage, MEM_RESERVE, PAGE_READWRITE))) {
		pDesiredBase = nullptr;
		if (!NT_SUCCESS(pLD->m_pNtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, 0, &unSizeOfImage, MEM_RESERVE, PAGE_READWRITE))) {
			return false;
		}
	}

	PVOID pHeaders = pDesiredBase;
	SIZE_T unSizeOfHeaders = pNTHs->OptionalHeader.SizeOfHeaders;
	if (!NT_SUCCESS(pLD->m_pNtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pHeaders, 0, &unSizeOfHeaders, MEM_COMMIT, PAGE_READWRITE))) {
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, &unSizeOfImage, MEM_RELEASE);
		return false;
	}

	if (!NT_SUCCESS(pLD->m_pNtWriteVirtualMemory(reinterpret_cast<HANDLE>(-1), pDesiredBase, pDH, pNTHs->OptionalHeader.SizeOfHeaders, nullptr))) {
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, &unSizeOfImage, MEM_RELEASE);
		return false;
	}

	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNTHs);
	for (WORD i = 0; i < pNTHs->FileHeader.NumberOfSections; ++i) {
		if (pFirstSection[i].SizeOfRawData == 0) {
			continue;
		}

		PVOID pSectionAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(pDesiredBase) + pFirstSection[i].VirtualAddress);
		SIZE_T unSectionSize = pFirstSection[i].Misc.VirtualSize;
		PVOID pSectionData = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(pDH) + pFirstSection[i].PointerToRawData);

		if (!NT_SUCCESS(pLD->m_pNtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pSectionAddress, 0, &unSectionSize, MEM_COMMIT, PAGE_READWRITE))) {
			pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, &unSizeOfImage, MEM_RELEASE);
			return false;
		}

		if (!NT_SUCCESS(pLD->m_pNtWriteVirtualMemory(reinterpret_cast<HANDLE>(-1), pSectionAddress, pSectionData, pFirstSection[i].SizeOfRawData, nullptr))) {
			pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, &unSizeOfImage, MEM_RELEASE);
			return false;
		}
	}

	SIZE_T unSize = 0;
	pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
	pLD->m_pImageAddress = pDesiredBase;

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool FixRelocations(PLOADER_DATA pLD) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);

	if (pNTHs->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
		return true;
	}

	const DWORD_PTR unDelta = reinterpret_cast<DWORD_PTR>(pDH) - pNTHs->OptionalHeader.ImageBase;
	if (!unDelta) {
		return true;
	}

	PIMAGE_DATA_DIRECTORY RelocationDirectory = &pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!RelocationDirectory->VirtualAddress || !RelocationDirectory->Size) {
		return true;
	}

	const WORD unMachine = pNTHs->FileHeader.Machine;

	PIMAGE_BASE_RELOCATION Relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<char*>(pDH) + RelocationDirectory->VirtualAddress);
	while (Relocation->VirtualAddress && Relocation->SizeOfBlock) {
		DWORD_PTR unRelocationBase = reinterpret_cast<DWORD_PTR>(pDH) + Relocation->VirtualAddress;
		DWORD unCount = (Relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD unEntries = reinterpret_cast<PWORD>(Relocation + 1);

		for (DWORD i = 0; i < unCount; ++i) {
			WORD unEntry = unEntries[i];
			BYTE unType = unEntry >> 12;
			WORD unOffset = unEntry & 0xFFF;

			DWORD_PTR unPatchAddress = unRelocationBase + unOffset;

			switch (unType) {
				case IMAGE_REL_BASED_ABSOLUTE:
					break;

				case IMAGE_REL_BASED_HIGH:
					*reinterpret_cast<WORD*>(unPatchAddress) += HIWORD(static_cast<DWORD>(unDelta));
					break;

				case IMAGE_REL_BASED_LOW:
					*reinterpret_cast<WORD*>(unPatchAddress) += LOWORD(static_cast<DWORD>(unDelta));
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					*reinterpret_cast<DWORD*>(unPatchAddress) += static_cast<DWORD>(unDelta);
					break;

				case IMAGE_REL_BASED_HIGHADJ: {
					if (i + 1 >= unCount) {
						return false;
					}

					WORD unNextEntry = unEntries[++i];
					if ((unNextEntry >> 12) != IMAGE_REL_BASED_LOW) {
						return false;
					}

					DWORD unHighAdj = *reinterpret_cast<WORD*>(unPatchAddress) << 16;
					unHighAdj += static_cast<DWORD>(unDelta);
					unHighAdj += static_cast<SHORT>(unNextEntry & 0xFFF);

					*reinterpret_cast<WORD*>(unPatchAddress) = HIWORD(unHighAdj);
					break;
				}

				case IMAGE_REL_BASED_DIR64:
					*reinterpret_cast<ULONGLONG*>(unPatchAddress) += unDelta;
					break;

				case IMAGE_REL_BASED_MACHINE_SPECIFIC_5:
					switch (unMachine) {
						case IMAGE_FILE_MACHINE_ARMNT:
						case IMAGE_FILE_MACHINE_THUMB:
							*reinterpret_cast<DWORD*>(unPatchAddress) += static_cast<DWORD>(unDelta);
							break;

						case IMAGE_FILE_MACHINE_MIPS16:
						case IMAGE_FILE_MACHINE_MIPSFPU:
						case IMAGE_FILE_MACHINE_MIPSFPU16: {
							DWORD unIns = *reinterpret_cast<DWORD*>(unPatchAddress);
							unIns = (unIns & ~0x03FFFFFF) | ((((unIns & 0x03FFFFFF) << 2) + static_cast<DWORD>(unDelta)) >> 2);
							*reinterpret_cast<DWORD*>(unPatchAddress) = unIns;
							break;
						}

						default:
							return false;
					}
					break;

				case IMAGE_REL_BASED_THUMB_MOV32:
					if (unMachine == IMAGE_FILE_MACHINE_ARMNT) {
						*reinterpret_cast<DWORD*>(unPatchAddress) += static_cast<DWORD>(unDelta);
					} else {
						return false;
					}
					break;

				case IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
					switch (unMachine) {
						case IMAGE_FILE_MACHINE_IA64:
							*reinterpret_cast<ULONGLONG*>(unPatchAddress) += unDelta;
							break;

						case IMAGE_FILE_MACHINE_MIPS16:
						case IMAGE_FILE_MACHINE_MIPSFPU:
						case IMAGE_FILE_MACHINE_MIPSFPU16: {
							WORD unIns = *reinterpret_cast<WORD*>(unPatchAddress);
							unIns = (unIns & ~0xFFFF) | ((((unIns & 0xFFFF) << 2) + static_cast<WORD>(unDelta)) >> 2);
							*reinterpret_cast<WORD*>(unPatchAddress) = unIns;
							break;
						}

						default:
							return false;
					}
					break;

				default:
					return false;
			}
		}

		Relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<char*>(Relocation) + Relocation->SizeOfBlock);
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool ResolveImports(PLOADER_DATA pLD) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);

	PIMAGE_DATA_DIRECTORY ImportDirectory = &pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!ImportDirectory->VirtualAddress) {
		return true;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<char*>(pDH) + ImportDirectory->VirtualAddress);
	while (pImportDescriptor->Name) {
		const char* szModuleName = reinterpret_cast<const char*>(reinterpret_cast<char*>(pDH) + pImportDescriptor->Name);

		ANSI_STRING as {};
		UNICODE_STRING NTModule {};
		pLD->m_pRtlInitAnsiString(&as, szModuleName);
		if (!NT_SUCCESS(pLD->m_pRtlAnsiStringToUnicodeString(&NTModule, &as, TRUE))) {
			return false;
		}

		HMODULE hModule = nullptr;
		if (!NT_SUCCESS(pLD->m_pLdrLoadDll(NULL, 0, &NTModule, reinterpret_cast<PHANDLE>(&hModule)))) {
		//if (!NT_SUCCESS(pLD->m_pLdrGetDllHandle(NULL, 0, &NTModule, reinterpret_cast<PHANDLE>(&hModule)))) {
			pLD->m_pRtlFreeUnicodeString(&NTModule);
			return false;
		}

		pLD->m_pRtlFreeUnicodeString(&NTModule);

		PIMAGE_THUNK_DATA pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<char*>(pDH) + pImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<char*>(pDH) + pImportDescriptor->FirstThunk);
		while (pThunk->u1.AddressOfData) {
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				ULONG unOrdinal = IMAGE_ORDINAL(pThunk->u1.Ordinal);
				PVOID pProcedure = nullptr;
				if (!NT_SUCCESS(pLD->m_pLdrGetProcedureAddress(hModule, NULL, unOrdinal, &pProcedure))) {
					return false;
				}

				pIAT->u1.Function = reinterpret_cast<ULONG_PTR>(pProcedure);
			} else {
				PIMAGE_IMPORT_BY_NAME NameData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<char*>(pDH) + pThunk->u1.AddressOfData);
				ANSI_STRING as;
				pLD->m_pRtlInitAnsiString(&as, NameData->Name);
				PVOID pProcedure = nullptr;
				if (!NT_SUCCESS(pLD->m_pLdrGetProcedureAddress(hModule, &as, 0, &pProcedure))) {
					return false;
				}

				pIAT->u1.Function = reinterpret_cast<ULONG_PTR>(pProcedure);
			}

			++pThunk;
			++pIAT;
		}

		++pImportDescriptor;
	}
	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool ProtectSections(PLOADER_DATA pLD) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);

	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNTHs);
	for (WORD i = 0; i < pNTHs->FileHeader.NumberOfSections; ++i) {
		DWORD unProtect = 0;
		DWORD unCharacteristics = pFirstSection[i].Characteristics;

		if (unCharacteristics & IMAGE_SCN_MEM_EXECUTE) {
			unProtect = (unCharacteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		} else if (unCharacteristics & IMAGE_SCN_MEM_WRITE) {
			unProtect = PAGE_READWRITE;
		} else if (unCharacteristics & IMAGE_SCN_MEM_READ) {
			unProtect = PAGE_READONLY;
		} else {
			unProtect = PAGE_NOACCESS;
		}

		PVOID pAddress = reinterpret_cast<PVOID>(reinterpret_cast<char*>(pDH) + pFirstSection[i].VirtualAddress);
		SIZE_T unVirtualSize = pFirstSection[i].Misc.VirtualSize;
		ULONG unOldProtect = 0;
		if (!NT_SUCCESS(pLD->m_pNtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &pAddress, &unVirtualSize, unProtect, &unOldProtect))) {
			return false;
		}

		if (unCharacteristics & IMAGE_SCN_MEM_EXECUTE) {
			pLD->m_pNtFlushInstructionCache(reinterpret_cast<HANDLE>(-1), nullptr, 0);
		}
	}
	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool ExecuteTLS(PLOADER_DATA pLD, DWORD unReason) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);

	PIMAGE_DATA_DIRECTORY TLSDirectory = &pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (!TLSDirectory->VirtualAddress) {
		return true;
	}

	PIMAGE_TLS_DIRECTORY pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(reinterpret_cast<char*>(pDH) + TLSDirectory->VirtualAddress);
	PIMAGE_TLS_CALLBACK* pCallBacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
	if (pCallBacks) {
		while (*pCallBacks) {
			(*pCallBacks)(pDH, unReason, nullptr);
			++pCallBacks;
		}
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool CallDllMain(PLOADER_DATA pLD, DWORD unReason) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);

	if (!pNTHs->OptionalHeader.AddressOfEntryPoint) {
		return true;
	}

	fnDllMain EntryPoint = reinterpret_cast<fnDllMain>(reinterpret_cast<char*>(pDH) + pNTHs->OptionalHeader.AddressOfEntryPoint);
	EntryPoint(reinterpret_cast<HINSTANCE>(pDH), unReason, pLD);

	return true;
}

DEFINE_DATA_IN_SECTION(".load") LOADER_DATA LoaderData;
DEFINE_CODE_IN_SECTION(".load") DWORD WINAPI Loader(LPVOID lpParameter) { SELF_INCLUDE;
	PLOADER_DATA pLD = reinterpret_cast<PLOADER_DATA>(lpParameter);
	if (!pLD) {
		return EXIT_FAILURE;
	}

	if (!pLD->m_hNTDLL || !pLD->m_pImageAddress) {
		return EXIT_FAILURE;
	}

	if (!MapImage(pLD)) {
		return EXIT_FAILURE;
	}

	if (!FixRelocations(pLD)) {
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

	if (!ResolveImports(pLD)) { // Compile only with /MT, /MTd
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

	if (!ProtectSections(pLD)) {
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

	if (!ExecuteTLS(pLD, DLL_PROCESS_ATTACH)) { // Useless for simple patching dlls
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

	if (!CallDllMain(pLD, DLL_PROCESS_ATTACH)) {
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void OnCreateProcessEvent(DWORD unProcessID) {
#ifdef _DEBUG
	_tprintf_s(_T("PROCESSCREATE: %lu\n"), unProcessID);
#endif // _DEBUG
}

void OnExitProcessEvent(DWORD unProcessID, DWORD unExitCode) {
#ifdef _DEBUG
	_tprintf_s(_T("PROCESSEXIT(%lu): %lu\n"), unProcessID, unExitCode);
#endif // _DEBUG
}

void OnCreateThreadEvent(DWORD unProcessID, DWORD unThreadID) {
#ifdef _DEBUG
	_tprintf_s(_T("THREADCREATE(%lu): %lu\n"), unProcessID, unThreadID);
#endif // _DEBUG
}

void OnExitThreadEvent(DWORD unProcessID, DWORD unThreadID, DWORD unExitCode) {
#ifdef _DEBUG
	_tprintf_s(_T("THREADEXIT(%lu, %lu): %lu\n"), unProcessID, unThreadID, unExitCode);
#endif // _DEBUG

	if ((g_ProcessInjectionThreads.find(unProcessID) != g_ProcessInjectionThreads.end()) && (g_ProcessSuspendedMainThreads.find(unProcessID) != g_ProcessSuspendedMainThreads.end())) {
		if (GetThreadId(g_ProcessInjectionThreads[unProcessID]) == unThreadID) {
			if (!unExitCode) {
#ifdef _DEBUG
				_tprintf_s(_T("INJECTED!\n"));
#endif

				RestoreAllProcessBreakPoints(unProcessID);

				g_bGlobalDisableThreadLibraryCalls = false;
				g_bContinueDebugging = false;
			}

			ResumeThread(g_ProcessSuspendedMainThreads[unProcessID]);
			CloseHandle(g_ProcessInjectionThreads[unProcessID]);
			g_ProcessSuspendedMainThreads.erase(unProcessID);
			g_ProcessInjectionThreads.erase(unProcessID);
			return;
		}
	}
}

void OnLoadModuleEvent(DWORD unProcessID, DWORD unThreadID, LPVOID pImageBase) {
#ifdef _DEBUG
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	auto ModuleFileName = GetDebugModuleName(unProcessID, pImageBase);
	if (!ModuleFileName.first) {
		return;
	}

#ifdef _WIN64
	_tprintf_s(_T("MODULELOAD(0x%016llX): %s\n"), reinterpret_cast<size_t>(pImageBase), ModuleFileName.second.c_str());
#else
	_tprintf_s(_T("MODULELOAD(0x%08X): %s\n"), reinterpret_cast<size_t>(pImageBase), ModuleFileName.second.c_str());
#endif
#endif // _DEBUG
}

void OnUnloadModuleEvent(DWORD unProcessID, DWORD unThreadID, LPVOID pImageBase) {
#ifdef _DEBUG
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	auto ModuleFileName = GetDebugModuleName(unProcessID, pImageBase);
	if (!ModuleFileName.first) {
		return;
	}

#ifdef _WIN64
	_tprintf_s(_T("MODULEUNLOAD(0x%016llX): %s\n"), reinterpret_cast<size_t>(pImageBase), ModuleFileName.second.c_str());
#else
	_tprintf_s(_T("MODULEUNLOAD(0x%08X): %s\n"), reinterpret_cast<size_t>(pImageBase), ModuleFileName.second.c_str());
#endif
#endif // _DEBUG
}

void OnDebugStringEvent(DWORD unProcessID, DWORD unThreadID, const OUTPUT_DEBUG_STRING_INFO Info) {
#ifdef _DEBUG
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	if ((Info.lpDebugStringData == 0) || (Info.nDebugStringLength == 0)) {
		return;
	}

	const SIZE_T cMaxChars = 8192; // 8 KiB

	if (Info.fUnicode) {
		static WCHAR szBuffer[cMaxChars + 1] {};
		memset(szBuffer, 0, sizeof(szBuffer));

		SIZE_T unCharsToRead = Info.nDebugStringLength;

		if (unCharsToRead > cMaxChars) {
			unCharsToRead = cMaxChars;
		}

		SIZE_T unBytesRead = 0;

		if (!ReadProcessMemory(Process, Info.lpDebugStringData, szBuffer, unCharsToRead * sizeof(WCHAR), &unBytesRead) || (unBytesRead == 0)) {
			return;
		}

		wprintf(L"ONDEBUGSTRING(%lu, %lu): \"%s\"\n", unProcessID, unThreadID, szBuffer);
	} else {
		static CHAR Buffer[cMaxChars + 1] {};
		memset(Buffer, 0, sizeof(Buffer));

		SIZE_T unCharsToRead = Info.nDebugStringLength;

		if (unCharsToRead > cMaxChars) {
			unCharsToRead = cMaxChars;
		}

		SIZE_T unBytesRead = 0;

		if (!ReadProcessMemory(Process, Info.lpDebugStringData, Buffer, unCharsToRead * sizeof(CHAR), &unBytesRead) || (unBytesRead == 0)) {
			return;
		}

		printf("ONDEBUGSTRING(%lu, %lu): \"%s\"\n", unProcessID, unThreadID, Buffer);
	}
#endif // _DEBUG
}

void OnRIPEvent(DWORD unProcessID, DWORD unThreadID, DWORD unError, DWORD unType) {
#ifdef _DEBUG
	_tprintf_s(_T("RIPEVENT(%lu, %lu): 0x%08X, 0x%08X\n"), unProcessID, unThreadID, unError, unType);
#endif // !_DEBUG
}

void OnExceptionEvent(DWORD unProcessID, DWORD unThreadID, const EXCEPTION_DEBUG_INFO& Info, bool bInitialBreakPoint, bool* pHandledException) {
#ifdef _DEBUG
	_tprintf_s(_T("ONEXCEPTION (%s)\n"), Info.dwFirstChance ? _T("First-Chance") : _T("Second-Chance"));
	_tprintf_s(_T("  CODE:       0x%08X\n"), Info.ExceptionRecord.ExceptionCode);
#ifdef _WIN64
	_tprintf_s(_T("  ADDRESS:    0x%016llX\n"), reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress));
#else
	_tprintf_s(_T("  ADDRESS:    0x%08X\n"), reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress));
#endif
	_tprintf_s(_T("  THREADID:   %lu\n"), unThreadID);
	_tprintf_s(_T("  FLAGS:      0x%08X\n"), Info.ExceptionRecord.ExceptionFlags);
	_tprintf_s(_T("  PARAMETERS: %lu\n"), Info.ExceptionRecord.NumberParameters);

	DWORD NumberParameters = Info.ExceptionRecord.NumberParameters;
	if (NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS) {
		NumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
	}

	for (DWORD i = 0; i < NumberParameters; ++i) {
#ifdef _WIN64
		_tprintf_s(_T("    PARAM[%lu]: 0x%016llX\n"), i, Info.ExceptionRecord.ExceptionInformation[i]);
#else
		_tprintf_s(_T("    PARAM[%lu]: 0x%08X\n"), i, Info.ExceptionRecord.ExceptionInformation[i]);
#endif
	}
#endif // _DEBUG
}

bool OnTLSCallBackEvent(DWORD unProcessID, DWORD unThreadID, LPVOID pCallback, LPVOID pModuleBase, DWORD unReason) {
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return false;
	}

	auto Thread = GetDebugThread(unProcessID, unThreadID);
	if (!Thread) {
		return false;
	}

	bool bRedirected = false;

	if (g_bGlobalDisableThreadLibraryCalls && ((unReason == 2) || (unReason == 3))) {
		LPVOID pStub = EnsureStub(unProcessID, Process);
		if (pStub) {
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (GetThreadContext(Thread, &ctx)) {
#ifdef _WIN64
				ctx.Rip = reinterpret_cast<DWORD64>(pStub);
#else
				ctx.Eip = reinterpret_cast<DWORD64>(pStub);
#endif

				if (SetThreadContext(Thread, &ctx)) {
					bRedirected = true;
				}
			}
		}
	}

#ifdef _DEBUG
	auto ModuleName = GetDebugModuleName(unProcessID, pModuleBase);
#ifdef _WIN64
	_tprintf_s(_T("ONTLSCALLBACK(%lu, %lu): CALLBACK: 0x%016llX, REASON: %lu, MODULE: %s%s\n"), unProcessID, unThreadID, reinterpret_cast<size_t>(pCallback), unReason, ModuleName.first ? ModuleName.second.c_str() : _T("<unknown>"), bRedirected ? _T(" --> STUB") : _T(""));
#else
	_tprintf_s(_T("ONTLSCALLBACK(%lu, %lu): CALLBACK: 0x%08X, REASON: %lu, MODULE: %s%s\n"), unProcessID, unThreadID, reinterpret_cast<size_t>(pCallback), unReason, ModuleName.first ? ModuleName.second.c_str() : _T("<unknown>"), bRedirected ? _T(" --> STUB") : _T(""));
#endif
#endif

	return bRedirected;
}

bool OnDLLEntryPoint(DWORD unProcessID, DWORD unThreadID, LPVOID pEntryPoint, LPVOID pModuleBase, DWORD unReason) {
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return false;
	}

	auto Thread = GetDebugThread(unProcessID, unThreadID);
	if (!Thread) {
		return false;
	}

	bool bRedirected = false;

	if (g_bGlobalDisableThreadLibraryCalls && ((unReason == 2) || (unReason == 3))) {
		LPVOID pStub = EnsureStub(unProcessID, Process);
		if (pStub) {
			CONTEXT ctx{};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (GetThreadContext(Thread, &ctx)) {
#ifdef _WIN64
				ctx.Rip = reinterpret_cast<DWORD64>(pStub);
#else
				ctx.Eip = reinterpret_cast<DWORD64>(pStub);
#endif

				if (SetThreadContext(Thread, &ctx)) {
					bRedirected = true;
				}
			}
		}
	}

#ifdef _DEBUG
	auto ModuleName = GetDebugModuleName(unProcessID, pModuleBase);
#ifdef _WIN64
	_tprintf_s(_T("ONDLLENTRYPOINT(%lu, %lu): ENTRYPOINT: 0x%016llX REASON: %lu MODULE: %s%s\n"), unProcessID, unThreadID, reinterpret_cast<size_t>(pEntryPoint), unReason, ModuleName.first ? ModuleName.second.c_str() : _T("<unknown>"), bRedirected ? _T(" --> STUB") : _T(""));
#else
	_tprintf_s(_T("ONDLLENTRYPOINT(%lu, %lu): ENTRYPOINT: 0x%08X REASON: %lu MODULE: %s%s\n"), unProcessID, unThreadID, reinterpret_cast<size_t>(pEntryPoint), unReason, ModuleName.first ? ModuleName.second.c_str() : _T("<unknown>"), bRedirected ? _T(" --> STUB") : _T(""));
#endif
#endif

	return bRedirected;
}

void OnEntryPoint(DWORD unProcessID, DWORD unThreadID) {
#ifdef _DEBUG
	_tprintf_s(_T("ONENTRYPOINT(%lu): %lu\n"), unProcessID, unThreadID);
#endif // !_DEBUG

	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	auto Thread = GetDebugThread(unProcessID, unThreadID);
	if (!Thread) {
		return;
	}

	auto ProcessDirectory = GetProcessDirectory(Process);
	if (!ProcessDirectory.first) {
		return;
	}

	auto ProcessInjectLibraryName = GetProcessOreansCrackLibraryName(Process);
	if (!ProcessInjectLibraryName.first) {
		return;
	}

	auto ProcessOreansCrackLibraryPath = ProcessDirectory.second + ProcessInjectLibraryName.second;

	DWORD dwAttrib = GetFileAttributes(ProcessOreansCrackLibraryPath.c_str());
	if (!((dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))) { // File not exist
		RestoreAllProcessBreakPoints(unProcessID);
		g_bContinueDebugging = false;
		return;
	}

	HANDLE hFile = CreateFile(ProcessOreansCrackLibraryPath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
		return;
	}

	HANDLE hMapFile = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapFile || (hMapFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hFile);
		return;
	}

	void* pMap = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS pTempNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	if (pTempNTHs->Signature != IMAGE_NT_SIGNATURE) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

#ifdef _WIN64
	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		_tprintf_s(_T("ERROR: This library cannot be loaded in 64 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}
#else
	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		_tprintf_s(_T("ERROR: This library cannot be loaded in 32 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}
#endif

	LARGE_INTEGER FileSize {};
	if (!GetFileSizeEx(hFile, &FileSize)) {
		_tprintf_s(_T("ERROR: GetFileSizeEx failed (Error = 0x%08X)\n"), GetLastError());
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	if (FileSize.QuadPart <= 0) {
		_tprintf_s(_T("ERROR: Invalid file size\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	const size_t unFileSize = static_cast<size_t>(FileSize.QuadPart);

	LPVOID pImageAddress = VirtualAllocEx(Process, nullptr, unFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pImageAddress) {
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	SIZE_T unBytesWritten = 0;
	if (!WriteProcessMemory(Process, pImageAddress, pMap, unFileSize, &unBytesWritten)) {
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	UnmapViewOfFile(pMap);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	void* pSection = nullptr;
	size_t unSectionSize = 0;
	if (!Detours::Scan::FindSection(GetModuleHandle(nullptr), { '.', 'l', 'o', 'a', 'd', 0, 0, 0 }, &pSection, &unSectionSize)) {
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	LoaderData.m_pImageAddress = pImageAddress;

	if (!FillLoaderData(Process, &LoaderData)) {
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	const size_t unLoaderDataOffset = reinterpret_cast<size_t>(&LoaderData) - reinterpret_cast<size_t>(pSection);
	const size_t unLoaderOffset = reinterpret_cast<size_t>(&Loader) - reinterpret_cast<size_t>(pSection);

	void* pRemoteSection = VirtualAllocEx(Process, nullptr, unSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteSection) {
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	SIZE_T unWritten = 0;
	if (!WriteProcessMemory(Process, pRemoteSection, pSection, unSectionSize, &unWritten) || (unWritten != unSectionSize)) {
		VirtualFreeEx(Process, pRemoteSection, 0, MEM_RELEASE);
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	NtFlushInstructionCache(Process, nullptr, 0);

	void* pRemoteLoaderData = reinterpret_cast<void*>(reinterpret_cast<size_t>(pRemoteSection) + unLoaderDataOffset);
	void* pRemoteLoader = reinterpret_cast<void*>(reinterpret_cast<size_t>(pRemoteSection) + unLoaderOffset);

	if (SuspendThread(Thread) != 0) {
		VirtualFreeEx(Process, pRemoteSection, 0, MEM_RELEASE);
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	g_ProcessSuspendedMainThreads[unProcessID] = Thread;

	HANDLE hThread = CreateRemoteThread(Process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pRemoteLoader), pRemoteLoaderData, 0, nullptr);
	if (hThread && (hThread != INVALID_HANDLE_VALUE)) {
		g_bGlobalDisableThreadLibraryCalls = true;
		g_ProcessInjectionThreads[unProcessID] = hThread;
	}
}

void OnTimeout() {
#ifdef _DEBUG
	_tprintf_s(_T("ONTIMEOUT!\n"));
#endif // _DEBUG
}

bool DebugProcess(DWORD unTimeout, bool* pbContinue, bool* pbStopped) {
	if (!pbContinue) {
		return false;
	}

	DEBUG_EVENT DebugEvent {};
	bool bSeenInitialBreakPoint = false;

	const BYTE unBreakPointByte = 0xCC;
	BYTE unOriginalEntryByte = 0;

	while (*pbContinue) {
		if (WaitForDebugEvent(&DebugEvent, unTimeout)) {
			DWORD ContinueStatus = DBG_CONTINUE;

			switch (DebugEvent.dwDebugEventCode) {
				case CREATE_PROCESS_DEBUG_EVENT:

					if (!EnsureStub(DebugEvent.dwProcessId, DebugEvent.u.CreateProcessInfo.hProcess)) {
						*pbContinue = false;
						break;
					}

					// Setting breakpoint for TLS

					if (!SetTLSBreakPointsForModule(DebugEvent.dwProcessId, DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpBaseOfImage)) {
						*pbContinue = false;
						break;
					}

					// Setting breakpoint for entrypoint

					if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, &unOriginalEntryByte, 1, nullptr)) {
						*pbContinue = false;
						break;
					}

					if (!WriteProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, &unBreakPointByte, 1, nullptr)) {
						*pbContinue = false;
						break;
					}

					FlushInstructionCache(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, 1);

					// Other stuff

					g_Processes[DebugEvent.dwProcessId] = { DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress };
					g_ProcessesOriginalEntryPointByte[DebugEvent.dwProcessId] = unOriginalEntryByte;
					g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = { DebugEvent.u.CreateProcessInfo.hThread, DebugEvent.u.CreateProcessInfo.lpStartAddress };
					g_Modules[DebugEvent.dwProcessId][DebugEvent.u.CreateProcessInfo.lpBaseOfImage] = GetFilePath(DebugEvent.u.CreateProcessInfo.hFile);

					OnCreateProcessEvent(DebugEvent.dwProcessId);
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.CreateProcessInfo.lpBaseOfImage);

					SafeCloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
					break;

				case EXIT_PROCESS_DEBUG_EVENT:
					OnExitProcessEvent(DebugEvent.dwProcessId, DebugEvent.u.ExitProcess.dwExitCode);

					g_ProcessSuspendedMainThreads.erase(DebugEvent.dwProcessId);
					g_ProcessInjectionThreads.erase(DebugEvent.dwProcessId);

					g_Modules.erase(DebugEvent.dwProcessId);
					g_Threads.erase(DebugEvent.dwProcessId);
					g_ProcessesOriginalEntryPointByte.erase(DebugEvent.dwProcessId);
					g_Processes.erase(DebugEvent.dwProcessId);
					g_DLLEntryPointOwner.erase(DebugEvent.dwProcessId);
					g_DLLEntryPointOriginalByte.erase(DebugEvent.dwProcessId);
					g_DLLEntryPointReArm.erase(DebugEvent.dwProcessId);
					g_TLSCallBackOwner.erase(DebugEvent.dwProcessId);
					g_TLSOriginalByte.erase(DebugEvent.dwProcessId);
					g_TLSReArm.erase(DebugEvent.dwProcessId);
					g_Stub.erase(DebugEvent.dwProcessId);

					if (g_Processes.empty()) {
						*pbContinue = false;
						*pbStopped = true;
					}

					break;

				case CREATE_THREAD_DEBUG_EVENT:
					g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = { DebugEvent.u.CreateThread.hThread, DebugEvent.u.CreateThread.lpStartAddress };
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					break;

				case EXIT_THREAD_DEBUG_EVENT:
					OnExitThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.ExitThread.dwExitCode);

					g_Threads[DebugEvent.dwProcessId].erase(DebugEvent.dwThreadId);
					if (g_Threads[DebugEvent.dwProcessId].empty()) {
						g_Threads.erase(DebugEvent.dwProcessId);
					}

					g_TLSReArm[DebugEvent.dwProcessId].erase(DebugEvent.dwThreadId);
					if (g_TLSReArm[DebugEvent.dwProcessId].empty()) {
						g_TLSReArm.erase(DebugEvent.dwProcessId);
					}

					break;

				case LOAD_DLL_DEBUG_EVENT:
					if (!SetTLSBreakPointsForModule(DebugEvent.dwProcessId, g_Processes[DebugEvent.dwProcessId].first, DebugEvent.u.LoadDll.lpBaseOfDll)) {
						*pbContinue = false;
						break;
					}

					if (!SetDLLEntryBreakPointForModule(DebugEvent.dwProcessId, g_Processes[DebugEvent.dwProcessId].first, DebugEvent.u.LoadDll.lpBaseOfDll)) {
						*pbContinue = false;
						break;
					}

					g_Modules[DebugEvent.dwProcessId][DebugEvent.u.LoadDll.lpBaseOfDll] = GetFilePath(DebugEvent.u.LoadDll.hFile);
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.LoadDll.lpBaseOfDll);
					SafeCloseHandle(DebugEvent.u.LoadDll.hFile);
					break;

				case UNLOAD_DLL_DEBUG_EVENT:
					OnUnloadModuleEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.UnloadDll.lpBaseOfDll);

					g_Modules[DebugEvent.dwProcessId].erase(DebugEvent.u.UnloadDll.lpBaseOfDll);
					if (g_Modules[DebugEvent.dwProcessId].empty()) {
						g_Modules.erase(DebugEvent.dwProcessId);
					}

					break;

				case OUTPUT_DEBUG_STRING_EVENT:
					OnDebugStringEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.DebugString);
					break;

				case RIP_EVENT:
					OnRIPEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.RipInfo.dwError, DebugEvent.u.RipInfo.dwType);
					break;

				case EXCEPTION_DEBUG_EVENT:
					bool bHandledException = false;

					if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
						auto itTLSReArm = g_TLSReArm.find(DebugEvent.dwProcessId);
						if (itTLSReArm != g_TLSReArm.end()) {
							auto& TLSThreadsRecord = itTLSReArm->second;
							auto itTLSReArmThread = TLSThreadsRecord.find(DebugEvent.dwThreadId);
							if (itTLSReArmThread != TLSThreadsRecord.end()) {
								auto Process = g_Processes[DebugEvent.dwProcessId].first;
								if (!WriteByte(Process, itTLSReArmThread->second, 0xCC)) {
									*pbContinue = false;
									break;
								}

								FlushInstructionCache(Process, itTLSReArmThread->second, 1);

								TLSThreadsRecord.erase(itTLSReArmThread);
								if (TLSThreadsRecord.empty()) {
									g_TLSReArm.erase(itTLSReArm);
								}

								ContinueStatus = DBG_EXCEPTION_HANDLED;
								bHandledException = true;
								OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
								break;
							}
						}

						auto itDLLReArm = g_DLLEntryPointReArm.find(DebugEvent.dwProcessId);
						if (itDLLReArm != g_DLLEntryPointReArm.end()) {
							auto& DLLThreadsRecord = itDLLReArm->second;
							auto itDLLReArmThread = DLLThreadsRecord.find(DebugEvent.dwThreadId);
							if (itDLLReArmThread != DLLThreadsRecord.end()) {
								auto Process = g_Processes[DebugEvent.dwProcessId].first;
								if (!WriteByte(Process, itDLLReArmThread->second, 0xCC)) {
									*pbContinue = false;
									break;
								}

								FlushInstructionCache(Process, itDLLReArmThread->second, 1);

								DLLThreadsRecord.erase(itDLLReArmThread);
								if (DLLThreadsRecord.empty()) {
									g_DLLEntryPointReArm.erase(itDLLReArm);
								}

								ContinueStatus = DBG_EXCEPTION_HANDLED;
								bHandledException = true;
								OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
								break;
							}
						}
					}

					auto itTLSOriginalByte = g_TLSOriginalByte.find(DebugEvent.dwProcessId);
					if ((itTLSOriginalByte != g_TLSOriginalByte.end()) && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)) {

						LPVOID pAddress = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
						auto itBP = itTLSOriginalByte->second.find(pAddress);
						if (itBP != itTLSOriginalByte->second.end()) {

							DWORD unReason = 0xFFFFFFFF;
							CONTEXT ctx {};

#ifdef _WIN64
							ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							unReason = static_cast<DWORD>(ctx.Rdx & 0xFFFFFFFFull);
#else
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							// [RET][DllHandle][Reason][Reserved]
							SIZE_T unReadden = 0;
							if (!ReadProcessMemory(g_Processes[DebugEvent.dwProcessId].first, reinterpret_cast<LPCVOID>(ctx.Esp + 8), &unReason, sizeof(unReason), &unReadden) || (unReadden != sizeof(unReason))) {
								*pbContinue = false;
								break;
							}
#endif

							LPVOID pOwnerBase = nullptr;
							auto itOwner = g_TLSCallBackOwner[DebugEvent.dwProcessId].find(pAddress);
							if (itOwner != g_TLSCallBackOwner[DebugEvent.dwProcessId].end()) {
								pOwnerBase = itOwner->second;
							}

							if (OnTLSCallBackEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, pAddress, pOwnerBase, unReason)) {
								ContinueStatus = DBG_EXCEPTION_HANDLED;
								bHandledException = true;
								OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
								break;
							}

							if (!WriteByte(g_Processes[DebugEvent.dwProcessId].first, pAddress, itBP->second)) {
								*pbContinue = false;
								break;
							}

							FlushInstructionCache(g_Processes[DebugEvent.dwProcessId].first, pAddress, 1);

#ifdef _WIN64
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							ctx.Rip = reinterpret_cast<DWORD64>(pAddress);
							ctx.EFlags |= 0x100; // Trap Flag

							if (!SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}
#else
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							ctx.Eip = reinterpret_cast<DWORD>(pAddress);
							ctx.EFlags |= 0x100; // Trap Flag

							if (!SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}
#endif

							g_TLSReArm[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = pAddress;

							ContinueStatus = DBG_EXCEPTION_HANDLED;
							bHandledException = true;
							OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
							break;
						}
					}

					auto itDLLOriginalByte = g_DLLEntryPointOriginalByte.find(DebugEvent.dwProcessId);
					if ((itDLLOriginalByte != g_DLLEntryPointOriginalByte.end()) && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)) {

						LPVOID pAddress = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
						auto itBP = itDLLOriginalByte->second.find(pAddress);
						if (itBP != itDLLOriginalByte->second.end()) {

							DWORD unReason = 0xFFFFFFFF;
							CONTEXT ctx{};

#ifdef _WIN64
							ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							unReason = static_cast<DWORD>(ctx.Rdx & 0xFFFFFFFFull);
#else
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							// [RET][DllHandle][Reason][Reserved]
							SIZE_T unReadden = 0;
							if (!ReadProcessMemory(g_Processes[DebugEvent.dwProcessId].first, reinterpret_cast<LPCVOID>(ctx.Esp + 8), &unReason, sizeof(unReason), &unReadden) || (unReadden != sizeof(unReason))) {
								*pbContinue = false;
								break;
							}
#endif

							LPVOID pOwnerBase = nullptr;
							auto itOwner = g_DLLEntryPointOwner[DebugEvent.dwProcessId].find(pAddress);
							if (itOwner != g_DLLEntryPointOwner[DebugEvent.dwProcessId].end()) {
								pOwnerBase = itOwner->second;
							}

							if (OnDLLEntryPoint(DebugEvent.dwProcessId, DebugEvent.dwThreadId, pAddress, pOwnerBase, unReason)) {
								ContinueStatus = DBG_EXCEPTION_HANDLED;
								bHandledException = true;
								OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
								break;
							}


							if (!WriteByte(g_Processes[DebugEvent.dwProcessId].first, pAddress, itBP->second)) {
								*pbContinue = false;
								break;
							}

							FlushInstructionCache(g_Processes[DebugEvent.dwProcessId].first, pAddress, 1);

#ifdef _WIN64
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							ctx.Rip = reinterpret_cast<DWORD64>(pAddress);
							ctx.EFlags |= 0x100; // Trap Flag

							if (!SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}
#else
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							ctx.Eip = reinterpret_cast<DWORD>(pAddress);
							ctx.EFlags |= 0x100; // Trap Flag

							if (!SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}
#endif

							g_DLLEntryPointReArm[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = pAddress;

							ContinueStatus = DBG_EXCEPTION_HANDLED;
							bHandledException = true;
							OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
							break;
						}
					}

					OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, !bSeenInitialBreakPoint, &bHandledException);

					ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

					if (bSeenInitialBreakPoint && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) && (DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == g_Processes[DebugEvent.dwProcessId].second) && (g_ProcessesOriginalEntryPointByte.find(DebugEvent.dwProcessId) != g_ProcessesOriginalEntryPointByte.end())) {
						if (!WriteProcessMemory(g_Processes[DebugEvent.dwProcessId].first, g_Processes[DebugEvent.dwProcessId].second, &g_ProcessesOriginalEntryPointByte[DebugEvent.dwProcessId], 1, nullptr)) {
							break;
						}

						FlushInstructionCache(g_Processes[DebugEvent.dwProcessId].first, g_Processes[DebugEvent.dwProcessId].second, 1);

						CONTEXT ctx {};
						ctx.ContextFlags = CONTEXT_CONTROL;
						if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
							break;
						}

#ifdef _WIN64
						ctx.Rip = reinterpret_cast<DWORD64>(g_Processes[DebugEvent.dwProcessId].second);
#else
						ctx.Eip = reinterpret_cast<DWORD>(g_Processes[DebugEvent.dwProcessId].second);
#endif

						SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx);

						OnEntryPoint(DebugEvent.dwProcessId, DebugEvent.dwThreadId);

						ContinueStatus = DBG_EXCEPTION_HANDLED;
					}

					if (bSeenInitialBreakPoint && bHandledException) {
						ContinueStatus = DBG_EXCEPTION_HANDLED;
					}

					if (!bSeenInitialBreakPoint && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)) {
						ContinueStatus = DBG_CONTINUE;
						bSeenInitialBreakPoint = true;
					}

					break;
			}

			if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus)) {
				return false;
			}
		} else {
			if (GetLastError() == ERROR_SEM_TIMEOUT) {
				OnTimeout();
			} else {
				return false;
			}
		}
	}

	return true;
}

void ShowHelp() {
	_tprintf_s(_T("Usage:\n"));
	_tprintf_s(_T("  /list\n"));
	_tprintf_s(_T("  /install\n"));
	_tprintf_s(_T("  /uninstall\n"));
}

bool OreansCrackAdd(const TCHAR* szFileName) {
	if (!szFileName) {
		return false;
	}

	TCHAR szKey[MAX_PATH] {};
	if (_stprintf_s(szKey, _countof(szKey), _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s"), szFileName) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	HKEY hKey = nullptr;
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
	if (!szSelfProcessPath) {
		_tprintf_s(_T("ERROR: PEB\n"));
		return false;
	}

#ifndef _UNICODE
	UNICODE_STRING us {};
	RtlInitUnicodeString(&us, szSelfProcessPath);

	ANSI_STRING as {};
	NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
		return false;
	}
#endif // !_UNICODE

#ifdef _UNICODE
	if (RegSetValueEx(hKey, _T("Debugger"), 0, REG_SZ, reinterpret_cast<const BYTE*>(szSelfProcessPath), (static_cast<DWORD>(_tcslen(szSelfProcessPath)) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
#else
	if (RegSetValueEx(hKey, _T("Debugger"), 0, REG_SZ, reinterpret_cast<const BYTE*>(as.Buffer), as.Length + 1) != ERROR_SUCCESS) {
#endif
		_tprintf_s(_T("ERROR: RegSetValueEx (Error = 0x%08X)\n"), GetLastError());
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);
	return true;
}

bool OreansCrackList() {
	HKEY hKey = nullptr;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegOpenKeyEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	DWORD unIndex = 0;
	TCHAR szSubKeyName[MAX_PATH] {};
	DWORD unSubKeyNameSize = MAX_PATH;
	while (RegEnumKeyEx(hKey, unIndex, szSubKeyName, &unSubKeyNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
		HKEY hSubKey = nullptr;
		if (RegOpenKeyEx(hKey, szSubKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
			DWORD unType = 0;
			TCHAR szDebuggerValue[MAX_PATH] {};
			DWORD unDebuggerValueSize = sizeof(szDebuggerValue);
			if ((RegQueryValueEx(hSubKey, _T("Debugger"), nullptr, &unType, reinterpret_cast<LPBYTE>(szDebuggerValue), &unDebuggerValueSize) == ERROR_SUCCESS) && (unType == REG_SZ) && (unDebuggerValueSize > sizeof(TCHAR))) {
				_tprintf_s(_T("> %s: %s\n"), szSubKeyName, szDebuggerValue);
			}

			RegCloseKey(hSubKey);
		}

		++unIndex;
		unSubKeyNameSize = MAX_PATH;
	}

	RegCloseKey(hKey);
	return true;
}

bool OreansCrackRemove(const TCHAR* szFileName) {
	if (!szFileName) {
		return false;
	}

	TCHAR szKey[MAX_PATH] {};
	if (_stprintf_s(szKey, _countof(szKey), _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s"), szFileName) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	HKEY hKey = nullptr;
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	RegDeleteValue(hKey, _T("Debugger"));
	RegCloseKey(hKey);

	hKey = nullptr;
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_READ, NULL, &hKey, NULL) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	DWORD unValuesCount = 0;
	if (RegQueryInfoKey(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &unValuesCount, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegQueryInfoKey (Error = 0x%08X)\n"), GetLastError());
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);

	if (!unValuesCount) {
		if (RegDeleteKey(HKEY_LOCAL_MACHINE, szKey) != ERROR_SUCCESS) {
			_tprintf_s(_T("WARNING: RegDeleteKey (Error = 0x%08X)\n"), GetLastError());
		}
	}

	return true;
}

bool FindExecutablePath(const TCHAR* szFileName, LPTSTR pResultPath, DWORD dwBufferSize) {
	if (!szFileName || !pResultPath || !dwBufferSize) {
		return false;
	}

	memset(pResultPath, 0, dwBufferSize * sizeof(TCHAR));

	DWORD unPathLength = SearchPath(nullptr, szFileName, nullptr, dwBufferSize, pResultPath, nullptr);
	if (!((unPathLength > 0) && (unPathLength < dwBufferSize))) {
		TCHAR szExecutableName[MAX_PATH] {};

		if (_stprintf_s(szExecutableName, _countof(szExecutableName), _T("%s.exe"), szFileName) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			return false;
		}

		memset(pResultPath, 0, dwBufferSize * sizeof(TCHAR));

		unPathLength = SearchPath(nullptr, szExecutableName, nullptr, dwBufferSize, pResultPath, nullptr);
		if (!((unPathLength > 0) && (unPathLength < dwBufferSize))) {
			_tprintf_s(_T("ERROR: Unable to locate executable '%s' (Error = 0x%08X)\n"), szFileName, GetLastError());
			return false;
		}
	}

	return true;
}

DWORD WINAPI TerminalServer(LPVOID) {
	if (!g_pTerminalServer->Open()) {
		_tprintf_s(_T("ERROR: Failed to open terminal server (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

	if (!g_pTerminalServer->Launch()) {
		_tprintf_s(_T("ERROR: Fail in terminal server loop (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int _tmain(int argc, PTCHAR argv[], PTCHAR envp[]) {
	Terminal::Window Window;
	Terminal::Screen Screen(&Window);
	Terminal::Console Console(&Screen);

	g_pTerminalServer = std::make_unique<Terminal::Server>(&Screen);
	if (!g_pTerminalServer) {
		_tprintf_s(_T("ERROR: g_pTerminalServer is null (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
#ifdef _WIN64
	_tprintf_s(_T("OreansCrack [Version " OREANSCRACK_VERSION "]\n\n"));
#else
	_tprintf_s(_T("OreansCrack32 [Version " OREANSCRACK_VERSION "]\n\n"));
#endif
#endif // _DEBUG

	if (argc < 2) {
#ifndef _DEBUG
#ifdef _WIN64
		_tprintf_s(_T("OreansCrack [Version " OREANSCRACK_VERSION "]\n\n"));
#else
		_tprintf_s(_T("OreansCrack32 [Version " OREANSCRACK_VERSION "]\n\n"));
#endif
#endif // !_DEBUG

		ShowHelp();

		return EXIT_SUCCESS;
	}

	if (_tcscmp(argv[1], _T("/list")) == 0) {
#ifndef _DEBUG
#ifdef _WIN64
		_tprintf_s(_T("OreansCrack [Version " OREANSCRACK_VERSION "]\n\n"));
#else
		_tprintf_s(_T("OreansCrack32 [Version " OREANSCRACK_VERSION "]\n\n"));
#endif
#endif // !_DEBUG

		if (!OreansCrackList()) {
			return EXIT_FAILURE;
		}

		return EXIT_SUCCESS;
	}

	if (_tcscmp(argv[1], _T("/install")) == 0) {
#ifndef _DEBUG
#ifdef _WIN64
		_tprintf_s(_T("OreansCrack [Version " OREANSCRACK_VERSION "]\n\n"));
#else
		_tprintf_s(_T("OreansCrack32 [Version " OREANSCRACK_VERSION "]\n\n"));
#endif
#endif // !_DEBUG

		if (argc < 2) {
			ShowHelp();
			return EXIT_SUCCESS;
		}

		if (!IsRunningAsAdmin()) {
			if (!ReLaunchAsAdmin()) {
				return EXIT_FAILURE;
			}

			_tprintf_s(_T("SUCCESS!\n"));
			return EXIT_SUCCESS;
		}

		if (!OreansCrackAdd(_T("Virtualizer.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackAdd(_T("VirtualizerArm64.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackAdd(_T("Themida.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackAdd(_T("Themida64.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackAdd(_T("WinLicense.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackAdd(_T("WinLicense64.exe"))) {
			return EXIT_FAILURE;
		}

		_tprintf_s(_T("SUCCESS!\n"));
		return EXIT_SUCCESS;
	}

	if (_tcscmp(argv[1], _T("/uninstall")) == 0) {
#ifndef _DEBUG
#ifdef _WIN64
		_tprintf_s(_T("OreansCrack [Version " OREANSCRACK_VERSION "]\n\n"));
#else
		_tprintf_s(_T("OreansCrack32 [Version " OREANSCRACK_VERSION "]\n\n"));
#endif
#endif // !_DEBUG

		if (argc < 2) {
			ShowHelp();
			return EXIT_SUCCESS;
		}

		if (!IsRunningAsAdmin()) {
			if (!ReLaunchAsAdmin()) {
				return EXIT_FAILURE;
			}

			_tprintf_s(_T("SUCCESS!\n"));
			return EXIT_SUCCESS;
		}


		if (!OreansCrackRemove(_T("WinLicense64.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackRemove(_T("WinLicense.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackRemove(_T("Themida64.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackRemove(_T("Themida.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackRemove(_T("VirtualizerArm64.exe"))) {
			return EXIT_FAILURE;
		}

		if (!OreansCrackRemove(_T("Virtualizer.exe"))) {
			return EXIT_FAILURE;
		}

		_tprintf_s(_T("SUCCESS!\n"));
		return EXIT_SUCCESS;
	}

	TCHAR szResultPath[MAX_PATH] {};
	if (!FindExecutablePath(argv[1], szResultPath, MAX_PATH)) {
		return EXIT_FAILURE;
	}

	HANDLE hFile = CreateFile(szResultPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

	HANDLE hMapFile = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapFile || (hMapFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	void* pMap = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS pTempNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	if (pTempNTHs->Signature != IMAGE_NT_SIGNATURE) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	HANDLE hJob = CreateJobObject(nullptr, nullptr);
	if (!hJob || (hJob == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateJobObject (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION joli{};
	joli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &joli, sizeof(joli))) {
		_tprintf_s(_T("ERROR: SetInformationJobObject (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

#ifdef _WIN64
	if (pTempNTHs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);

		PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
		if (!szSelfProcessPath) {
			_tprintf_s(_T("ERROR: PEB\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		UNICODE_STRING us {};
		RtlInitUnicodeString(&us, szSelfProcessPath);

		ANSI_STRING as {};
		NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
		if (!NT_SUCCESS(nStatus)) {
			_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}
#endif // !_UNICODE

		TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {}, szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
#ifdef _UNICODE
		errno_t err = _tsplitpath_s(szSelfProcessPath, szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), szName, _countof(szName), szExt, _countof(szExt));
#else
		errno_t err = _tsplitpath_s(as.Buffer, szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), szName, _countof(szName), szExt, _countof(szExt));
#endif
		if (err != 0) {
			_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		TCHAR szProcessPath[MAX_PATH] {};
		if (_stprintf_s(szProcessPath, _countof(szProcessPath), _T("%s%s%s32%s"), szDrive, szDirectory, szName, szExt) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		STARTUPINFO si {};
		PROCESS_INFORMATION pi {};
		si.cb = sizeof(si);

		if (!CreateProcess(szProcessPath, GetCommandLine(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
			_tprintf_s(_T("ERROR: Failed to launch 64-bit version (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
			_tprintf_s(_T("ERROR: AssignProcessToJobObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
			_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, EXIT_FAILURE);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD unExitCode = EXIT_FAILURE;
		if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
			_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		return unExitCode;
	}

	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		_tprintf_s(_T("ERROR: This process cannot be run in 64 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}
#else
	if (pTempNTHs->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);

		PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
		if (!szSelfProcessPath) {
			_tprintf_s(_T("ERROR: PEB\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		UNICODE_STRING us {};
		RtlInitUnicodeString(&us, szSelfProcessPath);

		ANSI_STRING as {};
		NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
		if (!NT_SUCCESS(nStatus)) {
			_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}
#endif // !_UNICODE

		TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {}, szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
#ifdef _UNICODE
		errno_t err = _tsplitpath_s(szSelfProcessPath, szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), szName, _countof(szName), szExt, _countof(szExt));
#else
		errno_t err = _tsplitpath_s(as.Buffer, szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), szName, _countof(szName), szExt, _countof(szExt));
#endif
		if (err != 0) {
			_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		PTCHAR szSubString = _tcsstr(szName, _T("32"));
		if (szSubString) {
			size_t unRemainingLength = _tcslen(szSubString + 2);
			std::memmove(szSubString, szSubString + 2, unRemainingLength + 1);
		}

		TCHAR szProcessPath[MAX_PATH] {};
		if (_stprintf_s(szProcessPath, _countof(szProcessPath), _T("%s%s%s%s"), szDrive, szDirectory, szName, szExt) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		STARTUPINFO si {};
		PROCESS_INFORMATION pi {};
		si.cb = sizeof(si);

		if (!CreateProcess(szProcessPath, GetCommandLine(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
			_tprintf_s(_T("ERROR: Failed to launch 64-bit version (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		if (hJob && (hJob != INVALID_HANDLE_VALUE)) {
			if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
				_tprintf_s(_T("ERROR: AssignProcessToJobObject (Error = 0x%08X)\n"), GetLastError());
				TerminateProcess(pi.hProcess, 0);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				CloseHandle(hJob);
				return EXIT_FAILURE;
			}
		}

		if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
			_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, EXIT_FAILURE);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD unExitCode = EXIT_FAILURE;
		if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
			_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		return unExitCode;
	}

	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		_tprintf_s(_T("ERROR: This process cannot be run in 32 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}
#endif

	UnmapViewOfFile(pMap);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	tstring CommandLine = _T("");
	for (int i = 1; i < argc; ++i) {

		if ((i == 1) || _tcschr(argv[i], _T(' '))) {
			CommandLine += _T('"');
			CommandLine += argv[i];
			CommandLine += _T('"');
		} else {
			CommandLine += argv[i];
		}

		if ((i + 1) < argc) {
			CommandLine += _T(' ');
		}
	}

	auto pCommandLine = std::make_unique<TCHAR[]>(CommandLine.size() + 1);
	if (!pCommandLine) {
		_tprintf_s(_T("ERROR: Not enough memory for new command line! (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	std::copy(CommandLine.begin(), CommandLine.end(), pCommandLine.get());

	pCommandLine[CommandLine.size()] = _T('\0');

	if (!EnableDebugPrivilege(GetCurrentProcess(), true)) {
		return EXIT_FAILURE;
	}

	PROCESS_INFORMATION pi {};
	if (!CreateDebugProcess(szResultPath, pCommandLine.get(), hJob, &pi)) {
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (ResumeThread(pi.hThread) != 1) {
		_tprintf_s(_T("ERROR: ResumeThread (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	HANDLE hTerminalThread = CreateThread(nullptr, 0, TerminalServer, nullptr, 0, nullptr);
	if (!hTerminalThread || (hTerminalThread == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateThread (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	bool bStopped = false;
	if (!DebugProcess(INFINITE, &g_bContinueDebugging, &bStopped)) {
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (bStopped) {
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	DWORD unSuspendCount = SuspendThread(pi.hThread);
	if ((unSuspendCount != 0) && (unSuspendCount != 1)) {
		_tprintf_s(_T("ERROR: SuspendThread (Error = 0x%08X)\n"), GetLastError());
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	DWORD unDebugFlags = 0;
	NTSTATUS nStatus = NtQueryInformationProcess(pi.hProcess, ProcessDebugFlags, &unDebugFlags, sizeof(unDebugFlags), nullptr);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), nStatus);
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	unDebugFlags = 0x00000001;

	nStatus = NtSetInformationProcess(pi.hProcess, ProcessDebugFlags, &unDebugFlags, sizeof(unDebugFlags));
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtSetInformationProcess (Error = 0x%08X)\n"), nStatus);
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	HANDLE hDebug = nullptr;
	nStatus = NtQueryInformationProcess(pi.hProcess, ProcessDebugObjectHandle, &hDebug, sizeof(HANDLE), nullptr);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), GetLastError());
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	nStatus = NtRemoveProcessDebug(pi.hProcess, hDebug);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtRemoveProcessDebug (Error = 0x%08X)\n"), GetLastError());
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	CloseHandle(hDebug);

	if (!EnableDebugPrivilege(GetCurrentProcess(), false)) {
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	unSuspendCount = ResumeThread(pi.hThread);
	if ((unSuspendCount != 1) && (unSuspendCount != 2)) {
		_tprintf_s(_T("ERROR: ResumeThread (Error = 0x%08X)\n"), GetLastError());
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
		_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
		TerminateThread(hTerminalThread, EXIT_SUCCESS);
		CloseHandle(hTerminalThread);
		TerminateThread(pi.hThread, EXIT_FAILURE);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	DWORD unExitCode = EXIT_FAILURE;
	if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
		_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hTerminalThread);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	return static_cast<int>(unExitCode);
}