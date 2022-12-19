#pragma once

#ifndef _DETOURS_H_
#define _DETOURS_H_

// Default
#include <Windows.h>

// C++
#include <cstdlib>

// STL
#include <array>

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#ifndef NSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef DETOURS_MAX_STRSIZE
#define DETOURS_MAX_STRSIZE 0x1000 // 4 KiB
#endif // !DETOURS_MAX_SIZE

// Macro to declare a const 8-byte array.
#define DECLARE_SECTOR_NAME(...) std::array<const unsigned char, 8>({ __VA_ARGS__ })

#ifdef _MSC_VER
// Macro to force a function to be included by the linker.
#define INCLUDE(SYMBOL_NAME) __pragma(comment(linker, "/INCLUDE:" SYMBOL_NAME))
#define SELF_INCLUDE INCLUDE(__FUNCDNAME__)

// Macro to declare an alias for the exported function.
#define EXPORT(SYMBOL_NAME, ALIAS_NAME) __pragma(comment(linker, "/EXPORT:" ALIAS_NAME "=" SYMBOL_NAME))
#define SELF_EXPORT(ALIAS_NAME) EXPORT(__FUNCDNAME__, ALIAS_NAME)
#endif

// ----------------------------------------------------------------
// Checking platform
// ----------------------------------------------------------------

#if !defined(_M_IX86) && !defined(_M_X64)
#error Only x86 and x86_64 platforms are supported.
#endif // !_M_IX86 && !_M_X64

#if !defined(_WIN32) && !defined(_WIN64)
#error Only Windows platform are supported.
#endif // !_WIN32 && !_WIN64

// ----------------------------------------------------------------
// Detours
// ----------------------------------------------------------------

namespace Detours {

	// ----------------------------------------------------------------
	// KUSER_SHARED_DATA
	// ----------------------------------------------------------------

#pragma pack(push, 4)
	typedef struct _KSYSTEM_TIME {
		ULONG LowPart;
		LONG High1Time;
		LONG High2Time;
	} KSYSTEM_TIME, *PKSYSTEM_TIME;

	typedef enum _NT_PRODUCT_TYPE : unsigned int {
		NtProductWinNt = 1,
		NtProductLanManNt = 2,
		NtProductServer = 3
	} NT_PRODUCT_TYPE;

	typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE : unsigned int {
		StandardDesign = 0,
		NEC98x86 = 1,
		EndAlternatives = 2
	} ALTERNATIVE_ARCHITECTURE_TYPE;

	typedef struct _KUSER_SHARED_DATA {
		ULONG TickCountLowDeprecated;
		ULONG TickCountMultiplier;
		volatile KSYSTEM_TIME InterruptTime;
		volatile KSYSTEM_TIME SystemTime;
		volatile KSYSTEM_TIME TimeZoneBias;
		USHORT ImageNumberLow;
		USHORT ImageNumberHigh;
		WCHAR NtSystemRoot[260];
		ULONG MaxStackTraceDepth;
		ULONG CryptoExponent;
		ULONG TimeZoneId;
		ULONG LargePageMinimum;
		ULONG AitSamplingValue;
		ULONG AppCompatFlag;
		ULONGLONG RNGSeedVersion;
		ULONG GlobalValidationRunlevel;
		LONG TimeZoneBiasStamp;
		ULONG NtBuildNumber;
		NT_PRODUCT_TYPE NtProductType;
		BOOLEAN ProductTypeIsValid;
		UCHAR Reserved0[1];
		USHORT NativeProcessorArchitecture;
		ULONG NtMajorVersion;
		ULONG NtMinorVersion;
		BOOLEAN ProcessorFeatures[64];
		ULONG Reserved1;
		ULONG Reserved3;
		volatile ULONG TimeSlip;
		ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
		ULONG BootId;
		LARGE_INTEGER SystemExpirationDate;
		ULONG SuiteMask;
		BOOLEAN KdDebuggerEnabled;
		union {
			UCHAR MitigationPolicies;
			struct {
				UCHAR NXSupportPolicy : 2;
				UCHAR SEHValidationPolicy : 2;
				UCHAR CurDirDevicesSkippedForDlls : 2;
				UCHAR Reserved : 2;
			};
		};
		USHORT CyclesPerYield;
		volatile ULONG ActiveConsoleId;
		volatile ULONG DismountCount;
		ULONG ComPlusPackage;
		ULONG LastSystemRITEventTickCount;
		ULONG NumberOfPhysicalPages;
		BOOLEAN SafeBootMode;
		UCHAR VirtualizationFlags;
		UCHAR Reserved12[2];
		union {
			ULONG SharedDataFlags;
			struct {
				ULONG DbgErrorPortPresent : 1;
				ULONG DbgElevationEnabled : 1;
				ULONG DbgVirtEnabled : 1;
				ULONG DbgInstallerDetectEnabled : 1;
				ULONG DbgLkgEnabled : 1;
				ULONG DbgDynProcessorEnabled : 1;
				ULONG DbgConsoleBrokerEnabled : 1;
				ULONG DbgSecureBootEnabled : 1;
				ULONG DbgMultiSessionSku : 1;
				ULONG DbgMultiUsersInSessionSku : 1;
				ULONG DbgStateSeparationEnabled : 1;
				ULONG SpareBits : 21;
			};
		};
		ULONG DataFlagsPad[1];
		ULONGLONG TestRetInstruction;
		LONGLONG QpcFrequency;
		ULONG SystemCall;
		union {
			ULONG AllFlags;
			struct {
				ULONG Win32Process : 1;
				ULONG Sgx2Enclave : 1;
				ULONG VbsBasicEnclave : 1;
				ULONG SpareBits : 29;
			};
		} UserCetAvailableEnvironments;
		ULONGLONG SystemCallPad[2];
		union {
			volatile KSYSTEM_TIME TickCount;
			volatile ULONG64 TickCountQuad;
			struct {
				ULONG ReservedTickCountOverlay[3];
				ULONG TickCountPad[1];
			};
		};
		ULONG Cookie;
		ULONG CookiePad[1];
		LONGLONG ConsoleSessionForegroundProcessId;
		ULONGLONG TimeUpdateLock;
		ULONGLONG BaselineSystemTimeQpc;
		ULONGLONG BaselineInterruptTimeQpc;
		ULONGLONG QpcSystemTimeIncrement;
		ULONGLONG QpcInterruptTimeIncrement;
		UCHAR QpcSystemTimeIncrementShift;
		UCHAR QpcInterruptTimeIncrementShift;
		USHORT UnparkedProcessorCount;
		ULONG EnclaveFeatureMask[4];
		ULONG TelemetryCoverageRound;
		USHORT UserModeGlobalLogger[16];
		ULONG ImageFileExecutionOptions;
		ULONG LangGenerationCount;
		ULONGLONG Reserved4;
		volatile ULONGLONG InterruptTimeBias;
		volatile ULONGLONG QpcBias;
		ULONG ActiveProcessorCount;
		volatile UCHAR ActiveGroupCount;
		UCHAR Reserved9;
		union {
			USHORT QpcData;
			struct {
				volatile UCHAR QpcBypassEnabled : 1;
				UCHAR QpcShift : 1;
			};
		};
		LARGE_INTEGER TimeZoneBiasEffectiveStart;
		LARGE_INTEGER TimeZoneBiasEffectiveEnd;
		XSTATE_CONFIGURATION XState;
		KSYSTEM_TIME FeatureConfigurationChangeStamp;
		ULONG Spare;
	} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#pragma pack(pop)

	extern const KUSER_SHARED_DATA& KUserSharedData;

	// ----------------------------------------------------------------
	// PEB
	// ----------------------------------------------------------------

#pragma pack(push, 8)
	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWCHAR Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _CURDIR {
		UNICODE_STRING DosPath;
		HANDLE Handle;
	} CURDIR, *PCURDIR;

	typedef struct _STRING {
		USHORT Length;
		USHORT MaximumLength;
		PCHAR Buffer;
	} STRING, *PSTRING;

	typedef struct _RTL_DRIVE_LETTER_CURDIR {
		USHORT Flags;
		USHORT Length;
		ULONG TimeStamp;
		STRING DosPath;
	} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		ULONG MaximumLength;
		ULONG Length;
		ULONG Flags;
		ULONG DebugFlags;
		HANDLE ConsoleHandle;
		ULONG ConsoleFlags;
		HANDLE StandardInput;
		HANDLE StandardOutput;
		HANDLE StandardError;
		CURDIR CurrentDirectory;
		UNICODE_STRING DllPath;
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
		PVOID Environment;
		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;
		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING WindowTitle;
		UNICODE_STRING DesktopInfo;
		UNICODE_STRING ShellInfo;
		UNICODE_STRING RuntimeData;
		RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
		ULONG_PTR EnvironmentSize;
		ULONG_PTR EnvironmentVersion;
		PVOID PackageDependencyData;
		ULONG ProcessGroupId;
		ULONG LoaderThreads;
		UNICODE_STRING RedirectionDllName;
		UNICODE_STRING HeapPartitionName;
		ULONG_PTR DefaultThreadpoolCpuSetMasks;
		ULONG DefaultThreadpoolCpuSetMaskCount;
	} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

	typedef struct _API_SET_NAMESPACE {
		ULONG Version;
		ULONG Size;
		ULONG Flags;
		ULONG Count;
		ULONG EntryOffset;
		ULONG HashOffset;
		ULONG HashFactor;
	} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

	typedef struct _LEAP_SECOND_DATA {
		UCHAR Enabled;
		ULONG Count;
		LARGE_INTEGER Data[1];
	} LEAP_SECOND_DATA, *PLEAP_SECOND_DATA;

	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union {
			BOOLEAN BitField;
			struct {
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN IsPackagedProcess : 1;
				BOOLEAN IsAppContainer : 1;
				BOOLEAN IsProtectedProcessLight : 1;
				BOOLEAN IsLongPathAwareProcess : 1;
			};
		};
		HANDLE Mutant;
		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
		PSLIST_HEADER AtlThunkSListPtr;
		PVOID IFEOKey;
		union {
			ULONG CrossProcessFlags;
			struct {
				ULONG ProcessInJob : 1;
				ULONG ProcessInitializing : 1;
				ULONG ProcessUsingVEH : 1;
				ULONG ProcessUsingVCH : 1;
				ULONG ProcessUsingFTH : 1;
				ULONG ProcessPreviouslyThrottled : 1;
				ULONG ProcessCurrentlyThrottled : 1;
				ULONG ProcessImagesHotPatched : 1;
				ULONG ReservedBits0 : 24;
			};
		};
		union {
			PVOID KernelCallbackTable;
			PVOID UserSharedInfoPtr;
		};
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		PAPI_SET_NAMESPACE ApiSetMap;
		ULONG TlsExpansionCounter;
		PVOID TlsBitmap;
		ULONG TlsBitmapBits[2];
		PVOID ReadOnlySharedMemoryBase;
		PVOID SharedData;
		PVOID* ReadOnlyStaticServerData;
		PVOID AnsiCodePageData;
		PVOID OemCodePageData;
		PVOID UnicodeCaseTableData;
		ULONG NumberOfProcessors;
		ULONG NtGlobalFlag;
		ULARGE_INTEGER CriticalSectionTimeout;
		SIZE_T HeapSegmentReserve;
		SIZE_T HeapSegmentCommit;
		SIZE_T HeapDeCommitTotalFreeThreshold;
		SIZE_T HeapDeCommitFreeBlockThreshold;
		ULONG NumberOfHeaps;
		ULONG MaximumNumberOfHeaps;
		PVOID* ProcessHeaps;
		PVOID GdiSharedHandleTable;
		PVOID ProcessStarterHelper;
		ULONG GdiDCAttributeList;
		PRTL_CRITICAL_SECTION LoaderLock;
		ULONG OSMajorVersion;
		ULONG OSMinorVersion;
		USHORT OSBuildNumber;
		USHORT OSCSDVersion;
		ULONG OSPlatformId;
		ULONG ImageSubsystem;
		ULONG ImageSubsystemMajorVersion;
		ULONG ImageSubsystemMinorVersion;
		KAFFINITY ActiveProcessAffinityMask;
#ifdef _M_X64
		ULONG GdiHandleBuffer[60];
#elif _M_IX86
		ULONG GdiHandleBuffer[34];
#endif
		PVOID PostProcessInitRoutine;
		PVOID TlsExpansionBitmap;
		ULONG TlsExpansionBitmapBits[32];
		ULONG SessionId;
		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		PVOID pShimData;
		PVOID AppCompatInfo;
		UNICODE_STRING CSDVersion;
		PVOID ActivationContextData;
		PVOID ProcessAssemblyStorageMap;
		PVOID SystemDefaultActivationContextData;
		PVOID SystemAssemblyStorageMap;
		SIZE_T MinimumStackCommit;
		PVOID SparePointers[2];
		PVOID PatchLoaderData;
		PVOID ChpeV2ProcessInfo;
		ULONG AppModelFeatureState;
		ULONG SpareUlongs[2];
		USHORT ActiveCodePage;
		USHORT OemCodePage;
		USHORT UseCaseMapping;
		USHORT UnusedNlsField;
		PVOID WerRegistrationData;
		PVOID WerShipAssertPtr;
		PVOID EcCodeBitMap;
		PVOID pImageHeaderHash;
		union {
			ULONG TracingFlags;
			struct {
				ULONG HeapTracingEnabled : 1;
				ULONG CritSecTracingEnabled : 1;
				ULONG LibLoaderTracingEnabled : 1;
				ULONG SpareTracingBits : 29;
			};
		};
		ULONGLONG CsrServerReadOnlySharedMemoryBase;
		PRTL_CRITICAL_SECTION TppWorkerpListLock;
		LIST_ENTRY TppWorkerpList;
		PVOID WaitOnAddressHashTable[128];
		PVOID TelemetryCoverageHeader;
		ULONG CloudFileFlags;
		ULONG CloudFileDiagFlags;
		CHAR PlaceholderCompatibilityMode;
		CHAR PlaceholderCompatibilityModeReserved[7];
		PLEAP_SECOND_DATA LeapSecondData;
		union {
			ULONG LeapSecondFlags;
			struct {
				ULONG SixtySecondEnabled : 1;
				ULONG Reserved : 31;
			};
		};
		ULONG NtGlobalFlag2;
		ULONGLONG ExtendedFeatureDisableMask;
	} PEB, *PPEB;
#pragma pack(pop)

	const PPEB GetPEB();

	// ----------------------------------------------------------------
	// TEB
	// ----------------------------------------------------------------

#pragma pack(push, 8)
#ifdef _M_X64
	typedef struct _CLIENT_ID {
		ULONGLONG UniqueProcess;
		ULONGLONG UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;
#elif _M_IX86
	typedef struct _CLIENT_ID {
		ULONG UniqueProcess;
		ULONG UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;
#endif

	typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
		struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
		struct _ACTIVATION_CONTEXT* ActivationContext;
		ULONG Flags;
	} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

	typedef struct _ACTIVATION_CONTEXT_STACK {
		PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
		LIST_ENTRY FrameListCache;
		ULONG Flags;
		ULONG NextCookieSequenceNumber;
		ULONG StackId;
	} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

	typedef struct _GDI_TEB_BATCH {
		ULONG Offset;
		ULONG_PTR HDC;
		ULONG Buffer[310];
	} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

	typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
		ULONG Flags;
		PSTR FrameName;
	} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

	typedef struct _TEB_ACTIVE_FRAME {
		ULONG Flags;
		struct _TEB_ACTIVE_FRAME* Previous;
		PTEB_ACTIVE_FRAME_CONTEXT Context;
	} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

	typedef struct _TEB {
		NT_TIB NtTib;
		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		PPEB ProcessEnvironmentBlock;
		ULONG LastErrorValue;
		ULONG CountOfOwnedCriticalSections;
		PVOID CsrClientThread;
		PVOID Win32ThreadInfo;
		ULONG User32Reserved[26];
		ULONG UserReserved[5];
		PVOID WOW32Reserved;
		LCID CurrentLocale;
		ULONG FpSoftwareStatusRegister;
		PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _M_X64
		PVOID SystemReserved1[30];
#elif _M_IX86
		PVOID SystemReserved1[26];
#endif
		CHAR PlaceholderCompatibilityMode;
		BOOLEAN PlaceholderHydrationAlwaysExplicit;
		CHAR PlaceholderReserved[10];
		ULONG ProxiedProcessId;
		ACTIVATION_CONTEXT_STACK ActivationStack;
		UCHAR WorkingOnBehalfTicket[8];
		NTSTATUS ExceptionCode;
		PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
		ULONG_PTR InstrumentationCallbackSp;
		ULONG_PTR InstrumentationCallbackPreviousPc;
		ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _M_X64
		ULONG TxFsContext;
#endif
		BOOLEAN InstrumentationCallbackDisabled;
#ifdef _M_X64
		BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifdef _M_IX86
		UCHAR SpareBytes[23];
		ULONG TxFsContext;
#endif
		GDI_TEB_BATCH GdiTebBatch;
		CLIENT_ID RealClientId;
		HANDLE GdiCachedProcessHandle;
		ULONG GdiClientPID;
		ULONG GdiClientTID;
		PVOID GdiThreadLocalInfo;
		ULONG_PTR Win32ClientInfo[62];
		PVOID glDispatchTable[233];
		ULONG_PTR glReserved1[29];
		PVOID glReserved2;
		PVOID glSectionInfo;
		PVOID glSection;
		PVOID glTable;
		PVOID glCurrentRC;
		PVOID glContext;
		NTSTATUS LastStatusValue;
		UNICODE_STRING StaticUnicodeString;
		WCHAR StaticUnicodeBuffer[261];
		PVOID DeallocationStack;
		PVOID TlsSlots[64];
		LIST_ENTRY TlsLinks;
		PVOID Vdm;
		PVOID ReservedForNtRpc;
		PVOID DbgSsReserved[2];
		ULONG HardErrorMode;
#ifdef _M_X64
		PVOID Instrumentation[11];
#elif _M_IX86
		PVOID Instrumentation[9];
#endif
		GUID ActivityId;
		PVOID SubProcessTag;
		PVOID PerflibData;
		PVOID EtwTraceData;
		PVOID WinSockData;
		ULONG GdiBatchCount;
		union {
			PROCESSOR_NUMBER CurrentIdealProcessor;
			ULONG IdealProcessorValue;
			struct {
				UCHAR ReservedPad0;
				UCHAR ReservedPad1;
				UCHAR ReservedPad2;
				UCHAR IdealProcessor;
			};
		};
		ULONG GuaranteedStackBytes;
		PVOID ReservedForPerf;
		PVOID ReservedForOle;
		ULONG WaitingOnLoaderLock;
		PVOID SavedPriorityState;
		ULONG_PTR ReservedForCodeCoverage;
		PVOID ThreadPoolData;
		PVOID* TlsExpansionSlots;
#ifdef _M_X64
		PVOID DeallocationBStore;
		PVOID BStoreLimit;
#endif
		ULONG MuiGeneration;
		ULONG IsImpersonating;
		PVOID NlsCache;
		PVOID pShimData;
		ULONG HeapData;
		HANDLE CurrentTransactionHandle;
		PTEB_ACTIVE_FRAME ActiveFrame;
		PVOID FlsData;
		PVOID PreferredLanguages;
		PVOID UserPrefLanguages;
		PVOID MergedPrefLanguages;
		ULONG MuiImpersonation;
		union {
			USHORT CrossTebFlags;
			USHORT SpareCrossTebBits : 16;
		};
		union {
			USHORT SameTebFlags;
			struct {
				USHORT SafeThunkCall : 1;
				USHORT InDebugPrint : 1;
				USHORT HasFiberData : 1;
				USHORT SkipThreadAttach : 1;
				USHORT WerInShipAssertCode : 1;
				USHORT RanProcessInit : 1;
				USHORT ClonedThread : 1;
				USHORT SuppressDebugMsg : 1;
				USHORT DisableUserStackWalk : 1;
				USHORT RtlExceptionAttached : 1;
				USHORT InitialThread : 1;
				USHORT SessionAware : 1;
				USHORT LoadOwner : 1;
				USHORT LoaderWorker : 1;
				USHORT SkipLoaderInit : 1;
				USHORT SkipFileAPIBrokering : 1;
			};
		};
		PVOID TxnScopeEnterCallback;
		PVOID TxnScopeExitCallback;
		PVOID TxnScopeContext;
		ULONG LockCount;
		LONG WowTebOffset;
		PVOID ResourceRetValue;
		PVOID ReservedForWdf;
		ULONGLONG ReservedForCrt;
		GUID EffectiveContainerId;
		ULONGLONG LastSleepCounter;
		ULONG SpinCallCount;
		ULONGLONG ExtendedFeatureDisableMask;
	} TEB, *PTEB;
#pragma pack(pop)

	const PTEB GetTEB();

	// ----------------------------------------------------------------
	// Scan
	// ----------------------------------------------------------------
	// TODO: Add multiple finding.

	namespace Scan {

		// ----------------------------------------------------------------
		// FindSection
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding section in module.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pAddress'>Section address.</param>
		/// <param name='pSize'>Section size.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool FindSection(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, void** pAddress, size_t* pSize);

		// ----------------------------------------------------------------
		// FindSectionPOGO
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding section in module.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pAddress'>Section address.</param>
		/// <param name='pSize'>Section size.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool FindSectionPOGO(const HMODULE hModule, const char* const szSectionName, void** pAddress, const size_t* pSize);

		// ----------------------------------------------------------------
		// FindSignature (Native)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data without SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (SSE2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>

		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		
		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		
		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (Auto)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data without/with SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		
		/// <summary>
		/// Finding signature in data without/with SIMD by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		
		/// <summary>
		/// Finding signature in data without/with SIMD by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindData (Native)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data without SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (SSE2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (Auto)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data without/with SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and seciton name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindRTTI
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTI(const void* const pBaseAddress, const size_t unSize, const char* const szRTTI);

		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTI(const HMODULE hModule, const char* const szRTTI);

		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTIA(const char* const szModuleName, const char* const szRTTI);

		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTIW(const wchar_t* const szModuleName, const char* const szRTTI);

#ifdef UNICODE
		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTI(const wchar_t* const szModuleName, const char* const szRTTI);
#else
		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTI(const char* const szModuleName, const char* const szRTTI);
#endif
	}

	// ----------------------------------------------------------------
	// Memory
	// ----------------------------------------------------------------

	namespace Memory {

		// ----------------------------------------------------------------
		// Server
		// ----------------------------------------------------------------

		class Server {
		public:
			Server(const size_t unMemorySize, bool bIsGlobal = false);
			~Server();

		public:
			bool GetSessionName(TCHAR szSessionName[64]);
			void* GetAddress();

		private:
			const size_t m_unMemorySize;
			TCHAR m_szSessionName[64];
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// Client
		// ----------------------------------------------------------------

		class Client {
		public:
			Client(const size_t unMemorySize, TCHAR szSessionName[64], bool bIsGlobal = false);
			~Client();

		public:
			void* GetAddress();

		private:
			const size_t m_unMemorySize;
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// Protection
		// ----------------------------------------------------------------

		/// <summary>
		/// Memory protection that automatically restores protection.
		/// </summary>
		class Protection {
		public:
			/// <summary>
			/// Memory protection that automatically restores protection.
			/// </summary>
			/// <param name='pAddress'>Memory address.</param>
			/// <param name='unSize'>Memory size.</param>
			Protection(const void* const pAddress, const size_t unSize);
			~Protection();

		public:
			/// <summary>
			/// Get current memory protection.</returns>
			/// </summary>
			/// <param name='pProtection'>Recording address.</param>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool GetProtection(const PDWORD pProtection);

			/// <summary>
			/// Change memory protection.
			/// </summary>
			/// <param name='unFlag'>Memory protection flag.</param>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool ChangeProtection(const DWORD unNewProtection);

			/// <summary>
			/// Restore memory protection.
			/// </summary>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool RestoreProtection();

		public:
			/// <returns>Returns memory address.</returns>
			const void* const GetAddress();

			/// <returns>Returns memory size.</returns>
			const size_t GetSize();

			/// <returns>Returns original memory protection.</returns>
			DWORD GetOriginalProtection();

		private:
			const void* const m_pAddress;
			const size_t m_unSize;
			DWORD m_unOriginalProtection;
		};

		// ----------------------------------------------------------------
		// Simple Protection
		// ----------------------------------------------------------------

		/// <summary>
		/// Change memory protection.
		/// </summary>
		/// <param name='pAddress'>Memory address.</param>
		/// <param name='unSize'>Memory size.</param>
		/// <param name='unFlag'>Memory protection flag.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool ChangeProtection(const void* const pAddress, const size_t unSize, const DWORD unNewProtection);

		/// <summary>
		/// Restore memory protection.
		/// </summary>
		/// <param name='pAddress'>Memory address.</param>
		bool RestoreProtection(const void* const pAddress);
	}

	// ----------------------------------------------------------------
	// Exception
	// ----------------------------------------------------------------

	namespace Exception {

		// ----------------------------------------------------------------
		// ExceptionCallBack
		// ----------------------------------------------------------------

		typedef bool(__fastcall* fnExceptionCallBack)(const EXCEPTION_RECORD Exception, const PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// Exception
		// ----------------------------------------------------------------

		// This class is needed only for the global exception handler initialization.
		class ExceptionListener {
		public:
			ExceptionListener();
			~ExceptionListener();

		public:
			bool Refresh(); // Handler reinitialization.

		private:
			PVOID m_pVEH;
		};

		extern ExceptionListener g_ExceptionListener; // Global exception handler

		bool AddCallBack(const fnExceptionCallBack pCallBack);
		bool RemoveCallBack(const fnExceptionCallBack pCallBack);
	}

	// ----------------------------------------------------------------
	// Hook
	// ----------------------------------------------------------------

	namespace Hook {

		// ----------------------------------------------------------------
		// Import Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook that automatically unhooking.
		/// </summary>
		class ImportHook {
		public:
			/// <summary>
			/// Hook that automatically unhooking.
			/// </summary>
			/// <param name='szModuleName'>Module name.</param>
			/// <param name='szExportName'>Importing name.</param>
			/// <param name='szImportModuleName'>Importing module name.</param>
			ImportHook(const HMODULE hModule, const char* const szImportName, const char* const szImportModuleName = nullptr);
			~ImportHook();

		public:
			/// <summary>
			/// Hook with a specific address.
			/// </summary>
			/// <param name='pHookAddress'>Hook address.</param>
			bool Hook(const void* const pHookAddress);

			/// <summary>
			/// UnHook.
			/// </summary>
			bool UnHook();

		public:
			/// <returns>Returns original address.</returns>
			const void* GetOriginalAddress();

			/// <returns>Returns hook address.</returns>
			const void* GetHookAddress();

		private:
			const void** m_pAddress;
			const void* m_pOriginalAddress;
			const void* m_pHookAddress;
		};

		// ----------------------------------------------------------------
		// Simple Import Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook with a specific address.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szImportName'>Importing name.</param>
		/// <param name='pHookAddress'>Hook address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool HookImport(const HMODULE hModule, const char* const szImportName, const void* const pHookAddress);

		/// <summary>
		/// UnHook.
		/// </summary>
		/// <param name='pHookAddress'>Hook address.</param>
		bool UnHookImport(const void* const pHookAddress);

		// ----------------------------------------------------------------
		// Export Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook that automatically unhooking.
		/// </summary>
		class ExportHook {
		public:
			/// <summary>
			/// Hook that automatically unhooking.
			/// </summary>
			/// <param name='szModuleName'>Module name.</param>
			/// <param name='szExportName'>Exporting name.</param>
			ExportHook(const HMODULE hModule, const char* const szExportName);
			~ExportHook();

		public:
			/// <summary>
			/// Hook with a specific address.
			/// </summary>
			/// <param name='pHookAddress'>Hook address.</param>
			bool Hook(const void* const pHookAddress);

			/// <summary>
			/// UnHook.
			/// </summary>
			bool UnHook();

		public:
			/// <returns>Returns original address.</returns>
			const void* GetOriginalAddress();

			/// <returns>Returns hook address.</returns>
			const void* GetHookAddress();

		private:
			HMODULE m_hModule;
			PDWORD m_pAddress;
			DWORD m_unOriginalAddress;
			const void* m_pHookAddress;
		};

		// ----------------------------------------------------------------
		// Simple Export Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook with a specific address.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szExportName'>Exporting name.</param>
		/// <param name='pHookAddress'>Hook address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool HookExport(const HMODULE hModule, const char* const szExportName, const void* const pHookAddress);

		/// <summary>
		/// UnHook.
		/// </summary>
		/// <param name='pHookAddress'>Hook address.</param>
		bool UnHookExport(const void* const pHookAddress);

		// ----------------------------------------------------------------
		// Memory Hook CallBack
		// ----------------------------------------------------------------

		typedef bool(__fastcall* fnMemoryHookCallBack)(class MemoryHook* pHook, PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// Memory Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook that automatically unhooking.
		/// </summary>
		class MemoryHook {
		public:
			/// <summary>
			/// Hook that automatically unhooking.
			/// </summary>
			/// <param name='pAddress'>Memory address.</param>
			/// <param name='unSize'>Memory size.</param>
			MemoryHook(const void* const pAddress, const size_t unSize = 1, bool bAutoDisable = false);
			~MemoryHook();

		public:
			/// <summary>
			/// Hook with a specific address.
			/// </summary>
			/// <param name='pCallBack'>Callback address.</param>
			bool Hook(const fnMemoryHookCallBack pCallBack);

			/// <summary>
			/// UnHook.
			/// </summary>
			bool UnHook();

		public:
			/// <summary>
			/// Enable hook.
			/// </summary>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool Enable();

			/// <summary>
			/// Disable hook.
			/// </summary>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool Disable();

		public:
			/// <returns>Returns memory address.</returns>
			const void* const GetAddress();

			/// <returns>Returns memory size.</returns>
			const size_t GetSize();

			/// <returns>Returns auto disable param.</returns>
			bool IsAutoDisable();

			/// <returns>Returns callback address.</returns>
			fnMemoryHookCallBack GetCallBack();

		private:
			const void* const m_pAddress;
			const size_t m_unSize;
			bool m_bAutoDisable;
			fnMemoryHookCallBack m_pCallBack;
		};

		// ----------------------------------------------------------------
		// Simple Memory Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook with a specific address.
		/// </summary>
		/// <param name='pAddress'>Memory address.</param>
		/// <param name='pCallBack'>Callback address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool HookMemory(const void* const pAddress, const fnMemoryHookCallBack pCallBack, bool bAutoDisable = false);

		/// <summary>
		/// UnHook.
		/// </summary>
		/// <param name='pCallBack'>Callback address.</param>
		bool UnHookMemory(const fnMemoryHookCallBack pCallBack);

		/// <summary>
		/// Enable hook.
		/// </summary>
		/// <param name='pCallBack'>Callback address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool EnableHookMemory(const fnMemoryHookCallBack pCallBack);

		/// <summary>
		/// Disable hook.
		/// </summary>
		/// <param name='pCallBack'>Callback address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool DisableHookMemory(const fnMemoryHookCallBack pCallBack);
	}
}

#endif // !_DETOURS_H_
