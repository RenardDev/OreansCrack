#pragma once

#ifndef _DETOURS_H_
#define _DETOURS_H_

#pragma warning(push)
#pragma warning(disable : 4201)

// Default
#include <Windows.h>
#include <TlHelp32.h>

// Advanced
#include <intrin.h>
#include <mmintrin.h>  // MMX
#include <xmmintrin.h> // SSE
#include <emmintrin.h> // SSE2
#include <pmmintrin.h> // SSE3
#include <tmmintrin.h> // SSSE3
#include <smmintrin.h> // SSE4.1
#include <nmmintrin.h> // SSE4.2
#include <immintrin.h> // AVX, AVX2, AVX-512, AMX, SVML

// STL
#include <array>
#include <set>
#include <list>
#include <deque>
#include <mutex>
#include <vector>
#include <memory>

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

// MSVC - Linker
#define LINKER_OPTION(OPTION) __pragma(comment(linker, OPTION))

// MSVC - Symbols
#define INCLUDE(SYMBOL_NAME) LINKER_OPTION("/INCLUDE:" SYMBOL_NAME)
#define SELF_INCLUDE INCLUDE(__FUNCDNAME__)
#define EXPORT(SYMBOL_NAME, ALIAS_NAME) LINKER_OPTION("/EXPORT:" ALIAS_NAME "=" SYMBOL_NAME)
#define SELF_EXPORT(ALIAS_NAME) EXPORT(__FUNCDNAME__, ALIAS_NAME)

// MSVC - Sections
#define SECTION_READONLY "R"
#define SECTION_READWRITE "RW"
#define SECTION_EXECUTE_READ "ER"
#define SECTION_EXECUTE_READWRITE "ERW"
#define DECLARE_SECTION(NAME) __pragma(section(NAME))
#define DEFINE_SECTION(NAME, ATTRIBUTES) LINKER_OPTION("/SECTION:" NAME "," ATTRIBUTES)
#define DEFINE_IN_SECTION(NAME) __declspec(allocate(NAME))

#ifndef PROCESSOR_FEATURE_MAX
#define PROCESSOR_FEATURE_MAX 64
#endif // !PROCESSOR_FEATURE_MAX

#ifndef RTL_MAX_DRIVE_LETTERS
#define RTL_MAX_DRIVE_LETTERS 32
#endif // !RTL_MAX_DRIVE_LETTERS

#ifndef GDI_HANDLE_BUFFER_SIZE32
#define GDI_HANDLE_BUFFER_SIZE32 34
#endif // !GDI_HANDLE_BUFFER_SIZE32

#ifndef GDI_HANDLE_BUFFER_SIZE64
#define GDI_HANDLE_BUFFER_SIZE64 60
#endif // !GDI_HANDLE_BUFFER_SIZE64

#ifndef GDI_BATCH_BUFFER_SIZE
#define GDI_BATCH_BUFFER_SIZE 310
#endif // !GDI_BATCH_BUFFER_SIZE

#ifdef _M_X64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#elif _M_IX86
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#else
#error Only x86 and x86_64 platforms are supported.
#endif

// rddisasm

#define RD_PREF_REP 0x0001
#define RD_PREF_REPC 0x0002
#define RD_PREF_LOCK 0x0004
#define RD_PREF_HLE 0x0008
#define RD_PREF_XACQUIRE 0x0010
#define RD_PREF_XRELEASE 0x0020
#define RD_PREF_BND 0x0040
#define RD_PREF_BHINT 0x0080
#define RD_PREF_HLE_WO_LOCK 0x0100
#define RD_PREF_DNT 0x0200

#define RD_MOD_R0 0x00000001
#define RD_MOD_R1 0x00000002
#define RD_MOD_R2 0x00000004
#define RD_MOD_R3 0x00000008

#define RD_MOD_REAL 0x00000010
#define RD_MOD_V8086 0x00000020
#define RD_MOD_PROT 0x00000040
#define RD_MOD_COMPAT 0x00000080
#define RD_MOD_LONG 0x00000100

#define RD_MOD_SMM 0x00001000
#define RD_MOD_SMM_OFF 0x00002000
#define RD_MOD_SGX 0x00004000
#define RD_MOD_SGX_OFF 0x00008000
#define RD_MOD_TSX 0x00010000
#define RD_MOD_TSX_OFF 0x00020000

#define RD_MOD_VMXR 0x00040000
#define RD_MOD_VMXN 0x00080000
#define RD_MOD_VMXR_SEAM 0x00100000
#define RD_MOD_VMXN_SEAM 0x00200000
#define RD_MOD_VMX_OFF 0x00400000

#define RD_MOD_RING_MASK 0x0000000F
#define RD_MOD_MODE_MASK 0x000001F0
#define RD_MOD_OTHER_MASK 0x0003F000
#define RD_MOD_VMX_MASK 0x007C0000

#define RD_MOD_ANY 0xFFFFFFFF

#define RD_DECO_ER 0x01
#define RD_DECO_SAE 0x02
#define RD_DECO_ZERO 0x04
#define RD_DECO_MASK 0x08
#define RD_DECO_BROADCAST 0x10

#define RD_OPS_CNT(EXPO, IMPO) ((EXPO) | ((IMPO) << 4))
#define RD_EXP_OPS_CNT(CNT) ((CNT) & 0xF)
#define RD_IMP_OPS_CNT(CNT) ((CNT) >> 4)

#define RD_FLAG_MODRM 0x00000001
#define RD_FLAG_F64 0x00000002
#define RD_FLAG_D64 0x00000004
#define RD_FLAG_O64 0x00000008
#define RD_FLAG_I64 0x00000010
#define RD_FLAG_COND 0x00000020
#define RD_FLAG_SSE_CONDB 0x00000040
#define RD_FLAG_VSIB 0x00000080
#define RD_FLAG_MIB 0x00000100
#define RD_FLAG_LIG 0x00000200
#define RD_FLAG_WIG 0x00000400
#define RD_FLAG_3DNOW 0x00000800
#define RD_FLAG_LOCK_SPECIAL 0x00001000
#define RD_FLAG_MMASK 0x00002000
#define RD_FLAG_NOMZ 0x00004000
#define RD_FLAG_NOL0 0x00008000
#define RD_FLAG_NOA16 0x00010000
#define RD_FLAG_MFR 0x00020000
#define RD_FLAG_VECTOR 0x00040000
#define RD_FLAG_S66 0x00080000
#define RD_FLAG_BITBASE 0x00100000
#define RD_FLAG_AG 0x00200000
#define RD_FLAG_SHS 0x00400000
#define RD_FLAG_CETT 0x00800000
#define RD_FLAG_SERIAL 0x01000000
#define RD_FLAG_NO_RIP_REL 0x02000000
#define RD_FLAG_NO66 0x04000000
#define RD_FLAG_SIBMEM 0x08000000
#define RD_FLAG_I67 0x10000000
#define RD_FLAG_IER 0x20000000
#define RD_FLAG_IWO64 0x40000000

#define RDR_RFLAG_CF (1 << 0)
#define RDR_RFLAG_PF (1 << 2)
#define RDR_RFLAG_AF (1 << 4)
#define RDR_RFLAG_ZF (1 << 6)
#define RDR_RFLAG_SF (1 << 7)
#define RDR_RFLAG_TF (1 << 8)
#define RDR_RFLAG_IF (1 << 9)
#define RDR_RFLAG_DF (1 << 10)
#define RDR_RFLAG_OF (1 << 11)
#define RDR_RFLAG_IOPL (3 << 12)
#define RDR_RFLAG_NT (1 << 14)
#define RDR_RFLAG_RF (1 << 16)
#define RDR_RFLAG_VM (1 << 17)
#define RDR_RFLAG_AC (1 << 18)
#define RDR_RFLAG_VIF (1 << 19)
#define RDR_RFLAG_VIP (1 << 20)
#define RDR_RFLAG_ID (1 << 21)

#define RD_CFF_NO_LEAF 0xFFFFFFFF
#define RD_CFF_NO_SUBLEAF 0x00FFFFFF

#define RD_CFF(LEAF, SUBLEAF, REG, BIT) (static_cast<unsigned long long>(LEAF) | (static_cast<unsigned long long>((SUBLEAF) & 0xFFFFFF) << 32) | (static_cast<unsigned long long>(REG) << 56) | (static_cast<unsigned long long>(BIT) << 59))

#define RD_CFF_FPU RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 0)
#define RD_CFF_MSR RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 5)
#define RD_CFF_CX8 RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 8)
#define RD_CFF_SEP RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 11)
#define RD_CFF_CMOV RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 15)
#define RD_CFF_CLFSH RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 19)
#define RD_CFF_MMX RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 23)
#define RD_CFF_FXSAVE RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 24)
#define RD_CFF_SSE RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 25)
#define RD_CFF_SSE2 RD_CFF(0x00000001, 0xFFFFFFFF, RDR_EDX, 26)
#define RD_CFF_SSE3 RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 0)
#define RD_CFF_PCLMULQDQ RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 1)
#define RD_CFF_MONITOR RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 3)
#define RD_CFF_VTX RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 5)
#define RD_CFF_SMX RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 6)
#define RD_CFF_SSSE3 RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 9)
#define RD_CFF_FMA RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 12)
#define RD_CFF_SSE4 RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 19)
#define RD_CFF_SSE42 RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 20)
#define RD_CFF_MOVBE RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 22)
#define RD_CFF_POPCNT RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 23)
#define RD_CFF_AES RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 25)
#define RD_CFF_XSAVE RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 26)
#define RD_CFF_AVX RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 28)
#define RD_CFF_F16C RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 29)
#define RD_CFF_RDRAND RD_CFF(0x00000001, 0xFFFFFFFF, RDR_ECX, 30)
#define RD_CFF_RDWRFSGS RD_CFF(0x00000007, 0x00000000, RDR_EBX, 0)
#define RD_CFF_SGX RD_CFF(0x00000007, 0x00000000, RDR_EBX, 2)
#define RD_CFF_BMI1 RD_CFF(0x00000007, 0x00000000, RDR_EBX, 3)
#define RD_CFF_HLE RD_CFF(0x00000007, 0x00000000, RDR_EBX, 4)
#define RD_CFF_AVX2 RD_CFF(0x00000007, 0x00000000, RDR_EBX, 5)
#define RD_CFF_BMI2 RD_CFF(0x00000007, 0x00000000, RDR_EBX, 8)
#define RD_CFF_INVPCID RD_CFF(0x00000007, 0x00000000, RDR_EBX, 10)
#define RD_CFF_RTM RD_CFF(0x00000007, 0x00000000, RDR_EBX, 11)
#define RD_CFF_MPX RD_CFF(0x00000007, 0x00000000, RDR_EBX, 14)
#define RD_CFF_AVX512F RD_CFF(0x00000007, 0x00000000, RDR_EBX, 16)
#define RD_CFF_AVX512DQ RD_CFF(0x00000007, 0x00000000, RDR_EBX, 17)
#define RD_CFF_RDSEED RD_CFF(0x00000007, 0x00000000, RDR_EBX, 18)
#define RD_CFF_ADX RD_CFF(0x00000007, 0x00000000, RDR_EBX, 19)
#define RD_CFF_SMAP RD_CFF(0x00000007, 0x00000000, RDR_EBX, 20)
#define RD_CFF_AVX512IFMA RD_CFF(0x00000007, 0x00000000, RDR_EBX, 21)
#define RD_CFF_CLFSHOPT RD_CFF(0x00000007, 0x00000000, RDR_EBX, 23)
#define RD_CFF_CLWB RD_CFF(0x00000007, 0x00000000, RDR_EBX, 24)
#define RD_CFF_AVX512PF RD_CFF(0x00000007, 0x00000000, RDR_EBX, 26)
#define RD_CFF_AVX512ER RD_CFF(0x00000007, 0x00000000, RDR_EBX, 27)
#define RD_CFF_AVX512CD RD_CFF(0x00000007, 0x00000000, RDR_EBX, 28)
#define RD_CFF_SHA RD_CFF(0x00000007, 0x00000000, RDR_EBX, 29)
#define RD_CFF_AVX512BW RD_CFF(0x00000007, 0x00000000, RDR_EBX, 30)
#define RD_CFF_PREFETCHWT1 RD_CFF(0x00000007, 0x00000000, RDR_ECX, 0)
#define RD_CFF_AVX512VBMI RD_CFF(0x00000007, 0x00000000, RDR_ECX, 1)
#define RD_CFF_PKU RD_CFF(0x00000007, 0x00000000, RDR_ECX, 3)
#define RD_CFF_WAITPKG RD_CFF(0x00000007, 0x00000000, RDR_ECX, 5)
#define RD_CFF_AVX512VBMI2 RD_CFF(0x00000007, 0x00000000, RDR_ECX, 6)
#define RD_CFF_CET_SS RD_CFF(0x00000007, 0x00000000, RDR_ECX, 7)
#define RD_CFF_GFNI RD_CFF(0x00000007, 0x00000000, RDR_ECX, 8)
#define RD_CFF_VAES RD_CFF(0x00000007, 0x00000000, RDR_ECX, 9)
#define RD_CFF_VPCLMULQDQ RD_CFF(0x00000007, 0x00000000, RDR_ECX, 10)
#define RD_CFF_AVX512VNNI RD_CFF(0x00000007, 0x00000000, RDR_ECX, 11)
#define RD_CFF_AVX512BITALG RD_CFF(0x00000007, 0x00000000, RDR_ECX, 12)
#define RD_CFF_AVX512VPOPCNTDQ RD_CFF(0x00000007, 0x00000000, RDR_ECX, 14)
#define RD_CFF_RDPID RD_CFF(0x00000007, 0x00000000, RDR_ECX, 22)
#define RD_CFF_KL RD_CFF(0x00000007, 0x00000000, RDR_ECX, 23)
#define RD_CFF_CLDEMOTE RD_CFF(0x00000007, 0x00000000, RDR_ECX, 25)
#define RD_CFF_MOVDIRI RD_CFF(0x00000007, 0x00000000, RDR_ECX, 27)
#define RD_CFF_MOVDIR64B RD_CFF(0x00000007, 0x00000000, RDR_ECX, 28)
#define RD_CFF_ENQCMD RD_CFF(0x00000007, 0x00000000, RDR_ECX, 29)
#define RD_CFF_AVX5124VNNIW RD_CFF(0x00000007, 0x00000000, RDR_EDX, 2)
#define RD_CFF_AVX5124FMAPS RD_CFF(0x00000007, 0x00000000, RDR_EDX, 3)
#define RD_CFF_UINTR RD_CFF(0x00000007, 0x00000000, RDR_EDX, 5)
#define RD_CFF_AVX512VP2INTERSECT RD_CFF(0x00000007, 0x00000000, RDR_EDX, 8)
#define RD_CFF_SERIALIZE RD_CFF(0x00000007, 0x00000000, RDR_EDX, 14)
#define RD_CFF_TSXLDTRK RD_CFF(0x00000007, 0x00000000, RDR_EDX, 16)
#define RD_CFF_PCONFIG RD_CFF(0x00000007, 0x00000000, RDR_EDX, 18)
#define RD_CFF_CET_IBT RD_CFF(0x00000007, 0x00000000, RDR_EDX, 20)
#define RD_CFF_AMXBF16 RD_CFF(0x00000007, 0x00000000, RDR_EDX, 22)
#define RD_CFF_AVX512FP16 RD_CFF(0x00000007, 0x00000000, RDR_EDX, 23)
#define RD_CFF_AMXTILE RD_CFF(0x00000007, 0x00000000, RDR_EDX, 24)
#define RD_CFF_AMXINT8 RD_CFF(0x00000007, 0x00000000, RDR_EDX, 25)
#define RD_CFF_SHA512 RD_CFF(0x00000007, 0x00000001, RDR_EAX, 0)
#define RD_CFF_SM3 RD_CFF(0x00000007, 0x00000001, RDR_EAX, 1)
#define RD_CFF_SM4 RD_CFF(0x00000007, 0x00000001, RDR_EAX, 2)
#define RD_CFF_RAOINT RD_CFF(0x00000007, 0x00000001, RDR_EAX, 3)
#define RD_CFF_AVXVNNI RD_CFF(0x00000007, 0x00000001, RDR_EAX, 4)
#define RD_CFF_AVX512BF16 RD_CFF(0x00000007, 0x00000001, RDR_EAX, 5)
#define RD_CFF_CMPCCXADD RD_CFF(0x00000007, 0x00000001, RDR_EAX, 7)
#define RD_CFF_FRED RD_CFF(0x00000007, 0x00000001, RDR_EAX, 17)
#define RD_CFF_LKGS RD_CFF(0x00000007, 0x00000001, RDR_EAX, 18)
#define RD_CFF_WRMSRNS RD_CFF(0x00000007, 0x00000001, RDR_EAX, 19)
#define RD_CFF_AMXFP16 RD_CFF(0x00000007, 0x00000001, RDR_EAX, 21)
#define RD_CFF_HRESET RD_CFF(0x00000007, 0x00000001, RDR_EAX, 22)
#define RD_CFF_AVXIFMA RD_CFF(0x00000007, 0x00000001, RDR_EAX, 23)
#define RD_CFF_MSRLIST RD_CFF(0x00000007, 0x00000001, RDR_EAX, 27)
#define RD_CFF_TSE RD_CFF(0x00000007, 0x00000001, RDR_EBX, 1)
#define RD_CFF_AVXVNNIINT8 RD_CFF(0x00000007, 0x00000001, RDR_EDX, 4)
#define RD_CFF_AVXNECONVERT RD_CFF(0x00000007, 0x00000001, RDR_EDX, 5)
#define RD_CFF_AMXCOMPLEX RD_CFF(0x00000007, 0x00000001, RDR_EDX, 8)
#define RD_CFF_AVXVNNIINT16 RD_CFF(0x00000007, 0x00000001, RDR_EDX, 10)
#define RD_CFF_PREFETCHITI RD_CFF(0x00000007, 0x00000001, RDR_EDX, 14)
#define RD_CFF_XSAVEOPT RD_CFF(0x0000000D, 0x00000001, RDR_EAX, 0)
#define RD_CFF_XSAVEC RD_CFF(0x0000000D, 0x00000001, RDR_EAX, 1)
#define RD_CFF_XSAVES RD_CFF(0x0000000D, 0x00000001, RDR_EAX, 3)
#define RD_CFF_PTWRITE RD_CFF(0x00000014, 0x00000000, RDR_EBX, 4)
#define RD_CFF_SVM RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 2)
#define RD_CFF_LZCNT RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 5)
#define RD_CFF_SSE4A RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 6)
#define RD_CFF_PREFETCHW RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 8)
#define RD_CFF_FSC RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 11)
#define RD_CFF_XOP RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 11)
#define RD_CFF_LWP RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 15)
#define RD_CFF_FMA4 RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 16)
#define RD_CFF_TBM RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 21)
#define RD_CFF_INVLPGB RD_CFF(0x80000001, 0xFFFFFFFF, RDR_EDX, 24)
#define RD_CFF_RDTSCP RD_CFF(0x80000001, 0xFFFFFFFF, RDR_ECX, 27)
#define RD_CFF_3DNOW RD_CFF(0x80000001, 0xFFFFFFFF, RDR_EDX, 31)
#define RD_CFF_WBNOINVD RD_CFF(0x80000008, 0xFFFFFFFF, RDR_EBX, 9)
#define RD_CFF_RDPRU RD_CFF(0x80000008, 0xFFFFFFFF, RDR_EBX, 4)
#define RD_CFF_MCOMMIT RD_CFF(0x80000008, 0xFFFFFFFF, RDR_EBX, 8)
#define RD_CFF_SNP RD_CFF(0x8000001F, 0xFFFFFFFF, RDR_EAX, 4)
#define RD_CFF_RMPQUERY RD_CFF(0x8000001F, 0xFFFFFFFF, RDR_EAX, 6)

#define RD_SUCCESS(STATUS) ((STATUS) < 0x80000000)
#define RD_STATUS_SUCCESS 0x00000000
#define RD_STATUS_HINT_OPERARD_NOT_USED 0x00000001
#define RD_STATUS_BUFFER_TOO_SMALL 0x80000001
#define RD_STATUS_INVALID_ENCODING 0x80000002
#define RD_STATUS_INSTRUCTION_TOO_LONG 0x80000003
#define RD_STATUS_INVALID_PREFIX_SEQUENCE 0x80000004
#define RD_STATUS_INVALID_REGISTER_IN_INSTRUCTION 0x80000005
#define RD_STATUS_XOP_WITH_PREFIX 0x80000006
#define RD_STATUS_VEX_WITH_PREFIX 0x80000007
#define RD_STATUS_EVEX_WITH_PREFIX 0x80000008
#define RD_STATUS_INVALID_ENCODING_IN_MODE 0x80000009
#define RD_STATUS_BAD_LOCK_PREFIX 0x8000000A
#define RD_STATUS_CS_LOAD 0x8000000B
#define RD_STATUS_66_NOT_ACCEPTED 0x8000000C
#define RD_STATUS_16_BIT_ADDRESSING_NOT_SUPPORTED 0x8000000D
#define RD_STATUS_RIP_REL_ADDRESSING_NOT_SUPPORTED 0x8000000E
#define RD_STATUS_VSIB_WITHOUT_SIB 0x80000030
#define RD_STATUS_INVALID_VSIB_REGS 0x80000031
#define RD_STATUS_VEX_VVVV_MUST_BE_ZERO 0x80000032
#define RD_STATUS_MASK_NOT_SUPPORTED 0x80000033
#define RD_STATUS_MASK_REQUIRED 0x80000034
#define RD_STATUS_ER_SAE_NOT_SUPPORTED 0x80000035
#define RD_STATUS_ZEROING_NOT_SUPPORTED 0x80000036
#define RD_STATUS_ZEROING_ON_MEMORY 0x80000037
#define RD_STATUS_ZEROING_NO_MASK 0x80000038
#define RD_STATUS_BROADCAST_NOT_SUPPORTED 0x80000039
#define RD_STATUS_BAD_EVEX_V_PRIME 0x80000040
#define RD_STATUS_BAD_EVEX_LL 0x80000041
#define RD_STATUS_SIBMEM_WITHOUT_SIB 0x80000042
#define RD_STATUS_INVALID_TILE_REGS 0x80000043
#define RD_STATUS_INVALID_DEST_REGS 0x80000044
#define RD_STATUS_INVALID_PARAMETER 0x80000100
#define RD_STATUS_INVALID_INSTRUX 0x80000101
#define RD_STATUS_BUFFER_OVERFLOW 0x80000103
#define RD_STATUS_INTERNAL_ERROR 0x80000200

#define RDR_IA32_TSC 0x00000010
#define RDR_IA32_SYSENTER_CS 0x00000174
#define RDR_IA32_SYSENTER_ESP 0x00000175
#define RDR_IA32_SYSENTER_EIP 0x00000176
#define RDR_IA32_STAR 0xC0000081
#define RDR_IA32_LSTAR 0xC0000082
#define RDR_IA32_FMASK 0xC0000084
#define RDR_IA32_FS_BASE 0xC0000100
#define RDR_IA32_GS_BASE 0xC0000101
#define RDR_IA32_KERNEL_GS_BASE 0xC0000102
#define RDR_IA32_TSC_AUX 0xC0000103
#define RDR_MSR_ANY 0xFFFFFFFF

#define RD_VERD_ANY 0
#define RD_VERD_INTEL 1
#define RD_VERD_AMD 2
#define RD_VERD_GEODE 3
#define RD_VERD_CYRIX 4

#define RD_FEAT_NONE 0x00
#define RD_FEAT_MPX 0x01
#define RD_FEAT_CET 0x02
#define RD_FEAT_CLDEMOTE 0x04
#define RD_FEAT_PITI 0x08
#define RD_FEAT_ALL 0xFF

#define RD_CODE_16 0
#define RD_CODE_32 1
#define RD_CODE_64 2

#define RD_DATA_16 0
#define RD_DATA_32 1
#define RD_DATA_64 2

#define RD_STACK_16 0
#define RD_STACK_32 1
#define RD_STACK_64 2

#define RD_ADDR_16 0
#define RD_ADDR_32 1
#define RD_ADDR_64 2

#define RD_OPSZ_16 0
#define RD_OPSZ_32 1
#define RD_OPSZ_64 2

#define RD_VECM_128 0
#define RD_VECM_256 1
#define RD_VECM_512 2

#define RD_ENCM_LEGACY 0
#define RD_ENCM_XOP 1
#define RD_ENCM_VEX 2
#define RD_ENCM_EVEX 3

#define RD_VEXM_2B 0
#define RD_VEXM_3B 1

#define RD_SIZE_8BIT 1
#define RD_SIZE_16BIT 2
#define RD_SIZE_32BIT 4
#define RD_SIZE_48BIT 6
#define RD_SIZE_64BIT 8
#define RD_SIZE_80BIT 10
#define RD_SIZE_112BIT 14
#define RD_SIZE_128BIT 16
#define RD_SIZE_224BIT 28
#define RD_SIZE_256BIT 32
#define RD_SIZE_384BIT 48
#define RD_SIZE_512BIT 64
#define RD_SIZE_752BIT 94
#define RD_SIZE_864BIT 108
#define RD_SIZE_4096BIT 512
#define RD_SIZE_1KB 1024
#define RD_SIZE_CACHE_LINE 0xFFFFFFFE
#define RD_SIZE_UNKNOWN 0xFFFFFFFF

#define RD_PREFIX_G0_LOCK 0xF0
#define RD_PREFIX_G1_REPNE_REPNZ 0xF2
#define RD_PREFIX_G1_XACQUIRE 0xF2
#define RD_PREFIX_G1_REPE_REPZ 0xF3
#define RD_PREFIX_G1_XRELEASE 0xF3
#define RD_PREFIX_G1_BND 0xF2
#define RD_PREFIX_G2_SEG_CS 0x2E
#define RD_PREFIX_G2_SEG_SS 0x36
#define RD_PREFIX_G2_SEG_DS 0x3E
#define RD_PREFIX_G2_SEG_ES 0x26
#define RD_PREFIX_G2_SEG_FS 0x64
#define RD_PREFIX_G2_SEG_GS 0x65
#define RD_PREFIX_G2_BR_NOT_TAKEN 0x2E
#define RD_PREFIX_G2_BR_TAKEN 0x3E
#define RD_PREFIX_G2_BR_ALT 0x64
#define RD_PREFIX_G2_NO_TRACK 0x3E
#define RD_PREFIX_G3_OPERARD_SIZE 0x66
#define RD_PREFIX_G4_ADDR_SIZE 0x67

#define RD_PREFIX_REX_MIN 0x40
#define RD_PREFIX_REX_MAX 0x4F
#define RD_PREFIX_VEX_2B 0xC5
#define RD_PREFIX_VEX_3B 0xC4
#define RD_PREFIX_XOP 0x8F
#define RD_PREFIX_EVEX 0x62

#define RD_ACCESS_NONE 0x00
#define RD_ACCESS_READ 0x01
#define RD_ACCESS_WRITE 0x02
#define RD_ACCESS_CORD_READ 0x04
#define RD_ACCESS_CORD_WRITE 0x08
#define RD_ACCESS_ANY_READ (RD_ACCESS_READ | RD_ACCESS_CORD_READ)
#define RD_ACCESS_ANY_WRITE (RD_ACCESS_WRITE | RD_ACCESS_CORD_WRITE)
#define RD_ACCESS_PREFETCH 0x10

#define RD_CORD_OVERFLOW 0x0
#define RD_CORD_CARRY 0x2
#define RD_CORD_BELOW 0x2
#define RD_CORD_NOT_ABOVE_OR_EQUAL 0x2
#define RD_CORD_ZERO 0x4
#define RD_CORD_EQUAL 0x4
#define RD_CORD_BELOW_OR_EQUAL 0x6
#define RD_CORD_NOT_ABOVE 0x6
#define RD_CORD_SIGN 0x8
#define RD_CORD_PARITY 0xA
#define RD_CORD_LESS 0xC
#define RD_CORD_LESS_OR_EQUAL 0xE
#define RD_CORD_NOT(X) ((X) | 0x1)

#define RD_PRED_OVERFLOW 0x0
#define RD_PRED_CARRY 0x2
#define RD_PRED_BELOW 0x2
#define RD_PRED_NOT_ABOVE_OR_EQUAL 0x2
#define RD_PRED_ZERO 0x4
#define RD_PRED_EQUAL 0x4
#define RD_PRED_BELOW_OR_EQUAL 0x6
#define RD_PRED_NOT_ABOVE 0x6
#define RD_PRED_SIGN 0x8
#define RD_PRED_PARITY 0xA
#define RD_PRED_LESS 0xC
#define RD_PRED_LESS_OR_EQUAL 0xE
#define RD_PRED_NOT(X) ((X) | 0x1)

#define RD_SSE_CORD_EQ 0x00
#define RD_SSE_CORD_LT 0x01
#define RD_SSE_CORD_LE 0x02
#define RD_SSE_CORD_UNORD 0x03
#define RD_SSE_COfalse1 0x03
#define RD_SSE_CORD_NEQ 0x04
#define RD_SSE_CORD_NLT 0x05
#define RD_SSE_CORD_NLE 0x06
#define RD_SSE_CORD_ORD 0x07
#define RD_SSE_COtrue1 0x07
#define RD_SSE_CORD_EQ_UQ 0x08
#define RD_SSE_CORD_NGE 0x09
#define RD_SSE_CORD_NGT 0x0A
#define RD_SSE_COfalse 0x0B
#define RD_SSE_CORD_NEQ_OQ 0x0C
#define RD_SSE_CORD_GE 0x0D
#define RD_SSE_CORD_GT 0x0E
#define RD_SSE_COtrue 0x0F
#define RD_SSE_CORD_EQ_OS 0x10
#define RD_SSE_CORD_LT_OQ 0x11
#define RD_SSE_CORD_LE_OQ 0x12
#define RD_SSE_CORD_UNORD_S 0x13
#define RD_SSE_CORD_NEQ_US 0x14
#define RD_SSE_CORD_NLT_UQ 0x15
#define RD_SSE_CORD_NLE_UQ 0x16
#define RD_SSE_CORD_ORD_S 0x17
#define RD_SSE_CORD_EQ_US 0x18
#define RD_SSE_CORD_NGE_UQ 0x19
#define RD_SSE_CORD_NGT_UQ 0x1A
#define RD_SSE_COfalse_OS 0x1B
#define RD_SSE_CORD_NEQ_OS 0x1C
#define RD_SSE_CORD_GE_OQ 0x1D
#define RD_SSE_CORD_GT_OQ 0x1E
#define RD_SSE_COtrue_US 0x1F

#define RD_MAX_INSTRUCTION_LENGTH 15
#define RD_MAX_MNEMONIC_LENGTH 32
#define RD_MIN_BUF_SIZE 128
#define RD_MAX_OPERAND 10
#define RD_MAX_REGISTER_SIZE 64

#define RD_MAX_GPR_REGS 16
#define RD_MAX_SEG_REGS 8
#define RD_MAX_FPU_REGS 8
#define RD_MAX_MMX_REGS 8
#define RD_MAX_SSE_REGS 32
#define RD_MAX_CR_REGS 16
#define RD_MAX_DR_REGS 16
#define RD_MAX_TR_REGS 16
#define RD_MAX_MSK_REGS 8
#define RD_MAX_BRD_REGS 4
#define RD_MAX_SYS_REGS 8
#define RD_MAX_X87_REGS 8
#define RD_MAX_TILE_REGS 8

#define RD_SIGN_EX_8(X) (((X) & 0x00000080) ? (0xFFFFFFFFFFFFFF00 | (X)) : ((X) & 0xFF))
#define RD_SIGN_EX_16(X) (((X) & 0x00008000) ? (0xFFFFFFFFFFFF0000 | (X)) : ((X) & 0xFFFF))
#define RD_SIGN_EX_32(X) (((X) & 0x80000000) ? (0xFFFFFFFF00000000 | (X)) : ((X) & 0xFFFFFFFF))
#define RD_SIGN_EX(S, X) ((S) == 1 ? RD_SIGN_EX_8(X) : (S) == 2 ? RD_SIGN_EX_16(X) : (S) == 4 ? RD_SIGN_EX_32(X) : (X))
#define RD_TRIM(S, X) ((S) == 1 ? (X) & 0xFF : (S) == 2 ? (X) & 0xFFFF : (S) == 4 ? (X) & 0xFFFFFFFF : (X))
#define RD_MSB(S, X) ((S) == 1 ? ((X) >> 7) & 1 : (S) == 2 ? ((X) >> 15) & 1 : (S) == 4 ? ((X) >> 31) & 1 : ((X) >> 63) & 1)
#define RD_LSB(S, X) ((X) & 1)
#define RD_SIZE_TO_MASK(S) (((S) < 8) ? ((1ULL << ((S) * 8)) - 1) : (0xFFFFFFFFFFFFFFFF))
#define RD_GET_BIT(BIT, X) (((X) >> (BIT)) & 1)
#define RD_GET_SIGN(S, X) RD_MSB(S, X)
#define RD_SET_SIGN(S, X) RD_SIGN_EX(S, X)

#define RD_FETCH_64(X) (*reinterpret_cast<unsigned long long*>(X))
#define RD_FETCH_32(X) (*reinterpret_cast<unsigned int*>(X))
#define RD_FETCH_16(X) (*reinterpret_cast<unsigned short*>(X))
#define RD_FETCH_8(X) (*reinterpret_cast<unsigned char*>(X))

#define RD_IS_3DNOW(X) ((X)->Attributes & RD_FLAG_3DNOW)
#define RD_HAS_PREDICATE(X) ((X)->Attributes & RD_FLAG_COND)
#define RD_HAS_CONDITION(X) ((X)->Attributes & RD_FLAG_COND)
#define RD_HAS_SSE_CONDITION(X) ((X)->Attributes & RD_FLAG_SSE_CONDB)
#define RD_HAS_MODRM(X) ((X)->Attributes & RD_FLAG_MODRM)
#define RD_HAS_VSIB(X) ((X)->Attributes & RD_FLAG_VSIB)
#define RD_HAS_MIB(X) ((X)->Attributes & RD_FLAG_MIB)
#define RD_HAS_VECTOR(X) ((X)->Attributes & RD_FLAG_VECTOR)
#define RD_HAS_BITBASE(X) ((X)->Attributes & RD_FLAG_BITBASE)
#define RD_HAS_AG(X) ((X)->Attributes & RD_FLAG_AG)
#define RD_HAS_SIBMEM(X) ((X)->Attributes & RD_FLAG_SIBMEM)
#define RD_HAS_SHS(X) ((X)->Attributes & RD_FLAG_SHS)
#define RD_HAS_CETT(X) ((X)->Attributes & RD_FLAG_CETT)

#define RD_REP_SUPPORT(X) ((X)->ValidPrefixes.Rep)
#define RD_REPC_SUPPORT(X) ((X)->ValidPrefixes.RepCond)
#define RD_LOCK_SUPPORT(X) ((X)->ValidPrefixes.Lock)
#define RD_HLE_SUPPORT(X) ((X)->ValidPrefixes.Hle)
#define RD_XACQUIRE_SUPPORT(X) ((X)->ValidPrefixes.Xacquire)
#define RD_XRELEASE_SUPPORT(X) ((X)->ValidPrefixes.Xrelease)
#define RD_BRD_SUPPORT(X) ((X)->ValidPrefixes.Bnd)
#define RD_BHINT_SUPPORT(X) ((X)->ValidPrefixes.Bhint)
#define RD_DNT_SUPPORT(X) ((X)->ValidPrefixes.Dnt)

#define RD_DECORATOR_SUPPORT(X) ((X)->ValidDecorators.Raw)
#define RD_MASK_SUPPORT(X) ((X)->ValidDecorators.Mask)
#define RD_ZERO_SUPPORT(X) ((X)->ValidDecorators.Zero)
#define RD_ER_SUPPORT(X) ((X)->ValidDecorators.Er)
#define RD_SAE_SUPPORT(X) ((X)->ValidDecorators.Sae)
#define RD_BROADCAST_SUPPORT(X) ((X)->ValidDecorators.Broadcast)

#define RD_OP_REG_ID(OP) ((static_cast<unsigned long long>((OP)->Type & 0xF) << 60) | (static_cast<unsigned long long>((OP)->Info.Register.Type & 0xFF) << 52) | (static_cast<unsigned long long>((op)->Info.Register.Size & 0xFFFF) << 36) | (static_cast<unsigned long long>((op)->Info.Register.Count & 0x3F) << 30) | (static_cast<unsigned long long>((OP)->Info.Register.IsHigh8 & 0x1) << 8) | (static_cast<unsigned long long>((OP)->Info.Register.Reg)))

#define RD_IS_OP_REG(OP, T, S, R) (RD_OP_REG_ID(OP) == ((static_cast<unsigned long long>(RD_OP_REG) << 60) | (static_cast<unsigned long long>((T) & 0xFF) << 52) | (static_cast<unsigned long long>((S) & 0xFFFF) << 36) | (1ULL << 30) | (static_cast<unsigned long long>(R))))
#define RD_IS_OP_REG_EX(OP, T, S, R, B, H) (RD_OP_REG_ID(OP) == ((static_cast<unsigned long long>(RD_OP_REG) << 60) | (static_cast<unsigned long long>((T) & 0xFF) << 52) | (static_cast<unsigned long long>((S) & 0xFFFF) << 36) | (static_cast<unsigned long long>((B) & 0x3F) << 30) | (static_cast<unsigned long long>((H) & 0x1) << 8) | (static_cast<unsigned long long>(R))))
#define RD_IS_OP_STACK(OP) (((OP)->Type == RD_OP_MEM) && (OP)->Info.Memory.IsStack)

#define RD_FPU_FLAG_SET_0 0
#define RD_FPU_FLAG_SET_1 1
#define RD_FPU_FLAG_MODIFIED 2
#define RD_FPU_FLAG_UNDEFINED 3

// Hook
#ifndef HOOK_STORAGE_CAPACITY
#define HOOK_STORAGE_CAPACITY 0x800000 // 8 MiB - Max memory usage for hooks.
#endif // !HOOK_STORAGE_CAPACITY

#ifndef HOOK_INLINE_TRAMPOLINE_SIZE
#define HOOK_INLINE_TRAMPOLINE_SIZE 0x30 // Max trampoline size.
#endif // !HOOK_INLINE_TRAMPOLINE_SIZE

#ifndef HOOK_INLINE_WRAPPER_SIZE
#ifdef _M_X64
#define HOOK_INLINE_WRAPPER_SIZE 0x18 // Max wrapper size.
#elif _M_IX86
#define HOOK_INLINE_WRAPPER_SIZE 0x18 // Max wrapper size.
#endif
#endif // !HOOK_INLINE_WRAPPER_SIZE

#ifndef HOOK_RAW_WRAPPER_SIZE
#ifdef _M_X64
#define HOOK_RAW_WRAPPER_SIZE 0x500 // Max wrapper size.
#elif _M_IX86
#define HOOK_RAW_WRAPPER_SIZE 0x300 // Max wrapper size.
#endif
#endif // !HOOK_RAW_WRAPPER_SIZE

#ifndef HOOK_RAW_TRAMPOLINE_SIZE
#define HOOK_RAW_TRAMPOLINE_SIZE 0x30 // Max trampoline size.
#endif // !HOOK_RAW_TRAMPOLINE_SIZE

// ----------------------------------------------------------------
// Detours
// ----------------------------------------------------------------

namespace Detours {

	// ----------------------------------------------------------------
	// KUSER_SHARED_DATA
	// ----------------------------------------------------------------

	typedef enum _NT_PRODUCT_TYPE {
		NtProductWinNt = 1,
		NtProductLanManNt,
		NtProductServer
	} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

	typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
		StandardDesign,
		NEC98x86,
		EndAlternatives
	} ALTERNATIVE_ARCHITECTURE_TYPE, *PALTERNATIVE_ARCHITECTURE_TYPE;

	typedef struct _KSYSTEM_TIME {
		ULONG LowPart;
		LONG High1Time;
		LONG High2Time;
	} KSYSTEM_TIME, *PKSYSTEM_TIME;

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
		volatile LONG TimeZoneBiasStamp;
		ULONG NtBuildNumber;
		NT_PRODUCT_TYPE NtProductType;
		BOOLEAN ProductTypeIsValid;
		BOOLEAN Reserved0[1];
		USHORT NativeProcessorArchitecture;
		ULONG NtMajorVersion;
		ULONG NtMinorVersion;
		BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
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
		ULONG Reserved2;
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
				volatile UCHAR QpcBypassEnabled;
				UCHAR QpcShift;
			};
		};
		LARGE_INTEGER TimeZoneBiasEffectiveStart;
		LARGE_INTEGER TimeZoneBiasEffectiveEnd;
		XSTATE_CONFIGURATION XState;
		KSYSTEM_TIME FeatureConfigurationChangeStamp;
		ULONG Spare;
		ULONG64 UserPointerAuthMask;
	} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

	extern const volatile KUSER_SHARED_DATA& KUserSharedData;

	// ----------------------------------------------------------------
	// LDR
	// ----------------------------------------------------------------

	typedef enum _LDR_DDAG_STATE {
		LdrModulesMerged = -5,
		LdrModulesInitError = -4,
		LdrModulesSnapError = -3,
		LdrModulesUnloaded = -2,
		LdrModulesUnloading = -1,
		LdrModulesPlaceHolder = 0,
		LdrModulesMapping = 1,
		LdrModulesMapped = 2,
		LdrModulesWaitingForDependencies = 3,
		LdrModulesSnapping = 4,
		LdrModulesSnapped = 5,
		LdrModulesCondensed = 6,
		LdrModulesReadyToInit = 7,
		LdrModulesInitializing = 8,
		LdrModulesReadyToRun = 9
	} LDR_DDAG_STATE, *PLDR_DDAG_STATE;

	typedef enum _LDR_DLL_LOAD_REASON {
		LoadReasonStaticDependency,
		LoadReasonStaticForwarderDependency,
		LoadReasonDynamicForwarderDependency,
		LoadReasonDelayloadDependency,
		LoadReasonDynamicLoad,
		LoadReasonAsImageLoad,
		LoadReasonAsDataLoad,
		LoadReasonEnclavePrimary,
		LoadReasonEnclaveDependency,
		LoadReasonPatchImage,
		LoadReasonUnknown = -1
	} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

	typedef enum _LDR_HOT_PATCH_STATE {
		LdrHotPatchBaseImage,
		LdrHotPatchNotApplied,
		LdrHotPatchAppliedReverse,
		LdrHotPatchAppliedForward,
		LdrHotPatchFailedToPatch,
		LdrHotPatchStateMax
	} LDR_HOT_PATCH_STATE, *PLDR_HOT_PATCH_STATE;

	typedef BOOLEAN(NTAPI* PLDR_INIT_ROUTINE)(PVOID DllHandle, ULONG Reason, PVOID Context);

	typedef struct _LDR_SERVICE_TAG_RECORD {
		struct _LDR_SERVICE_TAG_RECORD* Next;
		ULONG ServiceTag;
	} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

	typedef struct _LDRP_CSLIST {
		PSINGLE_LIST_ENTRY Tail;
	} LDRP_CSLIST, *PLDRP_CSLIST;

	typedef struct _LDR_DDAG_NODE {
		LIST_ENTRY Modules;
		PLDR_SERVICE_TAG_RECORD ServiceTagList;
		ULONG LoadCount;
		ULONG LoadWhileUnloadingCount;
		ULONG LowestLink;
		union {
			LDRP_CSLIST Dependencies;
			SINGLE_LIST_ENTRY RemovalLink;
		};
		LDRP_CSLIST IncomingDependencies;
		LDR_DDAG_STATE State;
		SINGLE_LIST_ENTRY CondenseLink;
		ULONG PreorderNumber;
	} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

	typedef struct _RTL_BALANCED_NODE {
		union {
			struct _RTL_BALANCED_NODE* Children[2];
			struct {
				struct _RTL_BALANCED_NODE* Left;
				struct _RTL_BALANCED_NODE* Right;
			};
		};
		union {
			UCHAR Red : 1;
			UCHAR Balance : 2;
			ULONG_PTR ParentValue;
		};
	} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

	typedef struct _RTL_RB_TREE {
		PRTL_BALANCED_NODE Root;
		PRTL_BALANCED_NODE Min;
	} RTL_RB_TREE, *PRTL_RB_TREE;

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWCH Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union {
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PLDR_INIT_ROUTINE EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		union {
			UCHAR FlagGroup[4];
			ULONG Flags;
			struct {
				ULONG PackagedBinary : 1;
				ULONG MarkedForRemoval : 1;
				ULONG ImageDll : 1;
				ULONG LoadNotificationsSent : 1;
				ULONG TelemetryEntryProcessed : 1;
				ULONG ProcessStaticImport : 1;
				ULONG InLegacyLists : 1;
				ULONG InIndexes : 1;
				ULONG ShimDll : 1;
				ULONG InExceptionTable : 1;
				ULONG ReservedFlags1 : 2;
				ULONG LoadInProgress : 1;
				ULONG LoadConfigProcessed : 1;
				ULONG EntryProcessed : 1;
				ULONG ProtectDelayLoad : 1;
				ULONG ReservedFlags3 : 2;
				ULONG DontCallForThreads : 1;
				ULONG ProcessAttachCalled : 1;
				ULONG ProcessAttachFailed : 1;
				ULONG CorDeferredValidate : 1;
				ULONG CorImage : 1;
				ULONG DontRelocate : 1;
				ULONG CorILOnly : 1;
				ULONG ChpeImage : 1;
				ULONG ChpeEmulatorImage : 1;
				ULONG ReservedFlags5 : 1;
				ULONG Redirected : 1;
				ULONG ReservedFlags6 : 2;
				ULONG CompatDatabaseProcessed : 1;
			};
		};
		USHORT ObsoleteLoadCount;
		USHORT TlsIndex;
		LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
		struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
		PVOID Lock;
		PLDR_DDAG_NODE DdagNode;
		LIST_ENTRY NodeModuleLink;
		struct _LDRP_LOAD_CONTEXT* LoadContext;
		PVOID ParentDllBase;
		PVOID SwitchBackContext;
		RTL_BALANCED_NODE BaseAddressIndexNode;
		RTL_BALANCED_NODE MappingInfoIndexNode;
		ULONG_PTR OriginalBase;
		LARGE_INTEGER LoadTime;
		ULONG BaseNameHashValue;
		LDR_DLL_LOAD_REASON LoadReason;
		ULONG ImplicitPathOptions;
		ULONG ReferenceCount;
		ULONG DependentLoadFlags;
		UCHAR SigningLevel;
		ULONG CheckSum;
		PVOID ActivePatchImageBase;
		LDR_HOT_PATCH_STATE HotPatchState;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	// ----------------------------------------------------------------
	// PEB
	// ----------------------------------------------------------------

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
		RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
		ULONG_PTR EnvironmentSize;
		ULONG_PTR EnvironmentVersion;
		PVOID PackageDependencyData;
		ULONG ProcessGroupId;
		ULONG LoaderThreads;
		UNICODE_STRING RedirectionDllName;
		UNICODE_STRING HeapPartitionName;
		ULONG_PTR DefaultThreadpoolCpuSetMasks;
		ULONG DefaultThreadpoolCpuSetMaskCount;
		ULONG DefaultThreadpoolThreadMaximum;
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

	using GDI_HANDLE_BUFFER = ULONG[GDI_HANDLE_BUFFER_SIZE];
	using GDI_HANDLE_BUFFER32 = ULONG[GDI_HANDLE_BUFFER_SIZE32];
	using GDI_HANDLE_BUFFER64 = ULONG[GDI_HANDLE_BUFFER_SIZE64];

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
		GDI_HANDLE_BUFFER GdiHandleBuffer;
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
		union {
			PVOID pContextData;
			PVOID pUnused;
			PVOID EcCodeBitMap;
		};
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
		RTL_SRWLOCK TppWorkerpListLock;
		LIST_ENTRY TppWorkerpList;
		PVOID WaitOnAddressHashTable[128];
		PVOID TelemetryCoverageHeader;
		ULONG CloudFileFlags;
		ULONG CloudFileDiagFlags;
		CHAR PlaceholderCompatibilityMode;
		CHAR PlaceholderCompatibilityModeReserved[7];
		struct _LEAP_SECOND_DATA* LeapSecondData;
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

	PPEB GetPEB();

	// ----------------------------------------------------------------
	// TEB
	// ----------------------------------------------------------------

	typedef struct _CLIENT_ID32 {
		ULONG UniqueProcess;
		ULONG UniqueThread;
	} CLIENT_ID32, *PCLIENT_ID32;

	typedef struct _CLIENT_ID64 {
		ULONGLONG UniqueProcess;
		ULONGLONG UniqueThread;
	} CLIENT_ID64, *PCLIENT_ID64;

#ifdef _M_X64
	typedef CLIENT_ID64 CLIENT_ID;
	typedef PCLIENT_ID64 PCLIENT_ID;
#elif _M_IX86
	typedef CLIENT_ID32 CLIENT_ID;
	typedef PCLIENT_ID32 PCLIENT_ID;
#endif

	typedef struct _ACTIVATION_CONTEXT_STACK {
		struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
		LIST_ENTRY FrameListCache;
		ULONG Flags;
		ULONG NextCookieSequenceNumber;
		ULONG StackId;
	} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

	typedef struct _GDI_TEB_BATCH {
		ULONG Offset;
		ULONG_PTR HDC;
		ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
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
		LONG ExceptionCode; // NTSTATUS
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
		LONG LastStatusValue; // NTSTATUS
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

	PTEB GetTEB();

	// ----------------------------------------------------------------
	// LDR
	// ----------------------------------------------------------------

	namespace LDR {

		// ----------------------------------------------------------------
		// List Entry APIs
		// ----------------------------------------------------------------

		void InitializeListHead(PLIST_ENTRY pListHead);
		void InsertHeadList(PLIST_ENTRY pListHead, PLIST_ENTRY pEntry);
		void InsertTailList(PLIST_ENTRY pListHead, PLIST_ENTRY pEntry);
		void RemoveEntryList(PLIST_ENTRY pEntry);
		void RemoveHeadList(PLIST_ENTRY pListHead);
		void RemoveTailList(PLIST_ENTRY pListHead);

		PLIST_ENTRY GetListHeadFromEntry(PLIST_ENTRY pEntry);

		// ----------------------------------------------------------------
		// GetHeadsOfLists
		// ----------------------------------------------------------------

		bool GetHeadsOfLists(PLIST_ENTRY* pInLoadOrderModuleList, PLIST_ENTRY* pInMemoryOrderModuleList, PLIST_ENTRY* pInInitializationOrderModuleList);

		// ----------------------------------------------------------------
		// FindModuleListEntry
		// ----------------------------------------------------------------

		PLIST_ENTRY FindModuleListEntry(void* pBaseAddress);
		PLIST_ENTRY FindModuleListEntry(HMODULE hModule);
		PLIST_ENTRY FindModuleListEntryA(const char* szModuleName);
		PLIST_ENTRY FindModuleListEntryW(const wchar_t* szModuleName);
#ifdef _UNICODE
		PLIST_ENTRY FindModuleListEntry(const wchar_t* szModuleName);
#else
		PLIST_ENTRY FindModuleListEntry(const char* szModuleName);
#endif

		// ----------------------------------------------------------------
		// FindModuleDataTableEntry
		// ----------------------------------------------------------------

		PLDR_DATA_TABLE_ENTRY FindModuleDataTableEntry(void* pBaseAddress);
		PLDR_DATA_TABLE_ENTRY FindModuleDataTableEntry(HMODULE hModule);
		PLDR_DATA_TABLE_ENTRY FindModuleDataTableEntryA(const char* szModuleName);
		PLDR_DATA_TABLE_ENTRY FindModuleDataTableEntryW(const wchar_t* szModuleName);
#ifdef _UNICODE
		PLDR_DATA_TABLE_ENTRY FindModuleDataTableEntry(const wchar_t* szModuleName);
#else
		PLDR_DATA_TABLE_ENTRY FindModuleDataTableEntry(const char* szModuleName);
#endif

		// ----------------------------------------------------------------
		// LINK_DATA
		// ----------------------------------------------------------------

		typedef struct _LINK_DATA {
			PLIST_ENTRY m_pHeadInLoadOrderLinks;
			PLIST_ENTRY m_pHeadInMemoryOrderLinks;
			PLIST_ENTRY m_pHeadInInitializationOrderLinks;
			PLIST_ENTRY m_pHeadHashLinks;
			PLIST_ENTRY m_pHeadNodeModuleLink;
			PLIST_ENTRY m_pSavedInLoadOrderLinks;
			PLIST_ENTRY m_pSavedInMemoryOrderLinks;
			PLIST_ENTRY m_pSavedInInitializationOrderLinks;
			PLIST_ENTRY m_pSavedHashLinks;
			PLIST_ENTRY m_pSavedNodeModuleLink;
		} LINK_DATA, *PLINK_DATA;

		// ----------------------------------------------------------------
		// UnLinkModule
		// ----------------------------------------------------------------

		bool UnLinkModule(void* pBaseAddress, PLINK_DATA pLinkData);
		bool UnLinkModule(HMODULE hModule, PLINK_DATA pLinkData);
		bool UnLinkModuleA(const char* szModuleName, PLINK_DATA pLinkData);
		bool UnLinkModuleW(const wchar_t* szModuleName, PLINK_DATA pLinkData);
#ifdef _UNICODE
		bool UnLinkModule(const wchar_t* szModuleName, PLINK_DATA pLinkData);
#else
		bool UnLinkModule(const char* szModuleName, PLINK_DATA pLinkData);
#endif

		// ----------------------------------------------------------------
		// ReLinkModule
		// ----------------------------------------------------------------

		bool ReLinkModule(LINK_DATA LinkData);
	}

	// ----------------------------------------------------------------
	// Codec
	// ----------------------------------------------------------------

	namespace Codec {

		// ----------------------------------------------------------------
		// Encode
		// ----------------------------------------------------------------

		int Encode(unsigned short unCodePage, char const* const szText, wchar_t* szBuffer = nullptr, const int nBufferSize = 0);

		// ----------------------------------------------------------------
		// Decode
		// ----------------------------------------------------------------

		int Decode(unsigned short unCodePage, wchar_t const* const szText, char* szBuffer = nullptr, const int nBufferSize = 0);
	}

	// ----------------------------------------------------------------
	// Hexadecimal
	// ----------------------------------------------------------------

	namespace Hexadecimal {

		// ----------------------------------------------------------------
		// Encode
		// ----------------------------------------------------------------

		bool EncodeA(void const* const pData, const size_t unSize, char* szHex, const unsigned char unIgnoredByte = 0x2A);
		bool EncodeW(void const* const pData, const size_t unSize, wchar_t* szHex, const unsigned char unIgnoredByte = 0x2A);
#ifdef _UNICODE
		bool Encode(void const* const pData, const size_t unSize, wchar_t* szHex, const unsigned char unIgnoredByte = 0x2A);
#else
		bool Encode(void const* const pData, const size_t unSize, char* szHex, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// Decode
		// ----------------------------------------------------------------

		bool DecodeA(char const* const szHex, void* pData, const unsigned char unIgnoredByte = 0x2A);
		bool DecodeW(wchar_t const* const szHex, void* pData, const unsigned char unIgnoredByte = 0x2A);
#ifdef _UNICODE
		bool Decode(wchar_t const* const szHex, void* pData, const unsigned char unIgnoredByte = 0x2A);
#else
		bool Decode(char const* const szHex, void* pData, const unsigned char unIgnoredByte = 0x2A);
#endif
	}

	// ----------------------------------------------------------------
	// Scan
	// ----------------------------------------------------------------

	namespace Scan {

		// ----------------------------------------------------------------
		// FindSection
		// ----------------------------------------------------------------

		bool FindSection(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, void** pAddress, size_t* pSize) noexcept;
		bool FindSectionA(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, void** pAddress, size_t* pSize) noexcept;
		bool FindSectionW(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, void** pAddress, size_t* pSize) noexcept;
#ifdef _UNICODE
		bool FindSection(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, void** pAddress, size_t* pSize) noexcept;
#else
		bool FindSection(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, void** pAddress, size_t* pSize) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindSectionPOGO
		// ----------------------------------------------------------------

		bool FindSectionPOGO(const HMODULE hModule, char const* const szSectionName, void** pAddress, size_t* pSize) noexcept;
		bool FindSectionPOGOA(char const* const szModuleName, char const* const szSectionName, void** pAddress, size_t* pSize) noexcept;
		bool FindSectionPOGOW(wchar_t const* const szModuleName, char const* const szSectionName, void** pAddress, size_t* pSize) noexcept;
#ifdef _UNICODE
		bool FindSectionPOGO(wchar_t const* const szModuleName, char const* const szSectionName, void** pAddress, size_t* pSize) noexcept;
#else
		bool FindSectionPOGO(char const* const szModuleName, char const* const szSectionName, void** pAddress, size_t* pSize) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindSignature (Native)
		// ----------------------------------------------------------------

		void const* FindSignatureNative(void const* const pAddress, const size_t unSize, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNative(const HMODULE hModule, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNative(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNative(const HMODULE hModule, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNativeA(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNativeA(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNativeA(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNativeW(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNativeW(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNativeW(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#ifdef _UNICODE
		void const* FindSignatureNative(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNative(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNative(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#else
		void const* FindSignatureNative(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNative(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureNative(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindSignature (SSE2)
		// ----------------------------------------------------------------

		void const* FindSignatureSSE2(void const* const pAddress, const size_t unSize, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2(const HMODULE hModule, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2(const HMODULE hModule, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2A(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2A(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2A(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2W(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2W(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2W(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#ifdef _UNICODE
		void const* FindSignatureSSE2(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#else
		void const* FindSignatureSSE2(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureSSE2(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX2)
		// ----------------------------------------------------------------

		void const* FindSignatureAVX2(void const* const pAddress, const size_t unSize, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2(const HMODULE hModule, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2(const HMODULE hModule, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2A(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2A(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2A(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2W(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2W(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2W(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#ifdef _UNICODE
		void const* FindSignatureAVX2(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#else
		void const* FindSignatureAVX2(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX2(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		void const* FindSignatureAVX512(void const* const pAddress, const size_t unSize, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512(const HMODULE hModule, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512(const HMODULE hModule, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512A(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512A(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512A(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512W(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512W(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512W(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#ifdef _UNICODE
		void const* FindSignatureAVX512(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#else
		void const* FindSignatureAVX512(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureAVX512(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindSignature (Auto)
		// ----------------------------------------------------------------

		void const* FindSignature(void const* const pAddress, const size_t unSize, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignature(const HMODULE hModule, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignature(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignature(const HMODULE hModule, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureA(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureA(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureA(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureW(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureW(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignatureW(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#ifdef _UNICODE
		void const* FindSignature(wchar_t const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignature(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignature(wchar_t const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#else
		void const* FindSignature(char const* const szModuleName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignature(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
		void const* FindSignature(char const* const szModuleName, char const* const szSectionName, char const* const szSignature, const unsigned char unIgnoredByte = '\x2A', const size_t unOffset = 0, const unsigned int unHash = 0) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindData (Native)
		// ----------------------------------------------------------------

		void const* FindDataNative(void const* const pAddress, const size_t unSize, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNative(const HMODULE hModule, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNative(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNative(const HMODULE hModule, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNativeA(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNativeA(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNativeA(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNativeW(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNativeW(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNativeW(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#ifdef _UNICODE
		void const* FindDataNative(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNative(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNative(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#else
		void const* FindDataNative(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNative(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataNative(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindData (SSE2)
		// ----------------------------------------------------------------

		void const* FindDataSSE2(void const* const pAddress, const size_t unSize, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2(const HMODULE hModule, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2(const HMODULE hModule, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2A(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2A(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2A(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2W(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2W(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2W(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#ifdef _UNICODE
		void const* FindDataSSE2(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#else
		void const* FindDataSSE2(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataSSE2(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindData (AVX2)
		// ----------------------------------------------------------------

		void const* FindDataAVX2(void const* const pAddress, const size_t unSize, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2(const HMODULE hModule, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2(const HMODULE hModule, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2A(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2A(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2A(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2W(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2W(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2W(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#ifdef _UNICODE
		void const* FindDataAVX2(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#else
		void const* FindDataAVX2(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX2(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindData (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		void const* FindDataAVX512(void const* const pAddress, const size_t unSize, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512(const HMODULE hModule, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512(const HMODULE hModule, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512A(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512A(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512A(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512W(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512W(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512W(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#ifdef _UNICODE
		void const* FindDataAVX512(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#else
		void const* FindDataAVX512(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataAVX512(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#endif

		// ----------------------------------------------------------------
		// FindData (Auto)
		// ----------------------------------------------------------------

		void const* FindData(void const* const pAddress, const size_t unSize, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindData(const HMODULE hModule, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindData(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindData(const HMODULE hModule, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataA(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataA(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataA(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataW(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataW(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindDataW(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#ifdef _UNICODE
		void const* FindData(wchar_t const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindData(wchar_t const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindData(wchar_t const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#else
		void const* FindData(char const* const szModuleName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindData(char const* const szModuleName, const std::array<const unsigned char, 8>& SectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
		void const* FindData(char const* const szModuleName, char const* const szSectionName, unsigned char const* const pData, const size_t unDataSize) noexcept;
#endif
	}

	// ----------------------------------------------------------------
	// Run-Time Type Information (RTTI)
	// ----------------------------------------------------------------

	namespace RTTI {

		// ----------------------------------------------------------------
		// Definitions
		// ----------------------------------------------------------------

#pragma pack(push, 1)

		typedef struct _RTTI_PMD {
			int m_nMDisp;
			int m_nPDisp;
			int m_nVDisp;
		} RTTI_PMD, *PRTTI_PMD;

		typedef struct _RTTI_TYPE_DESCRIPTOR {
			void* m_pVFTable;
			void* m_pSpare;
			char m_szName[1];
		} RTTI_TYPE_DESCRIPTOR, *PRTTI_TYPE_DESCRIPTOR;

		typedef struct _RTTI_BASE_CLASS_DESCRIPTOR {
#ifdef _M_X64
			unsigned int m_unTypeDescriptor;
#elif _M_IX86
			_RTTI_TYPE_DESCRIPTOR* m_pTypeDescriptor;
#endif
			unsigned int m_unNumberOfContainedBases;
			_RTTI_PMD m_Where;
			unsigned int m_unAttributes;
#if _M_X64
			unsigned int m_unClassHierarchyDescriptor;
#elif _M_IX86
			struct _RTTI_CLASS_HIERARCHY_DESCRIPTOR* m_pClassHierarchyDescriptor;
#endif
		} RTTI_BASE_CLASS_DESCRIPTOR, *PRTTI_BASE_CLASS_DESCRIPTOR;

		typedef struct _RTTI_BASE_CLASS_ARRAY {
#ifdef _M_X64
			unsigned int m_unBaseClassDescriptors[1];
#elif _M_IX86
			_RTTI_BASE_CLASS_DESCRIPTOR* m_pBaseClassDescriptors[1];
#endif
		} RTTI_BASE_CLASS_ARRAY, *PRTTI_BASE_CLASS_ARRAY;

		typedef struct _RTTI_CLASS_HIERARCHY_DESCRIPTOR {
			unsigned int m_unSignature;
			unsigned int m_unAttributes;
			unsigned int m_unNumberOfBaseClasses;
#ifdef _M_X64
			unsigned int m_unBaseClassArray;
#elif _M_IX86
			_RTTI_BASE_CLASS_ARRAY* m_pBaseClassArray;
#endif
		} RTTI_CLASS_HIERARCHY_DESCRIPTOR, *PRTTI_CLASS_HIERARCHY_DESCRIPTOR;

		typedef struct _RTTI_COMPLETE_OBJECT_LOCATOR {
			unsigned int m_unSignature;
			unsigned int m_unOffset;
			unsigned int m_unConstructorOffset;
#ifdef _M_X64
			unsigned int m_unTypeDescriptor;
			unsigned int m_unClassHierarchyDescriptor;
			unsigned int m_unSelf;
#elif _M_IX86
			_RTTI_TYPE_DESCRIPTOR* m_pTypeDescriptor;
			_RTTI_CLASS_HIERARCHY_DESCRIPTOR* m_pClassHierarchyDescriptor;
#endif
		} RTTI_COMPLETE_OBJECT_LOCATOR, *PRTTI_COMPLETE_OBJECT_LOCATOR;

#pragma pack(pop)

		// ----------------------------------------------------------------
		// Object
		// ----------------------------------------------------------------

		class Object {
		public:
			Object(void const* const pBaseAddress, void const* const pAddress, const size_t unSize, const PRTTI_TYPE_DESCRIPTOR pTypeDescriptor, const PRTTI_CLASS_HIERARCHY_DESCRIPTOR pClassHierarchyDescriptor, const PRTTI_BASE_CLASS_ARRAY pBaseClassArray, const PRTTI_COMPLETE_OBJECT_LOCATOR pCompleteObject, void** pVTable);
			~Object() = default;

		public:
			void const* const DynamicCast(void const* const pAddress, const Object* pObject);

		public:
			const PRTTI_TYPE_DESCRIPTOR GetTypeDescriptor() const;
			const PRTTI_CLASS_HIERARCHY_DESCRIPTOR GetClassHierarchyDescriptor() const;
			const PRTTI_COMPLETE_OBJECT_LOCATOR GetCompleteObject() const;
			void** GetVTable() const;
			std::vector<std::unique_ptr<Object>>& GetBaseObjects();

		private:
			void const* const m_pBaseAddress;
			void const* const m_pAddress;
			const size_t m_unSize;
			const PRTTI_TYPE_DESCRIPTOR m_pTypeDescriptor;
			const PRTTI_CLASS_HIERARCHY_DESCRIPTOR m_pClassHierarchyDescriptor;
			const PRTTI_BASE_CLASS_ARRAY m_pBaseClassArray;
			const PRTTI_COMPLETE_OBJECT_LOCATOR m_pCompleteObject;
			void** m_pVTable;
			std::vector<std::unique_ptr<Object>> m_vecBaseClasses;
		};

		// ----------------------------------------------------------------
		// FindObject
		// ----------------------------------------------------------------

		std::unique_ptr<Object> FindObject(void const* const pBaseAddress, void const* const pAddress, const size_t unSize, char const* const szName, bool bCompleteObject = true);
		std::unique_ptr<Object> FindObject(void const* const pAddress, const size_t unSize, char const* const szName, bool bCompleteObject = true);
		std::unique_ptr<Object> FindObject(const HMODULE hModule, char const* const szName, bool bCompleteObject = true);
		std::unique_ptr<Object> FindObjectA(char const* const szModuleName, char const* const szName, bool bCompleteObject = true);
		std::unique_ptr<Object> FindObjectW(wchar_t const* const szModuleName, char const* const szName, bool bCompleteObject = true);
#ifdef _UNICODE
		std::unique_ptr<Object> FindObject(wchar_t const* const szModuleName, char const* const szName, bool bCompleteObject = true);
#else
		std::unique_ptr<Object> FindObject(char const* const szModuleName, char const* const szName, bool bCompleteObject = true);
#endif
	}

	// ----------------------------------------------------------------
	// Sync
	// ----------------------------------------------------------------

	namespace Sync {

		// ----------------------------------------------------------------
		// Event
		// ----------------------------------------------------------------

		class Event {
		public:
			Event(bool bManualReset = true, bool bInitialState = false);
			~Event();

		public:
			HANDLE GetEvent() const;

		public:
			bool Signal();
			bool Reset();
			bool Pulse();

		public:
			bool Wait(DWORD unMilliseconds = INFINITE);

		private:
			HANDLE m_hEvent;
		};

		// ----------------------------------------------------------------
		// EventServer
		// ----------------------------------------------------------------

		class EventServer {
		public:
			EventServer(bool bIsGlobal = false, bool bManualReset = true, bool bInitialState = false);
			~EventServer();

		public:
			bool GetEventName(TCHAR szEventName[64]);
			HANDLE GetEvent() const;

		public:
			bool Signal();
			bool Reset();
			bool Pulse();

		public:
			bool Wait(DWORD unMilliseconds = INFINITE);

		private:
			TCHAR m_szEventName[64];
			HANDLE m_hEvent;
		};

		// ----------------------------------------------------------------
		// EventClient
		// ----------------------------------------------------------------

		class EventClient {
		public:
			EventClient(TCHAR szEventName[64], bool bIsGlobal = false);
			~EventClient();

		public:
			HANDLE GetEvent() const;

		public:
			bool Signal();
			bool Reset();
			bool Pulse();

		public:
			bool Wait(DWORD unMilliseconds = INFINITE);

		private:
			HANDLE m_hEvent;
		};

		// ----------------------------------------------------------------
		// Mutex
		// ----------------------------------------------------------------

		class Mutex {
		public:
			Mutex(bool bInitialState = false);
			~Mutex();

		public:
			HANDLE GetMutex() const;

		public:
			bool Lock(DWORD unMilliseconds = INFINITE);
			bool UnLock();

		private:
			HANDLE m_hMutex;
		};

		// ----------------------------------------------------------------
		// MutexServer
		// ----------------------------------------------------------------

		class MutexServer {
		public:
			MutexServer(bool bIsGlobal = false, bool bInitialState = false);
			~MutexServer();

		public:
			bool GetMutexName(TCHAR szMutexName[64]);
			HANDLE GetMutex() const;

		public:
			bool Lock(DWORD unMilliseconds = INFINITE);
			bool UnLock();

		private:
			TCHAR m_szMutexName[64];
			HANDLE m_hMutex;
		};

		// ----------------------------------------------------------------
		// MutexClient
		// ----------------------------------------------------------------

		class MutexClient {
		public:
			MutexClient(TCHAR szMutexName[64], bool bIsGlobal = false);
			~MutexClient();

		public:
			HANDLE GetMutex() const;

		public:
			bool Lock(DWORD unMilliseconds = INFINITE);
			bool UnLock();

		private:
			HANDLE m_hMutex;
		};
		

		// ----------------------------------------------------------------
		// Semaphore
		// ----------------------------------------------------------------

		class Semaphore {
		public:
			Semaphore(LONG nInitialCount = 1, LONG nMaximumCount = 1);
			~Semaphore();

		public:
			HANDLE GetSemaphore() const;

		public:
			bool Enter(DWORD unMilliseconds = 0);
			bool Leave(LONG nReleaseCount = 1);

		private:
			HANDLE m_hSemaphore;
		};

		// ----------------------------------------------------------------
		// SemaphoreServer
		// ----------------------------------------------------------------

		class SemaphoreServer {
		public:
			SemaphoreServer(bool bIsGlobal = false, LONG nInitialCount = 1, LONG nMaximumCount = 1);
			~SemaphoreServer();

		public:
			bool GetSemaphoreName(TCHAR szSemaphoreName[64]);
			HANDLE GetSemaphore() const;

		public:
			bool Enter(DWORD unMilliseconds = 0);
			bool Leave(LONG nReleaseCount = 1);

		private:
			TCHAR m_szSemaphoreName[64];
			HANDLE m_hSemaphore;
		};

		// ----------------------------------------------------------------
		// SemaphoreClient
		// ----------------------------------------------------------------

		class SemaphoreClient {
		public:
			SemaphoreClient(TCHAR szSemaphoreName[64], bool bIsGlobal = false);
			~SemaphoreClient();

		public:
			HANDLE GetSemaphore() const;

		public:
			bool Enter(DWORD unMilliseconds = 0);
			bool Leave(LONG nReleaseCount = 1);

		private:
			HANDLE m_hSemaphore;
		};

		// ----------------------------------------------------------------
		// CriticalSection
		// ----------------------------------------------------------------

		class CriticalSection {
		public:
			CriticalSection();
			CriticalSection(DWORD unSpinCount = 0);
			~CriticalSection();

		public:
			PCRITICAL_SECTION GetCriticalSection();

		public:
			void Enter();
			void Leave();

		private:
			CRITICAL_SECTION m_CriticalSection;
		};

		// ----------------------------------------------------------------
		// SRWLock
		// ----------------------------------------------------------------

		class SRWLock {
		public:
			SRWLock(bool bIsShared = false);
			~SRWLock();

		public:
			bool IsShared() const;
			PSRWLOCK GetSRWLock();

		public:
			void Acquire();
			void Release();

		private:
			bool m_bIsShared;
			SRWLOCK m_SRWLock;
		};

		// ----------------------------------------------------------------
		// ConditionVariable
		// ----------------------------------------------------------------

		class ConditionVariable {
		public:
			ConditionVariable();
			~ConditionVariable();

		public:
			CONDITION_VARIABLE GetConditionVariable() const;

		public:
			bool Sleep(CriticalSection* pLock, DWORD unMilliseconds = INFINITE);
			bool Sleep(SRWLock* pLock, DWORD unMilliseconds = INFINITE);
			void Wake();
			void WakeAll();

		private:
			CONDITION_VARIABLE m_ConditionVariable;
		};

		// ----------------------------------------------------------------
		// Suspender
		// ----------------------------------------------------------------

		class Suspender {
		public:
			Suspender() = default;
			~Suspender();

		public:
			bool Suspend();
			void Resume();
			void FixExecutionAddress(void* pAddress, void* pNewAddress);

		private:
			typedef struct _SUSPENDER_DATA {
				_SUSPENDER_DATA(DWORD unThreadID, HANDLE hHandle, CONTEXT CTX) {
					m_unThreadID = unThreadID;
					m_hHandle = hHandle;
					m_CTX = CTX;
				}

				DWORD m_unThreadID;
				HANDLE m_hHandle;
				CONTEXT m_CTX;
			} SUSPENDER_DATA, *PSUSPENDER_DATA;

			std::deque<SUSPENDER_DATA> m_Threads;
			Mutex m_Mutex;
		};

		extern Suspender g_Suspender;
	}

	// ----------------------------------------------------------------
	// Pipe
	// ----------------------------------------------------------------

	namespace Pipe {

		// ----------------------------------------------------------------
		// PipeServer
		// ----------------------------------------------------------------

		class PipeServer {
		public:
			PipeServer(const size_t unBufferSize);
			~PipeServer();

		public:
			bool GetPipeName(TCHAR szPipeName[64]);
			HANDLE GetPipe() const;

		public:
			bool Open();
			bool Close();

		public:
			bool Send(unsigned char pData[]);
			bool Receive(unsigned char pData[]);

		private:
			size_t m_unBufferSize;
			TCHAR m_szPipeName[64];
			HANDLE m_hPipe;
		};

		// ----------------------------------------------------------------
		// PipeClient
		// ----------------------------------------------------------------

		class PipeClient {
		public:
			PipeClient(const size_t unBufferSize);
			~PipeClient();

		public:
			HANDLE GetPipe() const;

		public:
			bool Open(TCHAR szPipeName[64]);
			bool Close();

		public:
			bool Send(unsigned char pData[]);
			bool Receive(unsigned char pData[]);

		private:
			size_t m_unBufferSize;
			HANDLE m_hPipe;
		};
	}

	// ----------------------------------------------------------------
	// Parallel
	// ----------------------------------------------------------------

	namespace Parallel {

		/*
		// ----------------------------------------------------------------
		// Thread CallBack
		// ----------------------------------------------------------------

		using fnThreadCallBack = void(*)(void* pData);

		// ----------------------------------------------------------------
		// Thread
		// ----------------------------------------------------------------

		class Thread {
		public:
			Thread();
			Thread(const fnThreadCallBack pCallBack);
			Thread(const fnThreadCallBack pCallBack, void* pData);
			~Thread();

		public:
			bool SetCallBack(const fnThreadCallBack pCallBack);
			bool SetData(void* pData);

		public:
			bool Start();
			bool Join();
			bool Suspend();
			bool Resume();

		public:
			fnThreadCallBack GetCallBack() const;
			void* GetData() const;

		private:
			fnThreadCallBack m_pCallBack;
			void* m_pData;
			HANDLE m_hThread;
		};
		*/

		// ----------------------------------------------------------------
		// Fiber CallBack
		// ----------------------------------------------------------------

		using fnFiberCallBack = void(*)(void* pData);

		// ----------------------------------------------------------------
		// Fiber
		// ----------------------------------------------------------------

		class Fiber {
		public:
			Fiber();
			Fiber(const fnFiberCallBack pCallBack);
			Fiber(const fnFiberCallBack pCallBack, void* pData);

		public:
			bool SetCallBack(const fnFiberCallBack pCallBack);
			bool SetData(void* pData);

		public:
			bool Switch();

		public:
			fnFiberCallBack GetCallBack() const;
			void* GetData() const;

		private:
			fnFiberCallBack m_pCallBack;
			void* m_pData;
		};
	};

	// ----------------------------------------------------------------
	// Memory
	// ----------------------------------------------------------------

	namespace Memory {

		// ----------------------------------------------------------------
		// Shared
		// ----------------------------------------------------------------

		class Shared {
		public:
			Shared(const size_t unSize);
			~Shared();

		public:
			HANDLE GetShared() const;
			void* GetAddress() const;

		private:
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// SharedServer
		// ----------------------------------------------------------------

		class SharedServer {
		public:
			SharedServer(const size_t unSize, bool bIsGlobal = false);
			~SharedServer();

		public:
			bool GetSharedName(TCHAR szSharedName[64]);
			HANDLE GetShared() const;
			void* GetAddress() const;

		private:
			TCHAR m_szSharedName[64];
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// SharedClient
		// ----------------------------------------------------------------

		class SharedClient {
		public:
			SharedClient(TCHAR szSharedName[64], bool bIsGlobal = false);
			~SharedClient();

		public:
			HANDLE GetShared() const;
			void* GetAddress() const;

		private:
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// Page
		// ----------------------------------------------------------------

		class Page {
		public:
			Page(size_t unCapacity = 0);
			~Page();

			void* Alloc(size_t unSize);
			bool DeAlloc(void* pAddress);
			void DeAllocAll();

		public:
			void* GetAddress() const;
			size_t GetCapacity() const;
			size_t GetSize() const;
			bool IsEmpty() const;

		private:
			void MergeFreeBlocks();

		private:
			struct Block {
				Block(void* pAddress, size_t unSize) {
					m_pAddress = pAddress;
					m_unSize = unSize;
				}

				bool operator<(const Block& block) const {
					return m_pAddress < block.m_pAddress;
				};

				void* m_pAddress;
				size_t m_unSize;
			};

			size_t m_unCapacity;
			void* m_pPageAddress;
			std::set<Block> m_FreeBlocks;
			std::set<Block> m_ActiveBlocks;
		};

		// ----------------------------------------------------------------
		// NearPage
		// ----------------------------------------------------------------

		class NearPage {
		public:
			NearPage(size_t unCapacity = 0, void* pDesiredAddress = nullptr);
			~NearPage();

			void* Alloc(size_t unSize);
			bool DeAlloc(void* pAddress);
			void DeAllocAll();

		public:
			void* GetAddress() const;
			size_t GetCapacity() const;
			size_t GetSize() const;
			bool IsEmpty() const;

		private:
			void MergeFreeBlocks();

		private:
			struct Block {
				Block(void* pAddress, size_t unSize) {
					m_pAddress = pAddress;
					m_unSize = unSize;
				}

				bool operator<(const Block& block) const {
					return m_pAddress < block.m_pAddress;
				};

				void* m_pAddress;
				size_t m_unSize;
			};

			size_t m_unCapacity;
			void* m_pPageAddress;
			std::set<Block> m_FreeBlocks;
			std::set<Block> m_ActiveBlocks;
		};

		// ----------------------------------------------------------------
		// Storage
		// ----------------------------------------------------------------

		class Storage {
		public:
			Storage(size_t unTotalCapacity = 0, size_t unPageCapacity = 0);
			~Storage() = default;

		public:
			void* Alloc(size_t unSize);
			bool DeAlloc(void* pAddress);
			bool DeAllocAll();

		public:
			size_t GetCapacity() const;
			size_t GetSize() const;
			bool IsEmpty() const;

		private:
			size_t m_unTotalCapacity;
			size_t m_unPageCapacity;
			size_t m_unUsedSpace;
			std::list<Page> m_Pages;
		};

		// ----------------------------------------------------------------
		// NearStorage
		// ----------------------------------------------------------------

		class NearStorage {
		public:
			NearStorage(size_t unTotalCapacity = 0, size_t unPageCapacity = 0);
			~NearStorage() = default;

		public:
			void* Alloc(size_t unSize, void* pDesiredAddress = nullptr);
			bool DeAlloc(void* pAddress);
			bool DeAllocAll();

		public:
			size_t GetCapacity() const;
			size_t GetSize() const;
			bool IsEmpty() const;

		private:
			size_t m_unTotalCapacity;
			size_t m_unPageCapacity;
			size_t m_unUsedSpace;
			std::list<NearPage> m_Pages;
		};

		// ----------------------------------------------------------------
		// Protection
		// ----------------------------------------------------------------

		class Protection {
		public:
			Protection(void const* const pAddress, const size_t unSize, const bool bAutoRestore = true);
			~Protection();

		public:
			bool GetProtection(const PDWORD pProtection);
			bool ChangeProtection(const DWORD unNewProtection);
			bool RestoreProtection();

		public:
			const void* GetAddress() const;
			size_t GetSize() const;
			DWORD GetOriginalProtection() const;

		private:
			void const* const m_pAddress;
			const size_t m_unSize;
			const bool m_bAutoRestore;
			DWORD m_unOriginalProtection;
		};
	}

	// ----------------------------------------------------------------
	// Exception
	// ----------------------------------------------------------------

	namespace Exception {

		// ----------------------------------------------------------------
		// Exception CallBack
		// ----------------------------------------------------------------

		using fnExceptionCallBack = bool(*)(const EXCEPTION_RECORD& Exception, const PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// Exception Listener
		// ----------------------------------------------------------------

		class ExceptionListener {
		public:
			ExceptionListener();
			~ExceptionListener();

		public:
			bool EnableHandler();
			bool DisableHandler();
			bool RefreshHandler();
			bool AddCallBack(const fnExceptionCallBack pCallBack);
			bool RemoveCallBack(const fnExceptionCallBack pCallBack);

		public:
			std::deque<fnExceptionCallBack>& GetCallBacks();

		private:
			PVOID m_pVEH;
			std::deque<fnExceptionCallBack> m_CallBacks;
		};

		extern ExceptionListener g_ExceptionListener;
	}

	// ----------------------------------------------------------------
	// rddisasm
	// ----------------------------------------------------------------

	namespace rddisasm {

		typedef enum _RD_OPERARD_TYPE {
			RD_OP_NOT_PRESENT = 0,
			RD_OP_REG,
			RD_OP_MEM,
			RD_OP_IMM,
			RD_OP_OFFS,
			RD_OP_ADDR,
			RD_OP_CONST,
			RD_OP_BANK
		} RD_OPERARD_TYPE, *PRD_OPERARD_TYPE;

		typedef enum _RD_OPERARD_ENCODING {
			RD_OPE_NP = 0,
			RD_OPE_R,
			RD_OPE_M,
			RD_OPE_V,
			RD_OPE_D,
			RD_OPE_O,
			RD_OPE_I,
			RD_OPE_C,
			RD_OPE_1,
			RD_OPE_L,
			RD_OPE_A,
			RD_OPE_E,
			RD_OPE_S
		} RD_OPERARD_ENCODING, *PRD_OPERARD_ENCODING;

		typedef enum _RD_REG_TYPE {
			RD_REG_NOT_PRESENT = 0,
			RD_REG_GPR,
			RD_REG_SEG,
			RD_REG_FPU,
			RD_REG_MMX,
			RD_REG_SSE,
			RD_REG_CR,
			RD_REG_DR,
			RD_REG_TR,
			RD_REG_BND,
			RD_REG_MSK,
			RD_REG_TILE,
			RD_REG_MSR,
			RD_REG_XCR,
			RD_REG_SYS,
			RD_REG_X87,
			RD_REG_MXCSR,
			RD_REG_PKRU,
			RD_REG_SSP,
			RD_REG_FLG,
			RD_REG_RIP,
			RD_REG_UIF
		} RD_REG_TYPE, *PRD_REG_TYPE;

		typedef enum _RD_INS_CLASS {
			RD_INS_INVALID = 0,
			RD_INS_AAA,
			RD_INS_AAD,
			RD_INS_AADD,
			RD_INS_AAM,
			RD_INS_AAND,
			RD_INS_AAS,
			RD_INS_ADC,
			RD_INS_ADCX,
			RD_INS_ADD,
			RD_INS_ADDPD,
			RD_INS_ADDPS,
			RD_INS_ADDSD,
			RD_INS_ADDSS,
			RD_INS_ADDSUBPD,
			RD_INS_ADDSUBPS,
			RD_INS_ADOX,
			RD_INS_AESDEC,
			RD_INS_AESDEC128KL,
			RD_INS_AESDEC256KL,
			RD_INS_AESDECLAST,
			RD_INS_AESDECWIDE128KL,
			RD_INS_AESDECWIDE256KL,
			RD_INS_AESENC,
			RD_INS_AESENC128KL,
			RD_INS_AESENC256KL,
			RD_INS_AESENCLAST,
			RD_INS_AESENCWIDE128KL,
			RD_INS_AESENCWIDE256KL,
			RD_INS_AESIMC,
			RD_INS_AESKEYGENASSIST,
			RD_INS_ALTINST,
			RD_INS_AND,
			RD_INS_ANDN,
			RD_INS_ANDNPD,
			RD_INS_ANDNPS,
			RD_INS_ANDPD,
			RD_INS_ANDPS,
			RD_INS_AOR,
			RD_INS_ARPL,
			RD_INS_AXOR,
			RD_INS_BEXTR,
			RD_INS_BLCFILL,
			RD_INS_BLCI,
			RD_INS_BLCIC,
			RD_INS_BLCMSK,
			RD_INS_BLCS,
			RD_INS_BLENDPD,
			RD_INS_BLENDPS,
			RD_INS_BLENDVPD,
			RD_INS_BLENDVPS,
			RD_INS_BLSFILL,
			RD_INS_BLSI,
			RD_INS_BLSIC,
			RD_INS_BLSMSK,
			RD_INS_BLSR,
			RD_INS_BNDCL,
			RD_INS_BNDCN,
			RD_INS_BNDCU,
			RD_INS_BNDLDX,
			RD_INS_BNDMK,
			RD_INS_BNDMOV,
			RD_INS_BNDSTX,
			RD_INS_BOUND,
			RD_INS_BSF,
			RD_INS_BSR,
			RD_INS_BSWAP,
			RD_INS_BT,
			RD_INS_BTC,
			RD_INS_BTR,
			RD_INS_BTS,
			RD_INS_BZHI,
			RD_INS_CALLFD,
			RD_INS_CALLFI,
			RD_INS_CALLNI,
			RD_INS_CALLNR,
			RD_INS_CBW,
			RD_INS_CDQ,
			RD_INS_CDQE,
			RD_INS_CLAC,
			RD_INS_CLC,
			RD_INS_CLD,
			RD_INS_CLDEMOTE,
			RD_INS_CLEVICT0,
			RD_INS_CLEVICT1,
			RD_INS_CLFLUSH,
			RD_INS_CLFLUSHOPT,
			RD_INS_CLGI,
			RD_INS_CLI,
			RD_INS_CLRSSBSY,
			RD_INS_CLTS,
			RD_INS_CLUI,
			RD_INS_CLWB,
			RD_INS_CLZERO,
			RD_INS_CMC,
			RD_INS_CMOVcc,
			RD_INS_CMP,
			RD_INS_CMPBEXADD,
			RD_INS_CMPCXADD,
			RD_INS_CMPLEXADD,
			RD_INS_CMPLXADD,
			RD_INS_CMPNBEXADD,
			RD_INS_CMPNCXADD,
			RD_INS_CMPNLEXADD,
			RD_INS_CMPNLXADD,
			RD_INS_CMPNOXADD,
			RD_INS_CMPNPXADD,
			RD_INS_CMPNSXADD,
			RD_INS_CMPNZXADD,
			RD_INS_CMPOXADD,
			RD_INS_CMPPD,
			RD_INS_CMPPS,
			RD_INS_CMPPXADD,
			RD_INS_CMPS,
			RD_INS_CMPSD,
			RD_INS_CMPSS,
			RD_INS_CMPSXADD,
			RD_INS_CMPXCHG,
			RD_INS_CMPXCHG16B,
			RD_INS_CMPXCHG8B,
			RD_INS_CMPZXADD,
			RD_INS_COMISD,
			RD_INS_COMISS,
			RD_INS_CPUID,
			RD_INS_CPU_READ,
			RD_INS_CPU_WRITE,
			RD_INS_CQO,
			RD_INS_CRC32,
			RD_INS_CVTDQ2PD,
			RD_INS_CVTDQ2PS,
			RD_INS_CVTPD2DQ,
			RD_INS_CVTPD2PI,
			RD_INS_CVTPD2PS,
			RD_INS_CVTPI2PD,
			RD_INS_CVTPI2PS,
			RD_INS_CVTPS2DQ,
			RD_INS_CVTPS2PD,
			RD_INS_CVTPS2PI,
			RD_INS_CVTSD2SI,
			RD_INS_CVTSD2SS,
			RD_INS_CVTSI2SD,
			RD_INS_CVTSI2SS,
			RD_INS_CVTSS2SD,
			RD_INS_CVTSS2SI,
			RD_INS_CVTTPD2DQ,
			RD_INS_CVTTPD2PI,
			RD_INS_CVTTPS2DQ,
			RD_INS_CVTTPS2PI,
			RD_INS_CVTTSD2SI,
			RD_INS_CVTTSS2SI,
			RD_INS_CWD,
			RD_INS_CWDE,
			RD_INS_DAA,
			RD_INS_DAS,
			RD_INS_DEC,
			RD_INS_DELAY,
			RD_INS_DIV,
			RD_INS_DIVPD,
			RD_INS_DIVPS,
			RD_INS_DIVSD,
			RD_INS_DIVSS,
			RD_INS_DMINT,
			RD_INS_DPPD,
			RD_INS_DPPS,
			RD_INS_EMMS,
			RD_INS_ENCLS,
			RD_INS_ENCLU,
			RD_INS_ENCLV,
			RD_INS_ENCODEKEY128,
			RD_INS_ENCODEKEY256,
			RD_INS_ENDBR,
			RD_INS_ENQCMD,
			RD_INS_ENQCMDS,
			RD_INS_ENTER,
			RD_INS_ERETS,
			RD_INS_ERETU,
			RD_INS_EXTRACTPS,
			RD_INS_EXTRQ,
			RD_INS_F2XM1,
			RD_INS_FABS,
			RD_INS_FADD,
			RD_INS_FADDP,
			RD_INS_FBLD,
			RD_INS_FBSTP,
			RD_INS_FCHS,
			RD_INS_FCMOVB,
			RD_INS_FCMOVBE,
			RD_INS_FCMOVE,
			RD_INS_FCMOVNB,
			RD_INS_FCMOVNBE,
			RD_INS_FCMOVNE,
			RD_INS_FCMOVNU,
			RD_INS_FCMOVU,
			RD_INS_FCOM,
			RD_INS_FCOMI,
			RD_INS_FCOMIP,
			RD_INS_FCOMP,
			RD_INS_FCOMPP,
			RD_INS_FCOS,
			RD_INS_FDECSTP,
			RD_INS_FDIV,
			RD_INS_FDIVP,
			RD_INS_FDIVR,
			RD_INS_FDIVRP,
			RD_INS_FEMMS,
			RD_INS_FFREE,
			RD_INS_FFREEP,
			RD_INS_FIADD,
			RD_INS_FICOM,
			RD_INS_FICOMP,
			RD_INS_FIDIV,
			RD_INS_FIDIVR,
			RD_INS_FILD,
			RD_INS_FIMUL,
			RD_INS_FINCSTP,
			RD_INS_FIST,
			RD_INS_FISTP,
			RD_INS_FISTTP,
			RD_INS_FISUB,
			RD_INS_FISUBR,
			RD_INS_FLD,
			RD_INS_FLD1,
			RD_INS_FLDCW,
			RD_INS_FLDENV,
			RD_INS_FLDL2E,
			RD_INS_FLDL2T,
			RD_INS_FLDLG2,
			RD_INS_FLDLN2,
			RD_INS_FLDPI,
			RD_INS_FLDZ,
			RD_INS_FMUL,
			RD_INS_FMULP,
			RD_INS_FNCLEX,
			RD_INS_FNDISI,
			RD_INS_FNINIT,
			RD_INS_FNOP,
			RD_INS_FNSAVE,
			RD_INS_FNSTCW,
			RD_INS_FNSTENV,
			RD_INS_FNSTSW,
			RD_INS_FPATAN,
			RD_INS_FPREM,
			RD_INS_FPREM1,
			RD_INS_FPTAN,
			RD_INS_FRINEAR,
			RD_INS_FRNDINT,
			RD_INS_FRSTOR,
			RD_INS_FSCALE,
			RD_INS_FSIN,
			RD_INS_FSINCOS,
			RD_INS_FSQRT,
			RD_INS_FST,
			RD_INS_FSTDW,
			RD_INS_FSTP,
			RD_INS_FSTPNCE,
			RD_INS_FSTSG,
			RD_INS_FSUB,
			RD_INS_FSUBP,
			RD_INS_FSUBR,
			RD_INS_FSUBRP,
			RD_INS_FTST,
			RD_INS_FUCOM,
			RD_INS_FUCOMI,
			RD_INS_FUCOMIP,
			RD_INS_FUCOMP,
			RD_INS_FUCOMPP,
			RD_INS_FXAM,
			RD_INS_FXCH,
			RD_INS_FXRSTOR,
			RD_INS_FXRSTOR64,
			RD_INS_FXSAVE,
			RD_INS_FXSAVE64,
			RD_INS_FXTRACT,
			RD_INS_FYL2X,
			RD_INS_FYL2XP1,
			RD_INS_GETSEC,
			RD_INS_GF2P8AFFINEINVQB,
			RD_INS_GF2P8AFFINEQB,
			RD_INS_GF2P8MULB,
			RD_INS_HADDPD,
			RD_INS_HADDPS,
			RD_INS_HLT,
			RD_INS_HRESET,
			RD_INS_HSUBPD,
			RD_INS_HSUBPS,
			RD_INS_IDIV,
			RD_INS_IMUL,
			RD_INS_IN,
			RD_INS_INC,
			RD_INS_INCSSP,
			RD_INS_INS,
			RD_INS_INSERTPS,
			RD_INS_INSERTQ,
			RD_INS_INT,
			RD_INS_INT1,
			RD_INS_INT3,
			RD_INS_INTO,
			RD_INS_INVD,
			RD_INS_INVEPT,
			RD_INS_INVLPG,
			RD_INS_INVLPGA,
			RD_INS_INVLPGB,
			RD_INS_INVPCID,
			RD_INS_INVVPID,
			RD_INS_IRET,
			RD_INS_JMPE,
			RD_INS_JMPFD,
			RD_INS_JMPFI,
			RD_INS_JMPNI,
			RD_INS_JMPNR,
			RD_INS_Jcc,
			RD_INS_JrCXZ,
			RD_INS_KADD,
			RD_INS_KAND,
			RD_INS_KANDN,
			RD_INS_KMERGE2L1H,
			RD_INS_KMERGE2L1L,
			RD_INS_KMOV,
			RD_INS_KNOT,
			RD_INS_KOR,
			RD_INS_KORTEST,
			RD_INS_KSHIFTL,
			RD_INS_KSHIFTR,
			RD_INS_KTEST,
			RD_INS_KUNPCKBW,
			RD_INS_KUNPCKDQ,
			RD_INS_KUNPCKWD,
			RD_INS_KXNOR,
			RD_INS_KXOR,
			RD_INS_LAHF,
			RD_INS_LAR,
			RD_INS_LDDQU,
			RD_INS_LDMXCSR,
			RD_INS_LDS,
			RD_INS_LDTILECFG,
			RD_INS_LEA,
			RD_INS_LEAVE,
			RD_INS_LES,
			RD_INS_LFENCE,
			RD_INS_LFS,
			RD_INS_LGDT,
			RD_INS_LGS,
			RD_INS_LIDT,
			RD_INS_LKGS,
			RD_INS_LLDT,
			RD_INS_LLWPCB,
			RD_INS_LMSW,
			RD_INS_LOADIWKEY,
			RD_INS_LODS,
			RD_INS_LOOP,
			RD_INS_LOOPNZ,
			RD_INS_LOOPZ,
			RD_INS_LSL,
			RD_INS_LSS,
			RD_INS_LTR,
			RD_INS_LWPINS,
			RD_INS_LWPVAL,
			RD_INS_LZCNT,
			RD_INS_MASKMOVDQU,
			RD_INS_MASKMOVQ,
			RD_INS_MAXPD,
			RD_INS_MAXPS,
			RD_INS_MAXSD,
			RD_INS_MAXSS,
			RD_INS_MCOMMIT,
			RD_INS_MFENCE,
			RD_INS_MINPD,
			RD_INS_MINPS,
			RD_INS_MINSD,
			RD_INS_MINSS,
			RD_INS_MONITOR,
			RD_INS_MONITORX,
			RD_INS_MONTMUL,
			RD_INS_MOV,
			RD_INS_MOVAPD,
			RD_INS_MOVAPS,
			RD_INS_MOVBE,
			RD_INS_MOVD,
			RD_INS_MOVDDUP,
			RD_INS_MOVDIR64B,
			RD_INS_MOVDIRI,
			RD_INS_MOVDQ2Q,
			RD_INS_MOVDQA,
			RD_INS_MOVDQU,
			RD_INS_MOVHLPS,
			RD_INS_MOVHPD,
			RD_INS_MOVHPS,
			RD_INS_MOVLHPS,
			RD_INS_MOVLPD,
			RD_INS_MOVLPS,
			RD_INS_MOVMSKPD,
			RD_INS_MOVMSKPS,
			RD_INS_MOVNTDQ,
			RD_INS_MOVNTDQA,
			RD_INS_MOVNTI,
			RD_INS_MOVNTPD,
			RD_INS_MOVNTPS,
			RD_INS_MOVNTQ,
			RD_INS_MOVNTSD,
			RD_INS_MOVNTSS,
			RD_INS_MOVQ,
			RD_INS_MOVQ2DQ,
			RD_INS_MOVS,
			RD_INS_MOVSD,
			RD_INS_MOVSHDUP,
			RD_INS_MOVSLDUP,
			RD_INS_MOVSS,
			RD_INS_MOVSX,
			RD_INS_MOVSXD,
			RD_INS_MOVUPD,
			RD_INS_MOVUPS,
			RD_INS_MOVZX,
			RD_INS_MOV_CR,
			RD_INS_MOV_DR,
			RD_INS_MOV_TR,
			RD_INS_MPSADBW,
			RD_INS_MUL,
			RD_INS_MULPD,
			RD_INS_MULPS,
			RD_INS_MULSD,
			RD_INS_MULSS,
			RD_INS_MULX,
			RD_INS_MWAIT,
			RD_INS_MWAITX,
			RD_INS_NEG,
			RD_INS_NOP,
			RD_INS_NOT,
			RD_INS_OR,
			RD_INS_ORPD,
			RD_INS_ORPS,
			RD_INS_OUT,
			RD_INS_OUTS,
			RD_INS_PABSB,
			RD_INS_PABSD,
			RD_INS_PABSW,
			RD_INS_PACKSSDW,
			RD_INS_PACKSSWB,
			RD_INS_PACKUSDW,
			RD_INS_PACKUSWB,
			RD_INS_PADDB,
			RD_INS_PADDD,
			RD_INS_PADDQ,
			RD_INS_PADDSB,
			RD_INS_PADDSW,
			RD_INS_PADDUSB,
			RD_INS_PADDUSW,
			RD_INS_PADDW,
			RD_INS_PALIGNR,
			RD_INS_PAND,
			RD_INS_PANDN,
			RD_INS_PAUSE,
			RD_INS_PAVGB,
			RD_INS_PAVGUSB,
			RD_INS_PAVGW,
			RD_INS_PBLENDVB,
			RD_INS_PBLENDW,
			RD_INS_PBNDKB,
			RD_INS_PCLMULQDQ,
			RD_INS_PCMPEQB,
			RD_INS_PCMPEQD,
			RD_INS_PCMPEQQ,
			RD_INS_PCMPEQW,
			RD_INS_PCMPESTRI,
			RD_INS_PCMPESTRM,
			RD_INS_PCMPGTB,
			RD_INS_PCMPGTD,
			RD_INS_PCMPGTQ,
			RD_INS_PCMPGTW,
			RD_INS_PCMPISTRI,
			RD_INS_PCMPISTRM,
			RD_INS_PCONFIG,
			RD_INS_PDEP,
			RD_INS_PEXT,
			RD_INS_PEXTRB,
			RD_INS_PEXTRD,
			RD_INS_PEXTRQ,
			RD_INS_PEXTRW,
			RD_INS_PF2ID,
			RD_INS_PF2IW,
			RD_INS_PFACC,
			RD_INS_PFADD,
			RD_INS_PFCMPEQ,
			RD_INS_PFCMPGE,
			RD_INS_PFCMPGT,
			RD_INS_PFMAX,
			RD_INS_PFMIN,
			RD_INS_PFMUL,
			RD_INS_PFNACC,
			RD_INS_PFPNACC,
			RD_INS_PFRCP,
			RD_INS_PFRCPIT1,
			RD_INS_PFRCPIT2,
			RD_INS_PFRCPV,
			RD_INS_PFRSQIT1,
			RD_INS_PFRSQRT,
			RD_INS_PFRSQRTV,
			RD_INS_PFSUB,
			RD_INS_PFSUBR,
			RD_INS_PHADDD,
			RD_INS_PHADDSW,
			RD_INS_PHADDW,
			RD_INS_PHMINPOSUW,
			RD_INS_PHSUBD,
			RD_INS_PHSUBSW,
			RD_INS_PHSUBW,
			RD_INS_PI2FD,
			RD_INS_PI2FW,
			RD_INS_PINSRB,
			RD_INS_PINSRD,
			RD_INS_PINSRQ,
			RD_INS_PINSRW,
			RD_INS_PMADDUBSW,
			RD_INS_PMADDWD,
			RD_INS_PMAXSB,
			RD_INS_PMAXSD,
			RD_INS_PMAXSW,
			RD_INS_PMAXUB,
			RD_INS_PMAXUD,
			RD_INS_PMAXUW,
			RD_INS_PMINSB,
			RD_INS_PMINSD,
			RD_INS_PMINSW,
			RD_INS_PMINUB,
			RD_INS_PMINUD,
			RD_INS_PMINUW,
			RD_INS_PMOVMSKB,
			RD_INS_PMOVSXBD,
			RD_INS_PMOVSXBQ,
			RD_INS_PMOVSXBW,
			RD_INS_PMOVSXDQ,
			RD_INS_PMOVSXWD,
			RD_INS_PMOVSXWQ,
			RD_INS_PMOVZXBD,
			RD_INS_PMOVZXBQ,
			RD_INS_PMOVZXBW,
			RD_INS_PMOVZXDQ,
			RD_INS_PMOVZXWD,
			RD_INS_PMOVZXWQ,
			RD_INS_PMULDQ,
			RD_INS_PMULHRSW,
			RD_INS_PMULHRW,
			RD_INS_PMULHUW,
			RD_INS_PMULHW,
			RD_INS_PMULLD,
			RD_INS_PMULLW,
			RD_INS_PMULUDQ,
			RD_INS_POP,
			RD_INS_POPA,
			RD_INS_POPAD,
			RD_INS_POPCNT,
			RD_INS_POPF,
			RD_INS_POR,
			RD_INS_PREFETCH,
			RD_INS_PREFETCHE,
			RD_INS_PREFETCHIT0,
			RD_INS_PREFETCHIT1,
			RD_INS_PREFETCHM,
			RD_INS_PREFETCHNTA,
			RD_INS_PREFETCHT0,
			RD_INS_PREFETCHT1,
			RD_INS_PREFETCHT2,
			RD_INS_PREFETCHW,
			RD_INS_PREFETCHWT1,
			RD_INS_PSADBW,
			RD_INS_PSHUFB,
			RD_INS_PSHUFD,
			RD_INS_PSHUFHW,
			RD_INS_PSHUFLW,
			RD_INS_PSHUFW,
			RD_INS_PSIGNB,
			RD_INS_PSIGND,
			RD_INS_PSIGNW,
			RD_INS_PSLLD,
			RD_INS_PSLLDQ,
			RD_INS_PSLLQ,
			RD_INS_PSLLW,
			RD_INS_PSMASH,
			RD_INS_PSRAD,
			RD_INS_PSRAW,
			RD_INS_PSRLD,
			RD_INS_PSRLDQ,
			RD_INS_PSRLQ,
			RD_INS_PSRLW,
			RD_INS_PSUBB,
			RD_INS_PSUBD,
			RD_INS_PSUBQ,
			RD_INS_PSUBSB,
			RD_INS_PSUBSW,
			RD_INS_PSUBUSB,
			RD_INS_PSUBUSW,
			RD_INS_PSUBW,
			RD_INS_PSWAPD,
			RD_INS_PTEST,
			RD_INS_PTWRITE,
			RD_INS_PUNPCKHBW,
			RD_INS_PUNPCKHDQ,
			RD_INS_PUNPCKHQDQ,
			RD_INS_PUNPCKHWD,
			RD_INS_PUNPCKLBW,
			RD_INS_PUNPCKLDQ,
			RD_INS_PUNPCKLQDQ,
			RD_INS_PUNPCKLWD,
			RD_INS_PUSH,
			RD_INS_PUSHA,
			RD_INS_PUSHAD,
			RD_INS_PUSHF,
			RD_INS_PVALIDATE,
			RD_INS_PXOR,
			RD_INS_RCL,
			RD_INS_RCPPS,
			RD_INS_RCPSS,
			RD_INS_RCR,
			RD_INS_RDFSBASE,
			RD_INS_RDGSBASE,
			RD_INS_RDMSR,
			RD_INS_RDMSRLIST,
			RD_INS_RDPID,
			RD_INS_RDPKRU,
			RD_INS_RDPMC,
			RD_INS_RDPRU,
			RD_INS_RDRAND,
			RD_INS_RDSEED,
			RD_INS_RDSHR,
			RD_INS_RDTSC,
			RD_INS_RDTSCP,
			RD_INS_RETF,
			RD_INS_RETN,
			RD_INS_RMPADJUST,
			RD_INS_RMPQUERY,
			RD_INS_RMPUPDATE,
			RD_INS_ROL,
			RD_INS_ROR,
			RD_INS_RORX,
			RD_INS_ROUNDPD,
			RD_INS_ROUNDPS,
			RD_INS_ROUNDSD,
			RD_INS_ROUNDSS,
			RD_INS_RSDC,
			RD_INS_RSLDT,
			RD_INS_RSM,
			RD_INS_RSQRTPS,
			RD_INS_RSQRTSS,
			RD_INS_RSSSP,
			RD_INS_RSTORSSP,
			RD_INS_RSTS,
			RD_INS_SAHF,
			RD_INS_SAL,
			RD_INS_SALC,
			RD_INS_SAR,
			RD_INS_SARX,
			RD_INS_SAVEPREVSSP,
			RD_INS_SBB,
			RD_INS_SCAS,
			RD_INS_SEAMCALL,
			RD_INS_SEAMOPS,
			RD_INS_SEAMRET,
			RD_INS_SENDUIPI,
			RD_INS_SERIALIZE,
			RD_INS_SETSSBSY,
			RD_INS_SETcc,
			RD_INS_SFENCE,
			RD_INS_SGDT,
			RD_INS_SHA1MSG1,
			RD_INS_SHA1MSG2,
			RD_INS_SHA1NEXTE,
			RD_INS_SHA1RNDS4,
			RD_INS_SHA256MSG1,
			RD_INS_SHA256MSG2,
			RD_INS_SHA256RNDS2,
			RD_INS_SHL,
			RD_INS_SHLD,
			RD_INS_SHLX,
			RD_INS_SHR,
			RD_INS_SHRD,
			RD_INS_SHRX,
			RD_INS_SHUFPD,
			RD_INS_SHUFPS,
			RD_INS_SIDT,
			RD_INS_SKINIT,
			RD_INS_SLDT,
			RD_INS_SLWPCB,
			RD_INS_SMINT,
			RD_INS_SMSW,
			RD_INS_SPFLT,
			RD_INS_SQRTPD,
			RD_INS_SQRTPS,
			RD_INS_SQRTSD,
			RD_INS_SQRTSS,
			RD_INS_STAC,
			RD_INS_STC,
			RD_INS_STD,
			RD_INS_STGI,
			RD_INS_STI,
			RD_INS_STMXCSR,
			RD_INS_STOS,
			RD_INS_STR,
			RD_INS_STTILECFG,
			RD_INS_STUI,
			RD_INS_SUB,
			RD_INS_SUBPD,
			RD_INS_SUBPS,
			RD_INS_SUBSD,
			RD_INS_SUBSS,
			RD_INS_SVDC,
			RD_INS_SVLDT,
			RD_INS_SVTS,
			RD_INS_SWAPGS,
			RD_INS_SYSCALL,
			RD_INS_SYSENTER,
			RD_INS_SYSEXIT,
			RD_INS_SYSRET,
			RD_INS_T1MSKC,
			RD_INS_TCMMIMFP16PS,
			RD_INS_TCMMRLFP16PS,
			RD_INS_TDCALL,
			RD_INS_TDPBF16PS,
			RD_INS_TDPBSSD,
			RD_INS_TDPBSUD,
			RD_INS_TDPBUSD,
			RD_INS_TDPBUUD,
			RD_INS_TDPFP16PS,
			RD_INS_TEST,
			RD_INS_TESTUI,
			RD_INS_TILELOADD,
			RD_INS_TILELOADDT1,
			RD_INS_TILERELEASE,
			RD_INS_TILESTORED,
			RD_INS_TILEZERO,
			RD_INS_TLBSYNC,
			RD_INS_TPAUSE,
			RD_INS_TZCNT,
			RD_INS_TZMSK,
			RD_INS_UCOMISD,
			RD_INS_UCOMISS,
			RD_INS_UD0,
			RD_INS_UD1,
			RD_INS_UD2,
			RD_INS_UIRET,
			RD_INS_UMONITOR,
			RD_INS_UMWAIT,
			RD_INS_UNPCKHPD,
			RD_INS_UNPCKHPS,
			RD_INS_UNPCKLPD,
			RD_INS_UNPCKLPS,
			RD_INS_V4FMADDPS,
			RD_INS_V4FMADDSS,
			RD_INS_V4FNMADDPS,
			RD_INS_V4FNMADDSS,
			RD_INS_VADDPD,
			RD_INS_VADDPH,
			RD_INS_VADDPS,
			RD_INS_VADDSD,
			RD_INS_VADDSH,
			RD_INS_VADDSS,
			RD_INS_VADDSUBPD,
			RD_INS_VADDSUBPS,
			RD_INS_VAESDEC,
			RD_INS_VAESDECLAST,
			RD_INS_VAESENC,
			RD_INS_VAESENCLAST,
			RD_INS_VAESIMC,
			RD_INS_VAESKEYGENASSIST,
			RD_INS_VALIGND,
			RD_INS_VALIGNQ,
			RD_INS_VANDNPD,
			RD_INS_VANDNPS,
			RD_INS_VANDPD,
			RD_INS_VANDPS,
			RD_INS_VBCSTNEBF162PS,
			RD_INS_VBCSTNESH2PS,
			RD_INS_VBLENDMPD,
			RD_INS_VBLENDMPS,
			RD_INS_VBLENDPD,
			RD_INS_VBLENDPS,
			RD_INS_VBLENDVPD,
			RD_INS_VBLENDVPS,
			RD_INS_VBROADCASTF128,
			RD_INS_VBROADCASTF32X2,
			RD_INS_VBROADCASTF32X4,
			RD_INS_VBROADCASTF32X8,
			RD_INS_VBROADCASTF64X2,
			RD_INS_VBROADCASTF64X4,
			RD_INS_VBROADCASTI128,
			RD_INS_VBROADCASTI32X2,
			RD_INS_VBROADCASTI32X4,
			RD_INS_VBROADCASTI32X8,
			RD_INS_VBROADCASTI64X2,
			RD_INS_VBROADCASTI64X4,
			RD_INS_VBROADCASTSD,
			RD_INS_VBROADCASTSS,
			RD_INS_VCMPPD,
			RD_INS_VCMPPH,
			RD_INS_VCMPPS,
			RD_INS_VCMPSD,
			RD_INS_VCMPSH,
			RD_INS_VCMPSS,
			RD_INS_VCOMISD,
			RD_INS_VCOMISH,
			RD_INS_VCOMISS,
			RD_INS_VCOMPRESSPD,
			RD_INS_VCOMPRESSPS,
			RD_INS_VCVTDQ2PD,
			RD_INS_VCVTDQ2PH,
			RD_INS_VCVTDQ2PS,
			RD_INS_VCVTNE2PS2BF16,
			RD_INS_VCVTNEEBF162PS,
			RD_INS_VCVTNEEPH2PS,
			RD_INS_VCVTNEOBF162PS,
			RD_INS_VCVTNEOPH2PS,
			RD_INS_VCVTNEPS2BF16,
			RD_INS_VCVTPD2DQ,
			RD_INS_VCVTPD2PH,
			RD_INS_VCVTPD2PS,
			RD_INS_VCVTPD2QQ,
			RD_INS_VCVTPD2UDQ,
			RD_INS_VCVTPD2UQQ,
			RD_INS_VCVTPH2DQ,
			RD_INS_VCVTPH2PD,
			RD_INS_VCVTPH2PS,
			RD_INS_VCVTPH2PSX,
			RD_INS_VCVTPH2QQ,
			RD_INS_VCVTPH2UDQ,
			RD_INS_VCVTPH2UQQ,
			RD_INS_VCVTPH2UW,
			RD_INS_VCVTPH2W,
			RD_INS_VCVTPS2DQ,
			RD_INS_VCVTPS2PD,
			RD_INS_VCVTPS2PH,
			RD_INS_VCVTPS2PHX,
			RD_INS_VCVTPS2QQ,
			RD_INS_VCVTPS2UDQ,
			RD_INS_VCVTPS2UQQ,
			RD_INS_VCVTQQ2PD,
			RD_INS_VCVTQQ2PH,
			RD_INS_VCVTQQ2PS,
			RD_INS_VCVTSD2SH,
			RD_INS_VCVTSD2SI,
			RD_INS_VCVTSD2SS,
			RD_INS_VCVTSD2USI,
			RD_INS_VCVTSH2SD,
			RD_INS_VCVTSH2SI,
			RD_INS_VCVTSH2SS,
			RD_INS_VCVTSH2USI,
			RD_INS_VCVTSI2SD,
			RD_INS_VCVTSI2SH,
			RD_INS_VCVTSI2SS,
			RD_INS_VCVTSS2SD,
			RD_INS_VCVTSS2SH,
			RD_INS_VCVTSS2SI,
			RD_INS_VCVTSS2USI,
			RD_INS_VCVTTPD2DQ,
			RD_INS_VCVTTPD2QQ,
			RD_INS_VCVTTPD2UDQ,
			RD_INS_VCVTTPD2UQQ,
			RD_INS_VCVTTPH2DQ,
			RD_INS_VCVTTPH2QQ,
			RD_INS_VCVTTPH2UDQ,
			RD_INS_VCVTTPH2UQQ,
			RD_INS_VCVTTPH2UW,
			RD_INS_VCVTTPH2W,
			RD_INS_VCVTTPS2DQ,
			RD_INS_VCVTTPS2QQ,
			RD_INS_VCVTTPS2UDQ,
			RD_INS_VCVTTPS2UQQ,
			RD_INS_VCVTTSD2SI,
			RD_INS_VCVTTSD2USI,
			RD_INS_VCVTTSH2SI,
			RD_INS_VCVTTSH2USI,
			RD_INS_VCVTTSS2SI,
			RD_INS_VCVTTSS2USI,
			RD_INS_VCVTUDQ2PD,
			RD_INS_VCVTUDQ2PH,
			RD_INS_VCVTUDQ2PS,
			RD_INS_VCVTUQQ2PD,
			RD_INS_VCVTUQQ2PH,
			RD_INS_VCVTUQQ2PS,
			RD_INS_VCVTUSI2SD,
			RD_INS_VCVTUSI2SH,
			RD_INS_VCVTUSI2SS,
			RD_INS_VCVTUW2PH,
			RD_INS_VCVTW2PH,
			RD_INS_VDBPSADBW,
			RD_INS_VDIVPD,
			RD_INS_VDIVPH,
			RD_INS_VDIVPS,
			RD_INS_VDIVSD,
			RD_INS_VDIVSH,
			RD_INS_VDIVSS,
			RD_INS_VDPBF16PS,
			RD_INS_VDPPD,
			RD_INS_VDPPS,
			RD_INS_VERR,
			RD_INS_VERW,
			RD_INS_VEXP2PD,
			RD_INS_VEXP2PS,
			RD_INS_VEXPANDPD,
			RD_INS_VEXPANDPS,
			RD_INS_VEXTRACTF128,
			RD_INS_VEXTRACTF32X4,
			RD_INS_VEXTRACTF32X8,
			RD_INS_VEXTRACTF64X2,
			RD_INS_VEXTRACTF64X4,
			RD_INS_VEXTRACTI128,
			RD_INS_VEXTRACTI32X4,
			RD_INS_VEXTRACTI32X8,
			RD_INS_VEXTRACTI64X2,
			RD_INS_VEXTRACTI64X4,
			RD_INS_VEXTRACTPS,
			RD_INS_VFCMADDCPH,
			RD_INS_VFCMADDCSH,
			RD_INS_VFCMULCPH,
			RD_INS_VFCMULCSH,
			RD_INS_VFIXUPIMMPD,
			RD_INS_VFIXUPIMMPS,
			RD_INS_VFIXUPIMMSD,
			RD_INS_VFIXUPIMMSS,
			RD_INS_VFMADD132PD,
			RD_INS_VFMADD132PH,
			RD_INS_VFMADD132PS,
			RD_INS_VFMADD132SD,
			RD_INS_VFMADD132SH,
			RD_INS_VFMADD132SS,
			RD_INS_VFMADD213PD,
			RD_INS_VFMADD213PH,
			RD_INS_VFMADD213PS,
			RD_INS_VFMADD213SD,
			RD_INS_VFMADD213SH,
			RD_INS_VFMADD213SS,
			RD_INS_VFMADD231PD,
			RD_INS_VFMADD231PH,
			RD_INS_VFMADD231PS,
			RD_INS_VFMADD231SD,
			RD_INS_VFMADD231SH,
			RD_INS_VFMADD231SS,
			RD_INS_VFMADDCPH,
			RD_INS_VFMADDCSH,
			RD_INS_VFMADDPD,
			RD_INS_VFMADDPS,
			RD_INS_VFMADDSD,
			RD_INS_VFMADDSS,
			RD_INS_VFMADDSUB132PD,
			RD_INS_VFMADDSUB132PH,
			RD_INS_VFMADDSUB132PS,
			RD_INS_VFMADDSUB213PD,
			RD_INS_VFMADDSUB213PH,
			RD_INS_VFMADDSUB213PS,
			RD_INS_VFMADDSUB231PD,
			RD_INS_VFMADDSUB231PH,
			RD_INS_VFMADDSUB231PS,
			RD_INS_VFMADDSUBPD,
			RD_INS_VFMADDSUBPS,
			RD_INS_VFMSUB132PD,
			RD_INS_VFMSUB132PH,
			RD_INS_VFMSUB132PS,
			RD_INS_VFMSUB132SD,
			RD_INS_VFMSUB132SH,
			RD_INS_VFMSUB132SS,
			RD_INS_VFMSUB213PD,
			RD_INS_VFMSUB213PH,
			RD_INS_VFMSUB213PS,
			RD_INS_VFMSUB213SD,
			RD_INS_VFMSUB213SH,
			RD_INS_VFMSUB213SS,
			RD_INS_VFMSUB231PD,
			RD_INS_VFMSUB231PH,
			RD_INS_VFMSUB231PS,
			RD_INS_VFMSUB231SD,
			RD_INS_VFMSUB231SH,
			RD_INS_VFMSUB231SS,
			RD_INS_VFMSUBADD132PD,
			RD_INS_VFMSUBADD132PH,
			RD_INS_VFMSUBADD132PS,
			RD_INS_VFMSUBADD213PD,
			RD_INS_VFMSUBADD213PH,
			RD_INS_VFMSUBADD213PS,
			RD_INS_VFMSUBADD231PD,
			RD_INS_VFMSUBADD231PH,
			RD_INS_VFMSUBADD231PS,
			RD_INS_VFMSUBADDPD,
			RD_INS_VFMSUBADDPS,
			RD_INS_VFMSUBPD,
			RD_INS_VFMSUBPS,
			RD_INS_VFMSUBSD,
			RD_INS_VFMSUBSS,
			RD_INS_VFMULCPH,
			RD_INS_VFMULCSH,
			RD_INS_VFNMADD132PD,
			RD_INS_VFNMADD132PH,
			RD_INS_VFNMADD132PS,
			RD_INS_VFNMADD132SD,
			RD_INS_VFNMADD132SH,
			RD_INS_VFNMADD132SS,
			RD_INS_VFNMADD213PD,
			RD_INS_VFNMADD213PH,
			RD_INS_VFNMADD213PS,
			RD_INS_VFNMADD213SD,
			RD_INS_VFNMADD213SH,
			RD_INS_VFNMADD213SS,
			RD_INS_VFNMADD231PD,
			RD_INS_VFNMADD231PH,
			RD_INS_VFNMADD231PS,
			RD_INS_VFNMADD231SD,
			RD_INS_VFNMADD231SH,
			RD_INS_VFNMADD231SS,
			RD_INS_VFNMADDPD,
			RD_INS_VFNMADDPS,
			RD_INS_VFNMADDSD,
			RD_INS_VFNMADDSS,
			RD_INS_VFNMSUB132PD,
			RD_INS_VFNMSUB132PH,
			RD_INS_VFNMSUB132PS,
			RD_INS_VFNMSUB132SD,
			RD_INS_VFNMSUB132SH,
			RD_INS_VFNMSUB132SS,
			RD_INS_VFNMSUB213PD,
			RD_INS_VFNMSUB213PH,
			RD_INS_VFNMSUB213PS,
			RD_INS_VFNMSUB213SD,
			RD_INS_VFNMSUB213SH,
			RD_INS_VFNMSUB213SS,
			RD_INS_VFNMSUB231PD,
			RD_INS_VFNMSUB231PH,
			RD_INS_VFNMSUB231PS,
			RD_INS_VFNMSUB231SD,
			RD_INS_VFNMSUB231SH,
			RD_INS_VFNMSUB231SS,
			RD_INS_VFNMSUBPD,
			RD_INS_VFNMSUBPS,
			RD_INS_VFNMSUBSD,
			RD_INS_VFNMSUBSS,
			RD_INS_VFPCLASSPD,
			RD_INS_VFPCLASSPH,
			RD_INS_VFPCLASSPS,
			RD_INS_VFPCLASSSD,
			RD_INS_VFPCLASSSH,
			RD_INS_VFPCLASSSS,
			RD_INS_VFRCZPD,
			RD_INS_VFRCZPS,
			RD_INS_VFRCZSD,
			RD_INS_VFRCZSS,
			RD_INS_VGATHERDPD,
			RD_INS_VGATHERDPS,
			RD_INS_VGATHERPF0DPD,
			RD_INS_VGATHERPF0DPS,
			RD_INS_VGATHERPF0QPD,
			RD_INS_VGATHERPF0QPS,
			RD_INS_VGATHERPF1DPD,
			RD_INS_VGATHERPF1DPS,
			RD_INS_VGATHERPF1QPD,
			RD_INS_VGATHERPF1QPS,
			RD_INS_VGATHERQPD,
			RD_INS_VGATHERQPS,
			RD_INS_VGETEXPPD,
			RD_INS_VGETEXPPH,
			RD_INS_VGETEXPPS,
			RD_INS_VGETEXPSD,
			RD_INS_VGETEXPSH,
			RD_INS_VGETEXPSS,
			RD_INS_VGETMANTPD,
			RD_INS_VGETMANTPH,
			RD_INS_VGETMANTPS,
			RD_INS_VGETMANTSD,
			RD_INS_VGETMANTSH,
			RD_INS_VGETMANTSS,
			RD_INS_VGF2P8AFFINEINVQB,
			RD_INS_VGF2P8AFFINEQB,
			RD_INS_VGF2P8MULB,
			RD_INS_VHADDPD,
			RD_INS_VHADDPS,
			RD_INS_VHSUBPD,
			RD_INS_VHSUBPS,
			RD_INS_VINSERTF128,
			RD_INS_VINSERTF32X4,
			RD_INS_VINSERTF32X8,
			RD_INS_VINSERTF64X2,
			RD_INS_VINSERTF64X4,
			RD_INS_VINSERTI128,
			RD_INS_VINSERTI32X4,
			RD_INS_VINSERTI32X8,
			RD_INS_VINSERTI64X2,
			RD_INS_VINSERTI64X4,
			RD_INS_VINSERTPS,
			RD_INS_VLDDQU,
			RD_INS_VLDMXCSR,
			RD_INS_VMASKMOVDQU,
			RD_INS_VMASKMOVPD,
			RD_INS_VMASKMOVPS,
			RD_INS_VMAXPD,
			RD_INS_VMAXPH,
			RD_INS_VMAXPS,
			RD_INS_VMAXSD,
			RD_INS_VMAXSH,
			RD_INS_VMAXSS,
			RD_INS_VMCALL,
			RD_INS_VMCLEAR,
			RD_INS_VMFUNC,
			RD_INS_VMGEXIT,
			RD_INS_VMINPD,
			RD_INS_VMINPH,
			RD_INS_VMINPS,
			RD_INS_VMINSD,
			RD_INS_VMINSH,
			RD_INS_VMINSS,
			RD_INS_VMLAUNCH,
			RD_INS_VMLOAD,
			RD_INS_VMMCALL,
			RD_INS_VMOVAPD,
			RD_INS_VMOVAPS,
			RD_INS_VMOVD,
			RD_INS_VMOVDDUP,
			RD_INS_VMOVDQA,
			RD_INS_VMOVDQA32,
			RD_INS_VMOVDQA64,
			RD_INS_VMOVDQU,
			RD_INS_VMOVDQU16,
			RD_INS_VMOVDQU32,
			RD_INS_VMOVDQU64,
			RD_INS_VMOVDQU8,
			RD_INS_VMOVHLPS,
			RD_INS_VMOVHPD,
			RD_INS_VMOVHPS,
			RD_INS_VMOVLHPS,
			RD_INS_VMOVLPD,
			RD_INS_VMOVLPS,
			RD_INS_VMOVMSKPD,
			RD_INS_VMOVMSKPS,
			RD_INS_VMOVNTDQ,
			RD_INS_VMOVNTDQA,
			RD_INS_VMOVNTPD,
			RD_INS_VMOVNTPS,
			RD_INS_VMOVQ,
			RD_INS_VMOVSD,
			RD_INS_VMOVSH,
			RD_INS_VMOVSHDUP,
			RD_INS_VMOVSLDUP,
			RD_INS_VMOVSS,
			RD_INS_VMOVUPD,
			RD_INS_VMOVUPS,
			RD_INS_VMOVW,
			RD_INS_VMPSADBW,
			RD_INS_VMPTRLD,
			RD_INS_VMPTRST,
			RD_INS_VMREAD,
			RD_INS_VMRESUME,
			RD_INS_VMRUN,
			RD_INS_VMSAVE,
			RD_INS_VMULPD,
			RD_INS_VMULPH,
			RD_INS_VMULPS,
			RD_INS_VMULSD,
			RD_INS_VMULSH,
			RD_INS_VMULSS,
			RD_INS_VMWRITE,
			RD_INS_VMXOFF,
			RD_INS_VMXON,
			RD_INS_VORPD,
			RD_INS_VORPS,
			RD_INS_VP2INTERSECTD,
			RD_INS_VP2INTERSECTQ,
			RD_INS_VP4DPWSSD,
			RD_INS_VP4DPWSSDS,
			RD_INS_VPABSB,
			RD_INS_VPABSD,
			RD_INS_VPABSQ,
			RD_INS_VPABSW,
			RD_INS_VPACKSSDW,
			RD_INS_VPACKSSWB,
			RD_INS_VPACKUSDW,
			RD_INS_VPACKUSWB,
			RD_INS_VPADDB,
			RD_INS_VPADDD,
			RD_INS_VPADDQ,
			RD_INS_VPADDSB,
			RD_INS_VPADDSW,
			RD_INS_VPADDUSB,
			RD_INS_VPADDUSW,
			RD_INS_VPADDW,
			RD_INS_VPALIGNR,
			RD_INS_VPAND,
			RD_INS_VPANDD,
			RD_INS_VPANDN,
			RD_INS_VPANDND,
			RD_INS_VPANDNQ,
			RD_INS_VPANDQ,
			RD_INS_VPAVGB,
			RD_INS_VPAVGW,
			RD_INS_VPBLENDD,
			RD_INS_VPBLENDMB,
			RD_INS_VPBLENDMD,
			RD_INS_VPBLENDMQ,
			RD_INS_VPBLENDMW,
			RD_INS_VPBLENDVB,
			RD_INS_VPBLENDW,
			RD_INS_VPBROADCASTB,
			RD_INS_VPBROADCASTD,
			RD_INS_VPBROADCASTMB2Q,
			RD_INS_VPBROADCASTMW2D,
			RD_INS_VPBROADCASTQ,
			RD_INS_VPBROADCASTW,
			RD_INS_VPCLMULQDQ,
			RD_INS_VPCMOV,
			RD_INS_VPCMPB,
			RD_INS_VPCMPD,
			RD_INS_VPCMPEQB,
			RD_INS_VPCMPEQD,
			RD_INS_VPCMPEQQ,
			RD_INS_VPCMPEQW,
			RD_INS_VPCMPESTRI,
			RD_INS_VPCMPESTRM,
			RD_INS_VPCMPGTB,
			RD_INS_VPCMPGTD,
			RD_INS_VPCMPGTQ,
			RD_INS_VPCMPGTW,
			RD_INS_VPCMPISTRI,
			RD_INS_VPCMPISTRM,
			RD_INS_VPCMPQ,
			RD_INS_VPCMPUB,
			RD_INS_VPCMPUD,
			RD_INS_VPCMPUQ,
			RD_INS_VPCMPUW,
			RD_INS_VPCMPW,
			RD_INS_VPCOMB,
			RD_INS_VPCOMD,
			RD_INS_VPCOMPRESSB,
			RD_INS_VPCOMPRESSD,
			RD_INS_VPCOMPRESSQ,
			RD_INS_VPCOMPRESSW,
			RD_INS_VPCOMQ,
			RD_INS_VPCOMUB,
			RD_INS_VPCOMUD,
			RD_INS_VPCOMUQ,
			RD_INS_VPCOMUW,
			RD_INS_VPCOMW,
			RD_INS_VPCONFLICTD,
			RD_INS_VPCONFLICTQ,
			RD_INS_VPDPBSSD,
			RD_INS_VPDPBSSDS,
			RD_INS_VPDPBSUD,
			RD_INS_VPDPBSUDS,
			RD_INS_VPDPBUSD,
			RD_INS_VPDPBUSDS,
			RD_INS_VPDPBUUD,
			RD_INS_VPDPBUUDS,
			RD_INS_VPDPWSSD,
			RD_INS_VPDPWSSDS,
			RD_INS_VPDPWSUD,
			RD_INS_VPDPWSUDS,
			RD_INS_VPDPWUSD,
			RD_INS_VPDPWUSDS,
			RD_INS_VPDPWUUD,
			RD_INS_VPDPWUUDS,
			RD_INS_VPERM2F128,
			RD_INS_VPERM2I128,
			RD_INS_VPERMB,
			RD_INS_VPERMD,
			RD_INS_VPERMI2B,
			RD_INS_VPERMI2D,
			RD_INS_VPERMI2PD,
			RD_INS_VPERMI2PS,
			RD_INS_VPERMI2Q,
			RD_INS_VPERMI2W,
			RD_INS_VPERMIL2PD,
			RD_INS_VPERMIL2PS,
			RD_INS_VPERMILPD,
			RD_INS_VPERMILPS,
			RD_INS_VPERMPD,
			RD_INS_VPERMPS,
			RD_INS_VPERMQ,
			RD_INS_VPERMT2B,
			RD_INS_VPERMT2D,
			RD_INS_VPERMT2PD,
			RD_INS_VPERMT2PS,
			RD_INS_VPERMT2Q,
			RD_INS_VPERMT2W,
			RD_INS_VPERMW,
			RD_INS_VPEXPANDB,
			RD_INS_VPEXPANDD,
			RD_INS_VPEXPANDQ,
			RD_INS_VPEXPANDW,
			RD_INS_VPEXTRB,
			RD_INS_VPEXTRD,
			RD_INS_VPEXTRQ,
			RD_INS_VPEXTRW,
			RD_INS_VPGATHERDD,
			RD_INS_VPGATHERDQ,
			RD_INS_VPGATHERQD,
			RD_INS_VPGATHERQQ,
			RD_INS_VPHADDBD,
			RD_INS_VPHADDBQ,
			RD_INS_VPHADDBW,
			RD_INS_VPHADDD,
			RD_INS_VPHADDDQ,
			RD_INS_VPHADDSW,
			RD_INS_VPHADDUBD,
			RD_INS_VPHADDUBQ,
			RD_INS_VPHADDUBW,
			RD_INS_VPHADDUDQ,
			RD_INS_VPHADDUWD,
			RD_INS_VPHADDUWQ,
			RD_INS_VPHADDW,
			RD_INS_VPHADDWD,
			RD_INS_VPHADDWQ,
			RD_INS_VPHMINPOSUW,
			RD_INS_VPHSUBBW,
			RD_INS_VPHSUBD,
			RD_INS_VPHSUBDQ,
			RD_INS_VPHSUBSW,
			RD_INS_VPHSUBW,
			RD_INS_VPHSUBWD,
			RD_INS_VPINSRB,
			RD_INS_VPINSRD,
			RD_INS_VPINSRQ,
			RD_INS_VPINSRW,
			RD_INS_VPLZCNTD,
			RD_INS_VPLZCNTQ,
			RD_INS_VPMACSDD,
			RD_INS_VPMACSDQH,
			RD_INS_VPMACSDQL,
			RD_INS_VPMACSSDD,
			RD_INS_VPMACSSDQH,
			RD_INS_VPMACSSDQL,
			RD_INS_VPMACSSWD,
			RD_INS_VPMACSSWW,
			RD_INS_VPMACSWD,
			RD_INS_VPMACSWW,
			RD_INS_VPMADCSSWD,
			RD_INS_VPMADCSWD,
			RD_INS_VPMADD52HUQ,
			RD_INS_VPMADD52LUQ,
			RD_INS_VPMADDUBSW,
			RD_INS_VPMADDWD,
			RD_INS_VPMASKMOVD,
			RD_INS_VPMASKMOVQ,
			RD_INS_VPMAXSB,
			RD_INS_VPMAXSD,
			RD_INS_VPMAXSQ,
			RD_INS_VPMAXSW,
			RD_INS_VPMAXUB,
			RD_INS_VPMAXUD,
			RD_INS_VPMAXUQ,
			RD_INS_VPMAXUW,
			RD_INS_VPMINSB,
			RD_INS_VPMINSD,
			RD_INS_VPMINSQ,
			RD_INS_VPMINSW,
			RD_INS_VPMINUB,
			RD_INS_VPMINUD,
			RD_INS_VPMINUQ,
			RD_INS_VPMINUW,
			RD_INS_VPMOVB2M,
			RD_INS_VPMOVD2M,
			RD_INS_VPMOVDB,
			RD_INS_VPMOVDW,
			RD_INS_VPMOVM2B,
			RD_INS_VPMOVM2D,
			RD_INS_VPMOVM2Q,
			RD_INS_VPMOVM2W,
			RD_INS_VPMOVMSKB,
			RD_INS_VPMOVQ2M,
			RD_INS_VPMOVQB,
			RD_INS_VPMOVQD,
			RD_INS_VPMOVQW,
			RD_INS_VPMOVSDB,
			RD_INS_VPMOVSDW,
			RD_INS_VPMOVSQB,
			RD_INS_VPMOVSQD,
			RD_INS_VPMOVSQW,
			RD_INS_VPMOVSWB,
			RD_INS_VPMOVSXBD,
			RD_INS_VPMOVSXBQ,
			RD_INS_VPMOVSXBW,
			RD_INS_VPMOVSXDQ,
			RD_INS_VPMOVSXWD,
			RD_INS_VPMOVSXWQ,
			RD_INS_VPMOVUSDB,
			RD_INS_VPMOVUSDW,
			RD_INS_VPMOVUSQB,
			RD_INS_VPMOVUSQD,
			RD_INS_VPMOVUSQW,
			RD_INS_VPMOVUSWB,
			RD_INS_VPMOVW2M,
			RD_INS_VPMOVWB,
			RD_INS_VPMOVZXBD,
			RD_INS_VPMOVZXBQ,
			RD_INS_VPMOVZXBW,
			RD_INS_VPMOVZXDQ,
			RD_INS_VPMOVZXWD,
			RD_INS_VPMOVZXWQ,
			RD_INS_VPMULDQ,
			RD_INS_VPMULHRSW,
			RD_INS_VPMULHUW,
			RD_INS_VPMULHW,
			RD_INS_VPMULLD,
			RD_INS_VPMULLQ,
			RD_INS_VPMULLW,
			RD_INS_VPMULTISHIFTQB,
			RD_INS_VPMULUDQ,
			RD_INS_VPOPCNTB,
			RD_INS_VPOPCNTD,
			RD_INS_VPOPCNTQ,
			RD_INS_VPOPCNTW,
			RD_INS_VPOR,
			RD_INS_VPORD,
			RD_INS_VPORQ,
			RD_INS_VPPERM,
			RD_INS_VPROLD,
			RD_INS_VPROLQ,
			RD_INS_VPROLVD,
			RD_INS_VPROLVQ,
			RD_INS_VPRORD,
			RD_INS_VPRORQ,
			RD_INS_VPRORVD,
			RD_INS_VPRORVQ,
			RD_INS_VPROTB,
			RD_INS_VPROTD,
			RD_INS_VPROTQ,
			RD_INS_VPROTW,
			RD_INS_VPSADBW,
			RD_INS_VPSCATTERDD,
			RD_INS_VPSCATTERDQ,
			RD_INS_VPSCATTERQD,
			RD_INS_VPSCATTERQQ,
			RD_INS_VPSHAB,
			RD_INS_VPSHAD,
			RD_INS_VPSHAQ,
			RD_INS_VPSHAW,
			RD_INS_VPSHLB,
			RD_INS_VPSHLD,
			RD_INS_VPSHLDD,
			RD_INS_VPSHLDQ,
			RD_INS_VPSHLDVD,
			RD_INS_VPSHLDVQ,
			RD_INS_VPSHLDVW,
			RD_INS_VPSHLDW,
			RD_INS_VPSHLQ,
			RD_INS_VPSHLW,
			RD_INS_VPSHRDD,
			RD_INS_VPSHRDQ,
			RD_INS_VPSHRDVD,
			RD_INS_VPSHRDVQ,
			RD_INS_VPSHRDVW,
			RD_INS_VPSHRDW,
			RD_INS_VPSHUFB,
			RD_INS_VPSHUFBITQMB,
			RD_INS_VPSHUFD,
			RD_INS_VPSHUFHW,
			RD_INS_VPSHUFLW,
			RD_INS_VPSIGNB,
			RD_INS_VPSIGND,
			RD_INS_VPSIGNW,
			RD_INS_VPSLLD,
			RD_INS_VPSLLDQ,
			RD_INS_VPSLLQ,
			RD_INS_VPSLLVD,
			RD_INS_VPSLLVQ,
			RD_INS_VPSLLVW,
			RD_INS_VPSLLW,
			RD_INS_VPSRAD,
			RD_INS_VPSRAQ,
			RD_INS_VPSRAVD,
			RD_INS_VPSRAVQ,
			RD_INS_VPSRAVW,
			RD_INS_VPSRAW,
			RD_INS_VPSRLD,
			RD_INS_VPSRLDQ,
			RD_INS_VPSRLQ,
			RD_INS_VPSRLVD,
			RD_INS_VPSRLVQ,
			RD_INS_VPSRLVW,
			RD_INS_VPSRLW,
			RD_INS_VPSUBB,
			RD_INS_VPSUBD,
			RD_INS_VPSUBQ,
			RD_INS_VPSUBSB,
			RD_INS_VPSUBSW,
			RD_INS_VPSUBUSB,
			RD_INS_VPSUBUSW,
			RD_INS_VPSUBW,
			RD_INS_VPTERNLOGD,
			RD_INS_VPTERNLOGQ,
			RD_INS_VPTEST,
			RD_INS_VPTESTMB,
			RD_INS_VPTESTMD,
			RD_INS_VPTESTMQ,
			RD_INS_VPTESTMW,
			RD_INS_VPTESTNMB,
			RD_INS_VPTESTNMD,
			RD_INS_VPTESTNMQ,
			RD_INS_VPTESTNMW,
			RD_INS_VPUNPCKHBW,
			RD_INS_VPUNPCKHDQ,
			RD_INS_VPUNPCKHQDQ,
			RD_INS_VPUNPCKHWD,
			RD_INS_VPUNPCKLBW,
			RD_INS_VPUNPCKLDQ,
			RD_INS_VPUNPCKLQDQ,
			RD_INS_VPUNPCKLWD,
			RD_INS_VPXOR,
			RD_INS_VPXORD,
			RD_INS_VPXORQ,
			RD_INS_VRANGEPD,
			RD_INS_VRANGEPS,
			RD_INS_VRANGESD,
			RD_INS_VRANGESS,
			RD_INS_VRCP14PD,
			RD_INS_VRCP14PS,
			RD_INS_VRCP14SD,
			RD_INS_VRCP14SS,
			RD_INS_VRCP28PD,
			RD_INS_VRCP28PS,
			RD_INS_VRCP28SD,
			RD_INS_VRCP28SS,
			RD_INS_VRCPPH,
			RD_INS_VRCPPS,
			RD_INS_VRCPSH,
			RD_INS_VRCPSS,
			RD_INS_VREDUCEPD,
			RD_INS_VREDUCEPH,
			RD_INS_VREDUCEPS,
			RD_INS_VREDUCESD,
			RD_INS_VREDUCESH,
			RD_INS_VREDUCESS,
			RD_INS_VRNDSCALEPD,
			RD_INS_VRNDSCALEPH,
			RD_INS_VRNDSCALEPS,
			RD_INS_VRNDSCALESD,
			RD_INS_VRNDSCALESH,
			RD_INS_VRNDSCALESS,
			RD_INS_VROUNDPD,
			RD_INS_VROUNDPS,
			RD_INS_VROUNDSD,
			RD_INS_VROUNDSS,
			RD_INS_VRSQRT14PD,
			RD_INS_VRSQRT14PS,
			RD_INS_VRSQRT14SD,
			RD_INS_VRSQRT14SS,
			RD_INS_VRSQRT28PD,
			RD_INS_VRSQRT28PS,
			RD_INS_VRSQRT28SD,
			RD_INS_VRSQRT28SS,
			RD_INS_VRSQRTPH,
			RD_INS_VRSQRTPS,
			RD_INS_VRSQRTSH,
			RD_INS_VRSQRTSS,
			RD_INS_VSCALEFPD,
			RD_INS_VSCALEFPH,
			RD_INS_VSCALEFPS,
			RD_INS_VSCALEFSD,
			RD_INS_VSCALEFSH,
			RD_INS_VSCALEFSS,
			RD_INS_VSCATTERDPD,
			RD_INS_VSCATTERDPS,
			RD_INS_VSCATTERPF0DPD,
			RD_INS_VSCATTERPF0DPS,
			RD_INS_VSCATTERPF0QPD,
			RD_INS_VSCATTERPF0QPS,
			RD_INS_VSCATTERPF1DPD,
			RD_INS_VSCATTERPF1DPS,
			RD_INS_VSCATTERPF1QPD,
			RD_INS_VSCATTERPF1QPS,
			RD_INS_VSCATTERQPD,
			RD_INS_VSCATTERQPS,
			RD_INS_VSHA512MSG1,
			RD_INS_VSHA512MSG2,
			RD_INS_VSHA512RNDS2,
			RD_INS_VSHUFF32X4,
			RD_INS_VSHUFF64X2,
			RD_INS_VSHUFI32X4,
			RD_INS_VSHUFI64X2,
			RD_INS_VSHUFPD,
			RD_INS_VSHUFPS,
			RD_INS_VSM3MSG1,
			RD_INS_VSM3MSG2,
			RD_INS_VSM3RNDS2,
			RD_INS_VSM4KEY4,
			RD_INS_VSM4RNDS4,
			RD_INS_VSQRTPD,
			RD_INS_VSQRTPH,
			RD_INS_VSQRTPS,
			RD_INS_VSQRTSD,
			RD_INS_VSQRTSH,
			RD_INS_VSQRTSS,
			RD_INS_VSTMXCSR,
			RD_INS_VSUBPD,
			RD_INS_VSUBPH,
			RD_INS_VSUBPS,
			RD_INS_VSUBSD,
			RD_INS_VSUBSH,
			RD_INS_VSUBSS,
			RD_INS_VTESTPD,
			RD_INS_VTESTPS,
			RD_INS_VUCOMISD,
			RD_INS_VUCOMISH,
			RD_INS_VUCOMISS,
			RD_INS_VUNPCKHPD,
			RD_INS_VUNPCKHPS,
			RD_INS_VUNPCKLPD,
			RD_INS_VUNPCKLPS,
			RD_INS_VXORPD,
			RD_INS_VXORPS,
			RD_INS_VZEROALL,
			RD_INS_VZEROUPPER,
			RD_INS_WAIT,
			RD_INS_WBINVD,
			RD_INS_WBNOINVD,
			RD_INS_WRFSBASE,
			RD_INS_WRGSBASE,
			RD_INS_WRMSR,
			RD_INS_WRMSRLIST,
			RD_INS_WRMSRNS,
			RD_INS_WRPKRU,
			RD_INS_WRSHR,
			RD_INS_WRSS,
			RD_INS_WRUSS,
			RD_INS_XABORT,
			RD_INS_XADD,
			RD_INS_XBEGIN,
			RD_INS_XCHG,
			RD_INS_XCRYPTCBC,
			RD_INS_XCRYPTCFB,
			RD_INS_XCRYPTCTR,
			RD_INS_XCRYPTECB,
			RD_INS_XCRYPTOFB,
			RD_INS_XEND,
			RD_INS_XGETBV,
			RD_INS_XLATB,
			RD_INS_XOR,
			RD_INS_XORPD,
			RD_INS_XORPS,
			RD_INS_XRESLDTRK,
			RD_INS_XRSTOR,
			RD_INS_XRSTORS,
			RD_INS_XSAVE,
			RD_INS_XSAVEC,
			RD_INS_XSAVEOPT,
			RD_INS_XSAVES,
			RD_INS_XSETBV,
			RD_INS_XSHA1,
			RD_INS_XSHA256,
			RD_INS_XSTORE,
			RD_INS_XSUSLDTRK,
			RD_INS_XTEST
		} RD_INS_CLASS, *PRD_INS_CLASS;

		typedef enum _RD_INS_TYPE {
			RD_CAT_INVALID = 0,
			RD_CAT_3DNOW,
			RD_CAT_AES,
			RD_CAT_AESKL,
			RD_CAT_AMX,
			RD_CAT_ARITH,
			RD_CAT_AVX,
			RD_CAT_AVX2,
			RD_CAT_AVX2GATHER,
			RD_CAT_AVX512,
			RD_CAT_AVX512BF16,
			RD_CAT_AVX512FP16,
			RD_CAT_AVX512VBMI,
			RD_CAT_AVX512VP2INTERSECT,
			RD_CAT_AVXIFMA,
			RD_CAT_AVXNECONVERT,
			RD_CAT_AVXVNNI,
			RD_CAT_AVXVNNIINT16,
			RD_CAT_AVXVNNIINT8,
			RD_CAT_BITBYTE,
			RD_CAT_BLEND,
			RD_CAT_BMI1,
			RD_CAT_BMI2,
			RD_CAT_BROADCAST,
			RD_CAT_CALL,
			RD_CAT_CET,
			RD_CAT_CLDEMOTE,
			RD_CAT_CMOV,
			RD_CAT_CMPCCXADD,
			RD_CAT_COMPRESS,
			RD_CAT_COND_BR,
			RD_CAT_CONFLICT,
			RD_CAT_CONVERT,
			RD_CAT_DATAXFER,
			RD_CAT_DECIMAL,
			RD_CAT_ENQCMD,
			RD_CAT_EXPAND,
			RD_CAT_FLAGOP,
			RD_CAT_FMA4,
			RD_CAT_GATHER,
			RD_CAT_GFNI,
			RD_CAT_HRESET,
			RD_CAT_I386,
			RD_CAT_IFMA,
			RD_CAT_INTERRUPT,
			RD_CAT_IO,
			RD_CAT_IOSTRINGOP,
			RD_CAT_KL,
			RD_CAT_KMASK,
			RD_CAT_KNL,
			RD_CAT_LKGS,
			RD_CAT_LOGIC,
			RD_CAT_LOGICAL,
			RD_CAT_LOGICAL_FP,
			RD_CAT_LWP,
			RD_CAT_LZCNT,
			RD_CAT_MISC,
			RD_CAT_MMX,
			RD_CAT_MOVDIR64B,
			RD_CAT_MOVDIRI,
			RD_CAT_MPX,
			RD_CAT_NOP,
			RD_CAT_PADLOCK,
			RD_CAT_PCLMULQDQ,
			RD_CAT_PCONFIG,
			RD_CAT_POP,
			RD_CAT_PREFETCH,
			RD_CAT_PTWRITE,
			RD_CAT_PUSH,
			RD_CAT_RAOINT,
			RD_CAT_RDPID,
			RD_CAT_RDRAND,
			RD_CAT_RDSEED,
			RD_CAT_RDWRFSGS,
			RD_CAT_RET,
			RD_CAT_ROTATE,
			RD_CAT_SCATTER,
			RD_CAT_SEGOP,
			RD_CAT_SEMAPHORE,
			RD_CAT_SGX,
			RD_CAT_SHA,
			RD_CAT_SHA512,
			RD_CAT_SHIFT,
			RD_CAT_SM3,
			RD_CAT_SM4,
			RD_CAT_SMAP,
			RD_CAT_SSE,
			RD_CAT_SSE2,
			RD_CAT_STRINGOP,
			RD_CAT_STTNI,
			RD_CAT_SYSCALL,
			RD_CAT_SYSRET,
			RD_CAT_SYSTEM,
			RD_CAT_TDX,
			RD_CAT_UD,
			RD_CAT_UINTR,
			RD_CAT_UNCOND_BR,
			RD_CAT_UNKNOWN,
			RD_CAT_VAES,
			RD_CAT_VFMA,
			RD_CAT_VFMAPS,
			RD_CAT_VNNI,
			RD_CAT_VNNIW,
			RD_CAT_VPCLMULQDQ,
			RD_CAT_VPOPCNT,
			RD_CAT_VTX,
			RD_CAT_WAITPKG,
			RD_CAT_WBNOINVD,
			RD_CAT_WIDENOP,
			RD_CAT_WIDE_KL,
			RD_CAT_X87_ALU,
			RD_CAT_XOP,
			RD_CAT_XSAVE
		} RD_INS_CATEGORY, *PRD_INS_CATEGORY;

		typedef enum _RD_INS_SET {
			RD_SET_INVALID = 0,
			RD_SET_3DNOW,
			RD_SET_ADX,
			RD_SET_AES,
			RD_SET_AMD,
			RD_SET_AMXBF16,
			RD_SET_AMXCOMPLEX,
			RD_SET_AMXFP16,
			RD_SET_AMXINT8,
			RD_SET_AMXTILE,
			RD_SET_AVX,
			RD_SET_AVX2,
			RD_SET_AVX2GATHER,
			RD_SET_AVX5124FMAPS,
			RD_SET_AVX5124VNNIW,
			RD_SET_AVX512BF16,
			RD_SET_AVX512BITALG,
			RD_SET_AVX512BW,
			RD_SET_AVX512CD,
			RD_SET_AVX512DQ,
			RD_SET_AVX512ER,
			RD_SET_AVX512F,
			RD_SET_AVX512FP16,
			RD_SET_AVX512IFMA,
			RD_SET_AVX512PF,
			RD_SET_AVX512VBMI,
			RD_SET_AVX512VBMI2,
			RD_SET_AVX512VNNI,
			RD_SET_AVX512VP2INTERSECT,
			RD_SET_AVX512VPOPCNTDQ,
			RD_SET_AVXIFMA,
			RD_SET_AVXNECONVERT,
			RD_SET_AVXVNNI,
			RD_SET_AVXVNNIINT16,
			RD_SET_AVXVNNIINT8,
			RD_SET_BMI1,
			RD_SET_BMI2,
			RD_SET_CET_IBT,
			RD_SET_CET_SS,
			RD_SET_CLDEMOTE,
			RD_SET_CLFSH,
			RD_SET_CLFSHOPT,
			RD_SET_CLWB,
			RD_SET_CLZERO,
			RD_SET_CMPCCXADD,
			RD_SET_CMPXCHG16B,
			RD_SET_CYRIX,
			RD_SET_CYRIX_SMM,
			RD_SET_ENQCMD,
			RD_SET_F16C,
			RD_SET_FMA,
			RD_SET_FMA4,
			RD_SET_FRED,
			RD_SET_FXSAVE,
			RD_SET_GFNI,
			RD_SET_HRESET,
			RD_SET_I186,
			RD_SET_I286PROT,
			RD_SET_I286REAL,
			RD_SET_I386,
			RD_SET_I486,
			RD_SET_I486REAL,
			RD_SET_I64,
			RD_SET_I86,
			RD_SET_INVLPGB,
			RD_SET_INVPCID,
			RD_SET_KL,
			RD_SET_LKGS,
			RD_SET_LONGMODE,
			RD_SET_LWP,
			RD_SET_LZCNT,
			RD_SET_MCOMMIT,
			RD_SET_MMX,
			RD_SET_MOVBE,
			RD_SET_MOVDIR64B,
			RD_SET_MOVDIRI,
			RD_SET_MPX,
			RD_SET_MSRLIST,
			RD_SET_MWAITT,
			RD_SET_PAUSE,
			RD_SET_PCLMULQDQ,
			RD_SET_PCONFIG,
			RD_SET_PENTIUMREAL,
			RD_SET_PKU,
			RD_SET_POPCNT,
			RD_SET_PPRO,
			RD_SET_PREFETCHITI,
			RD_SET_PREFETCH_NOP,
			RD_SET_PTWRITE,
			RD_SET_RAOINT,
			RD_SET_RDPID,
			RD_SET_RDPMC,
			RD_SET_RDPRU,
			RD_SET_RDRAND,
			RD_SET_RDSEED,
			RD_SET_RDTSCP,
			RD_SET_RDWRFSGS,
			RD_SET_SERIALIZE,
			RD_SET_SGX,
			RD_SET_SHA,
			RD_SET_SHA512,
			RD_SET_SM3,
			RD_SET_SM4,
			RD_SET_SMAP,
			RD_SET_SMX,
			RD_SET_SNP,
			RD_SET_SSE,
			RD_SET_SSE2,
			RD_SET_SSE3,
			RD_SET_SSE4,
			RD_SET_SSE42,
			RD_SET_SSE4A,
			RD_SET_SSSE3,
			RD_SET_SVM,
			RD_SET_TBM,
			RD_SET_TDX,
			RD_SET_TSE,
			RD_SET_TSX,
			RD_SET_TSXLDTRK,
			RD_SET_UD,
			RD_SET_UINTR,
			RD_SET_UNKNOWN,
			RD_SET_VAES,
			RD_SET_VPCLMULQDQ,
			RD_SET_VTX,
			RD_SET_WAITPKG,
			RD_SET_WBNOINVD,
			RD_SET_WRMSRNS,
			RD_SET_X87,
			RD_SET_XOP,
			RD_SET_XSAVE,
			RD_SET_XSAVEC,
			RD_SET_XSAVES
		} RD_INS_SET, *PRD_INS_SET;

		enum {
			RDR_AX = 0,
			RDR_CX,
			RDR_DX,
			RDR_BX,
			RDR_SP,
			RDR_BP,
			RDR_SI,
			RDR_DI,
			RDR_R8W,
			RDR_R9W,
			RDR_R10W,
			RDR_R11W,
			RDR_R12W,
			RDR_R13W,
			RDR_R14W,
			RDR_R15W
		};

		enum {
			RDR_AL = 0,
			RDR_CL,
			RDR_DL,
			RDR_BL,
			RDR_AH,
			RDR_CH,
			RDR_DH,
			RDR_BH
		};

		enum {
			RDR_AL64 = 0,
			RDR_CL64,
			RDR_DL64,
			RDR_BL64,
			RDR_SPL,
			RDR_BPL,
			RDR_SIL,
			RDR_DIL,
			RDR_R8L,
			RDR_R9L,
			RDR_R10L,
			RDR_R11L,
			RDR_R12L,
			RDR_R13L,
			RDR_R14L,
			RDR_R15L
		};

		enum {
			RDR_EAX = 0,
			RDR_ECX,
			RDR_EDX,
			RDR_EBX,
			RDR_ESP,
			RDR_EBP,
			RDR_ESI,
			RDR_EDI,
			RDR_R8D,
			RDR_R9D,
			RDR_R10D,
			RDR_R11D,
			RDR_R12D,
			RDR_R13D,
			RDR_R14D,
			RDR_R15D
		};

		enum {
			RDR_RAX = 0,
			RDR_RCX,
			RDR_RDX,
			RDR_RBX,
			RDR_RSP,
			RDR_RBP,
			RDR_RSI,
			RDR_RDI,
			RDR_R8,
			RDR_R9,
			RDR_R10,
			RDR_R11,
			RDR_R12,
			RDR_R13,
			RDR_R14,
			RDR_R15
		};

		enum {
			RDR_ES = 0,
			RDR_CS,
			RDR_SS,
			RDR_DS,
			RDR_FS,
			RDR_GS,
			RDR_INV6,
			RDR_INV7
		};

		enum {
			RDR_CR0 = 0,
			RDR_CR1,
			RDR_CR2,
			RDR_CR3,
			RDR_CR4,
			RDR_CR5,
			RDR_CR6,
			RDR_CR7,
			RDR_CR8,
			RDR_CR9,
			RDR_CR10,
			RDR_CR11,
			RDR_CR12,
			RDR_CR13,
			RDR_CR14,
			RDR_CR15
		};

		enum {
			RDR_DR0 = 0,
			RDR_DR1,
			RDR_DR2,
			RDR_DR3,
			RDR_DR4,
			RDR_DR5,
			RDR_DR6,
			RDR_DR7,
			RDR_DR8,
			RDR_DR9,
			RDR_DR10,
			RDR_DR11,
			RDR_DR12,
			RDR_DR13,
			RDR_DR14,
			RDR_DR15
		};

		enum {
			RDR_TR0 = 0,
			RDR_TR1,
			RDR_TR2,
			RDR_TR3,
			RDR_TR4,
			RDR_TR5,
			RDR_TR6,
			RDR_TR7,
			RDR_TR8,
			RDR_TR9,
			RDR_TR10,
			RDR_TR11,
			RDR_TR12,
			RDR_TR13,
			RDR_TR14,
			RDR_TR15
		};

		enum {
			RDR_K0 = 0,
			RDR_K1,
			RDR_K2,
			RDR_K3,
			RDR_K4,
			RDR_K5,
			RDR_K6,
			RDR_K7
		};

		enum {
			RDR_BND0 = 0,
			RDR_BND1,
			RDR_BND2,
			RDR_BND3
		};

		enum {
			RDR_ST0 = 0,
			RDR_ST1,
			RDR_ST2,
			RDR_ST3,
			RDR_ST4,
			RDR_ST5,
			RDR_ST6,
			RDR_ST7
		};

		enum {
			RDR_XMM0 = 0,
			RDR_XMM1,
			RDR_XMM2,
			RDR_XMM3,
			RDR_XMM4,
			RDR_XMM5,
			RDR_XMM6,
			RDR_XMM7,
			RDR_XMM8,
			RDR_XMM9,
			RDR_XMM10,
			RDR_XMM11,
			RDR_XMM12,
			RDR_XMM13,
			RDR_XMM14,
			RDR_XMM15,
			RDR_XMM16,
			RDR_XMM17,
			RDR_XMM18,
			RDR_XMM19,
			RDR_XMM20,
			RDR_XMM21,
			RDR_XMM22,
			RDR_XMM23,
			RDR_XMM24,
			RDR_XMM25,
			RDR_XMM26,
			RDR_XMM27,
			RDR_XMM28,
			RDR_XMM29,
			RDR_XMM30,
			RDR_XMM31
		};

		enum {
			RDR_YMM0 = 0,
			RDR_YMM1,
			RDR_YMM2,
			RDR_YMM3,
			RDR_YMM4,
			RDR_YMM5,
			RDR_YMM6,
			RDR_YMM7,
			RDR_YMM8,
			RDR_YMM9,
			RDR_YMM10,
			RDR_YMM11,
			RDR_YMM12,
			RDR_YMM13,
			RDR_YMM14,
			RDR_YMM15,
			RDR_YMM16,
			RDR_YMM17,
			RDR_YMM18,
			RDR_YMM19,
			RDR_YMM20,
			RDR_YMM21,
			RDR_YMM22,
			RDR_YMM23,
			RDR_YMM24,
			RDR_YMM25,
			RDR_YMM26,
			RDR_YMM27,
			RDR_YMM28,
			RDR_YMM29,
			RDR_YMM30,
			RDR_YMM31
		};

		enum {
			RDR_ZMM0 = 0,
			RDR_ZMM1,
			RDR_ZMM2,
			RDR_ZMM3,
			RDR_ZMM4,
			RDR_ZMM5,
			RDR_ZMM6,
			RDR_ZMM7,
			RDR_ZMM8,
			RDR_ZMM9,
			RDR_ZMM10,
			RDR_ZMM11,
			RDR_ZMM12,
			RDR_ZMM13,
			RDR_ZMM14,
			RDR_ZMM15,
			RDR_ZMM16,
			RDR_ZMM17,
			RDR_ZMM18,
			RDR_ZMM19,
			RDR_ZMM20,
			RDR_ZMM21,
			RDR_ZMM22,
			RDR_ZMM23,
			RDR_ZMM24,
			RDR_ZMM25,
			RDR_ZMM26,
			RDR_ZMM27,
			RDR_ZMM28,
			RDR_ZMM29,
			RDR_ZMM30,
			RDR_ZMM31
		};

		enum {
			RDR_GDTR = 0,
			RDR_IDTR,
			RDR_LDTR,
			RDR_TR
		};

		enum {
			RDR_X87_CONTROL = 0,
			RDR_X87_TAG,
			RDR_X87_STATUS
		};

		enum {
			RDR_XCR0 = 0,
			RDR_XCR1,
			RDR_XCR_ANY = 0xFF
		};

		typedef enum _RD_TUPLE {
			RD_TUPLE_None,
			RD_TUPLE_FV,
			RD_TUPLE_HV,
			RD_TUPLE_QV,
			RD_TUPLE_T1S8,
			RD_TUPLE_T1S16,
			RD_TUPLE_T1S,
			RD_TUPLE_T1F,
			RD_TUPLE_T2,
			RD_TUPLE_T4,
			RD_TUPLE_T8,
			RD_TUPLE_FVM,
			RD_TUPLE_HVM,
			RD_TUPLE_QVM,
			RD_TUPLE_OVM,
			RD_TUPLE_M128,
			RD_TUPLE_DUP,
			RD_TUPLE_T1_4X
		} RD_TUPLE, *PRD_TUPLE;

		typedef enum _RD_ROUNDING {
			RD_RRD_RNE,
			RD_RRD_RD,
			RD_RRD_RU,
			RD_RRD_RZ
		} RD_ROUNDING, *PRD_ROUNDING;

		typedef enum _RD_EX_CLASS {
			RD_EXC_None,
			RD_EXC_SSE_AVX,
			RD_EXC_EVEX,
			RD_EXC_OPMASK,
			RD_EXC_AMX
		} RD_EX_CLASS, *PRD_EX_CLASS;

		typedef enum _RD_EX_TYPE_SSE_AVX {
			RD_EXT_SSE_AVX_None,
			RD_EXT_1,
			RD_EXT_2,
			RD_EXT_3,
			RD_EXT_4,
			RD_EXT_5,
			RD_EXT_6,
			RD_EXT_7,
			RD_EXT_8,
			RD_EXT_9,
			RD_EXT_10,
			RD_EXT_11,
			RD_EXT_12,
			RD_EXT_13,
			RD_EXT_14
		} RD_EX_TYPE_SSE_AVX, *PRD_EX_TYPE_SSE_AVX;

		typedef enum _RD_EX_TYPE_EVEX {
			RD_EXT_EVEX_None,
			RD_EXT_E1,
			RD_EXT_E1NF,
			RD_EXT_E2,
			RD_EXT_E3,
			RD_EXT_E3NF,
			RD_EXT_E4,
			RD_EXT_E4S,
			RD_EXT_E4nb,
			RD_EXT_E4NF,
			RD_EXT_E4NFnb,
			RD_EXT_E5,
			RD_EXT_E5NF,
			RD_EXT_E6,
			RD_EXT_E6NF,
			RD_EXT_E7NM,
			RD_EXT_E9,
			RD_EXT_E9NF,
			RD_EXT_E10,
			RD_EXT_E10S,
			RD_EXT_E10NF,
			RD_EXT_E11,
			RD_EXT_E12,
			RD_EXT_E12NP
		} RD_EX_TYPE_EVEX, *PRD_EX_TYPE_EVEX;

		typedef enum _RD_EX_TYPE_OPMASK {
			RD_EXT_OPMASK_None,
			RD_EXT_K20,
			RD_EXT_K21
		} RD_EX_TYPE_OPMASK, *PRD_EX_TYPE_OPMASK;

		typedef enum _RD_EX_TYPE_AMX {
			RD_EXT_AMX_None,
			RD_EXT_AMX_E1,
			RD_EXT_AMX_E2,
			RD_EXT_AMX_E3,
			RD_EXT_AMX_E4,
			RD_EXT_AMX_E5,
			RD_EXT_AMX_E6
		} RD_EX_TYPE_AMX, *PRD_EX_TYPE_AMX;

		typedef enum _RD_SHSTK_ACCESS {
			RD_SHSTK_NONE = 0,
			RD_SHSTK_EXPLICIT,
			RD_SHSTK_SSP_LD_ST,
			RD_SHSTK_SSP_PUSH_POP,
			RD_SHSTK_PL0_SSP
		} RD_SHSTK_ACCESS, *PD_SHSTK_ACCESS;

		typedef union _RD_REX {
			unsigned char Rex;
			struct {
				unsigned char b : 1;
				unsigned char x : 1;
				unsigned char r : 1;
				unsigned char w : 1;
			};
		} RD_REX, *PRD_REX;

		typedef union _RD_MODRM {
			unsigned char ModRm;
			struct {
				unsigned char rm : 3;
				unsigned char reg : 3;
				unsigned char mod : 2;
			};
		} RD_MODRM, *PRD_MODRM;

		typedef union _RD_SIB {
			unsigned char Sib;
			struct {
				unsigned char base : 3;
				unsigned char index : 3;
				unsigned char scale : 2;
			};
		} RD_SIB, *PRD_SIB;

		typedef union _RD_DREX {
			unsigned char Drex;
			struct {
				unsigned char b : 1;
				unsigned char x : 1;
				unsigned char r : 1;
				unsigned char oc0 : 1;
				unsigned char vd : 3;
				unsigned char d : 1;
			};
		} RD_DREX, *PRD_DREX;

		typedef union _RD_VEX2 {
			unsigned char Vex[2];
			struct {
				unsigned char op;
				unsigned char p : 2;
				unsigned char l : 1;
				unsigned char v : 4;
				unsigned char r : 1;
			};
		} RD_VEX2, *PRD_VEX2;

		typedef union _RD_VEX3 {
			unsigned char Vex[3];
			struct {
				unsigned char op;
				unsigned char m : 5;
				unsigned char b : 1;
				unsigned char x : 1;
				unsigned char r : 1;
				unsigned char p : 2;
				unsigned char l : 1;
				unsigned char v : 4;
				unsigned char w : 1;
			};
		} RD_VEX3, *PRD_VEX3;

		typedef union _RD_XOP {
			unsigned char Xop[3];
			struct {
				unsigned char op;
				unsigned char m : 5;
				unsigned char b : 1;
				unsigned char x : 1;
				unsigned char r : 1;
				unsigned char p : 2;
				unsigned char l : 1;
				unsigned char v : 4;
				unsigned char w : 1;
			};
		} RD_XOP, *PRD_XOP;

		typedef union _RD_EVEX {
			unsigned char Evex[4];
			struct {
				unsigned char op;
				unsigned char m : 3;
				unsigned char zero : 1;
				unsigned char rp : 1;
				unsigned char b : 1;
				unsigned char x : 1;
				unsigned char r : 1;
				unsigned char p : 2;
				unsigned char one : 1;
				unsigned char v : 4;
				unsigned char w : 1;
				unsigned char a : 3;
				unsigned char vp : 1;
				unsigned char bm : 1;
				unsigned char l : 2;
				unsigned char z : 1;
			};
		} RD_EVEX, *PRD_EVEX;

		typedef union _RD_OPERARD_ACCESS {
			unsigned char Access;
			struct {
				unsigned char Read : 1;
				unsigned char Write : 1;
				unsigned char CondRead : 1;
				unsigned char CondWrite : 1;
				unsigned char Prefetch : 1;
			};
		} RD_OPERARD_ACCESS, *PRD_OPERARD_ACCESS;

		typedef union _RD_OPERARD_FLAGS {
			unsigned char Flags;
			struct {
				unsigned char IsDefault : 1;
				unsigned char SignExtendedOp1 : 1;
				unsigned char SignExtendedDws : 1;
			};
		} RD_OPERARD_FLAGS, *PRD_OPERARD_FLAGS;

		typedef struct _RD_OPDESC_CONSTANT {
			unsigned long long Const;
		} RD_OPDESC_CONSTANT, *PRD_OPDESC_CONSTANT;

		typedef struct _RD_OPDESC_IMMEDIATE {
			unsigned long long Imm;
		} RD_OPDESC_IMMEDIATE, *PRD_OPDESC_IMMEDIATE;

		typedef struct _RD_OPDESC_REGISTER {
			RD_REG_TYPE Type;
			unsigned int Size;
			unsigned int Reg;
			unsigned int Count;
			bool IsHigh8 : 1;
			bool IsBlock : 1;
		} RD_OPDESC_REGISTER, *PRD_OPDESC_REGISTER;

		typedef struct _RD_OPDESC_REL_OFFSET {
			unsigned long long Rel;
		} RD_OPDESC_RELOFFSET, *PRD_OPDESC_RELOFFSET;

		typedef struct _RD_OPDESC_ADDRESS {
			unsigned short BaseSeg;
			unsigned long long Offset;
		} RD_OPDESC_ADDRESS, *PRD_OPDESC_ADDRESS;

		typedef struct _RD_OPDESC_MEMORY {
			bool HasSeg : 1;
			bool HasBase : 1;
			bool HasIndex : 1;
			bool HasDisp : 1;
			bool HasCompDisp : 1;
			bool HasBroadcast : 1;
			bool IsRipRel : 1;
			bool IsStack : 1;
			bool IsString : 1;
			bool IsShadowStack : 1;
			bool IsDirect : 1;
			bool IsBitbase : 1;
			bool IsAG : 1;
			bool IsMib : 1;
			bool IsVSib : 1;
			bool IsSibMem : 1;
			unsigned int BaseSize;
			unsigned int IndexSize;
			unsigned char DispSize;
			unsigned char CompDispSize;
			unsigned char ShStkType;
			struct {
				unsigned char IndexSize;
				unsigned char ElemSize;
				unsigned char ElemCount;
			} VSib;
			unsigned char Seg;
			unsigned char Base;
			unsigned char Index;
			unsigned char Scale;
			unsigned long long Disp;
		} RD_OPDESC_MEMORY, *PRD_OPDESC_MEMORY;

		typedef struct _RD_OPERARD_DECORATOR {
			bool HasMask : 1;
			bool HasZero : 1;
			bool HasBroadcast : 1;
			bool HasSae : 1;
			bool HasEr : 1;
			struct {
				unsigned char Msk;
			} Mask;
			struct {
				unsigned char Count;
				unsigned char Size;
			} Broadcast;
		} RD_OPERARD_DECORATOR, *PRD_OPERARD_DECORATOR;

		typedef struct _RD_OPERAND {
			RD_OPERARD_TYPE Type;
			RD_OPERARD_ENCODING Encoding;
			unsigned int Size;
			unsigned int RawSize;
			RD_OPERARD_ACCESS Access;
			RD_OPERARD_FLAGS Flags;
			union {
				RD_OPDESC_CONSTANT Constant;
				RD_OPDESC_IMMEDIATE Immediate;
				RD_OPDESC_REGISTER Register;
				RD_OPDESC_RELOFFSET RelativeOffset;
				RD_OPDESC_ADDRESS Address;
				RD_OPDESC_MEMORY Memory;
			} Info;
			RD_OPERARD_DECORATOR Decorator;
		} RD_OPERAND, *PRD_OPERAND;

		typedef struct _RD_BRANCH_INFO {
			unsigned char IsBranch : 1;
			unsigned char IsConditional : 1;
			unsigned char IsIndirect : 1;
			unsigned char IsFar : 1;
		} RD_BRANCH_INFO, *PRD_BRANCH_INFO;

		typedef union _RD_RFLAGS {
			unsigned int Raw;
			struct {
				unsigned int CF : 1;
				unsigned int Reserved1 : 1;
				unsigned int PF : 1;
				unsigned int Reserved2 : 1;
				unsigned int AF : 1;
				unsigned int Reserved3 : 1;
				unsigned int ZF : 1;
				unsigned int SF : 1;
				unsigned int TF : 1;
				unsigned int IF : 1;
				unsigned int DF : 1;
				unsigned int OF : 1;
				unsigned int IOPL : 2;
				unsigned int NT : 1;
				unsigned int Reserved4 : 1;
				unsigned int RF : 1;
				unsigned int VM : 1;
				unsigned int AC : 1;
				unsigned int VIF : 1;
				unsigned int VIP : 1;
				unsigned int ID : 1;
			};
		} RD_RFLAGS, *PRD_RFLAGS;

		typedef struct _RD_FPU_FLAGS {
			unsigned char C0 : 2;
			unsigned char C1 : 2;
			unsigned char C2 : 2;
			unsigned char C3 : 2;
		} RD_FPU_FLAGS, *PRD_FPU_FLAGS;

		typedef union _RD_CPUID_FLAG {
			unsigned long long Flag;
			struct {
				unsigned int Leaf;
				unsigned int SubLeaf : 24;
				unsigned int Reg : 3;
				unsigned int Bit : 5;
			};
		} RD_CPUID_FLAG, *PRD_CPUID_FLAG;

		typedef union _RD_VALID_MODES {
			unsigned int Raw;
			struct {
				unsigned int Ring0 : 1;
				unsigned int Ring1 : 1;
				unsigned int Ring2 : 1;
				unsigned int Ring3 : 1;
				unsigned int Real : 1;
				unsigned int V8086 : 1;
				unsigned int Protected : 1;
				unsigned int Compat : 1;
				unsigned int Long : 1;
				unsigned int Reserved : 3;
				unsigned int Smm : 1;
				unsigned int SmmOff : 1;
				unsigned int Sgx : 1;
				unsigned int SgxOff : 1;
				unsigned int Tsx : 1;
				unsigned int TsxOff : 1;
				unsigned int VmxRoot : 1;
				unsigned int VmxNonRoot : 1;
				unsigned int VmxRootSeam : 1;
				unsigned int VmxNonRootSeam : 1;
				unsigned int VmxOff : 1;
			};
		} RD_VALID_MODES, *PRD_VALID_MODES;

		typedef union _RD_VALID_PREFIXES {
			unsigned short Raw;
			struct {
				unsigned short Rep : 1;
				unsigned short RepCond : 1;
				unsigned short Lock : 1;
				unsigned short Hle : 1;
				unsigned short Xacquire : 1;
				unsigned short Xrelease : 1;
				unsigned short Bnd : 1;
				unsigned short Bhint : 1;
				unsigned short HleNoLock : 1;
				unsigned short Dnt : 1;
			};
		} RD_VALID_PREFIXES, *PD_VALID_PREFIXES;

		typedef union _RD_VALID_DECORATORS {
			unsigned char Raw;
			struct {
				unsigned char Er : 1;
				unsigned char
					Sae : 1;
				unsigned char Zero : 1;
				unsigned char Mask : 1;
				unsigned char Broadcast : 1;
			};
		} RD_VALID_DECORATORS, *PRD_VALID_DECORATORS;

		typedef struct _INSTRUCTION {
			unsigned char DefCode : 4;
			unsigned char DefData : 4;
			unsigned char DefStack : 4;
			unsigned char VendMode : 4;
			unsigned char FeatMode;
			unsigned char EncMode : 4;
			unsigned char VexMode : 4;
			unsigned char AddrMode : 4;
			unsigned char OpMode : 4;
			unsigned char EfOpMode : 4;
			unsigned char VecMode : 4;
			unsigned char EfVecMode : 4;
			bool HasRex : 1;
			bool HasVex : 1;
			bool HasXop : 1;
			bool HasEvex : 1;
			bool HasMvex : 1;
			bool HasOpSize : 1;
			bool HasAddrSize : 1;
			bool HasLock : 1;
			bool HasRepnzXacquireBnd : 1;
			bool HasRepRepzXrelease : 1;
			bool HasSeg : 1;
			bool IsRepeated : 1;
			bool IsXacquireEnabled : 1;
			bool IsXreleaseEnabled : 1;
			bool IsRipRelative : 1;
			bool IsCetTracked : 1;
			bool HasModRm : 1;
			bool HasSib : 1;
			bool HasDrex : 1;
			bool HasDisp : 1;
			bool HasAddr : 1;
			bool HasMoffset : 1;
			bool HasImm1 : 1;
			bool HasImm2 : 1;
			bool HasImm3 : 1;
			bool HasRelOffs : 1;
			bool HasSseImm : 1;
			bool HasCompDisp : 1;
			bool HasBroadcast : 1;
			bool HasMask : 1;
			bool HasZero : 1;
			bool HasEr : 1;
			bool HasSae : 1;
			bool HasIgnEr : 1;
			bool SignDisp : 1;
			bool HasMandatory66 : 1;
			bool HasMandatoryF2 : 1;
			bool HasMandatoryF3 : 1;
			unsigned char Length;
			unsigned char WordLength : 4;
			unsigned char PrefLength : 4;
			unsigned char OpLength : 4;
			unsigned char DispLength : 4;
			unsigned char AddrLength : 4;
			unsigned char MoffsetLength : 4;
			unsigned char Imm1Length : 4;
			unsigned char Imm2Length : 4;
			unsigned char Imm3Length : 4;
			unsigned char RelOffsLength : 4;
			unsigned char OpOffset : 4;
			unsigned char MainOpOffset : 4;
			unsigned char DispOffset : 4;
			unsigned char AddrOffset : 4;
			unsigned char MoffsetOffset : 4;
			unsigned char Imm1Offset : 4;
			unsigned char Imm2Offset : 4;
			unsigned char Imm3Offset : 4;
			unsigned char RelOffsOffset : 4;
			unsigned char SseImmOffset : 4;
			unsigned char ModRmOffset : 4;
			unsigned char StackWords;
			unsigned char Rep;
			unsigned char Seg;
			unsigned char Bhint;
			RD_REX Rex;
			RD_MODRM ModRm;
			RD_SIB Sib;
			RD_DREX Drex;
			union {
				RD_VEX2 Vex2;
				RD_VEX3 Vex3;
				RD_XOP Xop;
				RD_EVEX Evex;
			};
			struct {
				unsigned int w : 1;
				unsigned int r : 1;
				unsigned int x : 1;
				unsigned int b : 1;
				unsigned int rp : 1;
				unsigned int p : 2;
				unsigned int m : 5;
				unsigned int l : 2;
				unsigned int v : 4;
				unsigned int vp : 1;
				unsigned int bm : 1;
				unsigned int e : 1;
				unsigned int z : 1;
				unsigned int k : 3;
				unsigned int s : 3;
			} Exs;
			union {
				struct {
					unsigned int Ip;
					unsigned short Cs;
				};
			} Address;
			unsigned long long Moffset;
			unsigned int Displacement;
			unsigned int RelativeOffset;
			unsigned long long Immediate1;
			unsigned char Immediate2;
			unsigned char Immediate3;
			unsigned char SseImmediate;
			unsigned char SseCondition;
			unsigned char Condition;
			unsigned char Predicate;
			unsigned char OperandsCount;
			unsigned char ExpOperandsCount;
			unsigned short OperandsEncodingMap;
			RD_OPERAND Operands[RD_MAX_OPERAND];
			unsigned char CsAccess;
			unsigned char RipAccess;
			unsigned char StackAccess;
			unsigned char MemoryAccess;
			RD_BRANCH_INFO BranchInfo;
			struct {
				unsigned char RegAccess;
				RD_RFLAGS Tested;
				RD_RFLAGS Modified;
				RD_RFLAGS Set;
				RD_RFLAGS Cleared;
				RD_RFLAGS Undefined;
			} FlagsAccess;
			RD_FPU_FLAGS FpuFlagsAccess;
			unsigned char ExceptionClass;
			unsigned char ExceptionType;
			unsigned char TupleType;
			unsigned char RoundingMode;
			unsigned int Attributes;
			union {
				RD_INS_CLASS Instruction;
				RD_INS_CLASS Iclass;
			};
			RD_INS_CATEGORY Category;
			RD_INS_SET IsaSet;
			RD_CPUID_FLAG CpuidFlag;
			RD_VALID_MODES ValidModes;
			RD_VALID_PREFIXES ValidPrefixes;
			RD_VALID_DECORATORS ValidDecorators;
			char Mnemonic[RD_MAX_MNEMONIC_LENGTH];
			unsigned char OpCodeBytes[3];
			unsigned char PrimaryOpCode;
			unsigned char InstructionBytes[16];
		} INSTRUCTION, *PINSTRUCTION;

		typedef struct _RD_CONTEXT {
			unsigned long long DefCode : 4;
			unsigned long long DefData : 4;
			unsigned long long DefStack : 4;
			unsigned long long VendMode : 4;
			unsigned long long FeatMode : 8;
			unsigned long long Reserved : 40;
		} RD_CONTEXT, *PRD_CONTEXT;

		typedef struct _RD_ACCESS_MAP {
			unsigned char RipAccess;
			unsigned char FlagsAccess;
			unsigned char StackAccess;
			unsigned char MemAccess;
			unsigned char MxcsrAccess;
			unsigned char PkruAccess;
			unsigned char SspAccess;
			unsigned char GprAccess[RD_MAX_GPR_REGS];
			unsigned char SegAccess[RD_MAX_SEG_REGS];
			unsigned char FpuAccess[RD_MAX_FPU_REGS];
			unsigned char MmxAccess[RD_MAX_MMX_REGS];
			unsigned char SseAccess[RD_MAX_SSE_REGS];
			unsigned char CrAccess[RD_MAX_CR_REGS];
			unsigned char DrAccess[RD_MAX_DR_REGS];
			unsigned char TrAccess[RD_MAX_TR_REGS];
			unsigned char BndAccess[RD_MAX_BRD_REGS];
			unsigned char MskAccess[RD_MAX_MSK_REGS];
			unsigned char TmmAccess[RD_MAX_TILE_REGS];
			unsigned char SysAccess[RD_MAX_SYS_REGS];
			unsigned char X87Access[RD_MAX_X87_REGS];
		} RD_ACCESS_MAP, *PRD_ACCESS_MAP;

		typedef struct _RD_OPERARD_RLUT {
			PRD_OPERAND Dst1;
			PRD_OPERAND Dst2;
			PRD_OPERAND Src1;
			PRD_OPERAND Src2;
			PRD_OPERAND Src3;
			PRD_OPERAND Src4;
			PRD_OPERAND Mem1;
			PRD_OPERAND Mem2;
			PRD_OPERAND Stack;
			PRD_OPERAND Flags;
			PRD_OPERAND Rip;
			PRD_OPERAND Cs;
			PRD_OPERAND Ss;
			PRD_OPERAND Rax;
			PRD_OPERAND Rcx;
			PRD_OPERAND Rdx;
			PRD_OPERAND Rbx;
			PRD_OPERAND Rsp;
			PRD_OPERAND Rbp;
			PRD_OPERAND Rsi;
			PRD_OPERAND Rdi;
		} RD_OPERARD_RLUT, *PRD_OPERARD_RLUT;

		void RdInitContext(PRD_CONTEXT pCTX);
		unsigned int RdDecodeWithContext(PINSTRUCTION pInstruction, unsigned char* pCode, size_t unSize, PRD_CONTEXT pCTX);
		unsigned int RdDecodeEx(PINSTRUCTION pInstruction, unsigned char* pCode, size_t unSize, unsigned char unDefCode, unsigned char unDefData, unsigned char unDefStack, unsigned char unPreferedVendor);
		unsigned int RdDecode(PINSTRUCTION pInstruction, unsigned char* pCode, size_t unSize, unsigned char unDefCode, unsigned char unDefData);
		unsigned int RdDecode(PINSTRUCTION pInstruction, unsigned char* pCode, unsigned char unDefCode, unsigned char unDefData);

		bool RdIsInstruxRipRelative(PINSTRUCTION pInstruction);
		unsigned int RdGetFullAccessMap(PINSTRUCTION pInstruction, PRD_ACCESS_MAP pAccessMap);
		unsigned int RdGetOperandRlut(PINSTRUCTION pInstruction, PRD_OPERARD_RLUT pRlut);
	}

	// ----------------------------------------------------------------
	// Hook
	// ----------------------------------------------------------------

	namespace Hook {

		// ----------------------------------------------------------------
		// Memory Hook CallBack
		// ----------------------------------------------------------------

		using fnMemoryHookCallBack = bool(*)(const std::unique_ptr<class MemoryHook>& pHook, const PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// Memory Hook (Don't use this to define hooks)
		// ----------------------------------------------------------------

		class MemoryHook {
		public:
			MemoryHook(void* pAddress, size_t unSize = 1, bool bAutoDisable = false);
			~MemoryHook();

		public:
			bool Hook(const fnMemoryHookCallBack pCallBack);
			bool UnHook();

		public:
			bool Enable();
			bool Disable();

		public:
			void* GetAddress() const;
			size_t GetSize() const;
			bool IsAutoDisable() const;
			fnMemoryHookCallBack GetCallBack() const;

		private:
			void* m_pAddress;
			size_t m_unSize;
			bool m_bAutoDisable;
			fnMemoryHookCallBack m_pCallBack;
		};

		// ----------------------------------------------------------------
		// Memory Hook
		// ----------------------------------------------------------------

		bool HookMemory(void* pAddress, const fnMemoryHookCallBack pCallBack, bool bAutoDisable = false);
		bool UnHookMemory(const fnMemoryHookCallBack pCallBack);
		bool EnableHookMemory(const fnMemoryHookCallBack pCallBack);
		bool DisableHookMemory(const fnMemoryHookCallBack pCallBack);

		// ----------------------------------------------------------------
		// Interrupt Hook CallBack
		// ----------------------------------------------------------------

		using fnInterruptHookCallBack = bool(*)(const std::unique_ptr<class InterruptHook>& pHook, const PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// Interrupt Hook (Don't use this to define hooks)
		// ----------------------------------------------------------------

		class InterruptHook {
		public:
			InterruptHook(unsigned char unInterrupt = 0x7E);
			~InterruptHook();

		public:
			bool Hook(const fnInterruptHookCallBack pCallBack);
			bool UnHook();

		public:
			unsigned char GetInterrupt() const;
			fnInterruptHookCallBack GetCallBack() const;

		private:
			unsigned char m_unInterrupt;
			fnInterruptHookCallBack m_pCallBack;
		};

		// ----------------------------------------------------------------
		// Interrupt Hook
		// ----------------------------------------------------------------

		bool HookInterrupt(const fnInterruptHookCallBack pCallBack, unsigned char unInterrupt = 0x7E);
		bool UnHookInterrupt(const fnInterruptHookCallBack pCallBack);

		// ----------------------------------------------------------------
		// VTable Function Hook
		// ----------------------------------------------------------------

		class VTableFunctionHook {
		public:
			VTableFunctionHook();
			VTableFunctionHook(void** pVTable, size_t unIndex);
			~VTableFunctionHook();

		public:
			bool Set(void** pVTable, size_t unIndex);
			bool Release();

		public:
			bool Hook(void* pHookAddress);
			bool UnHook();

		public:
			void* GetOriginal() const;

		private:
			bool m_bInitialized;
			void** m_pVTable;
			size_t m_unIndex;
			void* m_pOriginal;
		};

		// ----------------------------------------------------------------
		// VTable Hook
		// ----------------------------------------------------------------

		class VTableHook {
		public:
			VTableHook();
			VTableHook(void** pVTable, size_t unCount);
			~VTableHook();

		public:
			bool Set(void** pVTable, size_t unCount);
			bool Release();

		public:
			bool Hook(void** pHookVTable);
			bool UnHook();

		public:
			std::vector<std::unique_ptr<VTableFunctionHook>>& GetHookingFunctions();

		private:
			bool m_bInitialized;
			void** m_pVTable;
			size_t m_unCount;
			std::vector<std::unique_ptr<VTableFunctionHook>> m_vecHookingFunctions;
		};

		// ----------------------------------------------------------------
		// Inline Hook
		// ----------------------------------------------------------------

		class InlineHook {
		public:
			InlineHook();
			InlineHook(void* pAddress);
			~InlineHook();

		public:
			bool Set(void* pAddress);
			bool Release();

		public:
			bool Hook(void* pHookAddress, bool bSingleInstructionOnly = false);
			bool UnHook();

		public:
			void* GetTrampoline() const;

		private:
			bool m_bInitialized;
			void* m_pAddress;
			void* m_pTrampoline;
			size_t m_unOriginalBytes;
			std::unique_ptr<unsigned char[]> m_pOriginalBytes;
		};

		// ----------------------------------------------------------------
		// Inline Hook (With Wrapper)
		// ----------------------------------------------------------------

		class InlineWrapperHook {
		public:
			InlineWrapperHook();
			InlineWrapperHook(void* pAddress);
			~InlineWrapperHook();

		public:
			bool Set(void* pAddress);
			bool Release();

		public:
			bool Hook(void* pHookAddress, bool bSingleInstructionOnly = true);
			bool UnHook();

		public:
			void* GetTrampoline() const;

		private:
			bool m_bInitialized;
			void* m_pAddress;
			void* m_pWrapper;
			void* m_pTrampoline;
			size_t m_unOriginalBytes;
			std::unique_ptr<unsigned char[]> m_pOriginalBytes;
		};

		// ----------------------------------------------------------------
		// RAW_CONTEXT
		// ----------------------------------------------------------------

#pragma pack(push, r1, 1)

		typedef struct _RAW_CONTEXT_STACK {
			template <typename T = void*>
			inline void push(const T Value) {
				m_pAddress = reinterpret_cast<void*>(reinterpret_cast<size_t>(m_pAddress) - sizeof(T));
				*reinterpret_cast<T*>(m_pAddress) = Value;
			}

			template <typename T = void*>
			inline T& pop() {
				T& Value = *reinterpret_cast<T*>(m_pAddress);
				m_pAddress = reinterpret_cast<void*>(reinterpret_cast<size_t>(m_pAddress) + sizeof(T));
				return Value;
			}

			inline void* GetAddress() const {
				return m_pAddress;
			}

		private:
			void* m_pAddress;
		} RAW_CONTEXT_STACK, *PRAW_CONTEXT_STACK;

		typedef union _RAW_CONTEXT_FPU_REGISTER {
			unsigned char m_pRAW[10];
			double m_f64;
			float m_f32;
		} RAW_CONTEXT_FPU_REGISTER, *PRAW_CONTEXT_FPU_REGISTER;

		typedef struct _RAW_CONTEXT_FPU {
			union {
				unsigned short m_unControlWord;
				struct {
					unsigned int m_unInvalidOperation : 1;
					unsigned int m_unDenormalizedOperand : 1;
					unsigned int m_unDivideByZero : 1;
					unsigned int m_unOverflow : 1;
					unsigned int m_unUnderflow : 1;
					unsigned int m_unPrecision : 1;
					unsigned int m_unReserved6 : 1;
					unsigned int m_unReserved7 : 1;
					unsigned int m_unPrecisionControl0 : 1;
					unsigned int m_unPrecisionControl1 : 1;
					unsigned int m_unRoundingControl0 : 1;
					unsigned int m_unRoundingControl1 : 1;
					unsigned int m_unInfinityControl : 1;
				} ControlWord;
			};
			unsigned short m_unReserved1;
			union {
				unsigned short m_unStatusWord;
				struct {
					unsigned int m_unInvalidOperation : 1;
					unsigned int m_unDenormalizedOperand : 1;
					unsigned int m_unDivideByZero : 1;
					unsigned int m_unOverflow : 1;
					unsigned int m_unUnderflow : 1;
					unsigned int m_unPrecision : 1;
					unsigned int m_unStackFault : 1;
					unsigned int m_unExceptionSummary : 1;
					unsigned int m_unCondition0 : 1;
					unsigned int m_unCondition1 : 1;
					unsigned int m_unCondition2 : 1;
					unsigned int m_unCondition3 : 1;
					unsigned int m_unFPUBusy : 1;
				} StatusWord;
			};
			unsigned short m_unReserved2;
			unsigned short m_unTagWord;
			unsigned short m_unReserved3;
			unsigned int m_unIP;   // FPU instruction pointer offset
			unsigned short m_unCS; // FPU instruction pointer segment selector
			unsigned short m_unOP; // FPU opcode
			unsigned int m_unDP;   // FPU data pointer offset
			unsigned short m_unDS; // FPU data pointer segment selector
			unsigned short m_unReserved4;
			RAW_CONTEXT_FPU_REGISTER m_Registers[8];
		} RAW_CONTEXT_FPU, *PRAW_CONTEXT_FPU;

		typedef union _RAW_CONTEXT_M128 {
			unsigned long long m_un64[2];
			unsigned int m_un32[4];
			unsigned short m_un16[8];
			unsigned char m_un8[16];
			long long m_n64[2];
			int m_n32[4];
			short m_n16[8];
			char m_n8[16];
			double m_f64[2];
			float m_f32[4];
		} RAW_CONTEXT_M128, *PRAW_CONTEXT_M128;

		typedef union _RAW_CONTEXT_M256 {
			unsigned long long m_un64[4];
			unsigned int m_un32[8];
			unsigned short m_un16[16];
			unsigned char m_un8[32];
			long long m_n64[4];
			int m_n32[8];
			short m_n16[16];
			char m_n8[32];
			double m_f64[4];
			float m_f32[8];
		} RAW_CONTEXT_M256, *PRAW_CONTEXT_M256;

		typedef union _RAW_CONTEXT_M512 {
			unsigned long long m_un64[8];
			unsigned int m_un32[16];
			unsigned short m_un16[32];
			unsigned char m_un8[64];
			long long m_n64[8];
			int m_n32[16];
			short m_n16[32];
			char m_n8[64];
			double m_f64[8];
			float m_f32[16];
		} RAW_CONTEXT_M512, *PRAW_CONTEXT_M512;

#pragma pack(pop, r1)

		typedef struct _RAW_NATIVE_CONTEXT32 {

			// ----------------------------------------------------------------
			// Flags
			// ----------------------------------------------------------------

			union {
				unsigned int m_unEFLAGS;
				unsigned short m_unFLAGS;
				struct {
					unsigned int m_unCF : 1;    // Bit 0: Carry Flag
					unsigned int : 1;           // Bit 1: Reserved
					unsigned int m_unPF : 1;    // Bit 2: Parity Flag
					unsigned int : 1;           // Bit 3: Reserved
					unsigned int m_unAF : 1;    // Bit 4: Auxiliary Carry Flag
					unsigned int : 1;           // Bit 5: Reserved
					unsigned int m_unZF : 1;    // Bit 6: Zero Flag
					unsigned int m_unSF : 1;    // Bit 7: Sign Flag
					unsigned int m_unTF : 1;    // Bit 8: Trap Flag
					unsigned int m_unIF : 1;    // Bit 9: Interrupt Enable Flag
					unsigned int m_unDF : 1;    // Bit 10: Direction Flag
					unsigned int m_unOF : 1;    // Bit 11: Overflow Flag
					unsigned int m_unIOPL : 2;  // Bit 12-13: I/O Privilege Level
					unsigned int m_unNT : 1;    // Bit 14: Nested Task
					unsigned int m_unMD : 1;    // Bit 15: Mode Flag
					unsigned int m_unRF : 1;    // Bit 16: Resume Flag
					unsigned int m_unVM : 1;    // Bit 17: Virtual 8086 Mode Flag
					unsigned int m_unAC : 1;    // Bit 18: Alignment Check
					unsigned int m_unVIF : 1;   // Bit 19: Virtual Interrupt Flag
					unsigned int m_unVIP : 1;   // Bit 20: Virtual Interrupt Pending
					unsigned int m_unID : 1;    // Bit 21: ID Flag
					unsigned int : 8;           // Bit 22-29: Reserved
					unsigned int : 1;           // Bit 30: Reserved
					unsigned int m_unAI : 1;    // Bit 31: Alignment Indicator
				};
			};

			// ----------------------------------------------------------------
			// Registers (General)
			// ----------------------------------------------------------------

			// EAX
			union {
				unsigned int m_unEAX;
				unsigned short m_unAX;
				struct {
					unsigned char m_unAL;
					unsigned char m_unAH;
				};
			};

			// ECX
			union {
				unsigned int m_unECX;
				unsigned short m_unCX;
				struct {
					unsigned char m_unCL;
					unsigned char m_unCH;
				};
			};

			// EDX
			union {
				unsigned int m_unEDX;
				unsigned short m_unDX;
				struct {
					unsigned char m_unDL;
					unsigned char m_unDH;
				};
			};

			// EBX
			union {
				unsigned int m_unEBX;
				unsigned short m_unBX;
				struct {
					unsigned char m_unBL;
					unsigned char m_unBH;
				};
			};

			// ESP
			union {
				RAW_CONTEXT_STACK Stack;
				unsigned int m_unESP;
				unsigned short m_unSP;
				unsigned char m_unSPL;
			};

			// EBP
			union {
				unsigned int m_unEBP;
				unsigned short m_unBP;
				unsigned char m_unBPL;
			};

			// ESI
			union {
				unsigned int m_unESI;
				unsigned short m_unSI;
				unsigned char m_unSIL;
			};

			// EDI
			union {
				unsigned int m_unEDI;
				unsigned short m_unDI;
				unsigned char m_unDIL;
			};
		} RAW_NATIVE_CONTEXT32, *PRAW_NATIVE_CONTEXT32;

		typedef struct _RAW_CONTEXT32 : public RAW_NATIVE_CONTEXT32 {

			// ----------------------------------------------------------------
			// Registers (SIMD)
			// ----------------------------------------------------------------

			union {
				unsigned int m_unMXCSR;
				struct {
					unsigned int m_unInvalidOperation : 1;
					unsigned int m_unDenormalizedOperand : 1;
					unsigned int m_unDivideByZero : 1;
					unsigned int m_unOverflow : 1;
					unsigned int m_unUnderflow : 1;
					unsigned int m_unPrecision : 1;
					unsigned int m_unDenormalsAreZeros : 1;
					unsigned int m_unInvalidOperationMask : 1;
					unsigned int m_unDenormalMask : 1;
					unsigned int m_unDivideByZeroMask : 1;
					unsigned int m_unOverflowMask : 1;
					unsigned int m_unUnderflowMask : 1;
					unsigned int m_unPrecisionMask : 1;
					unsigned int m_unRoundingControl0 : 1;
					unsigned int m_unRoundingControl1 : 1;
					unsigned int m_unFlushToZero : 1;
				} MXCSR;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM0;
				RAW_CONTEXT_M256 m_YMM0;
				RAW_CONTEXT_M128 m_XMM0;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM1;
				RAW_CONTEXT_M256 m_YMM1;
				RAW_CONTEXT_M128 m_XMM1;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM2;
				RAW_CONTEXT_M256 m_YMM2;
				RAW_CONTEXT_M128 m_XMM2;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM3;
				RAW_CONTEXT_M256 m_YMM3;
				RAW_CONTEXT_M128 m_XMM3;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM4;
				RAW_CONTEXT_M256 m_YMM4;
				RAW_CONTEXT_M128 m_XMM4;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM5;
				RAW_CONTEXT_M256 m_YMM5;
				RAW_CONTEXT_M128 m_XMM5;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM6;
				RAW_CONTEXT_M256 m_YMM6;
				RAW_CONTEXT_M128 m_XMM6;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM7;
				RAW_CONTEXT_M256 m_YMM7;
				RAW_CONTEXT_M128 m_XMM7;
			};

			// ----------------------------------------------------------------
			// FPU
			// ----------------------------------------------------------------

			RAW_CONTEXT_FPU m_FPU;
		} RAW_CONTEXT32, *PRAW_CONTEXT32;

		typedef struct _RAW_NATIVE_CONTEXT64 {

			// ----------------------------------------------------------------
			// Flags
			// ----------------------------------------------------------------

			union {
				unsigned long long m_unRFLAGS;
				unsigned int m_unEFLAGS;
				unsigned short m_unFLAGS;
				struct {
					unsigned int m_unCF : 1;    // Bit 0: Carry Flag
					unsigned int : 1;           // Bit 1: Reserved
					unsigned int m_unPF : 1;    // Bit 2: Parity Flag
					unsigned int : 1;           // Bit 3: Reserved
					unsigned int m_unAF : 1;    // Bit 4: Auxiliary Carry Flag
					unsigned int : 1;           // Bit 5: Reserved
					unsigned int m_unZF : 1;    // Bit 6: Zero Flag
					unsigned int m_unSF : 1;    // Bit 7: Sign Flag
					unsigned int m_unTF : 1;    // Bit 8: Trap Flag
					unsigned int m_unIF : 1;    // Bit 9: Interrupt Enable Flag
					unsigned int m_unDF : 1;    // Bit 10: Direction Flag
					unsigned int m_unOF : 1;    // Bit 11: Overflow Flag
					unsigned int m_unIOPL : 2;  // Bit 12-13: I/O Privilege Level
					unsigned int m_unNT : 1;    // Bit 14: Nested Task
					unsigned int m_unMD : 1;    // Bit 15: Mode Flag
					unsigned int m_unRF : 1;    // Bit 16: Resume Flag
					unsigned int m_unVM : 1;    // Bit 17: Virtual 8086 Mode Flag
					unsigned int m_unAC : 1;    // Bit 18: Alignment Check
					unsigned int m_unVIF : 1;   // Bit 19: Virtual Interrupt Flag
					unsigned int m_unVIP : 1;   // Bit 20: Virtual Interrupt Pending
					unsigned int m_unID : 1;    // Bit 21: ID Flag
					unsigned int : 8;           // Bit 22-29: Reserved
					unsigned int : 1;           // Bit 30: Reserved
					unsigned int m_unAI : 1;    // Bit 31: Alignment Indicator
					unsigned int : 32;          // Bit 32-63: Reserved
				};
			};

			// ----------------------------------------------------------------
			// Registers (General)
			// ----------------------------------------------------------------

			// RAX
			union {
				unsigned long long m_unRAX;
				unsigned int m_unEAX;
				unsigned short m_unAX;
				struct {
					unsigned char m_unAL;
					unsigned char m_unAH;
				};
			};

			// RCX
			union {
				unsigned long long m_unRCX;
				unsigned int m_unECX;
				unsigned short m_unCX;
				struct {
					unsigned char m_unCL;
					unsigned char m_unCH;
				};
			};

			// RDX
			union {
				unsigned long long m_unRDX;
				unsigned int m_unEDX;
				unsigned short m_unDX;
				struct {
					unsigned char m_unDL;
					unsigned char m_unDH;
				};
			};

			// RBX
			union {
				unsigned long long m_unRBX;
				unsigned int m_unEBX;
				unsigned short m_unBX;
				struct {
					unsigned char m_unBL;
					unsigned char m_unBH;
				};
			};

			// RSP
			union {
				RAW_CONTEXT_STACK Stack;
				unsigned long long m_unRSP;
				unsigned int m_unESP;
				unsigned short m_unSP;
				unsigned char m_unSPL;
			};

			// RBP
			union {
				unsigned long long m_unRBP;
				unsigned int m_unEBP;
				unsigned short m_unBP;
				unsigned char m_unBPL;
			};

			// RSI
			union {
				unsigned long long m_unRSI;
				unsigned int m_unESI;
				unsigned short m_unSI;
				unsigned char m_unSIL;
			};

			// RDI
			union {
				unsigned long long m_unRDI;
				unsigned int m_unEDI;
				unsigned short m_unDI;
				unsigned char m_unDIL;
			};

			// R8
			union {
				unsigned long long m_unR8;
				unsigned int m_unR8D;
				unsigned short m_unR8W;
				unsigned char m_unR8B;
			};

			// R9
			union {
				unsigned long long m_unR9;
				unsigned int m_unR9D;
				unsigned short m_unR9W;
				unsigned char m_unR9B;
			};

			// R10
			union {
				unsigned long long m_unR10;
				unsigned int m_unR10D;
				unsigned short m_unR10W;
				unsigned char m_unR10B;
			};

			// R11
			union {
				unsigned long long m_unR11;
				unsigned int m_unR11D;
				unsigned short m_unR11W;
				unsigned char m_unR11B;
			};

			// R12
			union {
				unsigned long long m_unR12;
				unsigned int m_unR12D;
				unsigned short m_unR12W;
				unsigned char m_unR12B;
			};

			// R13
			union {
				unsigned long long m_unR13;
				unsigned int m_unR13D;
				unsigned short m_unR13W;
				unsigned char m_unR13B;
			};

			// R14
			union {
				unsigned long long m_unR14;
				unsigned int m_unR14D;
				unsigned short m_unR14W;
				unsigned char m_unR14B;
			};

			// R15
			union {
				unsigned long long m_unR15;
				unsigned int m_unR15D;
				unsigned short m_unR15W;
				unsigned char m_unR15B;
			};
		} RAW_NATIVE_CONTEXT64, *PRAW_NATIVE_CONTEXT64;

		typedef struct _RAW_CONTEXT64 : public RAW_NATIVE_CONTEXT64 {

			// ----------------------------------------------------------------
			// Registers (SIMD)
			// ----------------------------------------------------------------

			union {
				unsigned int m_unMXCSR;
				struct {
					unsigned int m_unInvalidOperation : 1;
					unsigned int m_unDenormalizedOperand : 1;
					unsigned int m_unDivideByZero : 1;
					unsigned int m_unOverflow : 1;
					unsigned int m_unUnderflow : 1;
					unsigned int m_unPrecision : 1;
					unsigned int m_unDenormalsAreZeros : 1;
					unsigned int m_unInvalidOperationMask : 1;
					unsigned int m_unDenormalMask : 1;
					unsigned int m_unDivideByZeroMask : 1;
					unsigned int m_unOverflowMask : 1;
					unsigned int m_unUnderflowMask : 1;
					unsigned int m_unPrecisionMask : 1;
					unsigned int m_unRoundingControl0 : 1;
					unsigned int m_unRoundingControl1 : 1;
					unsigned int m_unFlushToZero : 1;
				} MXCSR;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM0;
				RAW_CONTEXT_M256 m_YMM0;
				RAW_CONTEXT_M128 m_XMM0;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM1;
				RAW_CONTEXT_M256 m_YMM1;
				RAW_CONTEXT_M128 m_XMM1;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM2;
				RAW_CONTEXT_M256 m_YMM2;
				RAW_CONTEXT_M128 m_XMM2;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM3;
				RAW_CONTEXT_M256 m_YMM3;
				RAW_CONTEXT_M128 m_XMM3;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM4;
				RAW_CONTEXT_M256 m_YMM4;
				RAW_CONTEXT_M128 m_XMM4;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM5;
				RAW_CONTEXT_M256 m_YMM5;
				RAW_CONTEXT_M128 m_XMM5;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM6;
				RAW_CONTEXT_M256 m_YMM6;
				RAW_CONTEXT_M128 m_XMM6;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM7;
				RAW_CONTEXT_M256 m_YMM7;
				RAW_CONTEXT_M128 m_XMM7;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM8;
				RAW_CONTEXT_M256 m_YMM8;
				RAW_CONTEXT_M128 m_XMM8;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM9;
				RAW_CONTEXT_M256 m_YMM9;
				RAW_CONTEXT_M128 m_XMM9;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM10;
				RAW_CONTEXT_M256 m_YMM10;
				RAW_CONTEXT_M128 m_XMM10;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM11;
				RAW_CONTEXT_M256 m_YMM11;
				RAW_CONTEXT_M128 m_XMM11;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM12;
				RAW_CONTEXT_M256 m_YMM12;
				RAW_CONTEXT_M128 m_XMM12;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM13;
				RAW_CONTEXT_M256 m_YMM13;
				RAW_CONTEXT_M128 m_XMM13;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM14;
				RAW_CONTEXT_M256 m_YMM14;
				RAW_CONTEXT_M128 m_XMM14;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM15;
				RAW_CONTEXT_M256 m_YMM15;
				RAW_CONTEXT_M128 m_XMM15;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM16;
				RAW_CONTEXT_M256 m_YMM16;
				RAW_CONTEXT_M128 m_XMM16;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM17;
				RAW_CONTEXT_M256 m_YMM17;
				RAW_CONTEXT_M128 m_XMM17;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM18;
				RAW_CONTEXT_M256 m_YMM18;
				RAW_CONTEXT_M128 m_XMM18;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM19;
				RAW_CONTEXT_M256 m_YMM19;
				RAW_CONTEXT_M128 m_XMM19;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM20;
				RAW_CONTEXT_M256 m_YMM20;
				RAW_CONTEXT_M128 m_XMM20;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM21;
				RAW_CONTEXT_M256 m_YMM21;
				RAW_CONTEXT_M128 m_XMM21;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM22;
				RAW_CONTEXT_M256 m_YMM22;
				RAW_CONTEXT_M128 m_XMM22;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM23;
				RAW_CONTEXT_M256 m_YMM23;
				RAW_CONTEXT_M128 m_XMM23;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM24;
				RAW_CONTEXT_M256 m_YMM24;
				RAW_CONTEXT_M128 m_XMM24;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM25;
				RAW_CONTEXT_M256 m_YMM25;
				RAW_CONTEXT_M128 m_XMM25;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM26;
				RAW_CONTEXT_M256 m_YMM26;
				RAW_CONTEXT_M128 m_XMM26;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM27;
				RAW_CONTEXT_M256 m_YMM27;
				RAW_CONTEXT_M128 m_XMM27;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM28;
				RAW_CONTEXT_M256 m_YMM28;
				RAW_CONTEXT_M128 m_XMM28;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM29;
				RAW_CONTEXT_M256 m_YMM29;
				RAW_CONTEXT_M128 m_XMM29;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM30;
				RAW_CONTEXT_M256 m_YMM30;
				RAW_CONTEXT_M128 m_XMM30;
			};

			union {
				RAW_CONTEXT_M512 m_ZMM31;
				RAW_CONTEXT_M256 m_YMM31;
				RAW_CONTEXT_M128 m_XMM31;
			};

			// ----------------------------------------------------------------
			// FPU
			// ----------------------------------------------------------------

			RAW_CONTEXT_FPU m_FPU;
		} RAW_CONTEXT64, *PRAW_CONTEXT64;

#ifdef _M_X64
		typedef RAW_NATIVE_CONTEXT64 RAW_NATIVE_CONTEXT;
		typedef RAW_CONTEXT64 RAW_CONTEXT;
		typedef PRAW_CONTEXT64 PRAW_CONTEXT;
#elif _M_IX86
		typedef RAW_NATIVE_CONTEXT32 RAW_NATIVE_CONTEXT;
		typedef RAW_CONTEXT32 RAW_CONTEXT;
		typedef PRAW_CONTEXT32 PRAW_CONTEXT;
#endif

		// ----------------------------------------------------------------
		// Raw Hook CallBack
		// ----------------------------------------------------------------

#ifdef _M_X64
		using fnRawHookCallBack = bool(__fastcall*)(PRAW_CONTEXT pCTX);
#elif _M_IX86
		using fnRawHookCallBack = bool(__cdecl*)(PRAW_CONTEXT pCTX);
#endif

		// ----------------------------------------------------------------
		// Raw Hook
		// ----------------------------------------------------------------

		class RawHook {
		public:
			RawHook();
			RawHook(void* pAddress);
			~RawHook();

		public:
			bool Set(void* pAddress);
			bool Release();

		public:
			bool Hook(const fnRawHookCallBack pCallBack, bool bNative = false, const unsigned int unReserveStackSize = 0, bool bSingleInstructionOnly = false);
			bool UnHook();

		public:
			void* GetTrampoline() const;
			unsigned char GetFirstInstructionSize() const;

		private:
			bool m_bInitialized;
			void* m_pAddress;
			void* m_pWrapper;
			unsigned char m_unFirstInstructionSize;
			void* m_pTrampoline;
			size_t m_unOriginalBytes;
			std::unique_ptr<unsigned char[]> m_pOriginalBytes;
		};
	}
}

#pragma warning(pop)

#endif // !_DETOURS_H_
