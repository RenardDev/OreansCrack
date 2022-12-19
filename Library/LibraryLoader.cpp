#include "LibraryLoader.h"

__forceinline void MemoryCopy(void* const pDst, void* const pSrc, size_t unSize) {
	for (size_t i = 0; i < unSize; ++i) {
		reinterpret_cast<unsigned char* const>(pDst)[i] = reinterpret_cast<unsigned char* const>(pSrc)[i];
	}
}

DLL_EXPORT DWORD WINAPI LibraryMain(LPVOID lpParameter) {
	PLOADER_DATA pData = reinterpret_cast<PLOADER_DATA>(lpParameter);
	if (!pData) {
		return -1;
	}

	void* pBaseAddress = pData->m_pMemoryAddress;

	const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddress);
	const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddress) + pDH->e_lfanew);
	const PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

	void* pMemory = pData->m_pVirtualAlloc(nullptr, ((PIMAGE_NT_HEADERS)pNTHs)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pMemory) {
		return -1;
	}

	pData->m_pMemoryAddress = pMemory;

	MemoryCopy(pMemory, pBaseAddress, pOH->SizeOfHeaders);

	const PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pOH) + pFH->SizeOfOptionalHeader);
	const WORD unNumberOfSections = pFH->NumberOfSections;
	for (WORD i = 0; i < unNumberOfSections; ++i) {
		MemoryCopy(reinterpret_cast<char*>(pMemory) + pFirstSection[i].VirtualAddress, reinterpret_cast<char*>(pBaseAddress) + pFirstSection[i].PointerToRawData, pFirstSection[i].SizeOfRawData);
	}

	const PIMAGE_DATA_DIRECTORY pImportDD = &(pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	const PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<char*>(pMemory) + pImportDD->VirtualAddress);

	for (size_t i = 0; pImportDescriptor[i].Name != 0; ++i) {
		const HMODULE hModule = pData->m_pLoadLibraryA(reinterpret_cast<char*>(pMemory) + pImportDescriptor[i].Name);
		if (!hModule) {
			return -1;
		}

		PIMAGE_THUNK_DATA pThunkDataImportNameTable = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<char*>(pMemory) + pImportDescriptor[i].OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThunkDataImportAddressTable = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<char*>(pMemory) + pImportDescriptor[i].FirstThunk);

		while (pThunkDataImportAddressTable->u1.AddressOfData) {
			if (pThunkDataImportNameTable->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				const PIMAGE_DOS_HEADER pModuleDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
				const PIMAGE_NT_HEADERS pModuleNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pModuleDH->e_lfanew);
				const PIMAGE_OPTIONAL_HEADER pModuleOH = &(pModuleNTHs->OptionalHeader);

				const PIMAGE_DATA_DIRECTORY pExportDD = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&(pModuleOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]));
				const PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(hModule) + pExportDD->VirtualAddress);

				const PDWORD pAddressesOfFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(hModule) + pExportDirectory->AddressOfFunctions);

				pThunkDataImportAddressTable->u1.Ordinal = ((ULONG_PTR)hModule + pAddressesOfFunctions[IMAGE_ORDINAL(pThunkDataImportNameTable->u1.Ordinal - pExportDirectory->Base)]);
			} else {
				const PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<char*>(pMemory) + pThunkDataImportAddressTable->u1.AddressOfData);

				pThunkDataImportAddressTable->u1.Function = reinterpret_cast<DWORD_PTR>(pData->m_pGetProcAddress(hModule, pImportByName->Name));
			}

			++pThunkDataImportAddressTable;
			++pThunkDataImportNameTable;
		}
	}

	const PIMAGE_DATA_DIRECTORY pBaseRelocationDD = &(pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (pBaseRelocationDD->Size) {
		ULONG_PTR unDelta = reinterpret_cast<ULONG_PTR>(reinterpret_cast<char*>(pMemory) - pOH->ImageBase);
		PIMAGE_BASE_RELOCATION pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<char*>(pMemory) + pBaseRelocationDD->VirtualAddress);
		while (pBaseRelocation->SizeOfBlock) {

			unsigned char* pBlock = reinterpret_cast<unsigned char*>(pMemory) + pBaseRelocation->VirtualAddress;

			PIMAGE_RELOC pReloc = reinterpret_cast<PIMAGE_RELOC>(reinterpret_cast<char*>(pBaseRelocation) + sizeof(IMAGE_BASE_RELOCATION));

			size_t unSizeOfBlock = pBaseRelocation->SizeOfBlock;
			size_t unCount = (unSizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			while (unCount--) {
				if (pReloc->unType == IMAGE_REL_BASED_DIR64) {
					*reinterpret_cast<PULONG_PTR>(pBlock + pReloc->unOffset) += unDelta;
				} else if (pReloc->unType == IMAGE_REL_BASED_HIGHLOW) {
					*reinterpret_cast<PDWORD>(pBlock + pReloc->unOffset) += static_cast<DWORD>(unDelta);
				} else if (pReloc->unType == IMAGE_REL_BASED_HIGH) {
					*reinterpret_cast<PWORD>(pBlock + pReloc->unOffset) += HIWORD(unDelta);
				} else if (pReloc->unType == IMAGE_REL_BASED_LOW) {
					*reinterpret_cast<PWORD>(pBlock + pReloc->unOffset) += LOWORD(unDelta);
				}

				pReloc = reinterpret_cast<PIMAGE_RELOC>(reinterpret_cast<char*>(pReloc) + sizeof(IMAGE_RELOC));
			}

			pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<char*>(pBaseRelocation) + unSizeOfBlock);
		}
	}

	fnDllMain DllMain = nullptr;
	const DWORD unAddressOfEntryPoint = pOH->AddressOfEntryPoint;
	if (unAddressOfEntryPoint) {
		DllMain = reinterpret_cast<fnDllMain>(reinterpret_cast<char*>(pMemory) + unAddressOfEntryPoint);
	}

	pData->m_pNtFlushInstructionCache(HANDLE(-1), nullptr, 0);

	if (DllMain) {
		return DllMain(reinterpret_cast<HINSTANCE>(pMemory), DLL_PROCESS_ATTACH, lpParameter);
	}

	return 0;
}
