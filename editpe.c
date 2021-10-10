#include "editpe.h"

BOOL LoadPeFile(char* filename, PeHeaders* pe) {
	
	pe->filename = filename;

	// открываем файл (получаем файловый дескриптор)
	pe->fd = CreateFileA(filename,      // имя файла
						GENERIC_READ | GENERIC_WRITE,   // права доступа
						0,
						NULL,
						OPEN_EXISTING,          // открываемый файл должен существовать
						FILE_ATTRIBUTE_NORMAL,
						NULL);
	if (pe->fd == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	pe->filesize = GetFileSize(pe->fd, NULL);

	// создаем проекцию файла в память
	pe->mapd = CreateFileMapping(pe->fd, NULL, PAGE_READWRITE, 0, pe->filesize, NULL);
	if (pe->mapd == NULL) {
		CloseHandle(pe->fd);
		printf("Error create file map\n");
		return FALSE;
	}

	// отображаем проекцию в память
	pe->mem = (PBYTE)MapViewOfFile(pe->mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pe->mem == NULL) {
		CloseHandle(pe->fd);
		CloseHandle(pe->mapd);
		printf("Error mapping file\n");
		return FALSE;
	}

	// указатель на заголовок PE
	pe->doshead = (IMAGE_DOS_HEADER*)pe->mem;

	if (pe->doshead->e_magic != IMAGE_DOS_SIGNATURE) {
		UnmapViewOfFile(pe->mem);
		CloseHandle(pe->fd);
		CloseHandle(pe->mapd);
		printf("Error DOS signature\n");
		return FALSE;
	}

	// указатель на NT заголовок
	if (((IMAGE_NT_HEADERS32*)((SIZE_T)pe->mem + pe->doshead->e_lfanew))->OptionalHeader.Magic == 0x10b) {
		pe->nthead = (IMAGE_NT_HEADERS32*)((SIZE_T)pe->mem + pe->doshead->e_lfanew);
		pe->nthead64 = NULL;
		if (pe->nthead->Signature != IMAGE_NT_SIGNATURE) {
			UnmapViewOfFile(pe->mem);
			CloseHandle(pe->fd);
			CloseHandle(pe->mapd);
			printf("Error NT signature\n");
			return FALSE;
		}
	}
	else if (((IMAGE_NT_HEADERS32*)((SIZE_T)pe->mem + pe->doshead->e_lfanew))->OptionalHeader.Magic == 0x20b) {
		pe->nthead64 = (IMAGE_NT_HEADERS64*)((SIZE_T)pe->mem + pe->doshead->e_lfanew);
		pe->nthead = NULL;
		if (pe->nthead64->Signature != IMAGE_NT_SIGNATURE) {
			UnmapViewOfFile(pe->mem);
			CloseHandle(pe->fd);
			CloseHandle(pe->mapd);
			printf("Error NT signature\n");
			return FALSE;
		}
	} else return FALSE;

	// получаем информацию о секциях
	PIMAGE_DATA_DIRECTORY dataDirectory;
	if (pe->nthead64) {
		pe->sections = (IMAGE_SECTION_HEADER*)((SIZE_T) & (pe->nthead64->OptionalHeader) + pe->nthead64->FileHeader.SizeOfOptionalHeader);
		pe->countSec = pe->nthead64->FileHeader.NumberOfSections;
		dataDirectory = &pe->nthead64->OptionalHeader.DataDirectory;
	} else {
		pe->sections = (IMAGE_SECTION_HEADER*)((SIZE_T) & (pe->nthead->OptionalHeader) + pe->nthead->FileHeader.SizeOfOptionalHeader);
		pe->countSec = pe->nthead->FileHeader.NumberOfSections;
		dataDirectory = &pe->nthead->OptionalHeader.DataDirectory;
	}

	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
		pe->expdir = (IMAGE_EXPORT_DIRECTORY*)(pe->mem + RvaToOffset(dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pe));
		pe->sizeExpdir = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	} else {
		pe->expdir = 0;
		pe->sizeExpdir = 0;
	}

	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		pe->impdir = (IMAGE_IMPORT_DESCRIPTOR*)(pe->mem + RvaToOffset(dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pe));
		pe->sizeImpdir = dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	} else {
		pe->impdir = 0;
		pe->sizeImpdir = 0;
	}

	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
		pe->relocsDirectory = (IMAGE_BASE_RELOCATION*)((SIZE_T)pe->mem + RvaToOffset(dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, pe));
		pe->relocDirectorySize = dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	} else {
		pe->relocsDirectory = 0;
		pe->relocDirectorySize = 0;
	}

	return TRUE;
}

void UnloadPeFile(PeHeaders* pe) {


	UnmapViewOfFile(pe->mem);
	CloseHandle(pe->fd);
	CloseHandle(pe->mapd);

	return;
}

//
// Возвращает файловое смещение по RVA.
//
ULONG_PTR RvaToOffset(ULONG_PTR rva, PeHeaders* pe) {

	unsigned int i;
	IMAGE_SECTION_HEADER* sections = pe->sections;
	unsigned int NumberSection = pe->countSec;

	if (pe->nthead64) {
		if (rva > pe->nthead64->OptionalHeader.SizeOfImage) {
			return 0;
		}
	}
	else {
		if (rva > pe->nthead->OptionalHeader.SizeOfImage) {
			return 0;
		}
	}

	//проходим по всем секциям и ищем
	//в какую попадает RVA
	for (i = 0; i < NumberSection; ++i) {
		if ((rva >= sections[i].VirtualAddress) &&
			(rva <= sections[i].VirtualAddress + sections[i].Misc.VirtualSize))
			return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
	}

	return 0;
}


void EditSignature(PeHeaders* pe) {
	printf("new WORD : ");
	WORD newDOSHeaderMagic;
	scanf("%hd", &newDOSHeaderMagic);
	memcpy((char*)&pe->doshead->e_magic, (char*)&newDOSHeaderMagic, sizeof(WORD));
}

void EditNumberOfSections(PeHeaders* pe) {
	printf("new WORD : ");
	WORD newNumberOfSections;
	scanf("%hd", &newNumberOfSections);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->FileHeader.NumberOfSections, (char*)&newNumberOfSections, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->FileHeader.NumberOfSections, (char*)&newNumberOfSections, sizeof(DWORD));
	}
}

void EditTimeDateStamp(PeHeaders* pe) {
	printf("new WORD : ");
	DWORD newTimeDateStamp;
	scanf("%d", &newTimeDateStamp);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->FileHeader.TimeDateStamp, (char*)&newTimeDateStamp, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->FileHeader.TimeDateStamp, (char*)&newTimeDateStamp, sizeof(DWORD));
	}
}

void EditSizeOfOptionalHeader(PeHeaders* pe) {
	printf("new WORD : ");
	WORD newSizeOfOptionalHeader;
	scanf("%hd", &newSizeOfOptionalHeader);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->FileHeader.SizeOfOptionalHeader, (char*)&newSizeOfOptionalHeader, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->FileHeader.SizeOfOptionalHeader, (char*)&newSizeOfOptionalHeader, sizeof(DWORD));
	}
}

void EditCharacteristics(PeHeaders* pe) {
	printf("new WORD : ");
	WORD newCharacteristics;
	scanf("%hd", &newCharacteristics);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->FileHeader.Characteristics, (char*)&newCharacteristics, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->FileHeader.Characteristics, (char*)&newCharacteristics, sizeof(DWORD));
	}
}

void EditMagic(PeHeaders* pe) {
	printf("new WORD : ");
	WORD newMagic;
	scanf("%hd", &newMagic);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.Magic, (char*)&newMagic, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.Magic, (char*)&newMagic, sizeof(DWORD));
	}
}

void EditAddressOfEntryPoint(PeHeaders* pe) {
	printf("new DWORD : ");
	DWORD newAddressOfEntryPoint;
	scanf("%x", &newAddressOfEntryPoint);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.AddressOfEntryPoint, (char*)&newAddressOfEntryPoint, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.AddressOfEntryPoint, (char*)&newAddressOfEntryPoint, sizeof(DWORD));
	}
}

void EditImageBase(PeHeaders* pe) {
	printf("new DWORD : ");
	DWORD newImageBase;
	scanf("%x", &newImageBase);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.ImageBase, (char*)&newImageBase, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.ImageBase, (char*)&newImageBase, sizeof(DWORD));
	}
}

void EditSectionAlignment(PeHeaders* pe) {
	printf("new DWORD : ");
	DWORD newSectionAlignment;
	scanf("%x", &newSectionAlignment);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.SectionAlignment, (char*)&newSectionAlignment, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.SectionAlignment, (char*)&newSectionAlignment, sizeof(DWORD));
	}
}

void EditFileAlignment(PeHeaders* pe) {
	printf("new WORD : ");
	DWORD newFileAlignment;
	scanf("%x", &newFileAlignment);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.FileAlignment, (char*)&newFileAlignment, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.FileAlignment, (char*)&newFileAlignment, sizeof(DWORD));
	}
}

void EditSizeOfImage(PeHeaders* pe) {
	printf("new DWORD : ");
	DWORD newSize;
	scanf("%x", &newSize);

	PDWORD pSectionAllignment;
	if (pe->nthead64) {
		pSectionAllignment = &pe->nthead64->OptionalHeader.SectionAlignment;
	}
	else {
		pSectionAllignment = &pe->nthead->OptionalHeader.SectionAlignment;
	}

	if (newSize % *pSectionAllignment != 0) {
		newSize += *pSectionAllignment - (newSize % *pSectionAllignment);
	}

	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.SizeOfImage, (char*)&newSize, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.SizeOfImage, (char*)&newSize, sizeof(DWORD));
	}

}

void EditSizeOfHeaders(PeHeaders* pe) {
	printf("new DWORD : ");
	DWORD newSizeOfHeaders;
	scanf("%x", &newSizeOfHeaders);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.SizeOfHeaders, (char*)&newSizeOfHeaders, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.SizeOfHeaders, (char*)&newSizeOfHeaders, sizeof(DWORD));
	}
}

void EditSubsystem(PeHeaders* pe) {
	printf("new WORD : ");
	WORD newSubsystem;
	scanf("%hd", &newSubsystem);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.Subsystem, (char*)&newSubsystem, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.Subsystem, (char*)&newSubsystem, sizeof(DWORD));
	}
}

void EditNumberOfRvaAndSizes(PeHeaders* pe) {
	printf("new DWORD : ");
	DWORD newNumberOfRvaAndSizes;
	scanf("%x", &newNumberOfRvaAndSizes);
	if (pe->nthead64) {
		memcpy((char*)&pe->nthead64->OptionalHeader.NumberOfRvaAndSizes, (char*)&newNumberOfRvaAndSizes, sizeof(DWORD));
	}
	else {
		memcpy((char*)&pe->nthead->OptionalHeader.NumberOfRvaAndSizes, (char*)&newNumberOfRvaAndSizes, sizeof(DWORD));
	}
}

void EditTableSection(PeHeaders* pe) {

	DWORD i = 0, numberEdit, secnum;
	WORD value;
	//вывод всех секций
	if (pe->nthead64) {
		//printf("%d sections : \n\n", pe->nthead64->FileHeader.NumberOfSections);
		for (i = 0; i < pe->nthead64->FileHeader.NumberOfSections; i++) {
			printf("%d.\tsection name : %s\n", i, pe->sections[i].Name);
		}
	}
	else {
		//printf("%d sections : \n\n", pe->nthead->FileHeader.NumberOfSections);
		for (i = 0; i < pe->nthead->FileHeader.NumberOfSections; i++) {
			printf("%d.\tsection name : %s\n", i, pe->sections[i].Name);
		}
	}

	printf("Select number section : ");
	scanf("%d", &secnum);
	printf("1.\t%s\t\tName (8 byte)\n", pe->sections[secnum].Name);
	printf("2.\t0x%x\t\tVA (DWORD)\n", pe->sections[secnum].VirtualAddress);
	printf("3.\t0x%x\t\tSizeOfRawData (DWORD)\n", pe->sections[secnum].SizeOfRawData);
	printf("4.\t0x%x\t\tPointerToRawData (DWORD)\n", pe->sections[secnum].PointerToRawData);
	printf("5.\t0x%x\t\tPointerToRelocations (DWORD)\n", pe->sections[secnum].PointerToRelocations);
	printf("6.\t0x%x\t\tPointerLineNumbers (DWORD)\n", pe->sections[secnum].PointerToLinenumbers);
	printf("7.\t0x%x\t\tNumberOfRelocations (WORD)\n", pe->sections[secnum].NumberOfRelocations);
	printf("8.\t0x%x\t\tNumberOfLinenumbers (WORD)\n", pe->sections[secnum].NumberOfLinenumbers);
	printf("9.\t0x%x\tCharacteristics (DWORD)\n", pe->sections[secnum].Characteristics);
	printf("10.\t0x%x\t\tMisc.PhysicalAddress (DWORD)\n", pe->sections[secnum].Misc.PhysicalAddress);
	printf("11.\t0x%x\t\tMisc.VirtualSize (DWORD)\n", pe->sections[secnum].Misc.VirtualSize);

	printf("Select number for edit : ");
	scanf("%d", &numberEdit);
	printf("new value : ");
	if (numberEdit == 1) {
		BYTE newName[IMAGE_SIZEOF_SHORT_NAME];
		scanf("%s", &newName);
		memcpy((char*)&pe->sections[secnum].Name, "%s", newName);
	} else if (numberEdit == 2) {
		scanf("%x", &numberEdit);
		memcpy((char*)&pe->sections[secnum].VirtualAddress, (char*)&numberEdit, sizeof(DWORD));
	} else if (numberEdit == 3) {
		scanf("%d", &numberEdit);
		memcpy((char*)&pe->sections[secnum].SizeOfRawData, (char*)&numberEdit, sizeof(DWORD));
	} else if (numberEdit == 4) {
		scanf("%d", &numberEdit);
		memcpy((char*)&pe->sections[secnum].PointerToRawData, (char*)&numberEdit, sizeof(DWORD));
	} else if (numberEdit == 5) {
		scanf("%d", &numberEdit);
		memcpy((char*)&pe->sections[secnum].PointerToRelocations, (char*)&numberEdit, sizeof(DWORD));
	} else if (numberEdit == 6) {
		scanf("%d", &numberEdit);
		memcpy((char*)&pe->sections[secnum].PointerToLinenumbers, (char*)&numberEdit, sizeof(DWORD));
	} else if (numberEdit == 7) {
		scanf("%hd", &value);
		memcpy((char*)&pe->sections[secnum].NumberOfRelocations, (char*)&value, sizeof(DWORD));
	} else if (numberEdit == 8) {
		scanf("%hd", &value);
		memcpy((char*)&pe->sections[secnum].NumberOfLinenumbers, (char*)&value, sizeof(DWORD));
	} else if (numberEdit == 9) {
		scanf("%d", &numberEdit);
		memcpy((char*)&pe->sections[secnum].Characteristics, (char*)&numberEdit, sizeof(DWORD));
	} else if (numberEdit == 10) {
		scanf("%d", &numberEdit);
		memcpy((char*)&pe->sections[secnum].Misc.PhysicalAddress, (char*)&numberEdit, sizeof(DWORD));
	} else if (numberEdit == 11) {
		scanf("%d", &numberEdit);
		memcpy((char*)&pe->sections[secnum].Misc.VirtualSize, (char*)&numberEdit, sizeof(DWORD));
	}
}

void EditDataDirectory(PeHeaders* pe) {
	DWORD i = 0;

	for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		if (pe->nthead64) {
			printf("%d. Size: %d.\tVirtualAddress: %d\n", i, pe->nthead64->OptionalHeader.DataDirectory[i].Size, pe->nthead->OptionalHeader.DataDirectory[i].VirtualAddress);
		}
		else {
			printf("%d. Size: %d.\tVirtualAddress: %d\n", i, pe->nthead->OptionalHeader.DataDirectory[i].Size, pe->nthead->OptionalHeader.DataDirectory[i].VirtualAddress);
		}
	}

	printf("Select number for clean : ");
	scanf("%d", &i);
	if (pe->nthead64) {
		pe->nthead64->OptionalHeader.DataDirectory[i].Size = 0;
		pe->nthead64->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
	}
	else {
		pe->nthead->OptionalHeader.DataDirectory[i].Size = 0;
		pe->nthead->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
	}
}

void EditRelocSizeOfBlockAndVirtualaddress(PeHeaders* pe) {
	WORD select;
	DWORD offset = 0;
	DWORD newSizeOfBlock;
	DWORD newVirtualAddress;
	IMAGE_BASE_RELOCATION* reloc = pe->relocsDirectory;
	int i;
	for (i = 1; offset < pe->relocDirectorySize; ++i) {
		printf("%d. SizeOfBlock: 0x%x\tVirtualAddress: 0x%x\n", i, reloc->SizeOfBlock, reloc->VirtualAddress);

		offset += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
	}
	printf("Select number for edit : ");
	scanf("%hd", &select);
	if (select < 0 || select > i) {
		printf("incorrect select number");
		return;
	}

	printf("new SizeOfBlock (DWORD) : ");
	scanf("%x", &newSizeOfBlock);
	printf("new VirtualAddress (DWORD) : ");
	scanf("%x", &newVirtualAddress);

	reloc = pe->relocsDirectory;
	for (int i = 1; i != select; ++i) {
		reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
	}
	reloc->SizeOfBlock = newSizeOfBlock;
	reloc->VirtualAddress = newVirtualAddress;
}

void EditRelocTypeAndOffset(PeHeaders* pe) {

	WORD select;
	WORD newOffset;
	BYTE symb = 0, newType;
	WORD* baseRelocOffset;
	DWORD offset = 0, i;
	DWORD newSizeOfBlock;
	DWORD newVirtualAddress;
	IMAGE_BASE_RELOCATION* reloc = pe->relocsDirectory;

	char* relocType[] = { "IMAGE_REL_BASED_ABSOLUTE",
				 "IMAGE_REL_BASED_HIGH",
				 "IMAGE_REL_BASED_LOW",
				 "IMAGE_REL_BASED_HIGHLOW",
				 "IMAGE_REL_BASED_HIGHADJ",
				 "IMAGE_REL_BASED_MIPS_JMPADDR",
				 "", "", "",
				 "IMAGE_REL_BASED_IA64_IMM64",
				 "IMAGE_REL_BASED_DIR64" };

	while (offset < pe->relocDirectorySize) {
		printf("\nSizeOfBlock: 0x%x. VirtualAddress: 0x%x\n", reloc->SizeOfBlock, reloc->VirtualAddress);
		baseRelocOffset = (WORD*)((SIZE_T)reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
			printf("%d.\t%s (%d)\t0x%x\n", i, relocType[baseRelocOffset[i] >> 12], baseRelocOffset[i] >> 12, baseRelocOffset[i] & 0x0FFF);
		}
		
		printf("Press 'Y' or 'y' for edit block : ");
		scanf("%c", &symb);
		while (symb == 'Y' || symb == 'y') {

			printf("Select number for edit : ");
			scanf("%hd", &select);
			getchar();
			printf("New type : ");
			scanf("%hi", &newType);
			newType = newType << 12;
			memset(&baseRelocOffset[select], newType, 1);

			printf("New offset : ");
			scanf("%x", &newOffset);
			newOffset &= 0x0FFF;
			memcpy(&baseRelocOffset[select], &newOffset, sizeof(WORD));

		}
		offset += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
	}
}

void EditRelocsShiftAddress(PeHeaders* pe) {
	DWORD offset = 0;
	DWORD value;
	DWORD i;
	DWORD *offsetValue;
	DWORD *address;
	WORD *baseRelocOffset;
	IMAGE_BASE_RELOCATION* reloc = pe->relocsDirectory;

	printf("Enter number (address) to add : ");
	scanf("%x", &value);

	while (offset < pe->relocDirectorySize) {

		baseRelocOffset = (WORD*)((SIZE_T)reloc + sizeof(IMAGE_BASE_RELOCATION));
		offsetValue = (SIZE_T)(pe->mem + RvaToOffset(reloc->VirtualAddress, pe));


		for (i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
			if (baseRelocOffset[i] != 0) {
				address = (SIZE_T)offsetValue + (SIZE_T)(baseRelocOffset[i] & 0x0FFF);
				*address = (SIZE_T)*address + value;
			}
		}

		offset += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
	}

	if (pe->nthead64) pe->nthead64->OptionalHeader.ImageBase += value;
	else pe->nthead->OptionalHeader.ImageBase += value;
}

void EditRelocsNewEntryForBlock(PeHeaders* pe) {
	DWORD select;
	DWORD newType, newOffset;
	DWORD sizeRelocTable = 0;
	DWORD offset = 0, i;
	WORD* baseRelocOffset;
	IMAGE_BASE_RELOCATION* reloc = pe->relocsDirectory;
	

	SIZE_T checkFreeType = 0;
	while (offset < pe->relocDirectorySize) {
		DWORD freeType = 0;
		baseRelocOffset = (WORD*)((SIZE_T)reloc + sizeof(IMAGE_BASE_RELOCATION));
		for (i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i) {
			if ((baseRelocOffset[i] >> 12) == IMAGE_REL_BASED_ABSOLUTE) {
				freeType++;
			}
		}

		checkFreeType <<= 1;
		if (freeType) {
			checkFreeType += 0x1;
		} 

		printf("%d. SizeOfBlock: 0x%x\tVirtualAddress: 0x%x\tFreeType:%d\n",sizeRelocTable++, reloc->SizeOfBlock, reloc->VirtualAddress, freeType);

		offset += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
	}
	if (checkFreeType) {
		do {
			printf("Select number block for new entry : ");
			scanf("%d", &select);
		} while (!((checkFreeType >> (sizeRelocTable - select - 1)) & 0x1));


		//offset = 0;
		reloc = pe->relocsDirectory;
		for (i = 0; i < select; ++i) {
			reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
		}

		baseRelocOffset = (WORD*)((SIZE_T)reloc + sizeof(IMAGE_BASE_RELOCATION));
		for (i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i) {
			if ((baseRelocOffset[i] >> 12) == IMAGE_REL_BASED_ABSOLUTE) {
				printf("new type : ");
				scanf("%hi", &newType);
				newType <<= 12;

				printf("new offset : ");
				scanf("%hx", &newOffset);
				newType |= newOffset & 0x0fff;

				memcpy(&baseRelocOffset[i], &newType, sizeof(WORD));

				break;
			}
		}
	} else return;
}

void EditRelocsNewEntryForNewBlock(PeHeaders* pe) {
	SIZE_T write;
	DWORD select, oldsize, sizeRelocTable = 0, offset = 0, i, sizeReloc = 10;
	IMAGE_BASE_RELOCATION* reloc = pe->relocsDirectory;
	WORD baseRelocOffset = 0;
	while (offset < pe->relocDirectorySize) {
		printf("%d. SizeOfBlock: 0x%x\tVirtualAddress: 0x%x\n", sizeRelocTable++, reloc->SizeOfBlock, reloc->VirtualAddress);
		offset += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
	}

	printf("Select the number to insert : ");
	scanf("%d", &select);

	if (select >= 0 && select <= sizeRelocTable) {
		reloc = pe->relocsDirectory;
		offset = 0;
		sizeReloc = sizeof(WORD);
		for (i = 0; i < select; ++i) {
			offset += reloc->SizeOfBlock;
			reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
		}



		CreateSection(pe, pe->relocDirectorySize + sizeReloc);
		write = pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);

		memcpy(write, (DWORD*)pe->relocsDirectory, offset);
		oldsize = reloc->SizeOfBlock;
		reloc->SizeOfBlock += sizeReloc;
		//reloc->SizeOfBlock += sizeof(WORD);
		memcpy(write + offset, (DWORD*)reloc, oldsize);

		WORD insert, tmp;
		printf("New type (4 bits): ");
		scanf(" %hd", &tmp);
		insert = tmp << 12;
		printf("New offset (12 bits): ");
		scanf(" %hd", &tmp);
		insert = insert + (tmp & 0x0FFF);
		memcpy(write + offset + oldsize, &insert, sizeof(WORD));

		if (select + 1 < sizeRelocTable) {
			memcpy(write + offset + reloc->SizeOfBlock, (SIZE_T)reloc + oldsize, pe->relocDirectorySize - offset - oldsize);
		}
		pe->relocDirectorySize += sizeReloc;
		pe->relocsDirectory = (PIMAGE_BASE_RELOCATION)write;

		if (pe->nthead64) {
			pe->nthead64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pe->sections[pe->countSec - 1].VirtualAddress;
			pe->nthead64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeReloc;
		}
		else {
			pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pe->sections[pe->countSec - 1].VirtualAddress;
			pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeReloc;
		}
	}
}

void EditRelocsNewBlock(PeHeaders* pe) {
	DWORD offset = 0, size, lastVa = 0;
	SIZE_T write;
	IMAGE_BASE_RELOCATION newReloc;

	IMAGE_BASE_RELOCATION* reloc = pe->relocsDirectory;
	printf("Enter size block : ");
	scanf("%x", &size);
	while (offset < pe->relocDirectorySize) {
		offset += reloc->SizeOfBlock;
		lastVa = reloc->VirtualAddress;
		reloc = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc + reloc->SizeOfBlock);
	}


	CreateSection(pe, pe->relocDirectorySize + size);
	write = pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);

	memcpy(write, (DWORD*)pe->relocsDirectory, pe->relocDirectorySize);

	newReloc.SizeOfBlock = size;
	if (pe->nthead64) {
		newReloc.VirtualAddress = lastVa + pe->nthead64->OptionalHeader.SectionAlignment;
	}
	else {
		newReloc.VirtualAddress = lastVa + pe->nthead->OptionalHeader.SectionAlignment;
	}
	memcpy(write + pe->relocDirectorySize, &newReloc, sizeof(newReloc));
	if (pe->nthead64) {
		pe->relocDirectorySize += size;
		pe->nthead64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += size;
		pe->relocsDirectory = write;
		pe->nthead64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pe->sections[pe->countSec - 1].VirtualAddress;
	}
	else {
		pe->relocDirectorySize += size;
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += size;
		pe->relocsDirectory = write;
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pe->sections[pe->countSec - 1].VirtualAddress;
	}
}

void EditDescriptorImportTable(PeHeaders* pe) {
	if (pe->impdir) {
		BYTE symb;
		DWORD select, newValue, i, j;
		SIZE_T firstThunk;

		for (i = 0; (i + 1)*sizeof(IMAGE_IMPORT_DESCRIPTOR) < pe->sizeImpdir; ++i) {
			printf("\t1. Characteristics : %x\n", (pe->impdir + i)->Characteristics);
			printf("\t2. TimeDateStamp : %x\n", (pe->impdir + i)->TimeDateStamp);
			printf("\t3. Name : %s\n", pe->mem + RvaToOffset((pe->impdir + i)->Name, pe));
			printf("\t4. Name functions\nPress 'Y' or 'y' for edit block : ");
			scanf("%c", &symb);
			if (symb == 'y' || symb == 'Y') {
				printf("Slecet number for edit : ");
				scanf("%d", &select);
				if (select == 1) {
					printf("new Characteristics : ");
					scanf("%x", &newValue);
					(pe->impdir + i)->Characteristics = newValue;
				}
				else if (select == 2) {
					printf("new TimeDateStamp : ");
					scanf("%d", &newValue);
					(pe->impdir + i)->Characteristics = newValue;
				}
				else if(select == 3) {
					char* str = (char*)calloc(64, sizeof(char));
					printf("new name (max 64 symbols) : ");
					scanf("%s", str);

					if (strlen(str) > strlen(pe->mem + RvaToOffset((pe->impdir + i)->Name, pe))) {
						CreateSection(pe, strlen(str));
						memcpy(pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe), str, strlen(str));
						(pe->impdir + i)->Name = pe->sections[pe->countSec - 1].VirtualAddress;
					}
					else {
						strcpy(pe->mem + RvaToOffset((pe->impdir + i)->Name, pe), str);
					}
					free(str);
				}
				else if (select == 4) {
					if (pe->nthead64) {
						if ((pe->impdir + i)->OriginalFirstThunk) {
							firstThunk = (ULONGLONG*)(pe->mem + RvaToOffset((pe->impdir + i)->OriginalFirstThunk, pe));
						}
						else {
							firstThunk = (ULONGLONG*)(pe->mem + RvaToOffset((pe->impdir + i)->FirstThunk, pe));
						}
						for (j = 0; ((ULONGLONG*)firstThunk)[j]; ++j) {
							if (((ULONGLONG*)firstThunk)[j] & 0x8000000000000000) { //если старший бит 1 то импотр по ординалу
								printf("\t\t%lld. Ordinal: %lld\n", j, ((ULONGLONG*)firstThunk)[j] & 0x000000000000FFFF);
							}
							else {
								SIZE_T sum = pe->mem + RvaToOffset(((ULONGLONG*)firstThunk)[j], pe) + 2;  // если по имени то +2 
								printf("\t\t%lld. Name: %s\n", j, sum);
							}

						}
					}
					else {
						if ((pe->impdir + i)->OriginalFirstThunk) {
							firstThunk = (DWORD*)(pe->mem + RvaToOffset((pe->impdir + i)->OriginalFirstThunk, pe));
						}
						else {
							firstThunk = (DWORD*)(pe->mem + RvaToOffset((pe->impdir + i)->FirstThunk, pe));
						}
						for (j = 0; ((DWORD*)firstThunk)[j]; ++j) {
							if (((DWORD*)firstThunk)[j] & 0x80000000) {
								printf("\t\t%d. Ordinal: %d\n", j, ((DWORD*)firstThunk)[j] & 0x0000FFFF);
							}
							else {
								printf("\t\t%d. Name: %s\n", j, (char*)(pe->mem + RvaToOffset(((DWORD*)firstThunk)[j], pe) + 2));
							}
						}
					}
					WORD select, len;

					printf("Select number for edit (0 - %d): ", j - 1);
					scanf("%hd", &select);

					char* newName = (char*)calloc(64, sizeof(char));
					printf("new name (max 64 symbols) : ");
					scanf("%s", newName);

					len = strlen(pe->mem + RvaToOffset(((PDWORD)firstThunk)[select], pe));

					if (strlen(newName) > len) {
						CreateSection(pe, strlen(newName));
						memcpy(pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe) + 2, newName, strlen(newName));
						((PDWORD)firstThunk)[select] = pe->sections[pe->countSec - 1].VirtualAddress;
					}
					else {
						memcpy(pe->mem + RvaToOffset(((PDWORD)firstThunk)[select], pe), newName, len);
					}

					free(newName);

				} else printf("incorrect number\n");
			}
			
		}
	}
	else printf("bad import :(");
}

void EditDescriptorExportTable(PeHeaders* pe) {
	if (pe->expdir) {
		DWORD select, newValue, i;
		DWORD* pAddressOfNames;
		DWORD* pAddressOfFunctions;
		WORD* pAddressOfNameOrdinals;
		printf("\t1. Name : %s\n", pe->mem + RvaToOffset(pe->expdir->Name, pe));
		printf("\t2. Functions\n Select number for edit : ");
		scanf("%d", &select);
		if (select == 1) {
			char* str = (char*)calloc(64, sizeof(char));
			printf("new name (max 64 symbols) : ");
			scanf("%s", str);
			if (strlen(str) > strlen(pe->mem + RvaToOffset(pe->expdir->Name, pe))) {
				CreateSection(pe, strlen(str));
				memcpy(pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe), str, strlen(str));
				pe->expdir->Name = pe->sections[pe->countSec - 1].VirtualAddress;
			} else {
				strcpy(pe->mem + RvaToOffset(pe->expdir->Name, pe), str);
			}
			free(str);
		}
		else if (select == 2) {
			pAddressOfNames = (DWORD*)(pe->mem + RvaToOffset(pe->expdir->AddressOfNames, pe));
			pAddressOfFunctions = (DWORD*)(pe->mem + RvaToOffset(pe->expdir->AddressOfFunctions, pe));
			pAddressOfNameOrdinals = (WORD*)(pe->mem + RvaToOffset(pe->expdir->AddressOfNameOrdinals, pe));
			for (i = 0; i < pe->expdir->NumberOfNames; ++i) {
				printf("%d.\t0x%x\t", i, pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
				printf("%s\n", pe->mem + RvaToOffset(pAddressOfNames[i], pe));
			}

			printf("\n\n1. Edit name function\n2. Edit address function\nSelect numbder for edit : ");
			scanf("%d", &select);
			if (select == 1) {
				char* str = (char*)calloc(64, sizeof(char));
				printf("Number function : ");
				scanf("%hd", &select);
				printf("new name (max 64 symbols) : ");
				scanf("%s", str);
				if (strlen(str) > strlen(pe->mem + RvaToOffset(pAddressOfNames[select], pe))) {
					CreateSection(pe, strlen(str));
					memcpy(pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe), str, strlen(str));
					pAddressOfNames[select] = pe->sections[pe->countSec - 1].VirtualAddress;
				}
				else {
					strcpy(pe->mem + RvaToOffset(pAddressOfNames[select], pe), str);
				}
			}
			else if (select == 2) {
				printf("Number function : ");
				scanf("%hd", &select);
				printf("new address (DWORD) : ");
				scanf("%x", &newValue);
				pAddressOfFunctions[pAddressOfNameOrdinals[select]] = newValue;
			}
			else printf("incorrect number");
		} 
		else printf("incorrect number");
	} 
	else printf("bad export :(");
}

DWORD Align(DWORD value, DWORD align) {
	return (value + align - 1) & ~(align - 1);
}

void CreateSection(PeHeaders* pe, const DWORD size) {
	char* nameSection = ".mysec";
	IMAGE_SECTION_HEADER* last;
	DWORD newVirtualAndFileSize;
	DWORD rvaNewSection, offsetNewSection;
	if (pe->nthead64) {

		last = pe->sections + pe->countSec;
		newVirtualAndFileSize = Align(size, pe->nthead64->OptionalHeader.SectionAlignment);
		rvaNewSection = Align(pe->nthead64->OptionalHeader.SizeOfImage, pe->nthead64->OptionalHeader.SectionAlignment);
		offsetNewSection = Align(pe->filesize, pe->nthead64->OptionalHeader.FileAlignment);


		pe->nthead64->FileHeader.NumberOfSections++;
		pe->countSec++;

		memcpy(last->Name, nameSection, sizeof(nameSection));
		last->Misc.VirtualSize = newVirtualAndFileSize;
		last->VirtualAddress = rvaNewSection;
		last->SizeOfRawData = newVirtualAndFileSize;
		last->PointerToRawData = offsetNewSection;
		last->Characteristics = 0xE0000000;

		pe->nthead64->OptionalHeader.SizeOfImage = Align(pe->nthead64->OptionalHeader.SizeOfImage, pe->nthead64->OptionalHeader.SectionAlignment) + newVirtualAndFileSize;
		pe->filesize = pe->filesize + newVirtualAndFileSize;
		pe->mapd = CreateFileMapping(pe->fd, NULL, PAGE_READWRITE, 0, pe->filesize, NULL);
		pe->mem = (PBYTE)MapViewOfFile(pe->mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	}
	else {

		last = pe->sections + pe->countSec;
		newVirtualAndFileSize = Align(size, pe->nthead->OptionalHeader.SectionAlignment);
		rvaNewSection = Align(pe->nthead->OptionalHeader.SizeOfImage, pe->nthead->OptionalHeader.SectionAlignment);
		offsetNewSection = Align(pe->filesize, pe->nthead->OptionalHeader.FileAlignment);


		pe->nthead->FileHeader.NumberOfSections++;
		pe->countSec++;

		memcpy(last->Name, nameSection, sizeof(nameSection));
		last->Misc.VirtualSize = newVirtualAndFileSize;
		last->VirtualAddress = rvaNewSection;
		last->SizeOfRawData = newVirtualAndFileSize;
		last->PointerToRawData = offsetNewSection;
		last->Characteristics = 0xE0000000;

		pe->nthead->OptionalHeader.SizeOfImage = Align(pe->nthead->OptionalHeader.SizeOfImage, pe->nthead->OptionalHeader.SectionAlignment) + newVirtualAndFileSize;
		pe->filesize = pe->filesize + newVirtualAndFileSize;
		pe->mapd = CreateFileMapping(pe->fd, NULL, PAGE_READWRITE, 0, pe->filesize, NULL);
		pe->mem = (PBYTE)MapViewOfFile(pe->mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	}
}
