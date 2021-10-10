#include <Windows.h>
#include <stdio.h>
#include <malloc.h>

typedef struct _PeHeaders {
	char* filename;      // имя файла

	HANDLE              fd;             // хендл открытого файла
	HANDLE              mapd;           // хендл файловой проекции
	PBYTE               mem;            // указатель на память спроецированного файла
	DWORD               filesize;       // размер спроецированной части файла

	IMAGE_DOS_HEADER* doshead;       // указатель на DOS заголовок
	IMAGE_NT_HEADERS32* nthead;        // указатель на NT заголовок
	IMAGE_NT_HEADERS64* nthead64;        // указатель на NT заголовок

	IMAGE_IMPORT_DESCRIPTOR* impdir;    // указатель на массив дескрипторов таблицы импорта
	DWORD               sizeImpdir;     // размер таблицы импорта
	DWORD               countImpdes;    // количество элементов в таблице импорта

	IMAGE_EXPORT_DIRECTORY* expdir;    // указатель на таблицу экспорта
	DWORD               sizeExpdir;     // размер таблицы экспорта

	IMAGE_SECTION_HEADER* sections;  // указатель на таблицу секций (на первый элемент)
	DWORD                   countSec;   // количество секций

	IMAGE_BASE_RELOCATION* relocsDirectory;
	DWORD relocDirectorySize;

} PeHeaders;

ULONG_PTR RvaToOffset(ULONG_PTR rva, PeHeaders* pe);

BOOL LoadPeFile(char* filename, PeHeaders* pe);

void UnloadPeFile(PeHeaders* pe);

void EditSignature(PeHeaders* pe);

void EditNumberOfSections(PeHeaders* pe);

void EditTimeDateStamp(PeHeaders* pe);

void EditSizeOfOptionalHeader(PeHeaders* pe);

void EditCharacteristics(PeHeaders* pe);

void EditMagic(PeHeaders* pe);

void EditAddressOfEntryPoint(PeHeaders* pe);

void EditImageBase(PeHeaders* pe);

void EditSectionAlignment(PeHeaders* pe);

void EditFileAlignment(PeHeaders* pe);

void EditSizeOfImage(PeHeaders* pe);

void EditSizeOfHeaders(PeHeaders* pe);

void EditSubsystem(PeHeaders* pe);

void EditNumberOfRvaAndSizes(PeHeaders* pe);

void EditTableSection(PeHeaders* pe);

void EditDataDirectory(PeHeaders* pe);

void EditRelocSizeOfBlockAndVirtualaddress(PeHeaders* pe);

void EditRelocTypeAndOffset(PeHeaders* pe);

void EditRelocsShiftAddress(PeHeaders* pe);

void EditRelocsNewEntryForBlock(PeHeaders* pe);

void EditRelocsNewEntryForNewBlock(PeHeaders* pe);

void EditRelocsNewBlock(PeHeaders* pe);

void EditDescriptorImportTable(PeHeaders* pe);

void EditDescriptorExportTable(PeHeaders* pe);

void CreateSection(PeHeaders* pe, DWORD size);