#include <Windows.h>
#include <stdio.h>
#include <malloc.h>

typedef struct _PeHeaders {
	char* filename;      // ��� �����

	HANDLE              fd;             // ����� ��������� �����
	HANDLE              mapd;           // ����� �������� ��������
	PBYTE               mem;            // ��������� �� ������ ���������������� �����
	DWORD               filesize;       // ������ ��������������� ����� �����

	IMAGE_DOS_HEADER* doshead;       // ��������� �� DOS ���������
	IMAGE_NT_HEADERS32* nthead;        // ��������� �� NT ���������
	IMAGE_NT_HEADERS64* nthead64;        // ��������� �� NT ���������

	IMAGE_IMPORT_DESCRIPTOR* impdir;    // ��������� �� ������ ������������ ������� �������
	DWORD               sizeImpdir;     // ������ ������� �������
	DWORD               countImpdes;    // ���������� ��������� � ������� �������

	IMAGE_EXPORT_DIRECTORY* expdir;    // ��������� �� ������� ��������
	DWORD               sizeExpdir;     // ������ ������� ��������

	IMAGE_SECTION_HEADER* sections;  // ��������� �� ������� ������ (�� ������ �������)
	DWORD                   countSec;   // ���������� ������

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