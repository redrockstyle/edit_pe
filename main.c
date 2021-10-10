#include "editpe.h"


void usage(void) {
	printf("editpe <filepath> <opt>\n");
	printf("opt:\n"
		"\tsig\t\t-\tSignature DOS header\n"

		"\tnumbofsec\t-\tFileHeader.NumberOfSections\n"
		"\ttdstamp\t\t-\tFileHeader.TimeDateStamp\n"
		"\topthead\t\t-\tFileHeader.SizeOfOptionalHeader\n"
		"\tcharact\t\t-\tFileHeader.Characteristics\n"

		"\tmegic\t\t-\tOptionalHeader.Magic\n"
		"\tentpoint\t-\tOptionalHeader.AddressOfEntryPoint\n"
		"\timb\t\t-\tOptionalHeader.ImageBase\n"
		"\tsalig\t\t-\tOptionalHeader.SectionAlignment\n"
		"\tfalig\t\t-\tOptionalHeader.FileAlignment\n"
		"\tsizeimg\t\t-\tOptionalHeader.SizeOfImage\n"
		"\tsizehead\t-\tOptionalHeader.SizeOfHeaders\n"
		"\tsubsys\t\t-\tOptionalHeader.Subsystem\n"
		"\trvas\t\t-\tOptionalHeader.NumberOfRvaAndSizes\n"
		"\tsections\t-\tEdit table sections\n"
		"\tdatadir\t\t-\tClean one entry DataDirectory\n"

		"\treloc1\t\t-\tEdit reloc (SizeOfBlock and Virtualaddress)\n"
		"\treloc2\t\t-\tEdit reloc (Type and Offset)\n"
		"\treloc3\t\t-\tEdit relocs address (edit imageBase)\n"
		"\treloc4\t\t-\tAdd new entry for block (free block)\n"
		"\treloc5\t\t-\tAdd new entry for new block (create section block)\n"
		"\treloc6\t\t-\tCreate new block (create section)\n"
		"\timport\t\t-\tEdit import descriptor\n"
		"\texport\t\t-\tEdit export descriptor\n"
		"\tcreate\t\t-\tCreate section\n");
}

int main(int argc, char** argv) {
	PeHeaders pe;
	if (argc > 2) {
		if (!LoadPeFile(argv[1], &pe)) {
			puts("Error load PE file");
			return -1;
		}

		if (!strcmp(argv[2], "sig")) {
			EditSignature(&pe);
		} else if (!strcmp(argv[2], "numbofsec")) {
			EditNumberOfSections(&pe);
		} else if (!strcmp(argv[2], "tdstamp")) {
			EditTimeDateStamp(&pe);
		} else if (!strcmp(argv[2], "opthead")) {
			EditSizeOfOptionalHeader(&pe);
		} else if (!strcmp(argv[2], "charact")) {
			EditCharacteristics(&pe);
		} else if (!strcmp(argv[2], "megic")) {
			EditMagic(&pe);
		} else if (!strcmp(argv[2], "entpoint")) {
			EditAddressOfEntryPoint(&pe);
		} else if (!strcmp(argv[2], "imb")) {
			EditImageBase(&pe);
		} else if (!strcmp(argv[2], "salig")) {
			EditSectionAlignment(&pe);
		} else if (!strcmp(argv[2], "falig")) {
			EditFileAlignment(&pe);
		} else if (!strcmp(argv[2], "sizeimg")) {
			EditSizeOfImage(&pe);
		} else if (!strcmp(argv[2], "sizehead")) {
			EditSizeOfHeaders(&pe);
		} else if (!strcmp(argv[2], "subsys")) {
			EditSubsystem(&pe);
		} else if (!strcmp(argv[2], "rvas")) {
			EditNumberOfRvaAndSizes(&pe);
		} else if (!strcmp(argv[2], "sections")) {
			EditTableSection(&pe);
		} else if (!strcmp(argv[2], "datadir")) {
			EditDataDirectory(&pe);
		} else if (!strcmp(argv[2], "reloc1")) {
			EditRelocSizeOfBlockAndVirtualaddress(&pe);
		} else if (!strcmp(argv[2], "reloc2")) {
			EditRelocTypeAndOffset(&pe);
		} else if (!strcmp(argv[2], "reloc3")) {
			EditRelocsShiftAddress(&pe);
		} else if (!strcmp(argv[2], "reloc4")) {
			EditRelocsNewEntryForBlock(&pe);
		} else if (!strcmp(argv[2], "reloc5")) {
			EditRelocsNewEntryForNewBlock(&pe);
		} else if (!strcmp(argv[2], "reloc6")) {
			EditRelocsNewBlock(&pe);
		} else if (!strcmp(argv[2], "import")) {
			EditDescriptorImportTable(&pe);
		} else if (!strcmp(argv[2], "export")) {
			EditDescriptorExportTable(&pe);
		} else if (!strcmp(argv[2], "create")) {
			CreateSection(&pe, 1000);
		} else {
			usage();
		}

		UnloadPeFile(&pe);
	}
	else {
		usage();
	}

	return 0;
}