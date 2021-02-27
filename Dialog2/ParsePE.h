#include<stdio.h>
#include<windows.h>
#include<typeinfo>
#include<iostream>
#include<io.h>
#include <tchar.h>

#define DIRECTINJECTION 1
#define ADDSECTION 2
#define EXPANDLASTSECTION 3
#define MERGESECTION 4

#define ExportTable 1
#define RelocationTable 2
#define IMPORTTABLE 3

#define PRINTBASERELOCATIONTABLE 1
#define MODIFYBASEADDRESS 2

#define MESSAGEBOXADDRESS 0x76FE0C30

typedef struct _MY_IMAGE_DOS_
{  // DOS .EXE header
// offset: 0H
	WORD  e_magic;                // Magic number
	// offset: 2H
	WORD   e_cblp;                 // Bytes on last page of file
	// offset: 4H
	WORD  e_cp;                   // Pages infile
	// offset: 6H
	WORD   e_crlc;                 // Relocations
	// offset: 8H
	WORD  e_cparhdr;             // Size of header in paragraphs
	// offset: AH
	WORD  e_minalloc;            // Minimumextra paragraphs needed
	// offset: CH
	WORD  e_maxalloc;            // Maximumextra paragraphs needed
	// offset: EH
	WORD  e_ss;                   // Initial(relative) SS value
	// offset: 10H
	WORD  e_sp;                   // Initial SPvalue
	// offset: 12H
	WORD   e_csum;                 // Checksum
	// offset: 14h
	WORD  e_ip;                   // Initial IPvalue
	// offset: 16H
	WORD  e_cs;                   // Initial(relative) CS value
	// offset: 18H
	WORD  e_lfarlc;              // File address of relocation table
	// offset: 1AH
	WORD  e_ovno;                // Overlaynumber
	// offset: 1CH
	WORD  e_res[4];              // Reservedwords
	// offset: 24H
	WORD  e_oemid;               // OEMidentifier (for e_oeminfo)
	// offset: 26H
	WORD  e_oeminfo;             // OEMinformation; e_oemid specific
	// offset: 28H
	WORD  e_res2[10];            // Reservedwords
	// offset: 3CH
	LONG   e_lfanew;              // File address of new exe header
}MY_IMAGE_DOS_HEADER, *MY_PIMAGE_DOS_HEADER;

typedef struct _MY_IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD  NumberOfSymbols;
	WORD   SizeOfOptionalHeader;
	WORD   Characteristics;
}MY_IMAGE_FILE_HEADER, *MY_PIMAGE_FILE_HEADER;

typedef struct _MY_IMAGE_OPTIONAL_HEADER {
	// 必选部分
	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;
	// 可选部分
	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} MY_IMAGE_OPTIONAL_HEADER32, *MY_PIMAGE_OPTIONAL_HEADER32;

typedef struct _MY_IMAGE_NT_HEADERS {
	// offset: 0H
	DWORD Signature;
	// offset: 4H
	MY_IMAGE_FILE_HEADER FileHeader;
	// offset: 18H
	MY_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} MY_IMAGE_NT_HEADERS32, *MY_PIMAGE_NT_HEADERS32;

typedef struct _MY_IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]; //8个字节名字.自己可以起.编译器也可以给定.不重要.
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;           //节数据没有对齐后的大小.也就是没有对齐.节数据有多大.
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} MY_IMAGE_SECTION_HEADER, *MY_PIMAGE_SECTION_HEADER;


typedef void(*LPFunc)(char* FileBuffer, DWORD RelocDataRvA);


void PeLoad(char* ImageBuffer, char* FileBuffer);
void PeStore(char* NewBuffer, char* ImageBuffer);
void ParsePe(char* arr);
bool CodeInjectionMode(char* FileBuffer, int Mode);
DWORD RvAToFoA(char* FileBuffer, DWORD RvA);
DWORD FoAToRvA(char* FileBuffer, DWORD FoA);
char* GetSectionNameByRvA(char* FileBuffer, DWORD RvA);
void DirectInjection(char* fpINname, char* fpOUTname);
bool IsAllZero(_MY_IMAGE_SECTION_HEADER* Post_Of_Last_sec_ptr);
void AddSection(char* fpINname, char* fpOUTname, DWORD CodeInjectionFlag);
void ExpandLastSection(char* fpINname, char* fpOUTname, DWORD CodeInjectionFlag);
DWORD GetFunAddress(char* FileBuffer, char* Func);
bool IsEndOfBaseRelocationTable(IMAGE_BASE_RELOCATION* Relocation_Table_Ptr);

void ModifyBaseAddress(char* FileBuffer, DWORD RelocDataRvA);
void GetBaseRelocation(char* FileBuffer, DWORD Mode);
void MoveExportDirectoryTable(char* FileBuffer);
void MoveBaseRelocationTable(char* FileBuffer);
void MoveImportTable(char* FileBuffer);
void MoveTable(char* fpINname, char* fpOUTname, DWORD WhichTable);
void ManualRelocation(char* fpINname, char* fpOUTname);
bool IsEndOfImportDescriptor(_IMAGE_IMPORT_DESCRIPTOR* Import_Descriptor_Address);
void PrintImportTable(char* FileBuffer);
void PrintResourceType(DWORD Name, char* ResBase);
void PrintResourceNameOrId(DWORD Name, char* ResBase);
void PrintRsrcTable(char* FileBuffer);




