#pragma warning(disable:4996)
#include"ParsePE.h"




void PeLoad(char* ImageBuffer, char* FileBuffer)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_MY_IMAGE_SECTION_HEADER* sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	::memcpy(ImageBuffer, FileBuffer, nt_ptr->OptionalHeader.SizeOfHeaders);
	for (int i = 0; i < nt_ptr->FileHeader.NumberOfSections; i++)
	{
		::memcpy(ImageBuffer + (sec_ptr + i)->VirtualAddress, FileBuffer + (sec_ptr + i)->PointerToRawData, (sec_ptr + i)->SizeOfRawData);
	}
}

void PeStore(char* NewBuffer, char* ImageBuffer)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)ImageBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(ImageBuffer + dos_head_ptr->e_lfanew);
	_MY_IMAGE_SECTION_HEADER* sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(ImageBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	::memcpy(NewBuffer, ImageBuffer, nt_ptr->OptionalHeader.SizeOfHeaders);
	for (int i = 0; i < nt_ptr->FileHeader.NumberOfSections; i++)
	{
		::memcpy(NewBuffer + (sec_ptr + i)->PointerToRawData, ImageBuffer + (sec_ptr + i)->VirtualAddress, (sec_ptr + i)->SizeOfRawData);
	}
}

void ParsePe(char* arr)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)arr;
	printf("DOS HEAD\n");
	printf("e_magic:2:	%hx\ne_cblp:2:	%hx\ne_cp:2:	%hx\ne_crlc:2:	%hx\n",
		dos_head_ptr->e_magic, dos_head_ptr->e_cblp, dos_head_ptr->e_cp, dos_head_ptr->e_crlc);


	printf("e_cparhdr:%hx\ne_minalloc:%hx\ne_maxalloc:%hx\ne_ss:%hx\n",
		dos_head_ptr->e_cparhdr, dos_head_ptr->e_minalloc, dos_head_ptr->e_maxalloc, dos_head_ptr->e_ss);


	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(arr + dos_head_ptr->e_lfanew);
	printf("\nNT Signature\n");
	printf("Signature:4:	%x\n", nt_ptr->Signature);


	printf("\nFILE HEAD\n");
	printf("%Machine:2:	%hx\nNumberOfSections:2:	%hx\nTimeDateStamp:4:	%x\nPointerToSymbolTable:4:	%x\n",
		nt_ptr->FileHeader.Machine, nt_ptr->FileHeader.NumberOfSections, nt_ptr->FileHeader.TimeDateStamp, nt_ptr->FileHeader.PointerToSymbolTable);

	printf("\nOPTION HEAD\n");
	printf("%Magic:2:	%hx\nMajorLinkerVersion:1:	%hhx\nMinorLinkerVersion:1:	%hhx\nSizeOfCode:4:	%x\n",
		nt_ptr->OptionalHeader.Magic, nt_ptr->OptionalHeader.MajorLinkerVersion, nt_ptr->OptionalHeader.MinorLinkerVersion, nt_ptr->OptionalHeader.SizeOfCode);


}

bool CodeInjectionMode(char* FileBuffer, int Mode)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_MY_IMAGE_SECTION_HEADER* Injection_sec_ptr = First_sec_ptr;


	DWORD CallAddress = 0;
	DWORD JmpAddress = 0;

	if (Mode==DIRECTINJECTION)
	{
		Injection_sec_ptr = First_sec_ptr;
		CallAddress = MESSAGEBOXADDRESS - (nt_ptr->OptionalHeader.ImageBase + Injection_sec_ptr->Misc.VirtualSize + Injection_sec_ptr->VirtualAddress + 8 + 5);
		JmpAddress = nt_ptr->OptionalHeader.AddressOfEntryPoint - (Injection_sec_ptr->Misc.VirtualSize + Injection_sec_ptr->VirtualAddress + 8 + 5 + 5);
	}
	if (Mode == EXPANDLASTSECTION)
	{
		Injection_sec_ptr = Last_sec_ptr;
		CallAddress = MESSAGEBOXADDRESS - (nt_ptr->OptionalHeader.ImageBase + Injection_sec_ptr->Misc.VirtualSize + Injection_sec_ptr->VirtualAddress + 8 + 5);
		JmpAddress = nt_ptr->OptionalHeader.AddressOfEntryPoint - (Injection_sec_ptr->Misc.VirtualSize + Injection_sec_ptr->VirtualAddress + 8 + 5 + 5);
	}
	if (Mode==ADDSECTION)
	{
		Injection_sec_ptr = Last_sec_ptr;
		CallAddress = MESSAGEBOXADDRESS - (nt_ptr->OptionalHeader.ImageBase + Injection_sec_ptr->VirtualAddress + 8 + 5);
		JmpAddress = nt_ptr->OptionalHeader.AddressOfEntryPoint - (Injection_sec_ptr->VirtualAddress + 8 + 5 + 5);
	}
	

	//printf("ssssss:%x	%x\n", CallAddress, JmpAddress);
	BYTE shellcode[18] = { 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,
		0xe8, (BYTE)(CallAddress), (BYTE)(CallAddress >> 8), (BYTE)(CallAddress >> 16), (BYTE)(CallAddress >> 24),
		0xe9, (BYTE)(JmpAddress), (BYTE)(JmpAddress >> 8), (BYTE)(JmpAddress >> 16), (BYTE)(JmpAddress >> 24) };

	if (Mode == DIRECTINJECTION)
	{
		if ((int)(Injection_sec_ptr->SizeOfRawData) - (int)(Injection_sec_ptr->Misc.VirtualSize) < (int)sizeof(shellcode))
		{
			return 0;
		}
		::memcpy(FileBuffer + Injection_sec_ptr->Misc.VirtualSize + Injection_sec_ptr->PointerToRawData, shellcode, sizeof(shellcode));
		nt_ptr->OptionalHeader.AddressOfEntryPoint = Injection_sec_ptr->Misc.VirtualSize + Injection_sec_ptr->VirtualAddress;
	}
	if (Mode == EXPANDLASTSECTION)
	{
		::memcpy(FileBuffer + Injection_sec_ptr->Misc.VirtualSize + Injection_sec_ptr->PointerToRawData, shellcode, sizeof(shellcode));
		nt_ptr->OptionalHeader.AddressOfEntryPoint = Injection_sec_ptr->Misc.VirtualSize + Injection_sec_ptr->VirtualAddress;
	}
	if (Mode == ADDSECTION)
	{
		::memcpy(FileBuffer + Injection_sec_ptr->PointerToRawData, shellcode, sizeof(shellcode));
		nt_ptr->OptionalHeader.AddressOfEntryPoint = Injection_sec_ptr->VirtualAddress;
	}

	Injection_sec_ptr->Characteristics = First_sec_ptr->Characteristics | Injection_sec_ptr->Characteristics;

	printf("代码注入成功。\n");
	return 1;
}

DWORD RvAToFoA(char* FileBuffer, DWORD RvA)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_MY_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

	DWORD FoA = RvA;

	for (int i = 0; i < nt_ptr->FileHeader.NumberOfSections; i++)
	{
		if (RvA >= Curr_sec_ptr->VirtualAddress && RvA <= Curr_sec_ptr->VirtualAddress + Curr_sec_ptr->Misc.VirtualSize)
		{
			FoA = Curr_sec_ptr->PointerToRawData + (RvA - Curr_sec_ptr->VirtualAddress);
			//printf("第%d节,节名:%s\n",i, Curr_sec_ptr->Name);
			break;
		}
		Curr_sec_ptr++;
	}
	return FoA;
}

DWORD FoAToRvA(char* FileBuffer, DWORD FoA)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_MY_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

	DWORD RvA = FoA;

	for (int i = 0; i < nt_ptr->FileHeader.NumberOfSections; i++)
	{
		if (FoA >= Curr_sec_ptr->PointerToRawData && FoA < Curr_sec_ptr->PointerToRawData + Curr_sec_ptr->SizeOfRawData)
		{
			RvA = Curr_sec_ptr->VirtualAddress + (FoA - Curr_sec_ptr->PointerToRawData);
			//printf("第%d节,节名:%s\n", i, Curr_sec_ptr->Name);
			break;
		}
		Curr_sec_ptr++;
	}
	return RvA;
}

char* GetSectionNameByRvA(char* FileBuffer, DWORD RvA)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_MY_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

	for (int i = 0; i < nt_ptr->FileHeader.NumberOfSections; i++)
	{
		if (RvA >= Curr_sec_ptr->VirtualAddress && RvA < Curr_sec_ptr->VirtualAddress + Curr_sec_ptr->Misc.VirtualSize)
		{
			break;
		}
		Curr_sec_ptr++;
	}
	return (char*)Curr_sec_ptr->Name;
}

void DirectInjection(char* fpINname, char* fpOUTname)
{
	printf("正在尝试直接注入...\n");
	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len, fpr);

	//printf("%x\n",RvAToFoA(arr, 0x1090));

	if (!CodeInjectionMode(arr, DIRECTINJECTION))
	{
		printf("原始节空间不足，无法直接注入代码，请尝试增加节数或者扩展最后一节。\n");
		free(arr);
		return;
	}

	FILE* fpw = NULL;
	fpw = fopen(fpOUTname, "wb");
	if (fpw == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_SET);
	::fwrite(arr, 1, len, fpw);

	if (arr != NULL)
	{
		free(arr);
		arr = NULL;
	}


	::fclose(fpr);
	::fclose(fpw);

	printf("存盘成功。\n");
}

bool IsAllZero(_MY_IMAGE_SECTION_HEADER* Post_Of_Last_sec_ptr)
{
	for (int i = 0; i < 2 * 0x28; i++)
	{
		if (*((char*)Post_Of_Last_sec_ptr + i) != 0)
		{
			return 0;
		}
	}
	return 1;
}

void AddSection(char* fpINname, char* fpOUTname, DWORD CodeInjectionFlag)
{
	printf("| /正在尝试增加节数...\n");
	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr) + 4096;
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len - 4096, fpr);

	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)arr;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(arr + dos_head_ptr->e_lfanew);
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(arr + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	int NotAlignmentHeaderSize = dos_head_ptr->e_lfanew + sizeof(_MY_IMAGE_NT_HEADERS) + nt_ptr->FileHeader.NumberOfSections * 0x28;

	_MY_IMAGE_SECTION_HEADER* Add_Sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(arr + NotAlignmentHeaderSize);


	if ((int)nt_ptr->OptionalHeader.SizeOfHeaders - NotAlignmentHeaderSize >= 2 * 0x28 && IsAllZero(Last_sec_ptr + 1))
	{
		memcpy(Add_Sec_ptr->Name, "NewSec", 6);
		Add_Sec_ptr->Misc.VirtualSize = 0x1000;
		Add_Sec_ptr->VirtualAddress = nt_ptr->OptionalHeader.SizeOfImage;
		Add_Sec_ptr->SizeOfRawData = 0x1000;
		Add_Sec_ptr->PointerToRawData = Last_sec_ptr->PointerToRawData + Last_sec_ptr->SizeOfRawData;
		Add_Sec_ptr->PointerToRelocations = 0;
		Add_Sec_ptr->PointerToLinenumbers = 0;
		Add_Sec_ptr->NumberOfRelocations = 0;
		Add_Sec_ptr->NumberOfLinenumbers = 0;
		Add_Sec_ptr->NumberOfLinenumbers = 0;
		Add_Sec_ptr->Characteristics = First_sec_ptr->Characteristics;

		nt_ptr->FileHeader.NumberOfSections++;
		nt_ptr->OptionalHeader.SizeOfImage = nt_ptr->OptionalHeader.SizeOfImage + 0x1000;
	}
	else if (dos_head_ptr->e_lfanew - sizeof(_MY_IMAGE_DOS_) > 0x28)
	{
		char* dst = arr + sizeof(_MY_IMAGE_DOS_);
		char* src = arr + dos_head_ptr->e_lfanew;
		int cpylen = sizeof(_MY_IMAGE_NT_HEADERS) + nt_ptr->FileHeader.NumberOfSections * 0x28;
		memcpy(dst, src, cpylen);
		memset(dst + cpylen, 0, dos_head_ptr->e_lfanew - sizeof(_MY_IMAGE_DOS_));
		dos_head_ptr->e_lfanew = sizeof(_MY_IMAGE_DOS_);
		nt_ptr = (_MY_IMAGE_NT_HEADERS*)(arr + dos_head_ptr->e_lfanew);
		First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(arr + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
		Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
		NotAlignmentHeaderSize = dos_head_ptr->e_lfanew + sizeof(_MY_IMAGE_NT_HEADERS) + nt_ptr->FileHeader.NumberOfSections * 0x28;
		Add_Sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(arr + NotAlignmentHeaderSize);

		memcpy(Add_Sec_ptr->Name, "NewSec", 6);
		Add_Sec_ptr->Misc.VirtualSize = 0x1000;
		Add_Sec_ptr->VirtualAddress = nt_ptr->OptionalHeader.SizeOfImage;
		Add_Sec_ptr->SizeOfRawData = 0x1000;
		Add_Sec_ptr->PointerToRawData = Last_sec_ptr->PointerToRawData + Last_sec_ptr->SizeOfRawData;
		Add_Sec_ptr->PointerToRelocations = 0;
		Add_Sec_ptr->PointerToLinenumbers = 0;
		Add_Sec_ptr->NumberOfRelocations = 0;
		Add_Sec_ptr->NumberOfLinenumbers = 0;
		Add_Sec_ptr->NumberOfLinenumbers = 0;
		Add_Sec_ptr->Characteristics = First_sec_ptr->Characteristics;

		nt_ptr->FileHeader.NumberOfSections++;
		nt_ptr->OptionalHeader.SizeOfImage = nt_ptr->OptionalHeader.SizeOfImage + 0x1000;
	}
	else 
	{
		printf("不满足增加节数的条件，请尝试扩展最后一节。\n");
		free(arr);
		::fclose(fpr);
	}

	Last_sec_ptr++;
	for (int i = 0; i < nt_ptr->FileHeader.NumberOfSections; i++)
	{
		Last_sec_ptr->Characteristics = Last_sec_ptr->Characteristics | (First_sec_ptr + i)->Characteristics;
	}

	if (CodeInjectionFlag)
	{
		CodeInjectionMode(arr,ADDSECTION);
	}

	FILE* fpw = NULL;
	fpw = fopen(fpOUTname, "wb");
	if (fpw == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_SET);
	::fwrite(arr, 1, len, fpw);

	if (arr != NULL)
	{
		free(arr);
		arr = NULL;
	}

	dos_head_ptr = NULL;
	nt_ptr = NULL;

	::fclose(fpr);
	::fclose(fpw);

	printf("| \\存盘成功。\n");

}

void ExpandLastSection(char* fpINname, char* fpOUTname, DWORD CodeInjectionFlag)
{
	printf("正在尝试扩展最后一节...\n");
	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr) + 4096;
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len - 4096, fpr);

	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)arr;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(arr + dos_head_ptr->e_lfanew);
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(arr + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	/*int NotAlignmentHeaderSize = dos_head_ptr->e_lfanew + sizeof(_MY_IMAGE_NT_HEADERS) + nt_ptr->FileHeader.NumberOfSections * 0x28;

	_MY_IMAGE_SECTION_HEADER* Add_Sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(arr + NotAlignmentHeaderSize);*/
	if (CodeInjectionFlag)
	{
		CodeInjectionMode(arr, EXPANDLASTSECTION);
	}

	nt_ptr->OptionalHeader.SizeOfImage += 0x1000;
	Last_sec_ptr->SizeOfRawData += 0x1000;
	Last_sec_ptr->Characteristics = Last_sec_ptr->Characteristics | First_sec_ptr->Characteristics;
	Last_sec_ptr->Misc.VirtualSize += 0x1000;


	FILE* fpw = NULL;
	fpw = fopen(fpOUTname, "wb");
	if (fpw == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_SET);
	::fwrite(arr, 1, len, fpw);

	if (arr != NULL)
	{
		free(arr);
		arr = NULL;
	}

	dos_head_ptr = NULL;
	nt_ptr = NULL;

	::fclose(fpr);
	::fclose(fpw);

	printf("存盘成功。\n");

}

DWORD GetFunAddress(char* FileBuffer, char* Func)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_EXPORT_DIRECTORY* Export_Directory_Address = (_IMAGE_EXPORT_DIRECTORY*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[0].VirtualAddress));	
	
	DWORD* AddressOfNamesTable = (DWORD*)( FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfNames));
	WORD* AddressOfNameOrdinalsTable = (WORD*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfNameOrdinals));;
	DWORD* AddressOfFunctionsTable = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfFunctions));
	/*printf("0x18da9:%x  AddressOfNames:%x  AddressOfNameOrdinals:%x  AddressOfFunctions:%x\n", RvAToFoA(FileBuffer, 0x262610),
		RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfNames), 
		RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfNameOrdinals),
		RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfFunctions));
	*/

	if (HIWORD((DWORD)Func) == 0)
	{
		return (DWORD)*(AddressOfFunctionsTable + ((DWORD)Func - Export_Directory_Address->Base));
	}
	else
	{
		char* Name = "pantaifeng";
		for (int i = 0; i < Export_Directory_Address->NumberOfNames; i++)
		{
			Name = (char*)(FileBuffer + RvAToFoA(FileBuffer, (*(AddressOfNamesTable + i))));
			if (strcmp(Name, Func) == 0)
			{
				return (DWORD)*(AddressOfFunctionsTable + *(AddressOfNameOrdinalsTable + i));
			}
		}
	}
	
	return 0;
}

bool IsEndOfBaseRelocationTable(IMAGE_BASE_RELOCATION* Relocation_Table_Ptr)
{
	if (Relocation_Table_Ptr->VirtualAddress==0 && Relocation_Table_Ptr->SizeOfBlock==0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


typedef void(*LPFunc)(char* FileBuffer, DWORD RelocDataRvA);

void ModifyBaseAddress(char* FileBuffer, DWORD RelocDataRvA)
{
	*(DWORD*)(FileBuffer + RvAToFoA(FileBuffer, RelocDataRvA)) -= 0x30000000;
	*(DWORD*)(FileBuffer + RvAToFoA(FileBuffer, RelocDataRvA)) += 0x10000000;
}

void GetBaseRelocation(char* FileBuffer, DWORD Mode)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	IMAGE_BASE_RELOCATION* Base_Relocation_Address = (IMAGE_BASE_RELOCATION*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[5].VirtualAddress));
	WORD* Relocation_Table_Ptr = (WORD*)Base_Relocation_Address;
	DWORD RelocDataRvA = 0;
	if (Mode == PRINTBASERELOCATIONTABLE)
	{
		printf("index	section	RvA	FoA	type\n");
	}
	while (!IsEndOfBaseRelocationTable((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr))
	{
		for (int i=0; i< (((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->SizeOfBlock-8)/2; i++)
		{
			RelocDataRvA = ((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->VirtualAddress + (*(Relocation_Table_Ptr + 4 + i) & 0x0FFF);
			if (*(Relocation_Table_Ptr + 4 + i) >> 12==0)
			{
				continue;
			}
			if (Mode == MODIFYBASEADDRESS)
			{
				ModifyBaseAddress(FileBuffer, RelocDataRvA);
				continue;
			}
			printf("%d	%s	%x	%x	HIGHLOW[%d]\n", i + 1, GetSectionNameByRvA(FileBuffer, RelocDataRvA), RelocDataRvA, RvAToFoA(FileBuffer, RelocDataRvA), *(Relocation_Table_Ptr + 4 + i) >> 12);
		}
		Relocation_Table_Ptr = (WORD*)((DWORD)Relocation_Table_Ptr + ((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->SizeOfBlock);
	}
}

void MoveExportDirectoryTable(char* FileBuffer)
{
	printf("| /正在尝试移动导出表...\n");

	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_EXPORT_DIRECTORY* Export_Directory_Address = (_IMAGE_EXPORT_DIRECTORY*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[0].VirtualAddress));
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_MY_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;
	DWORD* AddressOfNamesTable = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfNames));
	WORD* AddressOfNameOrdinalsTable = (WORD*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfNameOrdinals));;
	DWORD* AddressOfFunctionsTable = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfFunctions));

	char* Dst = FileBuffer + Last_sec_ptr->PointerToRawData;
	char* Src = (char*)AddressOfFunctionsTable;
	DWORD CpyLen = 4 * Export_Directory_Address->NumberOfFunctions;
	memcpy(Dst, Src, CpyLen);
	DWORD* NewAddressOfFunctionsTable = (DWORD*)Dst;

	Dst = Dst + CpyLen;
	Src = (char*)AddressOfNameOrdinalsTable;
	CpyLen = 2 * Export_Directory_Address->NumberOfFunctions;
	memcpy(Dst, Src, CpyLen);
	DWORD* NewAddressOfNameOrdinalsTable = (DWORD*)Dst;

	Dst = Dst + CpyLen;
	Src = (char*)AddressOfNamesTable;
	CpyLen = 4 * Export_Directory_Address->NumberOfNames;
	memcpy(Dst, Src, CpyLen);
	DWORD* NewAddressOfNamesTable = (DWORD*)Dst;

	char* Name = "pantaifeng";
	for (int i = 0; i < Export_Directory_Address->NumberOfNames; i++)
	{
		Dst = Dst + CpyLen;
		Name = (char*)(FileBuffer + RvAToFoA(FileBuffer, (*(AddressOfNamesTable + i))));
		CpyLen = strlen(Name)+1;
		memcpy(Dst, Name, CpyLen);
		*(NewAddressOfNamesTable + i) = *(AddressOfNamesTable + i);
	}

	Dst = Dst + CpyLen;
	Src = (char*)Export_Directory_Address;
	CpyLen = sizeof(_IMAGE_EXPORT_DIRECTORY);
	memcpy(Dst, Src, CpyLen);
	_IMAGE_EXPORT_DIRECTORY* New_Export_Directory_Address = (_IMAGE_EXPORT_DIRECTORY*)Dst;

	New_Export_Directory_Address->AddressOfFunctions = FoAToRvA(FileBuffer, (char*)NewAddressOfFunctionsTable - FileBuffer);
	New_Export_Directory_Address->AddressOfNameOrdinals = FoAToRvA(FileBuffer, (char*)NewAddressOfNameOrdinalsTable - FileBuffer);
	New_Export_Directory_Address->AddressOfNames = FoAToRvA(FileBuffer, (char*)NewAddressOfNamesTable - FileBuffer);

	nt_ptr->OptionalHeader.DataDirectory[0].VirtualAddress = FoAToRvA(FileBuffer, Dst-FileBuffer);

	printf("| \\导出表移动成功\n");
}

void MoveBaseRelocationTable(char* FileBuffer)
{
	printf("| /正在尝试移动重定位表...\n");


	printf("| \\导出表移动成功\n");
	return;
}

extern bool IsEndOfImportDescriptor(_IMAGE_IMPORT_DESCRIPTOR* Import_Descriptor_Address);
void MoveImportTable(char* FileBuffer)
{
	printf("| /正在尝试移动导入表...\n");

	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_IMPORT_DESCRIPTOR* Import_Descriptor_Address = (_IMAGE_IMPORT_DESCRIPTOR*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[1].VirtualAddress));
	
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_MY_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

	_IMAGE_IMPORT_DESCRIPTOR* Curr_Import_Descriptor_Address = Import_Descriptor_Address;
	DWORD* OriginalFirstThunkPtr;
	DWORD* FirstThunkPtr;

	char* Dst = FileBuffer + Last_sec_ptr->PointerToRawData;
	char* Src = (char*)Curr_Import_Descriptor_Address;
	DWORD CpyLen = 0;

	while (!IsEndOfImportDescriptor(Curr_Import_Descriptor_Address))
	{
		Dst = Dst + CpyLen;
		Src = (char*)Curr_Import_Descriptor_Address;
		CpyLen = sizeof(_IMAGE_IMPORT_DESCRIPTOR);
		memcpy(Dst, Src, CpyLen);
		Curr_Import_Descriptor_Address++;
	}
	_IMAGE_IMPORT_DESCRIPTOR* Add_Import_Descriptor_Address = (_IMAGE_IMPORT_DESCRIPTOR*)(Dst + CpyLen);
	//Add_Import_Descriptor_Address->Characteristics = 0x0;
	DWORD Foa = (DWORD)((char*)Add_Import_Descriptor_Address +
		2 * sizeof(_IMAGE_IMPORT_DESCRIPTOR) + 2 * sizeof(_IMAGE_THUNK_DATA32) - FileBuffer);
	Add_Import_Descriptor_Address->OriginalFirstThunk = FoAToRvA(FileBuffer, Foa);
	Add_Import_Descriptor_Address->TimeDateStamp = 0;
	Add_Import_Descriptor_Address->ForwarderChain = 0x0;
	Foa = (DWORD)((char*)Add_Import_Descriptor_Address +
		2*sizeof(_IMAGE_IMPORT_DESCRIPTOR) + 4*sizeof(_IMAGE_THUNK_DATA32) - FileBuffer);
	Add_Import_Descriptor_Address->Name = FoAToRvA(FileBuffer, Foa);
	Foa = (DWORD)((char*)Add_Import_Descriptor_Address + 
		2*sizeof(_IMAGE_IMPORT_DESCRIPTOR) + 2*sizeof(_IMAGE_THUNK_DATA32) - FileBuffer);
	Add_Import_Descriptor_Address->FirstThunk = FoAToRvA(FileBuffer, Foa);
	memset((char*)Add_Import_Descriptor_Address+sizeof(_IMAGE_IMPORT_DESCRIPTOR),0,sizeof(_IMAGE_IMPORT_DESCRIPTOR));

	_IMAGE_THUNK_DATA32 * Add_Image_Thunk_DataO = 
		(_IMAGE_THUNK_DATA32 *)(Add_Import_Descriptor_Address + 2);
	Foa = (DWORD)((char*)Add_Image_Thunk_DataO + 4 * sizeof(_IMAGE_THUNK_DATA32) + strlen("Dll1.dll") + 1 - FileBuffer);
	Add_Image_Thunk_DataO->u1.AddressOfData = FoAToRvA(FileBuffer, Foa);
	memset((char*)Add_Image_Thunk_DataO + sizeof(_IMAGE_THUNK_DATA32), 0, sizeof(_IMAGE_THUNK_DATA32));

	_IMAGE_THUNK_DATA32 * Add_Image_Thunk_Data = 
		(_IMAGE_THUNK_DATA32 *)((char*)Add_Import_Descriptor_Address + 2*sizeof(_IMAGE_IMPORT_DESCRIPTOR) + 2*sizeof(_IMAGE_THUNK_DATA32));
	Foa = (DWORD)((char*)Add_Image_Thunk_Data + 2*sizeof(_IMAGE_THUNK_DATA32) + strlen("Dll1.dll") + 1 - FileBuffer);
	Add_Image_Thunk_Data->u1.AddressOfData = FoAToRvA(FileBuffer, Foa);
	memset((char*)Add_Image_Thunk_Data + sizeof(_IMAGE_THUNK_DATA32), 0, sizeof(_IMAGE_THUNK_DATA32));

	Dst = (char*)(Add_Image_Thunk_Data + 2);
	Src = "Dll1.dll";
	CpyLen = strlen("Dll1.dll") + 1;
	memcpy(Dst, Src, CpyLen);

	_IMAGE_IMPORT_BY_NAME* Add_Image_Import_By_Name = (_IMAGE_IMPORT_BY_NAME*)(Dst + CpyLen);
	Add_Image_Import_By_Name->Hint = 0x0;
	memcpy(Add_Image_Import_By_Name->Name, "MyAdd", strlen("MyAdd")+1);
	Add_Image_Import_By_Name->Name[0] = 'M';

	nt_ptr->OptionalHeader.DataDirectory[1].VirtualAddress = FoAToRvA(FileBuffer, Last_sec_ptr->PointerToRawData);
	

	printf("| \\导入表移动成功\n");
}

void MoveTable(char* fpINname, char* fpOUTname, DWORD WhichTable)
{
	printf(" /准备移表...\n");

	AddSection(fpINname, fpOUTname, 0);

	FILE* fpr = NULL;
	fpr = fopen(fpOUTname, "r+b");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len, fpr);

	if (WhichTable == ExportTable)
	{
		MoveExportDirectoryTable(arr);
	}
	if (WhichTable == RelocationTable)
	{
		MoveBaseRelocationTable(arr);
	}
	if (WhichTable == IMPORTTABLE)
	{
		MoveImportTable(arr);
	}

	fseek(fpr, 0, SEEK_SET);
	::fwrite(arr, 1, len, fpr);

	if (arr != NULL)
	{
		free(arr);
		arr = NULL;
	}

	::fclose(fpr);
	printf(" \\移表成功\n");
}

void ManualRelocation(char* fpINname, char* fpOUTname)
{
	printf("正在进行重定位...\n");
	FILE* fpr = NULL;
	fpr = fopen(fpINname, "r+b");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len, fpr);

	GetBaseRelocation(arr, MODIFYBASEADDRESS);

	fseek(fpr, 0, SEEK_SET);
	::fwrite(arr, 1, len, fpr);

	if (arr != NULL)
	{
		free(arr);
		arr = NULL;
	}

	::fclose(fpr);
	printf("重定位完成\n");
}

bool IsEndOfImportDescriptor(_IMAGE_IMPORT_DESCRIPTOR* Import_Descriptor_Address)
{
	if (Import_Descriptor_Address->Characteristics==0&& Import_Descriptor_Address->FirstThunk==0&& Import_Descriptor_Address->ForwarderChain==0
		&& Import_Descriptor_Address->Name==0&& Import_Descriptor_Address->OriginalFirstThunk==0&& Import_Descriptor_Address->TimeDateStamp==0)
	{
		return 1;
	}
	return 0;
}

bool IsEndOfFirstThunk(DWORD* FirstThunkPtr)
{
	if (*(FirstThunkPtr)==0)
	{
		return 1;
	}
	return 0;
}

void PrintImportTable(char* FileBuffer)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_IMPORT_DESCRIPTOR* Import_Descriptor_Address = (_IMAGE_IMPORT_DESCRIPTOR*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[1].VirtualAddress));
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_MY_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

	_IMAGE_IMPORT_DESCRIPTOR* Curr_Import_Descriptor_Address = Import_Descriptor_Address;
	DWORD* OriginalFirstThunkPtr;
	DWORD* FirstThunkPtr;

	while (!IsEndOfImportDescriptor(Curr_Import_Descriptor_Address))
	{
		if (Curr_Import_Descriptor_Address->OriginalFirstThunk)
		{
			printf("\nOriginalFirstThunkPtr--TimeDateStamp: %x\n", Curr_Import_Descriptor_Address->TimeDateStamp);
			printf("DLL name: %s\n", (FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->Name)));
			OriginalFirstThunkPtr = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->OriginalFirstThunk));
			while (!IsEndOfFirstThunk(OriginalFirstThunkPtr))
			{
				if (*OriginalFirstThunkPtr & 0x80000000)
				{
					printf("	%d\n", *OriginalFirstThunkPtr & 0xFFFF);
				}
				else
				{
					printf("	%s\n", ((_IMAGE_IMPORT_BY_NAME*)(FileBuffer + RvAToFoA(FileBuffer, *OriginalFirstThunkPtr)))->Name);
				}
				OriginalFirstThunkPtr++;
			}
		}
		else if(!Curr_Import_Descriptor_Address->TimeDateStamp)
		{
			printf("\nFirstThunkPtr--TimeDateStamp: %x\n", Curr_Import_Descriptor_Address->TimeDateStamp);
			printf("DLL name: %s\n", (FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->Name)));
			FirstThunkPtr = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->FirstThunk));
			while (!IsEndOfFirstThunk(FirstThunkPtr))
			{
				if (*FirstThunkPtr & 0x80000000)
				{
					printf("	%d\n", *FirstThunkPtr & 0xFFFF);
				}
				else
				{
					printf("	%s\n", ((_IMAGE_IMPORT_BY_NAME*)(FileBuffer + RvAToFoA(FileBuffer, *FirstThunkPtr)))->Name);
				}
				FirstThunkPtr++;
			}
		}
		else
		{
			printf("\nFirstThunkPtr--TimeDateStamp: %x\n", Curr_Import_Descriptor_Address->TimeDateStamp);
			printf("DLL name: %s\n", (FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->Name)));
			FirstThunkPtr = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->FirstThunk));
			while (!IsEndOfFirstThunk(FirstThunkPtr))
			{
				printf("	%x\n", *FirstThunkPtr);
				FirstThunkPtr++;
			}
		}

		Curr_Import_Descriptor_Address++;
	}
}

void PrintResourceType(DWORD Name, char* ResBase)
{
	if ((Name&0x80000000) == 0)//按位操作&的优先级特别低，索引必须加上()
	{
		switch (Name)
		{
		case 0x01:
			printf("光标(Cursor)\n");
			break;
		case 0x02:
			printf("位图(Bitmap)\n");
			break;
		case 0x03:
			printf("图标(Icon)\n");
			break;
		case 0x04:
			printf("菜单(Menu)\n");
			break;
		case 0x05:
			printf("对话框(Dialog)\n");
			break;
		case 0x06:
			printf("字符串(String)\n");
			break;
		case 0x07:
			printf("字体目录(Font Directory)\n");
			break;
		case 0x08:
			printf("字体(Font)\n");
			break;
		case 0x09:
			printf("加速键(Accelerators)\n");
			break;
		case 0x0a:
			printf("未格式化资源(Unformatted)\n");
			break;
		case 0x0b:
			printf("消息表(MessageTable)\n");
			break;
		case 0x0c:
			printf("光标组(Group Cursor)\n");
			break;
		case 0x0e:
			printf("图标组(Group Icon)\n");
			break;
		case 0x10:
			printf("版本信息(Version Information)\n");
			break;
		}
	}
	else
	{
		IMAGE_RESOURCE_DIR_STRING_U* res_dir_str_ptr = (IMAGE_RESOURCE_DIR_STRING_U*)(ResBase + (Name & 0x7FFFFFFF));
		wchar_t NameString[0x40] = { 0 };
		wmemcpy(NameString, res_dir_str_ptr->NameString, res_dir_str_ptr->Length);
		wprintf(L"NameString:%s\n", NameString);
	}
	
}

void PrintResourceNameOrId(DWORD Name, char* ResBase)
{
	if ((Name & 0x80000000) == 0)
	{
		printf("	%d\n", Name);
	}
	else
	{
		IMAGE_RESOURCE_DIR_STRING_U* res_dir_str_ptr = (IMAGE_RESOURCE_DIR_STRING_U*)(ResBase + (Name & 0x7FFFFFFF));
		wchar_t NameString[0x40] = { 0 };
		wmemcpy(NameString, res_dir_str_ptr->NameString, res_dir_str_ptr->Length);
		wprintf(L"	%s\n", NameString);
	}
}

void PrintRsrcTable(char* FileBuffer)
{
	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_RESOURCE_DIRECTORY* ResourceDirectory_Ptr = (_IMAGE_RESOURCE_DIRECTORY*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[2].VirtualAddress));
	_MY_IMAGE_SECTION_HEADER* First_sec_ptr = (_MY_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_MY_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_MY_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_MY_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

	_IMAGE_RESOURCE_DIRECTORY* First_ResourceDirectory_Ptr = ResourceDirectory_Ptr;
	IMAGE_RESOURCE_DIRECTORY_ENTRY* First_ResourceDirectoryEntry_Ptr = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((char*)First_ResourceDirectory_Ptr + sizeof(_IMAGE_RESOURCE_DIRECTORY));
	DWORD FirstCount = First_ResourceDirectory_Ptr->NumberOfIdEntries + First_ResourceDirectory_Ptr->NumberOfNamedEntries;
	
	_IMAGE_RESOURCE_DIRECTORY* Second_ResourceDirectory_Ptr = NULL;
	IMAGE_RESOURCE_DIRECTORY_ENTRY* Second_ResourceDirectoryEntry_Ptr = NULL;
	DWORD SecondCount = 0;

	_IMAGE_RESOURCE_DIRECTORY* Third_ResourceDirectory_Ptr = NULL;
	IMAGE_RESOURCE_DIRECTORY_ENTRY* Third_ResourceDirectoryEntry_Ptr = NULL;
	DWORD ThirdCount = 0;

	TCHAR NameString[0x20] = { 0 };
	IMAGE_RESOURCE_DATA_ENTRY* res_data_entry_ptr = NULL;
	for (int i=0;i< FirstCount;i++)
	{
		PrintResourceType(First_ResourceDirectoryEntry_Ptr->Name, (char*)ResourceDirectory_Ptr);

		Second_ResourceDirectory_Ptr = (_IMAGE_RESOURCE_DIRECTORY*)((char*)ResourceDirectory_Ptr + First_ResourceDirectoryEntry_Ptr->OffsetToDirectory);
		Second_ResourceDirectoryEntry_Ptr = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((char*)Second_ResourceDirectory_Ptr + sizeof(_IMAGE_RESOURCE_DIRECTORY));
		SecondCount = Second_ResourceDirectory_Ptr->NumberOfIdEntries + Second_ResourceDirectory_Ptr->NumberOfNamedEntries;
		for (int j=0;j< SecondCount;j++)
		{

			Third_ResourceDirectory_Ptr = (_IMAGE_RESOURCE_DIRECTORY*)((char*)ResourceDirectory_Ptr + Second_ResourceDirectoryEntry_Ptr->OffsetToDirectory);
			Third_ResourceDirectoryEntry_Ptr = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((char*)Third_ResourceDirectory_Ptr + sizeof(_IMAGE_RESOURCE_DIRECTORY));
			ThirdCount = Third_ResourceDirectory_Ptr->NumberOfIdEntries + Third_ResourceDirectory_Ptr->NumberOfNamedEntries;
			for (int k=0;k<ThirdCount;k++)
			{
				res_data_entry_ptr = (IMAGE_RESOURCE_DATA_ENTRY*)((char*)ResourceDirectory_Ptr + Third_ResourceDirectoryEntry_Ptr->OffsetToDirectory);
				PrintResourceNameOrId(Second_ResourceDirectoryEntry_Ptr->Name, (char*)ResourceDirectory_Ptr);
				printf("	RVA:%x	Size:%x\n\n", res_data_entry_ptr->OffsetToData, res_data_entry_ptr->Size);
				Third_ResourceDirectoryEntry_Ptr++;
			}
			Second_ResourceDirectoryEntry_Ptr++;
		}
		First_ResourceDirectoryEntry_Ptr++;
	}
}

void test17()
{
	/*char* fpINname = "C:\\Users\\86139\\Desktop\\SocketTool.exe";
	char* fpOUTname = "C:\\Users\\86139\\Desktop\\SocketTool - 副本.exe";*/

	char* fpINname = "E:\\真空实验室\\ReadPE.exe";
	char* fpOUTname = "E:\\真空实验室\\ReadPE2.exe";

	//char* fpINname = "E:\\真空实验室\\JQTools_V18.1.28.exe";
	//char* fpOUTname = "E:\\真空实验室\\JQTools_V18.1.282.exe";

	//DirectInjection(fpINname, fpOUTname);
	AddSection(fpINname, fpOUTname, 1);
	//ExpandLastSection(fpINname, fpOUTname, 1);

}

typedef int(*LPMyAdd)(int a, int b);
typedef int(*LPMySub)(int a, int b);
typedef int(*LPMyMul)(int a, int b);
typedef float(*LPMyDiv)(float a, float b);

void test18()
{
	LPMyAdd PMyAdd;
	LPMySub PMySub;
	LPMyMul PMyMul;
	LPMyDiv PMyDiv;

	HINSTANCE HMode = LoadLibrary("C:\\Users\\86139\\Desktop\\Dllx1.dll");
	printf("HMode:%x\n",HMode);
	PMyAdd = (LPMyAdd)GetProcAddress(HMode, "MyAdd");
	PMySub = (LPMySub)GetProcAddress(HMode, "MySub");
	PMyMul = (LPMyMul)GetProcAddress(HMode, "MyMul");
	PMyDiv = (LPMyDiv)GetProcAddress(HMode, "MyDiv");


	printf("MyAdd:	%d\n", PMyAdd(2,3));
	printf("MyAdd:	%d\n", PMySub(2,3));
	printf("MyAdd:	%d\n", PMyMul(2,3));
	printf("MyAdd:	%f\n", PMyDiv(2,3));

	FreeLibrary(HMode);
	return;
}

void test19()
{
	char* fpINname = "C:\\Users\\86139\\Desktop\\Dll2.dll";

	LPMyAdd PMyAdd;
	LPMySub PMySub;
	LPMyMul PMyMul;
	LPMyDiv PMyDiv;

	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len, fpr);

	printf("AddressOfMyAdd:	%x\n", GetFunAddress(arr, "MyAdd"));
	printf("AddressOfMySub:	%x\n", GetFunAddress(arr, "MySub"));
	printf("AddressOfMyMul:	%x\n", GetFunAddress(arr, "MyMul"));
	printf("AddressOfMyDiv:	%x\n", GetFunAddress(arr, "MyDiv"));

	printf("%u\n", (DWORD)(char*)0);
	printf("%u\n", (DWORD)(char*)1);
	printf("%u\n", (DWORD)(char*)2);
	printf("%u\n", (DWORD)(char*)3);

	::fclose(fpr);
	return;
}

void test20()
{
	char* fpINname = "C:\\Users\\86139\\Desktop\\Dll1.dll";
	
	LPMyAdd PMyAdd;
	LPMySub PMySub;
	LPMyMul PMyMul;
	LPMyDiv PMyDiv;

	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len, fpr);

	printf("\n");
	GetBaseRelocation(arr, PRINTBASERELOCATIONTABLE);

	::fclose(fpr);
	
	return;
}

void test21()
{
	
	//char* fpINname = "E:\\真空实验室\\SocketTool.exe";
	//char* fpOUTname = "E:\\真空实验室\\SocketTool2.exe";
	//char* fpINname = "E:\\真空实验室\\PETool 1.0.0.5.exe";
	//char* fpOUTname = "E:\\真空实验室\\PETool 1.0.0.52.exe";
	//char* fpINname = "E:\\真空实验室\\ReadPE.exe";
	//char* fpOUTname = "E:\\真空实验室\\ReadPE2.exe";
	char* fpINname = "E:\\真空实验室\\JQTools_V18.1.28.exe";
	char* fpOUTname = "E:\\真空实验室\\JQTools_V18.1.282.exe";
	if (_access(fpOUTname, 0)==0)
	{
		//system("del E:\\真空实验室\\SocketTool2.exe");
		//system("del E:\\真空实验室\\PETool 1.0.0.52.exe");
		//system("del E:\\真空实验室\\ReadPE2.exe");
	}
	MoveTable(fpINname, fpOUTname, IMPORTTABLE);
}

void test22()
{
	char* fpINname = "C:\\Users\\86139\\Desktop\\Dllx1.dll";
	char* fpOUTname = "C:\\Users\\86139\\Desktop\\Dllx2.dll";
	ManualRelocation(fpINname, fpOUTname);
}

void test23()
{
	//char* fpINname = "C:\\Users\\86139\\Desktop\\JQTools_V18.1.28.exe";
	//char* fpINname = "C:\\Users\\86139\\Desktop\\SocketTool.exe";
	//char* fpINname = "C:\\Users\\86139\\Desktop\\PETool 1.0.0.5.exe";
	//char* fpINname = "C:\\Users\\86139\\Desktop\\ReadPE.exe";
	//char* fpINname = "E:\\真空实验室\\ReadPE2.exe";
	char* fpINname = "E:\\真空实验室\\PETool 1.0.0.52.exe";
	//char* fpINname = "E:\\真空实验室\\SocketTool2.exe";
	/*
	64位系统本来就有两个记事本！C:\Windows\System32\notepad.exe这个是64位，
	C:\Windows\SysWOW64\calc.exe这是32位。
	（不要搞反了，没写错，就是这样，SysWOW64里面存放32位兼容文件。）
	https://zhidao.baidu.com/question/420926825.html
	*/

	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len, fpr);

	printf("正在打印%s的导入表...\n", fpINname);
	PrintImportTable(arr);
	printf("\n%s的导入表打印成功.\n", fpINname);

	if (arr != NULL)
	{
		free(arr);
		arr = NULL;
	}

	::fclose(fpr);
}

void test24()
{
	//char* fpINname = "E:\\真空实验室\\Dialog.exe";
	char* fpINname = "C:\\Users\\86139\\Desktop\\SocketTool.exe";
	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		printf("打开文件失败\n");
		return;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	char* arr = (char*)malloc(len);
	if (!arr)
	{
		printf("arr分配失败\n");
		return;
	}
	::memset(arr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(arr, sizeof(char), len, fpr);

	printf("正在打印%s的资源表...\n", fpINname);
	PrintRsrcTable(arr);
	printf("\n%s的资源表打印成功.\n", fpINname);

	if (arr != NULL)
	{
		free(arr);
		arr = NULL;
	}

	::fclose(fpr);

}
