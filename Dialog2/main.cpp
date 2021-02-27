#include <Windows.h>
#include <tchar.h>
#include "resource.h"
#include <commctrl.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include "ParsePE.h"


#pragma comment(lib,"comctl32.lib")	
#pragma warning(disable : 4996)

/**************************************宏定义*********************************************/
#define PARSEOPTHEADER 1 
#define PARSECONTENT 2 
#define ENUMSECTION 3
#define PARSEEXPORTTABLE 4
#define PARSEIMPORTTABLE_UP 5
#define PARSEIMPORTTABLE_DOWN 6
#define ADDSECTION 7
#define PASTETARGET 8


/****************************************************************************************/


/**************************************全局变量*******************************************/
HINSTANCE g_hInstance = 0;
char* ImageArr = NULL;
char* ImageArrShell = NULL;
char* ImageArrTarget = NULL;
char* ImageArrTargetEncryption = NULL;
DWORD ImageArrShell_size = 0;
DWORD ImageArrTarget_size = 0;
char InputName[0x20];



/****************************************************************************************/


/**************************************变量申明*******************************************/
extern char szFileName[MAX_PATH];
/****************************************************************************************/

/**************************************函数申明*******************************************/
void OpenFileFunction(char* fpINname, HWND hDlg, DWORD FLAG);
bool IsEndOfFirstThunk(DWORD* FirstThunkPtr);
bool IsEndOfImportDescriptor(_IMAGE_IMPORT_DESCRIPTOR* Import_Descriptor_Address);
void ChooseMode(char* arr, HWND hDlg, DWORD FLAG);
//void ParseImportTable(char* FileBuffer, HWND hDlg);
void ParseImportTable(HWND hListImportDown, HWND hListImportUp);

/****************************************************************************************/

DWORD RvAToFoA(char* FileBuffer, DWORD RvA)
{
	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)FileBuffer;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_SECTION_HEADER* First_sec_ptr = (_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

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
	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)FileBuffer;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_SECTION_HEADER* First_sec_ptr = (_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

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


bool IsEndOfImportDescriptor(_IMAGE_IMPORT_DESCRIPTOR* Import_Descriptor_Address)
{
	if (Import_Descriptor_Address->Characteristics == 0 && Import_Descriptor_Address->FirstThunk == 0 && Import_Descriptor_Address->ForwarderChain == 0
		&& Import_Descriptor_Address->Name == 0 && Import_Descriptor_Address->OriginalFirstThunk == 0 && Import_Descriptor_Address->TimeDateStamp == 0)
	{
		return 1;
	}
	return 0;
}


bool IsEndOfFirstThunk(DWORD* FirstThunkPtr)
{
	if (*(FirstThunkPtr) == 0)
	{
		return 1;
	}
	return 0;
}


bool IsEndOfBaseRelocationTable(IMAGE_BASE_RELOCATION* Relocation_Table_Ptr)
{
	if (Relocation_Table_Ptr->VirtualAddress == 0 && Relocation_Table_Ptr->SizeOfBlock == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


char* GetSectionNameByRvA(char* FileBuffer, DWORD RvA)
{
	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)FileBuffer;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_SECTION_HEADER* First_sec_ptr = (_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

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


BOOL EnumProcess(HWND hListProc)
{
	ListView_DeleteAllItems(hListProc);

	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;
	int i = 0;
	TCHAR szPID[10] = { 0 };


	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		MessageBox(hListProc, _T("INVALID_HANDLE_VALUE"), _T("tip"), 48);
		return 0;
	}
	PROCESSENTRY32 pi = { 0 };
	pi.dwSize = sizeof(PROCESSENTRY32); //第一次使用必须初始化成员
	BOOL bRet = Process32First(hSnapshot, &pi);
	while (bRet)
	{
		lv.pszText = (LPSTR)pi.szExeFile;
		lv.iItem = i;
		lv.iSubItem = 0;
		SendMessage(hListProc, LVM_INSERTITEM, 0, (DWORD)&lv);


		sprintf(szPID, "%d", pi.th32ProcessID);
		lv.pszText = (LPSTR)szPID;
		lv.iItem = i;
		lv.iSubItem = 1;
		SendMessage(hListProc, LVM_SETITEM, 1, (DWORD)&lv);
		//ListView_SetItem(hListProc, &lv);

		HANDLE hSnapshot_Modu = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pi.th32ProcessID);
		if (INVALID_HANDLE_VALUE != hSnapshot_Modu)
		{
			MODULEENTRY32  mo = { 0 };
			mo.dwSize = sizeof(MODULEENTRY32); //第一次使用必须初始化成员
			Module32First(hSnapshot_Modu, &mo);

			char* BaseAddr = (char*)malloc(0x20);
			memset(BaseAddr, 0, 0x20);
			sprintf(BaseAddr, "0x%08X", mo.modBaseAddr);
			lv.pszText = (LPSTR)BaseAddr;
			lv.iItem = i;
			lv.iSubItem = 2;
			SendMessage(hListProc, LVM_SETITEM, 2, (DWORD)&lv);
			//ListView_SetItem(hListProc, &lv);
			free(BaseAddr);
			memset(BaseAddr, 0, 0x20);

			char BaseSize[0x20] = { 0 };
			sprintf(BaseSize, "0x%08X", mo.modBaseSize);
			lv.pszText = BaseSize;
			lv.iItem = i;
			lv.iSubItem = 3;
			SendMessage(hListProc, LVM_SETITEM, 3, (DWORD)&lv);
			//ListView_SetItem(hListProc, &lv);

			CloseHandle(hSnapshot_Modu);
		}
		i++;
		bRet = Process32Next(hSnapshot, &pi);
	}
	CloseHandle(hSnapshot);

	return 1;
	
}

BOOL EnumModule(HWND hListModu, HWND hListProc)
{
	ListView_DeleteAllItems(hListModu);

	LV_ITEM _lv_;
	memset(&_lv_, 0, sizeof(LV_ITEM));

	TCHAR pid[0x20];
	memset(pid, 0, 0x20);

	DWORD rowId = ::SendMessage(hListProc, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	_lv_.iSubItem = 1;
	_lv_.pszText = pid;
	_lv_.cchTextMax = 0x20;
	::SendMessage(hListProc, LVM_GETITEMTEXT, rowId, (DWORD)&_lv_);
	
	DWORD dwPid;
	sscanf(pid, "%d", &dwPid);

	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;
	int i = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		MessageBox(hListModu, _T("INVALID_HANDLE_VALUE"), _T("tip"), 48);
		return 0;
	}
	MODULEENTRY32  mo = { 0 };
	mo.dwSize = sizeof(MODULEENTRY32); //第一次使用必须初始化成员
	BOOL bRet = Module32First(hSnapshot, &mo);
	while (bRet)
	{
		lv.pszText = (LPSTR)mo.szModule;
		lv.iItem = i;
		lv.iSubItem = 0;
		SendMessage(hListModu, LVM_INSERTITEM, 0, (DWORD)&lv);


		lv.pszText = (LPSTR)mo.szExePath;
		lv.iItem = i;
		lv.iSubItem = 1;
		SendMessage(hListModu, LVM_SETITEM, 1, (DWORD)&lv);

		i++;
		bRet = Module32Next(hSnapshot, &mo);
	}
	CloseHandle(hSnapshot);

	return 1;

}

DWORD WINAPI ThreadFunc(LPVOID hListProc)
{
	while (1)
	{
		EnumProcess((HWND)hListProc);
		Sleep(15000);
	}
}

void InitProcessView(HWND hDlg)
{

	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));
	HWND hListProc = GetDlgItem(hDlg, IDC_LIST_PROCESS);

	SendMessage(hListProc, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lv.pszText = (LPSTR)TEXT("进程");
	lv.cx = 140;
	lv.iSubItem = 0;
	SendMessage(hListProc, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("PID");
	lv.cx = 120;
	lv.iSubItem = 1;
	SendMessage(hListProc, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("基址");
	lv.cx = 120;
	lv.iSubItem = 2;
	SendMessage(hListProc, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

	lv.pszText = (LPSTR)TEXT("大小");
	lv.cx = 120;
	lv.iSubItem = 3;
	SendMessage(hListProc, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

	HANDLE hThread = CreateThread(NULL, 0, ThreadFunc, (LPVOID)hListProc, 0, NULL);
	CloseHandle(hThread);
}

void InitModuleView(HWND hDlg)
{
	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));
	HWND hListModu = GetDlgItem(hDlg, IDC_LIST_MODULE);

	SendMessage(hListModu, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lv.pszText = (LPSTR)TEXT("模块名");
	lv.cx = 180;
	lv.iSubItem = 0;
	SendMessage(hListModu, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("模块位置");
	lv.cx = 300;
	lv.iSubItem = 1;
	SendMessage(hListModu, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

}

BOOL EnumSection(char* FileBuffer, HWND hDlg)
{
	HWND hListSection = GetDlgItem(hDlg, IDC_LIST_SECTION);
	ListView_DeleteAllItems(hListSection);

	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;
	
	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)FileBuffer;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	IMAGE_FILE_HEADER* header_ptr = &(nt_ptr->FileHeader);
	_IMAGE_SECTION_HEADER* First_sec_ptr = (_IMAGE_SECTION_HEADER*)(FileBuffer + dos_head_ptr->e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_IMAGE_SECTION_HEADER* Curr_sec_ptr = First_sec_ptr;

	char TempArr[0x14] = { 0 };
	int i = 0;

	for (int i=0; i<header_ptr->NumberOfSections; i++)
	{
		lv.pszText = (LPSTR)Curr_sec_ptr->Name;
		lv.iItem = i;
		lv.iSubItem = 0;
		SendMessage(hListSection, LVM_INSERTITEM, 0, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_sec_ptr->VirtualAddress);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 1;
		SendMessage(hListSection, LVM_SETITEM, 1, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_sec_ptr->Misc);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 2;
		SendMessage(hListSection, LVM_SETITEM, 2, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_sec_ptr->PointerToRawData);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 3;
		SendMessage(hListSection, LVM_SETITEM, 3, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_sec_ptr->SizeOfRawData);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 4;
		SendMessage(hListSection, LVM_SETITEM, 4, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_sec_ptr->Characteristics);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 5;
		SendMessage(hListSection, LVM_SETITEM, 5, (DWORD)&lv);

		Curr_sec_ptr++;

	}

	return 1;

}

void InitSectionView(HWND hDlg)
{

	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));
	HWND hListSection = GetDlgItem(hDlg, IDC_LIST_SECTION);

	SendMessage(hListSection, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lv.pszText = (LPSTR)TEXT("名称");
	lv.cx = 100;
	lv.iSubItem = 0;
	SendMessage(hListSection, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("VOffset");
	lv.cx = 100;
	lv.iSubItem = 1;
	SendMessage(hListSection, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("VSize");
	lv.cx = 100;
	lv.iSubItem = 2;
	SendMessage(hListSection, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

	lv.pszText = (LPSTR)TEXT("ROffset");
	lv.cx = 100;
	lv.iSubItem = 3;
	SendMessage(hListSection, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("RSize");
	lv.cx = 100;
	lv.iSubItem = 4;
	SendMessage(hListSection, LVM_INSERTCOLUMN, 4, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("标志");
	lv.cx = 100;
	lv.iSubItem = 5;
	SendMessage(hListSection, LVM_INSERTCOLUMN, 5, (DWORD)&lv);

	//OpenFileFunction(szFileName, hDlg, ENUMSECTION);
	ChooseMode(ImageArr, hDlg, ENUMSECTION);

}

void InitImportViewUp(HWND hDlg)
{

	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));
	HWND hListImport = GetDlgItem(hDlg, IDC_LIST_IMPORTTABLE_UP);

	SendMessage(hListImport, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lv.pszText = (LPSTR)TEXT("DllName");
	lv.cx = 120;
	lv.iSubItem = 0;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("OriginalFirstThunk");
	lv.cx = 100;
	lv.iSubItem = 1;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("TimeDateStamp");
	lv.cx = 100;
	lv.iSubItem = 2;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

	lv.pszText = (LPSTR)TEXT("ForwarderChain");
	lv.cx = 100;
	lv.iSubItem = 3;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
	
	lv.pszText = (LPSTR)TEXT("Name(RVA)");
	lv.cx = 100;
	lv.iSubItem = 4;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 4, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

	lv.pszText = (LPSTR)TEXT("FirstThunk");
	lv.cx = 100;
	lv.iSubItem = 5;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 5, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("附加信息");
	lv.cx = 100;
	lv.iSubItem = 6;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 6, (DWORD)&lv);
	
	
	//OpenFileFunction(szFileName, hDlg, PARSEIMPORTTABLE_UP);
	ChooseMode(ImageArr, hDlg, PARSEIMPORTTABLE_UP);
}


void InitImportViewDown(HWND hDlg)
{

	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));
	HWND hListImport = GetDlgItem(hDlg, IDC_LIST_IMPORTTABLE_DOWN);

	SendMessage(hListImport, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lv.pszText = (LPSTR)TEXT("ThunkRVA");
	lv.cx = 120;
	lv.iSubItem = 0;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("ThunkOffset");
	lv.cx = 120;
	lv.iSubItem = 1;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("ThunkValue");
	lv.cx = 120;
	lv.iSubItem = 2;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

	lv.pszText = (LPSTR)TEXT("Hint");
	lv.cx = 80;
	lv.iSubItem = 3;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("ApiName");
	lv.cx = 180;
	lv.iSubItem = 4;
	SendMessage(hListImport, LVM_INSERTCOLUMN, 4, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

}


BOOL EnumReLocateUp(char* FileBuffer, HWND hDlg)
{
	HWND hListReLocateUp = GetDlgItem(hDlg, IDC_LIST_RELOCATETABLE_UP);
	ListView_DeleteAllItems(hListReLocateUp);

	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;

	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)FileBuffer;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	IMAGE_BASE_RELOCATION* Base_Relocation_Address = (IMAGE_BASE_RELOCATION*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[5].VirtualAddress));
	
	if (nt_ptr->OptionalHeader.DataDirectory[5].VirtualAddress == 0)
	{
		MessageBox(hDlg, _T("没有重定位表!"), _T("ERROR"), 48);
		EndDialog(hDlg, 0);
		return 0;
	}

	WORD* Relocation_Table_Ptr = (WORD*)Base_Relocation_Address;
	DWORD RelocRvA = 0;
	char TempArr[0x20] = { 0 };
	int i = 0;

	while (!IsEndOfBaseRelocationTable((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr))
	{
		RelocRvA = ((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->VirtualAddress;
			
		sprintf(TempArr, "%d", i+1);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 0;
		SendMessage(hListReLocateUp, LVM_INSERTITEM, 0, (DWORD)&lv);

		sprintf(TempArr, "%s", GetSectionNameByRvA(FileBuffer, RelocRvA));
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 1;
		SendMessage(hListReLocateUp, LVM_SETITEM, 1, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", RelocRvA);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 2;
		SendMessage(hListReLocateUp, LVM_SETITEM, 2, (DWORD)&lv);

		sprintf(TempArr, "%X[H] / %d[D]", ((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->SizeOfBlock, ((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->SizeOfBlock);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 3;
		SendMessage(hListReLocateUp, LVM_SETITEM, 3, (DWORD)&lv);

		sprintf(TempArr, "%08X", Relocation_Table_Ptr);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 4;
		SendMessage(hListReLocateUp, LVM_SETITEM, 4, (DWORD)&lv);

		Relocation_Table_Ptr = (WORD*)((DWORD)Relocation_Table_Ptr + ((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->SizeOfBlock);
		i++;
	}
	return 1;
}

void InitReLocateViewUp(HWND hDlg)
{

	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));
	HWND hListReLocateUp = GetDlgItem(hDlg, IDC_LIST_RELOCATETABLE_UP);

	SendMessage(hListReLocateUp, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lv.pszText = (LPSTR)TEXT("Index");
	lv.cx = 60;
	lv.iSubItem = 0;
	SendMessage(hListReLocateUp, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("Section");
	lv.cx = 100;
	lv.iSubItem = 1;
	SendMessage(hListReLocateUp, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("RVA");
	lv.cx = 100;
	lv.iSubItem = 2;
	SendMessage(hListReLocateUp, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

	lv.pszText = (LPSTR)TEXT("Items");
	lv.cx = 100;
	lv.iSubItem = 3;
	SendMessage(hListReLocateUp, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("附加信息");
	lv.cx = 100;
	lv.iSubItem = 4;
	SendMessage(hListReLocateUp, LVM_INSERTCOLUMN, 4, (DWORD)&lv);
	//ChooseMode(ImageArr, hDlg, PARSERELOCATE_UP);
	EnumReLocateUp(ImageArr, hDlg);
}

void InitReLocateViewDown(HWND hDlg)
{

	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));
	HWND hListReLocateDowm = GetDlgItem(hDlg, IDC_LIST_RELOCATETABLE_DOWN);

	SendMessage(hListReLocateDowm, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lv.pszText = (LPSTR)TEXT("Index");
	lv.cx = 60;
	lv.iSubItem = 0;
	SendMessage(hListReLocateDowm, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("RVA");
	lv.cx = 100;
	lv.iSubItem = 1;
	SendMessage(hListReLocateDowm, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("Offset");
	lv.cx = 100;
	lv.iSubItem = 2;
	SendMessage(hListReLocateDowm, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

	lv.pszText = (LPSTR)TEXT("Type");
	lv.cx = 100;
	lv.iSubItem = 3;
	SendMessage(hListReLocateDowm, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("Far Address");
	lv.cx = 100;
	lv.iSubItem = 4;
	SendMessage(hListReLocateDowm, LVM_INSERTCOLUMN, 4, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("Data Inperpretation");
	lv.cx = 100;
	lv.iSubItem = 5;
	SendMessage(hListReLocateDowm, LVM_INSERTCOLUMN, 5, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

}

BOOL CALLBACK dialogproc_Section(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		InitSectionView(hDlg);
		
		return 1;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_SECTION_EXIT:
			EndDialog(hDlg, 0);
			return 1;
		}
		return 1;
	case WM_NOTIFY:

		return 1;
	}
	return 0;
}

BOOL CALLBACK dialogproc_ExportTable(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		//OpenFileFunction(szFileName, hDlg, PARSEEXPORTTABLE);
		ChooseMode(ImageArr, hDlg, PARSEEXPORTTABLE);
		return 1;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_EXPORTTABLE_EXIT:
			EndDialog(hDlg, 0);
			return 1;
		}
		return 1;
	case WM_NOTIFY:

		return 1;
	}
	return 0;
}

BOOL CALLBACK dialogproc_ImportTable(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		InitImportViewUp(hDlg);
		InitImportViewDown(hDlg);
		return 1;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_IMPORTTABLE_EXIT:
			EndDialog(hDlg, 0);
			return 1;
		}
		return 1;
	case WM_NOTIFY:
		NMHDR* pNmhdr = (NMHDR*)lParam;
		if (wParam == IDC_LIST_IMPORTTABLE_UP && pNmhdr->code == NM_CLICK)
		{
			//OpenFileFunction(szFileName, hDlg, PARSEIMPORTTABLE_DOWN);
			//ChooseMode(ImageArr, hDlg, PARSEIMPORTTABLE_DOWN);
			//ParseImportTable(ImageArr, hDlg);
			ParseImportTable(GetDlgItem(hDlg, IDC_LIST_IMPORTTABLE_DOWN), GetDlgItem(hDlg, IDC_LIST_IMPORTTABLE_UP));
		}
		return 1;
	}
	return 0;
}

void ParseReLocateDown(HWND hListReLocateDown, HWND hListReLocateUp)
{
	char* FileBuffer = ImageArr;

	LV_ITEM _lv_;
	memset(&_lv_, 0, sizeof(LV_ITEM));

	TCHAR Base_Relocation_Address[0x20];
	memset(Base_Relocation_Address, 0, 0x20);

	DWORD rowId = ::SendMessage(hListReLocateUp, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	_lv_.iSubItem = 4;
	_lv_.pszText = Base_Relocation_Address;
	_lv_.cchTextMax = 0x20;
	::SendMessage(hListReLocateUp, LVM_GETITEMTEXT, rowId, (DWORD)&_lv_);

	DWORD BaseAddress;
	sscanf(Base_Relocation_Address, "%X", &BaseAddress);

	WORD* Relocation_Table_Ptr = (WORD*)BaseAddress;
	DWORD RelocDataRvA = 0;


	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;
	char TempArr[0x28] = { 0 };

	ListView_DeleteAllItems(hListReLocateDown);
	for (int i = 0; i < (((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->SizeOfBlock - 8) / 2; i++)
	{
		RelocDataRvA = ((IMAGE_BASE_RELOCATION*)Relocation_Table_Ptr)->VirtualAddress + (*(Relocation_Table_Ptr + 4 + i) & 0x0FFF);
		if (*(Relocation_Table_Ptr + 4 + i) >> 12 == 0)
		{
			sprintf(TempArr, "%d", i + 1);
			lv.pszText = TempArr;
			lv.iItem = i;
			lv.iSubItem = 0;
			SendMessage(hListReLocateDown, LVM_INSERTITEM, 0, (DWORD)&lv);

			lv.pszText = (LPSTR)"-";
			lv.iItem = i;
			lv.iSubItem = 1;
			SendMessage(hListReLocateDown, LVM_SETITEM, 1, (DWORD)&lv);

			lv.pszText = (LPSTR)"-";
			lv.iItem = i;
			lv.iSubItem = 2;
			SendMessage(hListReLocateDown, LVM_SETITEM, 2, (DWORD)&lv);

			sprintf(TempArr, "ABSOLUTE[%d]", *(Relocation_Table_Ptr + 4 + i) >> 12);
			lv.pszText = TempArr;
			lv.iItem = i;
			lv.iSubItem = 3;
			SendMessage(hListReLocateDown, LVM_SETITEM, 3, (DWORD)&lv);

			lv.pszText = (LPSTR)"-";
			lv.iItem = i;
			lv.iSubItem = 4;
			SendMessage(hListReLocateDown, LVM_SETITEM, 4, (DWORD)&lv);

			lv.pszText = (LPSTR)"-";
			lv.iItem = i;
			lv.iSubItem = 5;
			SendMessage(hListReLocateDown, LVM_SETITEM, 5, (DWORD)&lv);
		}
		else
		{
			sprintf(TempArr, "%d", i + 1);
			lv.pszText = TempArr;
			lv.iItem = i;
			lv.iSubItem = 0;
			SendMessage(hListReLocateDown, LVM_INSERTITEM, 0, (DWORD)&lv);

			sprintf(TempArr, "0x%08X", RelocDataRvA);
			lv.pszText = TempArr;
			lv.iItem = i;
			lv.iSubItem = 1;
			SendMessage(hListReLocateDown, LVM_SETITEM, 1, (DWORD)&lv);

			sprintf(TempArr, "0x%08X", RvAToFoA(FileBuffer, RelocDataRvA));
			lv.pszText = TempArr;
			lv.iItem = i;
			lv.iSubItem = 2;
			SendMessage(hListReLocateDown, LVM_SETITEM, 2, (DWORD)&lv);

			sprintf(TempArr, "HIGHLOW[%d]", *(Relocation_Table_Ptr + 4 + i) >> 12);
			lv.pszText = TempArr;
			lv.iItem = i;
			lv.iSubItem = 3;
			SendMessage(hListReLocateDown, LVM_SETITEM, 3, (DWORD)&lv);

			sprintf(TempArr, "0x%08X", *(DWORD*)(FileBuffer + RvAToFoA(FileBuffer, RelocDataRvA)));
			lv.pszText = TempArr;
			lv.iItem = i;
			lv.iSubItem = 4;
			SendMessage(hListReLocateDown, LVM_SETITEM, 4, (DWORD)&lv);

			sprintf(TempArr, "%s", "-");
			lv.pszText = TempArr;
			lv.iItem = i;
			lv.iSubItem = 5;
			SendMessage(hListReLocateDown, LVM_SETITEM, 5, (DWORD)&lv);
		}
	}
}

BOOL CALLBACK dialogproc_ReLocate(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		InitReLocateViewUp(hDlg);
		InitReLocateViewDown(hDlg);
		return 1;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_RELOCATETABLE_EXIT:
			EndDialog(hDlg, 0);
			return 1;
		}
		return 1;
	case WM_NOTIFY:
		NMHDR* pNmhdr = (NMHDR*)lParam;
		if (wParam == IDC_LIST_RELOCATETABLE_UP && pNmhdr->code == NM_CLICK)
		{
			//OpenFileFunction(szFileName, hDlg, PARSEIMPORTTABLE_DOWN);
			//ChooseMode(ImageArr, hDlg, PARSEIMPORTTABLE_DOWN);
			//ParseImportTable(ImageArr, hDlg);
			//ParseImportTable(GetDlgItem(hDlg, IDC_LIST_IMPORTTABLE_DOWN), GetDlgItem(hDlg, IDC_LIST_IMPORTTABLE_UP));
			ParseReLocateDown(GetDlgItem(hDlg, IDC_LIST_RELOCATETABLE_DOWN), GetDlgItem(hDlg, IDC_LIST_RELOCATETABLE_UP));
		}
		return 1;
	}
	return 0;
}

BOOL CALLBACK dialogproc_Content(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		//OpenFileFunction(szFileName, hDlg, PARSECONTENT);
		ChooseMode(ImageArr, hDlg, PARSECONTENT);
		return 1;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND://today
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_CONTENT_EXPORT:
			DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_EXPORTTABLE), hDlg, dialogproc_ExportTable);
			return 1;
		case IDC_BUTTON_CONTENT_IMPORT:
			DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_IMPORTTABLE), hDlg, dialogproc_ImportTable);
			return 1;
		case IDC_BUTTON_CONTENT_RESOURCE:

			return 1;
		case IDC_BUTTON_CONTENT_RELOCATE:
			DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_RELOCATETABLE), hDlg, dialogproc_ReLocate);
			return 1;
		case IDC_BUTTON_CONTENT_DEBUG:

			return 1;
		case IDC_BUTTON_CONTENT_COPYRIGHT:

			return 1;
		case IDC_BUTTON_CONTENT_TLS:

			return 1;
		case IDC_BUTTON_CONTENT_IMPORTRANGE:

			return 1;
		case IDC_BUTTON_CONTENT_COM:

			return 1;
		case IDC_BUTTON_CONTENT_EXIT:
			EndDialog(hDlg, 0);
			return 1;
		}
		return 1;
	case WM_NOTIFY:

		return 1;
	}
	return 0;
}

void ParseOptHeader(char* arr, HWND hDlg)
{
	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)arr;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(arr + dos_head_ptr->e_lfanew);
	IMAGE_FILE_HEADER* header_ptr = &(nt_ptr->FileHeader);
	IMAGE_OPTIONAL_HEADER32* opt_header_ptr = &(nt_ptr->OptionalHeader);

	char TempArr[0x10] = { 0 };
	sprintf(TempArr, "0x%08X", opt_header_ptr->AddressOfEntryPoint);
	SetDlgItemText(hDlg, IDC_EDIT_ENTRYPOINT, TempArr);

	sprintf(TempArr, "0x%08X", opt_header_ptr->ImageBase);
	SetDlgItemText(hDlg, IDC_EDIT_IMAGEBASE, TempArr);

	sprintf(TempArr, "0x%08X", opt_header_ptr->SizeOfImage);
	SetDlgItemText(hDlg, IDC_EDIT_IMAGESIZE, TempArr);

	sprintf(TempArr, "0x%08X", opt_header_ptr->BaseOfCode);
	SetDlgItemText(hDlg, IDC_EDIT_CODEBASE, TempArr);

	sprintf(TempArr, "0x%08X", opt_header_ptr->BaseOfData);
	SetDlgItemText(hDlg, IDC_EDIT_DATABASE, TempArr);

	sprintf(TempArr, "0x%08X", opt_header_ptr->SectionAlignment);
	SetDlgItemText(hDlg, IDC_EDIT_RAWALIGNMENT, TempArr);

	sprintf(TempArr, "0x%08X", opt_header_ptr->FileAlignment);
	SetDlgItemText(hDlg, IDC_EDIT_FILEALIGEMENT, TempArr);

	sprintf(TempArr, "0x%04X", opt_header_ptr->Magic);
	SetDlgItemText(hDlg, IDC_EDIT_FLAG, TempArr);

	sprintf(TempArr, "0x%04X", opt_header_ptr->Subsystem);
	SetDlgItemText(hDlg, IDC_EDIT_SUBSYSTEM, TempArr);

	sprintf(TempArr, "0x%04X", header_ptr->NumberOfSections);
	SetDlgItemText(hDlg, IDC_EDIT_SECTIONNUM, TempArr);

	sprintf(TempArr, "0x%08X", header_ptr->TimeDateStamp);//
	SetDlgItemText(hDlg, IDC_EDIT_TIMEFLAG, TempArr);

	sprintf(TempArr, "0x%08X", opt_header_ptr->SizeOfHeaders);
	SetDlgItemText(hDlg, IDC_EDIT_HEADERSIZE, TempArr);

	sprintf(TempArr, "0x%04X", header_ptr->Characteristics);
	SetDlgItemText(hDlg, IDC_EDIT_CHARACTERISTIC, TempArr);

	sprintf(TempArr, "0x%08X", opt_header_ptr->CheckSum);
	SetDlgItemText(hDlg, IDC_EDIT_CHECKSUM, TempArr);

	sprintf(TempArr, "0x%04X", header_ptr->SizeOfOptionalHeader);
	SetDlgItemText(hDlg, IDC_EDIT_FOPTHEADERSIZE, TempArr);
	
	sprintf(TempArr, "0x%08X", opt_header_ptr->NumberOfRvaAndSizes);
	SetDlgItemText(hDlg, IDC_EDIT_RVANUM, TempArr);
}

void ParseContent(char* FileBuffer, HWND hDlg)
{
	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)FileBuffer;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	IMAGE_FILE_HEADER* header_ptr = &(nt_ptr->FileHeader);
	IMAGE_OPTIONAL_HEADER32* opt_header_ptr = &(nt_ptr->OptionalHeader);

	char TempArr_RVA[0x10] = { 0 };
	char TempArr_Size[0x10] = { 0 };
	
	DWORD TempArr_ID1[0x10] = { IDC_EDIT_EXPORTTABLE , IDC_EDIT_IMPORTTABLE , IDC_EDIT_RESOURCE , IDC_EDIT_EXCEPTION , IDC_EDIT_SECURITY ,
	IDC_EDIT_RELOCATE , IDC_EDIT_DEBUG , IDC_EDIT_COPYRIGHT , IDC_EDIT_GLOBALPOINT , IDC_EDIT_TLSTABLE , IDC_EDIT_LOADCONF, 
	IDC_EDIT_INPUTRANGE , IDC_EDIT_IAT , IDC_EDIT_DELAYEDINPUT , IDC_EDIT_COM , IDC_EDIT_RESERVED };
	
	DWORD TempArr_ID2[0x10] = { IDC_EDIT_EXPORTTABLE2 , IDC_EDIT_IMPORTTABLE2 , IDC_EDIT_RESOURCE2 , IDC_EDIT_EXCEPTION2 , IDC_EDIT_SECURITY2 ,
	IDC_EDIT_RELOCATE2 , IDC_EDIT_DEBUG2 , IDC_EDIT_COPYRIGHT2 , IDC_EDIT_GLOBALPOINT2 , IDC_EDIT_TLSTABLE2 , IDC_EDIT_LOADCONF2,
	IDC_EDIT_INPUTRANGE2 , IDC_EDIT_IAT2 , IDC_EDIT_DELAYEDINPUT2 , IDC_EDIT_COM2 , IDC_EDIT_RESERVED2 };
	for (int i=0;i<16;i++)
	{
		sprintf(TempArr_RVA, "0x%08X", nt_ptr->OptionalHeader.DataDirectory[i].VirtualAddress);
		SetDlgItemText(hDlg, TempArr_ID1[i], TempArr_RVA);
		sprintf(TempArr_Size, "0x%08X", nt_ptr->OptionalHeader.DataDirectory[i].Size);
		SetDlgItemText(hDlg, TempArr_ID2[i], TempArr_Size);
	}
	
}

BOOL EnumExportTable(char* FileBuffer, HWND hListExport)
{
	ListView_DeleteAllItems(hListExport);

	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;

	_MY_IMAGE_DOS_* dos_head_ptr = (_MY_IMAGE_DOS_*)FileBuffer;
	_MY_IMAGE_NT_HEADERS* nt_ptr = (_MY_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_EXPORT_DIRECTORY* Export_Directory_Address = (_IMAGE_EXPORT_DIRECTORY*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[0].VirtualAddress));

	DWORD* AddressOfNamesTable = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfNames));
	WORD* AddressOfNameOrdinalsTable = (WORD*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfNameOrdinals));;
	DWORD* AddressOfFunctionsTable = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->AddressOfFunctions));
	
	char TempArr[0x28] = { 0 };

	for (DWORD i = 0; i < Export_Directory_Address->NumberOfNames; i++)
	{
		sprintf(TempArr, "0x%04X", i);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 0;
		SendMessage(hListExport, LVM_INSERTITEM, 0, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", (DWORD)*(AddressOfFunctionsTable + *(AddressOfNameOrdinalsTable + i)));
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 1;
		SendMessage(hListExport, LVM_SETITEM, 1, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", RvAToFoA(FileBuffer, (DWORD)*(AddressOfFunctionsTable + *(AddressOfNameOrdinalsTable + i))));
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 2;
		SendMessage(hListExport, LVM_SETITEM, 2, (DWORD)&lv);

		sprintf(TempArr, "%s", (char*)(FileBuffer + RvAToFoA(FileBuffer, (*(AddressOfNamesTable + i)))));
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 3;
		SendMessage(hListExport, LVM_SETITEM, 3, (DWORD)&lv);

	}

	return 1;
}//////////

void InitExportTableView(char* FileBuffer, HWND hListExport)
{
	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));

	SendMessage(hListExport, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lv.pszText = (LPSTR)TEXT("Ordinal");
	lv.cx = 100;
	lv.iSubItem = 0;
	SendMessage(hListExport, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("RVA");
	lv.cx = 100;
	lv.iSubItem = 1;
	SendMessage(hListExport, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

	lv.pszText = (LPSTR)TEXT("Offset");
	lv.cx = 100;
	lv.iSubItem = 2;
	SendMessage(hListExport, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//ListView_InsertColumn(hListProc, 2, &lv);

	lv.pszText = (LPSTR)TEXT("Function Name");
	lv.cx = 180;
	lv.iSubItem = 3;
	SendMessage(hListExport, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
	
}

void ParseExportTable(char* FileBuffer, HWND hDlg)
{
	HWND hListExport = GetDlgItem(hDlg, IDC_LIST_EXPORTTABLE);
	InitExportTableView(FileBuffer, hListExport);

	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)FileBuffer;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	IMAGE_FILE_HEADER* header_ptr = &(nt_ptr->FileHeader);
	IMAGE_OPTIONAL_HEADER32* opt_header_ptr = &(nt_ptr->OptionalHeader);
	_IMAGE_EXPORT_DIRECTORY* Export_Directory_Address = (_IMAGE_EXPORT_DIRECTORY*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[0].VirtualAddress));

	if (nt_ptr->OptionalHeader.DataDirectory[0].VirtualAddress == 0)
	{
		MessageBox(hDlg, _T("没有导出表!"), _T("ERROR"), 48);
		EndDialog(hDlg, 0);
		return;
	}

	char TempArr[0x28] = { 0 };

	sprintf(TempArr, "0x%08X", Export_Directory_Address->Base);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_OFFSET, TempArr);

	sprintf(TempArr, "0x%08X", Export_Directory_Address->Characteristics);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_CHARARISTIC, TempArr);

	sprintf(TempArr, "0x%08X", Export_Directory_Address->Base);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_BASE, TempArr);

	sprintf(TempArr, "0x%08X", Export_Directory_Address->Name);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_NAME, TempArr);

	//sprintf(TempArr, "0x%08X", Export_Directory_Address->Name);
	strcpy(TempArr, (char*)(FileBuffer + RvAToFoA(FileBuffer, Export_Directory_Address->Name)));
	SetDlgItemText(hDlg, IDC_EDITEXPORTTABLE_DTRNAME, TempArr);

	sprintf(TempArr, "0x%08X", Export_Directory_Address->NumberOfFunctions);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_FUNCNUM, TempArr);

	sprintf(TempArr, "0x%08X", Export_Directory_Address->NumberOfNames);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_FUNCNAMENUM, TempArr);

	sprintf(TempArr, "0x%08X", Export_Directory_Address->AddressOfFunctions);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_FUNCADDRESS, TempArr);

	sprintf(TempArr, "0x%08X", Export_Directory_Address->AddressOfNames);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_FUNCNAMEADDRESS, TempArr);

	sprintf(TempArr, "0x%08X", Export_Directory_Address->AddressOfNameOrdinals);
	SetDlgItemText(hDlg, IDC_EDIT_EXPORTTABLE_FUNCNAMEORDERADDRESS, TempArr);

	if (Export_Directory_Address->NumberOfNames <= 0)
	{
		MessageBox(hDlg, _T("得不到偏移信息!"), _T("ERROR"), 48);
		return;
	}

	EnumExportTable(FileBuffer, hListExport);
}



void EnumImportTableUp(char* FileBuffer, HWND hDlg)
{
	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)FileBuffer;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(FileBuffer + dos_head_ptr->e_lfanew);
	_IMAGE_IMPORT_DESCRIPTOR* Import_Descriptor_Address = (_IMAGE_IMPORT_DESCRIPTOR*)(FileBuffer + RvAToFoA(FileBuffer, nt_ptr->OptionalHeader.DataDirectory[1].VirtualAddress));
	_IMAGE_IMPORT_DESCRIPTOR* Curr_Import_Descriptor_Address = Import_Descriptor_Address;

	if (nt_ptr->OptionalHeader.DataDirectory[1].VirtualAddress == 0)
	{
		MessageBox(hDlg, _T("没有导入表!"), _T("ERROR"), 48);
		EndDialog(hDlg, 0);
		return;
	}

	HWND hListImport = GetDlgItem(hDlg, IDC_LIST_IMPORTTABLE_UP);
	ListView_DeleteAllItems(hListImport);

	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;
	int i = 0;
	char TempArr[0x40] = { 0 };

	while (!IsEndOfImportDescriptor(Curr_Import_Descriptor_Address))
	{
		sprintf(TempArr, "%s", FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->Name));
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 0;
		SendMessage(hListImport, LVM_INSERTITEM, 0, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_Import_Descriptor_Address->OriginalFirstThunk);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 1;
		SendMessage(hListImport, LVM_SETITEM, 1, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_Import_Descriptor_Address->TimeDateStamp);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 2;
		SendMessage(hListImport, LVM_SETITEM, 2, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_Import_Descriptor_Address->ForwarderChain);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 3;
		SendMessage(hListImport, LVM_SETITEM, 3, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_Import_Descriptor_Address->Name);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 4;
		SendMessage(hListImport, LVM_SETITEM, 4, (DWORD)&lv);

		sprintf(TempArr, "0x%08X", Curr_Import_Descriptor_Address->FirstThunk);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 5;
		SendMessage(hListImport, LVM_SETITEM, 5, (DWORD)&lv);

		sprintf(TempArr, "%X", Curr_Import_Descriptor_Address);
		lv.pszText = TempArr;
		lv.iItem = i;
		lv.iSubItem = 6;
		SendMessage(hListImport, LVM_SETITEM, 6, (DWORD)&lv);

		Curr_Import_Descriptor_Address++;
		i++;
	}
}

struct _IMPORT_
{
	char ThunkRVA[0x10];
	char ThunkOffset[0x10];
	char ThunkValue[0x10];
	char Hint[0x10];
	char ApiName[0x40];
};

void EnumImportTableDown(char* FileBuffer, _IMPORT_* _import_ptr, HWND hListImportDown, int i)
{
	
	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;
	char TempArr[0x28] = { 0 };

	lv.pszText = _import_ptr->ThunkRVA;
	lv.iItem = i;
	lv.iSubItem = 0;
	SendMessage(hListImportDown, LVM_INSERTITEM, 0, (DWORD)&lv);

	lv.pszText = _import_ptr->ThunkOffset;
	lv.iItem = i;
	lv.iSubItem = 1;
	SendMessage(hListImportDown, LVM_SETITEM, 1, (DWORD)&lv);

	lv.pszText = _import_ptr->ThunkValue;
	lv.iItem = i;
	lv.iSubItem = 2;
	SendMessage(hListImportDown, LVM_SETITEM, 2, (DWORD)&lv);

	lv.pszText = _import_ptr->Hint;
	lv.iItem = i;
	lv.iSubItem = 3;
	SendMessage(hListImportDown, LVM_SETITEM, 3, (DWORD)&lv);

	lv.pszText = _import_ptr->ApiName;
	lv.iItem = i;
	lv.iSubItem = 4;
	SendMessage(hListImportDown, LVM_SETITEM, 4, (DWORD)&lv);
}

void ParseImportTable(HWND hListImportDown, HWND hListImportUp)
{
	char* FileBuffer = ImageArr;

	LV_ITEM _lv_;
	memset(&_lv_, 0, sizeof(LV_ITEM));

	TCHAR CurrImportPtr[0x20];
	memset(CurrImportPtr, 0, 0x20);

	DWORD rowId = ::SendMessage(hListImportUp, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	_lv_.iSubItem = 6;
	_lv_.pszText = CurrImportPtr;
	_lv_.cchTextMax = 0x20;
	::SendMessage(hListImportUp, LVM_GETITEMTEXT, rowId, (DWORD)&_lv_);

	DWORD CurrPtr;
	sscanf(CurrImportPtr, "%X", &CurrPtr);

	_IMAGE_IMPORT_DESCRIPTOR* Curr_Import_Descriptor_Address = (_IMAGE_IMPORT_DESCRIPTOR*)CurrPtr;
	DWORD* OriginalFirstThunkPtr;
	DWORD* FirstThunkPtr;
	_IMPORT_ _import_;
	int i = 0;
	
	if (Curr_Import_Descriptor_Address->OriginalFirstThunk)
	{
		ListView_DeleteAllItems(hListImportDown);
		//printf("\nOriginalFirstThunkPtr--TimeDateStamp: %x\n", Curr_Import_Descriptor_Address->TimeDateStamp);
		//printf("DLL name: %s\n", (FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->Name)));
		OriginalFirstThunkPtr = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->OriginalFirstThunk));
		while (!IsEndOfFirstThunk(OriginalFirstThunkPtr))
		{
			if (*OriginalFirstThunkPtr & 0x80000000)
			{
				//printf("	%d\n", *OriginalFirstThunkPtr & 0xFFFF);
				
				sprintf(_import_.ThunkRVA, "0x%08X", Curr_Import_Descriptor_Address->OriginalFirstThunk + 4*i);
				sprintf(_import_.ThunkOffset, "0x%08X", RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->OriginalFirstThunk + 4 * i));
				sprintf(_import_.ThunkValue, "0x%08X", *OriginalFirstThunkPtr); 
				sprintf(_import_.Hint, "%s", "-");
				sprintf(_import_.ApiName, "0x%08X", *OriginalFirstThunkPtr & 0x7FFFFFFF);
				EnumImportTableDown(FileBuffer, &_import_, hListImportDown, i);
			}
			else
			{
				//printf("	%s\n", ((_IMAGE_IMPORT_BY_NAME*)(FileBuffer + RvAToFoA(FileBuffer, *OriginalFirstThunkPtr)))->Name);
				/*现在遍历IAT表无法得到导入函数的实际地址Function ，实际地址只有在真正加载完所需模块后，IAT通过GetProcAddress获得，现在IAT里面存的和INT内容一样，都是指向一个_IMAGE_IMPORT_BY_NAME 结构，
				当然如果是TimeDateStamp为-1时除外*/
				sprintf(_import_.ThunkRVA, "0x%08X", Curr_Import_Descriptor_Address->OriginalFirstThunk + 4*i);//_IMAGE_THUNK_DATA32的RVA
				sprintf(_import_.ThunkOffset, "0x%08X", RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->OriginalFirstThunk + 4 * i));
				sprintf(_import_.ThunkValue, "0x%08X", *OriginalFirstThunkPtr);//_IMAGE_THUNK_DATA32.AddressOfData
				sprintf(_import_.Hint, "0x%04X", ((_IMAGE_IMPORT_BY_NAME*)(FileBuffer + RvAToFoA(FileBuffer, *OriginalFirstThunkPtr)))->Hint);
				sprintf(_import_.ApiName, "%s", ((_IMAGE_IMPORT_BY_NAME*)(FileBuffer + RvAToFoA(FileBuffer, *OriginalFirstThunkPtr)))->Name);
				EnumImportTableDown(FileBuffer, &_import_, hListImportDown, i);

			}
			OriginalFirstThunkPtr++;
			i++;
		}
	}
	else if (!Curr_Import_Descriptor_Address->TimeDateStamp)
	{
		ListView_DeleteAllItems(hListImportDown);
		//printf("\nFirstThunkPtr--TimeDateStamp: %x\n", Curr_Import_Descriptor_Address->TimeDateStamp);
		//printf("DLL name: %s\n", (FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->Name)));
		FirstThunkPtr = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->FirstThunk));
		while (!IsEndOfFirstThunk(FirstThunkPtr))
		{
			if (*FirstThunkPtr & 0x80000000)
			{
				//printf("	%d\n", *FirstThunkPtr & 0xFFFF);
				sprintf(_import_.ThunkRVA, "0x%08X", Curr_Import_Descriptor_Address->FirstThunk + 4*i);
				sprintf(_import_.ThunkOffset, "0x%08X", RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->FirstThunk + 4 * i));
				sprintf(_import_.ThunkValue, "0x%08X", *FirstThunkPtr);
				sprintf(_import_.Hint, "%s", "-");
				sprintf(_import_.ApiName, "0x%08X", *FirstThunkPtr & 0x7FFFFFFF);
				EnumImportTableDown(FileBuffer, &_import_, hListImportDown, i);

			}
			else
			{
				//printf("	%s\n", ((_IMAGE_IMPORT_BY_NAME*)(FileBuffer + RvAToFoA(FileBuffer, *FirstThunkPtr)))->Name);
				sprintf(_import_.ThunkRVA, "0x%08X", Curr_Import_Descriptor_Address->FirstThunk + 4*i);
				sprintf(_import_.ThunkOffset, "0x%08X", RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->FirstThunk + 4 * i));
				sprintf(_import_.ThunkValue, "0x%08X", *FirstThunkPtr);
				sprintf(_import_.Hint, "0x%04X", ((_IMAGE_IMPORT_BY_NAME*)(FileBuffer + RvAToFoA(FileBuffer, *FirstThunkPtr)))->Hint);
				sprintf(_import_.ApiName, "%s", ((_IMAGE_IMPORT_BY_NAME*)(FileBuffer + RvAToFoA(FileBuffer, *FirstThunkPtr)))->Name);
				EnumImportTableDown(FileBuffer, &_import_, hListImportDown, i);

			}
			FirstThunkPtr++;
			i++;
		}
	}
	else
	{
		ListView_DeleteAllItems(hListImportDown);
		//printf("\nFirstThunkPtr--TimeDateStamp: %x\n", Curr_Import_Descriptor_Address->TimeDateStamp);
		//printf("DLL name: %s\n", (FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->Name)));
		FirstThunkPtr = (DWORD*)(FileBuffer + RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->FirstThunk));
		while (!IsEndOfFirstThunk(FirstThunkPtr))
		{
			//printf("	%x\n", *FirstThunkPtr);
			sprintf(_import_.ThunkRVA, "0x%08X", Curr_Import_Descriptor_Address->FirstThunk + 4*i);
			sprintf(_import_.ThunkOffset, "0x%08X", RvAToFoA(FileBuffer, Curr_Import_Descriptor_Address->FirstThunk + 4 * i));
			sprintf(_import_.ThunkValue, "0x%08X", *FirstThunkPtr);
			sprintf(_import_.Hint, "%s", "-");
			sprintf(_import_.Hint, "%s", "-");
			EnumImportTableDown(FileBuffer, &_import_, hListImportDown, i);

			FirstThunkPtr++;
			i++;
		}
	}

}

bool IsAllZeroX(_IMAGE_SECTION_HEADER* Post_Of_Last_sec_ptr)
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

void AddSectionX(char* arr)
{
	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)arr;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(arr + dos_head_ptr->e_lfanew);
	_IMAGE_SECTION_HEADER* First_sec_ptr = (_IMAGE_SECTION_HEADER*)(arr + dos_head_ptr->e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
	int NotAlignmentHeaderSize = dos_head_ptr->e_lfanew + sizeof(_IMAGE_NT_HEADERS) + nt_ptr->FileHeader.NumberOfSections * 0x28;

	_IMAGE_SECTION_HEADER* Add_Sec_ptr = (_IMAGE_SECTION_HEADER*)(arr + NotAlignmentHeaderSize);


	if ((int)nt_ptr->OptionalHeader.SizeOfHeaders - NotAlignmentHeaderSize >= 2 * 0x28 && IsAllZeroX(Last_sec_ptr + 1))
	{
		memcpy(Add_Sec_ptr->Name, "NewSec", 6);
		Add_Sec_ptr->Misc.VirtualSize = ImageArrTarget_size;
		Add_Sec_ptr->VirtualAddress = nt_ptr->OptionalHeader.SizeOfImage;
		Add_Sec_ptr->SizeOfRawData = ImageArrTarget_size;
		Add_Sec_ptr->PointerToRawData = Last_sec_ptr->PointerToRawData + Last_sec_ptr->SizeOfRawData;
		Add_Sec_ptr->PointerToRelocations = 0;
		Add_Sec_ptr->PointerToLinenumbers = 0;
		Add_Sec_ptr->NumberOfRelocations = 0;
		Add_Sec_ptr->NumberOfLinenumbers = 0;
		Add_Sec_ptr->NumberOfLinenumbers = 0;
		Add_Sec_ptr->Characteristics = First_sec_ptr->Characteristics;

		nt_ptr->FileHeader.NumberOfSections++;
		nt_ptr->OptionalHeader.SizeOfImage = nt_ptr->OptionalHeader.SizeOfImage + ImageArrTarget_size;
	}
	else if (dos_head_ptr->e_lfanew - sizeof(_IMAGE_DOS_HEADER) > 0x28)
	{
		char* dst = arr + sizeof(_IMAGE_DOS_HEADER);
		char* src = arr + dos_head_ptr->e_lfanew;
		int cpylen = sizeof(_IMAGE_NT_HEADERS) + nt_ptr->FileHeader.NumberOfSections * 0x28;
		memcpy(dst, src, cpylen);
		memset(dst + cpylen, 0, dos_head_ptr->e_lfanew - sizeof(_IMAGE_DOS_HEADER));
		dos_head_ptr->e_lfanew = sizeof(_IMAGE_DOS_HEADER);
		nt_ptr = (_IMAGE_NT_HEADERS*)(arr + dos_head_ptr->e_lfanew);
		First_sec_ptr = (_IMAGE_SECTION_HEADER*)(arr + dos_head_ptr->e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
		Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;
		NotAlignmentHeaderSize = dos_head_ptr->e_lfanew + sizeof(_IMAGE_NT_HEADERS) + nt_ptr->FileHeader.NumberOfSections * 0x28;
		Add_Sec_ptr = (_IMAGE_SECTION_HEADER*)(arr + NotAlignmentHeaderSize);

		memcpy(Add_Sec_ptr->Name, "NewSec", 6);
		Add_Sec_ptr->Misc.VirtualSize = ImageArrTarget_size;
		Add_Sec_ptr->VirtualAddress = nt_ptr->OptionalHeader.SizeOfImage;
		Add_Sec_ptr->SizeOfRawData = ImageArrTarget_size;
		Add_Sec_ptr->PointerToRawData = Last_sec_ptr->PointerToRawData + Last_sec_ptr->SizeOfRawData;
		Add_Sec_ptr->PointerToRelocations = 0;
		Add_Sec_ptr->PointerToLinenumbers = 0;
		Add_Sec_ptr->NumberOfRelocations = 0;
		Add_Sec_ptr->NumberOfLinenumbers = 0;
		Add_Sec_ptr->NumberOfLinenumbers = 0;
		Add_Sec_ptr->Characteristics = First_sec_ptr->Characteristics;

		nt_ptr->FileHeader.NumberOfSections++;
		nt_ptr->OptionalHeader.SizeOfImage = nt_ptr->OptionalHeader.SizeOfImage + ImageArrTarget_size;
	}
	else
	{
		MessageBox(0,_T("不满足增加节数的条件，请尝试扩展最后一节"), _T("警告:"), 0);
		//free(arr);
	}

	Last_sec_ptr++;
	for (int i = 0; i < nt_ptr->FileHeader.NumberOfSections; i++)
	{
		Last_sec_ptr->Characteristics = Last_sec_ptr->Characteristics | (First_sec_ptr + i)->Characteristics;
	}

}

void EncryptionFun()
{
	for (int i=0;i< ImageArrTarget_size;i++)
	{
		*(ImageArrTargetEncryption + i) = ~*(ImageArrTarget + i);
	}
}

BOOL CALLBACK dialogproc_InputName(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		return 1;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_INPUTNAME_OK:
			GetDlgItemText(hDlg, IDC_EDIT_INPUTNAME, InputName, 0x20);
			EndDialog(hDlg, 0);
			return 1;
		}
		return 1;
	case WM_NOTIFY:

		return 1;
	}
	return 0;
}

void PasteTargetX(HWND hDlg)
{
	DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_INPUTNAME), hDlg, dialogproc_InputName);

	_IMAGE_DOS_HEADER* dos_head_ptr = (_IMAGE_DOS_HEADER*)ImageArrShell;
	_IMAGE_NT_HEADERS* nt_ptr = (_IMAGE_NT_HEADERS*)(ImageArrShell + dos_head_ptr->e_lfanew);
	_IMAGE_SECTION_HEADER* First_sec_ptr = (_IMAGE_SECTION_HEADER*)(ImageArrShell + dos_head_ptr->e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER) + nt_ptr->FileHeader.SizeOfOptionalHeader);
	_IMAGE_SECTION_HEADER* Last_sec_ptr = First_sec_ptr + nt_ptr->FileHeader.NumberOfSections - 1;

	char* Add_Section = ImageArrShell + Last_sec_ptr->PointerToRawData;
	memcpy(Add_Section, ImageArrTargetEncryption, ImageArrTarget_size);
	
	FILE* fpw = NULL;
	fpw = fopen(InputName, "wb");
	if (fpw == NULL)
	{
		MessageBox(0, _T("fpw == NULL"), _T("Tip"), 0);
		//printf("打开文件失败\n");
		return;
	}
	::fwrite(ImageArrShell, 1, ImageArrShell_size, fpw);

	if (ImageArrShell != NULL)
	{
		free(ImageArrShell);
		ImageArrShell = NULL;
	}
	if (ImageArrTargetEncryption != NULL)
	{
		free(ImageArrTargetEncryption);
		ImageArrTargetEncryption = NULL;
	}

	MessageBox(0, _T("加壳完成"),_T("Tip"), 0);
	dos_head_ptr = NULL;
	nt_ptr = NULL;

	::fclose(fpw);
}

void ChooseMode(char* arr, HWND hDlg, DWORD FLAG)
{
	switch (FLAG)
	{
	case PARSEOPTHEADER:
		ParseOptHeader(arr, hDlg);
		break;
	case PARSECONTENT:
		ParseContent(arr, hDlg);
		break;
	case ENUMSECTION:
		EnumSection(arr, hDlg);
		break;
	case PARSEEXPORTTABLE:
		ParseExportTable(arr, hDlg);
		break;
	case PARSEIMPORTTABLE_UP:
		EnumImportTableUp(arr, hDlg);
		break;
	case ADDSECTION:
		AddSectionX(arr);
		break;
	case PASTETARGET:
		PasteTargetX(hDlg);
		break;
	}
}

void OpenFileFunction(char* fpINname, HWND hDlg, DWORD FLAG)
{
	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		//printf("打开文件失败\n");
		return;	
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	ImageArr = (char*)malloc(len);
	if (!ImageArr)
	{
		//printf("arr分配失败\n");
		return;
	}
	::memset(ImageArr, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(ImageArr, sizeof(char), len, fpr);
	
	ChooseMode(ImageArr, hDlg, FLAG);

	::fclose(fpr);
}

int OpenFileFunctionAddShell(char* fpINname, HWND hDlg)
{
	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		MessageBox(0, _T("文件打开失败"), _T("Tip"), 0);
		return -1;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr) + ImageArrTarget_size;
	ImageArrShell_size = len;
	ImageArrShell = (char*)malloc(len);
	if (!ImageArrShell)
	{
		MessageBox(0, _T("ImageArrShell分配失败"), _T("Tip"), 0);
		return -1;
	}
	::memset(ImageArrShell, 0, len);
	fseek(fpr, 0, SEEK_SET);
	fread(ImageArrShell, sizeof(char), len- ImageArrTarget_size, fpr);

	ChooseMode(ImageArrShell, hDlg, ADDSECTION);
	ChooseMode(ImageArrTarget, hDlg, PASTETARGET);

	if (ImageArrShell != NULL)
	{
		free(ImageArrShell);
		ImageArrShell = NULL;
	}
	if (ImageArrTargetEncryption != NULL)
	{
		free(ImageArrTargetEncryption);
		ImageArrTargetEncryption = NULL;
	}

	::fclose(fpr);
	return 0;
}

int OpenFileFunctionAddTarget(char* fpINname, HWND hDlg)
{
	FILE* fpr = NULL;
	fpr = fopen(fpINname, "rb");
	if (fpr == NULL)
	{
		MessageBox(0, _T("文件打开失败"), _T("Tip"), 0);
		return -1;
	}
	fseek(fpr, 0, SEEK_END);
	int len = ftell(fpr);
	ImageArrTarget_size = len;

	ImageArrTarget = (char*)malloc(len);
	if (!ImageArrTarget)
	{
		MessageBox(0, _T("ImageArrTarget分配失败"), _T("Tip"), 0);
		return -1;
	}

	ImageArrTargetEncryption = (char*)malloc(ImageArrTarget_size);
	if (!ImageArrTargetEncryption)
	{
		free(ImageArrTarget);
		ImageArrTarget = NULL;
		MessageBox(0, _T("ImageArrTargetEncryption分配失败"), _T("Tip"), 0);
		return -1;
	}

	::memset(ImageArrTarget, 0, len);
	memset(ImageArrTargetEncryption, 0, ImageArrTarget_size);

	fseek(fpr, 0, SEEK_SET);
	fread(ImageArrTarget, sizeof(char), len, fpr);

	EncryptionFun();

	if (ImageArrTarget != NULL)
	{
		free(ImageArrTarget);
		ImageArrTarget = NULL;
	}
	::fclose(fpr);
	return 0;
}

BOOL CALLBACK dialogproc_PE(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		OpenFileFunction(szFileName, hDlg, PARSEOPTHEADER);
		return 1;

	case WM_CLOSE:
		if (ImageArr != NULL)
		{
		free(ImageArr);
		ImageArr = NULL;
		}
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_SECTION:
			DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_SECTION), hDlg, dialogproc_Section);
			return 1;
		case IDC_BUTTON_CONTENT:
			DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_CONTENT), hDlg, dialogproc_Content);
			return 1;
		case IDC_BUTTON_PE_EXIT:
			if (ImageArr != NULL)
			{
				free(ImageArr);
				ImageArr = NULL;
			}
			EndDialog(hDlg, 0);
			return 1;
		}
		return 1;
	case WM_NOTIFY:
		
		return 1;
	}
	return 0;
}

char szFileName[MAX_PATH] = { 0 };

BOOL CALLBACK dialogproc_ADDSHELL(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static int Warning = 0;

	OPENFILENAME openFileName = { 0 };
	switch (uMsg)
	{
	case WM_INITDIALOG:
		return 1;

	case WM_CLOSE:
		Warning = 0;
		if (ImageArr != NULL)
		{
			free(ImageArr);
			ImageArr = NULL;
		}
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_TARGETCODE:
			Warning = 1;

			openFileName.lStructSize = sizeof(OPENFILENAME);
			openFileName.nMaxFile = MAX_PATH;  //这个必须设置，不设置的话不会出现打开文件对话框 
			openFileName.lpstrFilter = "*.exe;*.dll;*.scr;*.drv;*.sys";
			openFileName.lpstrFile = szFileName;
			openFileName.nFilterIndex = 1;
			openFileName.hwndOwner = hDlg;
			openFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			GetOpenFileName(&openFileName);
			SetDlgItemText(hDlg, IDC_EDIT_TARGET, openFileName.lpstrFile);

			if (OpenFileFunctionAddTarget(szFileName, hDlg) == -1)
			{
				MessageBox(0, _T("无法正确加载目标代码"), _T("错误："), 0);
				Warning = 0;
			}
			memset(szFileName, 0, sizeof(szFileName));

			return 1;

		case IDC_BUTTON_SHELLCODE:
			if (Warning)
			{
				openFileName.lStructSize = sizeof(OPENFILENAME);
				openFileName.nMaxFile = MAX_PATH;  //这个必须设置，不设置的话不会出现打开文件对话框 
				openFileName.lpstrFilter = "*.exe;*.dll;*.scr;*.drv;*.sys";
				openFileName.lpstrFile = szFileName;
				openFileName.nFilterIndex = 1;
				openFileName.hwndOwner = hDlg;
				openFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

				GetOpenFileName(&openFileName);
				SetDlgItemText(hDlg, IDC_EDIT_SHELL, openFileName.lpstrFile);

				if (OpenFileFunctionAddShell(szFileName, hDlg))
				{
					MessageBox(0, _T("无法正确加载ShellCode"), _T("错误："), 0);
				}
				Warning = 0;
				memset(szFileName, 0, sizeof(szFileName));

				SetDlgItemText(hDlg, IDC_EDIT_TARGET, _T(""));
				SetDlgItemText(hDlg, IDC_EDIT_SHELL, _T(""));

			}
			else
			{
				MessageBox(0, _T("请先选择目标代码！"), _T("警告:"), 0);
			}

			return 1;
		

		case IDC_BUTTON_SHELL_EXIT:
			
			Warning = 0;
			EndDialog(hDlg, 0);
			return 1;
		}
		return 1;
	case WM_NOTIFY:

		return 1;
	}
	return 0;
}



BOOL CALLBACK dialogproc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HICON hIconB;
	OPENFILENAME openFileName = { 0 };
	switch (uMsg)
	{
	case WM_INITDIALOG:
		hIconB = LoadIcon(g_hInstance, MAKEINTRESOURCE(MY_ICON_HOUSE));

		SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM)hIconB);
		SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIconB);

		InitProcessView(hDlg);
		InitModuleView(hDlg);
		
		return 1;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return 1;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_PE:
			openFileName.lStructSize = sizeof(OPENFILENAME);
			openFileName.nMaxFile = MAX_PATH;  //这个必须设置，不设置的话不会出现打开文件对话框 
			openFileName.lpstrFilter = "*.exe;*.dll;*.scr;*.drv;*.sys";
			openFileName.lpstrFile = szFileName;
			openFileName.nFilterIndex = 1;
			openFileName.hwndOwner = hDlg;
			openFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			GetOpenFileName(&openFileName);

			DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_PE), hDlg, dialogproc_PE);

			return 1;
		case IDC_BUTTON_ADDSHELL:
			DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_ADDSHELL), hDlg, dialogproc_ADDSHELL);

			return 1;

		case IDC_BUTTON_ABOUT:
			return 1;

		case IDC_BUTTON_EXIT:
			//MessageBox(hDlg, _T("退出"), _T("tip"), 48);
			EndDialog(hDlg, 0);
			return 1;
		}
	case WM_NOTIFY:
		NMHDR* pNmhdr = (NMHDR*)lParam;
		if (wParam == IDC_LIST_PROCESS && pNmhdr->code == NM_CLICK)
		{
			EnumModule(GetDlgItem(hDlg, IDC_LIST_MODULE), GetDlgItem(hDlg, IDC_LIST_PROCESS));
		}
		return 1;
	}
	return 0;
}


int PASCAL WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);

	g_hInstance = hInstance;
	DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, dialogproc);
	return 0;
}

