// WeiXinBootEx.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

#include "ntdll.h"


#define STATUS_INFO_LENGTH_MISMATCH          0xC0000004                 //内存块不够
#define STATUS_WAIT_0                ((DWORD)0x00000000)   

static HMODULE hNtdllLibrary = NULL;
static HMODULE hKernel32Library = NULL;


NTQUERYSYSTEMINFORMATION  NtQuerySystemInformation = NULL;              //由ntdll导出的函数指针
NTQUERYINFORMATIONFILE    NtQueryInformationFile = NULL;
K32GETMODULEFILENAMEEXW   K32GetModuleFileNameExW = NULL;               //由kernel32导出的函数指针

HANDLE hHeap;

/**
 *	加载程序所需的系统函数
 */
BOOL loadSystemLibrary() 
{
	hNtdllLibrary = LoadLibrary(L"ntdll.dll");
	if (hNtdllLibrary != NULL) {
		NtQueryInformationFile = (NTQUERYINFORMATIONFILE)GetProcAddress(hNtdllLibrary, "NtQueryInformationFile");
		NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtdllLibrary, "NtQuerySystemInformation");
	}
	else {
		std::cout << "动态库 ntdll.dll 相关函数加载失败！" << std::endl;
		return FALSE;
	}


	hKernel32Library = LoadLibrary(L"Kernel32.dll");
	if (hKernel32Library != NULL) {
		K32GetModuleFileNameExW = (K32GETMODULEFILENAMEEXW)GetProcAddress(hKernel32Library, "K32GetModuleFileNameExW");
	}
	else {
		std::cout << "动态库 Kernel32.dll 相关函数加载失败！" << std::endl;
		return FALSE;
	}

	std::cout << "动态库加载完成。" << std::endl;
	return TRUE;
}


/**
 *	释放已加载的动态库
 */
VOID freeSystemLibrary() 
{
	if (hNtdllLibrary != NULL) {
		FreeLibrary(hNtdllLibrary);
		std::cout << "动态库 ntdll.dll 已释放！" << std::endl;
	}

	if (hKernel32Library != NULL) {
		FreeLibrary(hKernel32Library);
		std::cout << "动态库 Kernel32.dll 已释放！" << std::endl;
	}
}


/**
 * 为当前进程启用 SE_DEBUG_NAME 特权,以访问其他进程的句柄
 */
BOOL adjustPrivilege()
{
	BOOL bResult = FALSE;

	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)){
		TOKEN_PRIVILEGES tp = {0};

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)){
			bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
			std::cout << (bResult ? "提权成功" : "提权失败") << std::endl;
		}
		CloseHandle(hToken);
	}
	return bResult;
}


/**
 * 进程 rundll32.exe 会阻止解除文件占用操作，所以解除前先终止掉该进程
 */
BOOL closeBlockingProcess(void)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);

	BOOL bMore = Process32First(hSnapshot, &pe);
	while (bMore) {
		if (wcscmp(pe.szExeFile, L"rundll32.exe") == 0) {
			HANDLE hOpen = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
			TerminateProcess(hOpen, 0);

			std::cout << "成功终止 rundll32.exe 进程" << std::endl;
			return TRUE;
		}
		bMore = Process32Next(hSnapshot, &pe);
	}

	return FALSE;
}

/**
 * 系统中获取特定信息表，该表中存有系统所有的句柄信息
 */
PVOID getInfoTable(IN SYSTEMINFOCLASS ATableType)
{
	ULONG    mSize = 0x8000;
	PVOID    mPtr;
	NTSTATUS status;

	do {
		mPtr = HeapAlloc(hHeap, 0, mSize); // 申请内存
		if (!mPtr) {
			return NULL;
		}

		memset(mPtr, 0, mSize);

		status = NtQuerySystemInformation(ATableType, mPtr, mSize, NULL);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(hHeap, 0, mPtr);
			mSize = mSize * 2;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		return mPtr;	// 返回存放信息内存块指针
	}

	HeapFree(hHeap, 0, mPtr);
	return NULL;
}


/**
 * 获取系统分配的文件对象的值，以便于在后续遍历句柄时确认目标句柄是文件
 */
UCHAR getFileHandleType()
{
	// 此处随便创建一个文件，用于获取文件对象的值
	HANDLE hFile = CreateFile(L"boot.ex", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	UCHAR uResult = 0;

	if (hFile != INVALID_HANDLE_VALUE) {
		PSYSTEM_HANDLE_INFORMATION pInfo = (PSYSTEM_HANDLE_INFORMATION)getInfoTable(SystemHandleInformation);
 
		if (pInfo) {
			for (ULONG i = 0; i < pInfo->uCount; i++) {
				// 在当前进程中找到创建的文件句柄，以此确定文件对象的值
				if (pInfo->aSH[i].Handle == (USHORT)hFile && pInfo->aSH[i].uIdProcess == GetCurrentProcessId()) {
					uResult = pInfo->aSH[i].ObjectType;
					std::cout << "成功获取文件对象值 uResult = " << std::hex << std::showbase << int(uResult) << std::endl;
					break;
				}
			}
			HeapFree(hHeap, 0, pInfo);
		}
		CloseHandle(hFile);
	}
	else {
		std::cout << "未成功获取文件对象值 last err = " << GetLastError() << std::endl;
	}
	return uResult;
}


int main()
{
	PSYSTEM_HANDLE_INFORMATION pInfo = NULL;

	// 加载程序所需动态库
	if (!loadSystemLibrary()) {
		return 0;
	}
	
	// 提权至 SE_DEBUG_NAME
	if (!adjustPrivilege()) {
		return 0;
	}

	// 关闭 rundll32.exe 进程
	closeBlockingProcess();

	hHeap = GetProcessHeap();
	

	UCHAR fileHandleType = getFileHandleType();


	//HeapFree(hHeap, 0, pInfo);
	freeSystemLibrary();
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
