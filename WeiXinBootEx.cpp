// WeiXinBootEx.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <ShlObj.h>

#include "ntdll.h"


#define STATUS_INFO_LENGTH_MISMATCH          0xC0000004                 //内存块不够
#define STATUS_WAIT_0                ((DWORD)0x00000000)   

HMODULE hNtdllLibrary = NULL;
HMODULE hKernel32Library = NULL;

HANDLE  hHeap = NULL;

NTQUERYINFORMATIONFILE    NtQueryInformationFile = NULL;
NTQUERYSYSTEMINFORMATION  NtQuerySystemInformation = NULL;              //由ntdll导出的函数指针
K32GETMODULEFILENAMEEXW   K32GetModuleFileNameExW = NULL;               //由kernel32导出的函数指针


typedef struct _NM_INFO
{
	HANDLE  hFile;
	FILE_NAME_INFORMATION Info;
	WCHAR Name[MAX_PATH];
} NM_INFO, * PNM_INFO;


/**
 *	查询系统信息，用于获取文件句柄对应的文件名称，线程中执行，防止卡死
 */
EXTERN_C DWORD WINAPI GetFileNameThread(PVOID lpParameter)
{
	IO_STATUS_BLOCK IoStatus;
	PNM_INFO NmInfo = (PNM_INFO)lpParameter;

	NtQueryInformationFile(NmInfo->hFile, &IoStatus, &NmInfo->Info, sizeof(NM_INFO) - sizeof(HANDLE), FileNameInformation);
	Sleep(1);
	return 0;
}

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
UCHAR getFileHandleType(PSYSTEM_HANDLE_INFORMATION pInfo, HANDLE hFile)
{
	UCHAR uResult = 0;
	if (hFile != INVALID_HANDLE_VALUE) {

		// 在当前进程中找到创建的文件句柄，以此确定文件对象的值
		for (ULONG i = 0; i < pInfo->uCount; i++) {
			if ((HANDLE)pInfo->aSH[i].Handle == hFile && pInfo->aSH[i].uIdProcess == GetCurrentProcessId()) {
				uResult = pInfo->aSH[i].ObjectType;
				std::cout << "成功获取文件对象值 uResult = " << std::hex << std::showbase << int(uResult) << std::endl;
				break;
			}
		}
		CloseHandle(hFile);
	}
	else {
		std::cout << "未成功获取文件对象值 last err = " << GetLastError() << std::endl;
	}
	return uResult;
}

/**
 * 获取名为 Weixin.exe 的进程 PID
 */
ULONG getWeixinPID(ULONG* pPid)
{
	ULONG nPid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return nPid;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (wcscmp(pe.szExeFile, L"Weixin.exe") == 0) {
				pPid[nPid] = pe.th32ProcessID;
				std::cout << "weixin,exe index = " << (nPid + 1) << "pid = " << pPid[nPid] << std::endl;
				nPid++;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot); // 确保句柄在任何情况下都关闭
	return nPid;
}


/**
 *	通过句柄获取文件名称
 */
void getFileName(HANDLE hFile, WCHAR* TheName)
{
	HANDLE hThread = NULL;

	PNM_INFO Info = (PNM_INFO)HeapAlloc(hHeap, 0, sizeof(NM_INFO));

	if (Info != NULL) {
		Info->hFile = hFile;

		hThread = CreateThread(NULL, 0, GetFileNameThread, Info, 0, NULL);
		if (hThread) {
			if (WaitForSingleObject(hThread, 1000) == WAIT_TIMEOUT) {
				
				TerminateThread(hThread, 0);		// 超时后终止查询，防止卡死
			}
			CloseHandle(hThread);
		}

		UINT length = (UINT)(Info->Info.FileNameLength / sizeof(WCHAR));
		if (length <= MAX_PATH) {
			wcsncpy_s(TheName, MAX_PATH, Info->Info.FileName, length);
		}
	}
	HeapFree(hHeap, 0, Info);
}


/**
 *	通过句柄和文件名称，获取文件当前所在的磁盘盘符
 */
BOOL getVolume(HANDLE hFile, PWCHAR Name)
{
	DWORD dwSize = MAX_PATH;
	WCHAR szLogicalDrives[MAX_PATH] = { 0 };
	
	// 获取逻辑驱动器号字符串
	DWORD dwResult = GetLogicalDriveStrings(dwSize, szLogicalDrives);

	// 获取盘符字符串
	if (dwResult > 0 && dwResult <= MAX_PATH) {
		PWCHAR szSingleDrive = szLogicalDrives;  // 从缓冲区起始地址开始
		while (*szSingleDrive) {

			DWORD VolumeSerialNumber;
			WCHAR VolumeName[MAX_PATH] = { 0 };

			GetVolumeInformation(szSingleDrive, VolumeName, 12, &VolumeSerialNumber, NULL, NULL, NULL, 10); // 获取盘符的卷序号

			BY_HANDLE_FILE_INFORMATION pFileInfo;
			if (!GetFileInformationByHandle(hFile, &pFileInfo)) {
				return FALSE;
			}
			
			//获取文件的序列号
			if (pFileInfo.dwVolumeSerialNumber == VolumeSerialNumber) {

				szSingleDrive[wcslen(szSingleDrive) - 1] = L'\0';	// 去掉"/"
				swprintf(Name, MAX_PATH, L"%s", szSingleDrive);
				return TRUE;
			}
			szSingleDrive += wcslen(szSingleDrive) + 1;				// 获取下一个驱动器号起始地址
		}
	}
	return FALSE;
}


int main()
{
	WCHAR wsLockPath[MAX_PATH] = { 0 };

	// 获取 Roaming 路径
	PWSTR wsRoamingPath = NULL;
	HRESULT hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &wsRoamingPath);

	// 获取微信 4.0 互斥文件路径
	if (SUCCEEDED(hr)) {
		swprintf(wsLockPath, MAX_PATH, L"%s\\Tencent\\xwechat\\lock\\lock.ini", wsRoamingPath);
		CoTaskMemFree(wsRoamingPath);
	}
	else {
		wprintf(L"Roaming 路径获取错误。\r\n");
		return 0;
	}

	wprintf(L"Lock File: %s\r\n", wsLockPath);

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

	// 此处随便创建一个文件，用于获取文件对象的值
	HANDLE hFile = CreateFile(L"boot.ex", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// 获取系统信息表
	PSYSTEM_HANDLE_INFORMATION pInfo = (PSYSTEM_HANDLE_INFORMATION)getInfoTable(SystemHandleInformation);
	if (!pInfo) {
		return 0;
	}

	// 获取文件句柄类型
	UCHAR fileObjectType = getFileHandleType(pInfo, hFile);

	// 获取所有的微信 PID
	BOOL  isWeixinPid = FALSE;
	ULONG weixinPidList[MAX_PATH] = { 0 };
	ULONG weixinPidListLen = getWeixinPID(weixinPidList);

	WCHAR  wsFilePath[MAX_PATH] = { 0 };
	WCHAR  wsFileVolumePath[MAX_PATH] = { 0 };

	std::cout << "weixinPidListLen:" << weixinPidListLen << std::endl;

	for (ULONG i = 0; i < pInfo->uCount; i++) {
		// 检索微信进程
		isWeixinPid = FALSE;
		for (ULONG j = 0; j < weixinPidListLen; j++) {
			if (pInfo->aSH[i].uIdProcess == weixinPidList[j]) {
				isWeixinPid = TRUE;
			}
		}

		if (isWeixinPid == FALSE) {
			continue;
		}

		// 目标对象类型为文件
		if (pInfo->aSH[i].ObjectType == fileObjectType) {
			HANDLE hFile;
			HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pInfo->aSH[i].uIdProcess);

			if (hProcess) {
				//先复制到本地句柄表
				if (DuplicateHandle(hProcess, (HANDLE)pInfo->aSH[i].Handle, GetCurrentProcess(), &hFile, 0, FALSE, DUPLICATE_SAME_ACCESS)) {

					getFileName(hFile, wsFilePath);
					if (getVolume(hFile, wsFileVolumePath)) {
						wcscat_s(wsFileVolumePath, wsFilePath);

						if (wcscmp(wsLockPath, wsFileVolumePath) == 0) {
							wprintf(L"wsFileVolumePath: %s\r\n", wsFileVolumePath);
							break;
						}
					}
				}
			}
		}
	}

	HeapFree(hHeap, 0, pInfo);
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
