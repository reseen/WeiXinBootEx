// WeiXinBootEx.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <ShlObj.h>
#include <stdarg.h>

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
 *	自定义输出函数，格式化宽字符字符串并转换为GBK输出
 */
void wprintf_gbk(const wchar_t* format, ...)
{
	wchar_t wsFormatted[1024];

	// 变长参数列表
	va_list args;
	va_start(args, format);
	vswprintf(wsFormatted, 1024, format, args);
	va_end(args);

	// 获取宽字符字符串的长度
	int len = (int)wcslen(wsFormatted);

	int gbkLength = WideCharToMultiByte(CP_ACP, 0, wsFormatted, len, NULL, 0, NULL, NULL);

	if (gbkLength > 0) {
		char* gbkStr = new char[gbkLength + 1];
		WideCharToMultiByte(CP_ACP, 0, wsFormatted, len, gbkStr, gbkLength, NULL, NULL);

		// 输出GBK字符串
		gbkStr[gbkLength] = '\0';  // 确保字符串以'\0'结尾
		printf("%s", gbkStr);

		// 释放内存
		delete[] gbkStr;
	}
}


/**
 *	检测文件是否存在
 */
BOOL FileExists(PWCHAR filename) {
	DWORD dwAttrib = GetFileAttributesW(filename);

	// 如果返回 INVALID_FILE_ATTRIBUTES，说明文件不存在
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}



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
BOOL LoadSystemLibrary() 
{
	hNtdllLibrary = LoadLibrary(L"ntdll.dll");
	if (hNtdllLibrary != NULL) {
		NtQueryInformationFile = (NTQUERYINFORMATIONFILE)GetProcAddress(hNtdllLibrary, "NtQueryInformationFile");
		NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtdllLibrary, "NtQuerySystemInformation");
	}
	else {
		wprintf_gbk(L"动态库 ntdll.dll 相关函数加载失败！");
		return FALSE;
	}


	hKernel32Library = LoadLibrary(L"Kernel32.dll");
	if (hKernel32Library != NULL) {
		K32GetModuleFileNameExW = (K32GETMODULEFILENAMEEXW)GetProcAddress(hKernel32Library, "K32GetModuleFileNameExW");
	}
	else {
		wprintf_gbk(L"动态库 Kernel32.dll 相关函数加载失败！");
		return FALSE;
	}

	return TRUE;
}


/**
 *	释放已加载的动态库
 */
VOID FreeSystemLibrary() 
{
	if (hNtdllLibrary != NULL) {
		FreeLibrary(hNtdllLibrary);
	}

	if (hKernel32Library != NULL) {
		FreeLibrary(hKernel32Library);
	}
}

/**
 * 为当前进程启用 SE_DEBUG_NAME 特权,以访问其他进程的句柄
 */
BOOL AdjustPrivilege()
{
	BOOL bResult = FALSE;

	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)){
		TOKEN_PRIVILEGES tp = {0};

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)){
			bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
			wprintf_gbk(L"提权%s\r\n", (bResult ? L"成功" : L"失败"));
		}
		CloseHandle(hToken);
	}
	return bResult;
}

/**
 * 进程 rundll32.exe 会阻止解除文件占用操作，所以解除前先终止掉该进程
 */
BOOL CloseBlockingProcess(void)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);

	BOOL bMore = Process32First(hSnapshot, &pe);
	while (bMore) {
		if (wcscmp(pe.szExeFile, L"rundll32.exe") == 0) {
			HANDLE hOpen = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
			TerminateProcess(hOpen, 0);
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
				break;
			}
		}
		CloseHandle(hFile);
	}
	else {
		wprintf_gbk(L"未成功获取文件对象值 lasterr = %d", GetLastError());
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
void GetFileName(HANDLE hFile, WCHAR* TheName)
{
	HANDLE hThread = NULL;

	PNM_INFO Info = (PNM_INFO)HeapAlloc(hHeap, 0, sizeof(NM_INFO));

	if (Info != NULL) {
		Info->hFile = hFile;

		hThread = CreateThread(NULL, 0, GetFileNameThread, Info, 0, NULL);
		if (hThread) {
			if (WaitForSingleObject(hThread, 1000) == WAIT_TIMEOUT) {
				// 超时后终止查询，防止卡死
				TerminateThread(hThread, 0);		
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
BOOL GetVolume(HANDLE hFile, PWCHAR Name)
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


/**
 *	关闭远程句柄，解除文件占用
 */
BOOL CloseRemoteHandle(__in DWORD dwProcessId, __in HANDLE hRemoteHandle)
{
	HANDLE hExecutHandle = NULL;
	BOOL bFlag = FALSE;
	HANDLE hProcess = NULL;
	HMODULE hKernel32Module = NULL;

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);

	if (NULL == hProcess) {
		bFlag = FALSE;
		goto ExitFlag;
	}

	hKernel32Module = LoadLibrary(L"kernel32.dll ");

	hExecutHandle = CreateRemoteThread(hProcess, 0, 0,
		(DWORD(__stdcall*)(void*))GetProcAddress(hKernel32Module, "CloseHandle"),
		hRemoteHandle, 0, NULL);

	if (NULL == hExecutHandle) {
		bFlag = FALSE;
		goto ExitFlag;
	}

	if (WaitForSingleObject(hExecutHandle, 2000) == WAIT_OBJECT_0) {
		bFlag = TRUE;
		goto ExitFlag;
	}
	else {
		bFlag = FALSE;
		goto ExitFlag;
	}

ExitFlag:
	if (hExecutHandle != NULL) {
		CloseHandle(hExecutHandle);
	}

	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}

	if (hKernel32Module != NULL) {
		FreeLibrary(hKernel32Module);
	}
	return bFlag;
}


/**
 *	获取 Lock.ini 文件路径
 */
PWCHAR GetLockIni()
{
	static WCHAR wsLockPath[MAX_PATH] = { 0 };
	
	PWSTR wsRoamingPath = NULL;
	HRESULT hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &wsRoamingPath);		// 获取 Roaming 路径

	if (SUCCEEDED(hr)) {
		swprintf(wsLockPath, MAX_PATH, L"%s\\Tencent\\xwechat\\lock\\lock.ini", wsRoamingPath);	// 获取微信 4.0 互斥文件路径
		CoTaskMemFree(wsRoamingPath);
	}
	else {
		wprintf_gbk(L"Roaming 路径获取错误。\r\n");
		return NULL;
	}

	return wsLockPath;
}


/**
 *	解除微信 Lock.ini 文件占用并删除
 */
INT UnlockWeixinMutex(PWCHAR wsLockPath)
{
	WCHAR wsModuleFilePath[MAX_PATH] = { 0 };

	// 加载程序所需动态库
	if (!LoadSystemLibrary()) {
		return -1;
	}
	
	// 提权至 SE_DEBUG_NAME
	if (!AdjustPrivilege()) {
		return -1;
	}

	// 关闭 rundll32.exe 进程
	CloseBlockingProcess();

	hHeap = GetProcessHeap();

	// 此处随便创建一个文件，用于获取文件对象的值
	HANDLE hFile = CreateFile(L"boot.ex", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// 获取系统信息表
	PSYSTEM_HANDLE_INFORMATION pInfo = (PSYSTEM_HANDLE_INFORMATION)getInfoTable(SystemHandleInformation);
	if (!pInfo) {
		return -1;
	}

	// 获取文件句柄类型
	UCHAR fileObjectType = getFileHandleType(pInfo, hFile);

	// 获取所有的微信 PID
	BOOL  isWeixinPid = FALSE;
	ULONG weixinPidList[MAX_PATH] = { 0 };
	ULONG weixinPidListLen = getWeixinPID(weixinPidList);

	WCHAR  wsFilePath[MAX_PATH] = { 0 };
	WCHAR  wsFileVolumePath[MAX_PATH] = { 0 };

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

			if (!hProcess) {
				continue;
			}

			// 成功获取到目标文件句柄后，先复制到本地句柄表
			if (DuplicateHandle(hProcess, (HANDLE)pInfo->aSH[i].Handle, GetCurrentProcess(), &hFile, 0, FALSE, DUPLICATE_SAME_ACCESS)) {

				GetFileName(hFile, wsFilePath);
				// wprintf_gbk(L"wsFilePath: %s\r\n", wsFilePath);

				if (GetVolume(hFile, wsFileVolumePath)) {
					wcscat_s(wsFileVolumePath, wsFilePath);

					if (wcscmp(wsLockPath, wsFileVolumePath) == 0) {
						// wprintf_gbk(L"wsFileVolumePath: %s\r\n", wsFileVolumePath);

						HANDLE hPid = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pInfo->aSH[i].uIdProcess);
						K32GetModuleFileNameExW(hPid, NULL, wsModuleFilePath, MAX_PATH);
						// wprintf_gbk(L"文件占用程序：%s\r\n", wsModuleFilePath);

						// 关闭远程句柄
						if (CloseRemoteHandle(pInfo->aSH[i].uIdProcess, (HANDLE)pInfo->aSH[i].Handle)) {

							// 关闭本地句柄，解除文件占用
							CloseHandle(hFile);

							// 删除文件
							//wprintf_gbk(L"开始删除文件：%s\\rn", wsFileVolumePath);
							if (DeleteFile(wsFileVolumePath)) {
								wprintf_gbk(L"解除占用成功!\r\n");
							}
							else {
								wprintf_gbk(L"解除占用失败!\r\n");
							}
						}
						else {
							// 继续遍历，也许有其他占用句柄
							continue;
						}
						CloseHandle(hPid);
						break;
					}
				}
			}
		}
	}

	DeleteFile(L"boot.ex");
	HeapFree(hHeap, 0, pInfo);
	FreeSystemLibrary();
	return 0;
}


/**
 *	获取微信主程序文件位置
 */

PWCHAR GetWeixinInstallPath()
{
	LPCWSTR keyPath = L"SOFTWARE\\Tencent\\Weixin";
	static WCHAR swWeixinPath[MAX_PATH] = { 0 };

	HKEY hKey;
	LONG openResult = RegOpenKeyEx(HKEY_CURRENT_USER, keyPath, 0, KEY_ALL_ACCESS, &hKey);

	if (openResult == ERROR_SUCCESS) {
		DWORD valueSize = MAX_PATH;
		LONG queryResult = RegQueryValueEx(hKey, L"InstallPath", NULL, NULL, (LPBYTE)swWeixinPath, &valueSize);
		if (queryResult == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			return swWeixinPath;
		}
		else {
			wprintf_gbk(L"无法读取注册表值");
		}
	}
	else {
		wprintf_gbk(L"无法打开注册表键");
	}
	RegCloseKey(hKey);
	return NULL;
}


int main()
{
	PWCHAR pwsLockIniPath = GetLockIni();
	PWCHAR pwsWeiXinPath = GetWeixinInstallPath();

	// 首先检测 Lock.ini 是否存在
	if (FileExists(pwsLockIniPath)) {

		// 如果存在先删除一次试试，无法删除的情况下再尝试解除占用
		if (!DeleteFile(pwsLockIniPath)) {

			// 解除文件占用
			wprintf_gbk(L"尝试解除占用…\r\n");
			UnlockWeixinMutex(pwsLockIniPath);
		}
	}

	if (!pwsWeiXinPath) {
		system("pause");
		return 0;
	}

	if (!wcscat_s(pwsWeiXinPath, MAX_PATH, L"\\Weixin.exe")) {
		wprintf_gbk(L"启动微信:%s\r\n", pwsWeiXinPath);
		ShellExecute(NULL, NULL, pwsWeiXinPath, NULL, NULL, SW_NORMAL);
	}

	system("pause");
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
