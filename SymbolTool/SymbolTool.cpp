#include <windows.h>
#include <iostream>
#include <imagehlp.h>
#include <locale.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <vector>
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shlwapi.lib")

typedef struct _tagCALLBACKPACKAGE
{
	LPCTSTR   szDllPath = NULL;
	FILE*     logfile = NULL;
	DWORD64   BaseOfDll = NULL;
	DWORD     OffsetDll = NULL;
}CALLBACKPACKAGE, *LPCALLBACKPACKAGE;

BOOL CALLBACK CallBackProc(
	PSYMBOL_INFO pSymInfo,
	ULONG SymbolSize,
	PVOID UserContext
	)
{
	if (UserContext == nullptr)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		printf("参数 UserContext 不能为空。\n");
		return FALSE;
	}

	auto      pkg = (LPCALLBACKPACKAGE)UserContext;
	FILE*     hLogFile = pkg->logfile;
	DWORD64   BaseOfDll = pkg->BaseOfDll;
	fprintf(hLogFile,
		"函数名: %s\r\n地址: 0x%I64X \r\n\r\n",
		pSymInfo->Name,
		pSymInfo->Address - BaseOfDll);
	return TRUE;
}

char* UnicodeToAnsi(const wchar_t* szStr, char* szDest)
{
	int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
	if (nLen == 0)
	{
		return NULL;
	}
	char* pResult = new char[nLen];
	WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
	strcpy_s(szDest, nLen, pResult);
	delete[] pResult;
	return szDest;
}

BOOL GetSymbolProc(LPCALLBACKPACKAGE* lpCallBackPackage)
{
	if ((*lpCallBackPackage) == nullptr)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		printf("参数 lpCallBackPackage 不能为空。\n");
		return FALSE;
	}

	CALLBACKPACKAGE* pkg = (*lpCallBackPackage);
	HANDLE hProcess = GetCurrentProcess();
	//hProcess = OpenProcess(PROCESS_ALL_ACCESS,
	//	FALSE, GetCurrentProcessId()); // 获取当前进程的句柄

	/* 初始化进程的符号处理程序。
	// SymInitialize 函数用于初始化进程的符号处理程序。
	// 在符号处理程序的上下文中，进程是收集符号信息时要使用的方便对象。
	// 通常，调试器和其他工具使用符号处理程序，
	// 这些工具需要为正在调试的进程加载符号。
	*/

	if (!SymInitialize(hProcess, NULL, FALSE))
	{
		CloseHandle(hProcess);
		SetLastError(ERROR_DELAY_LOAD_FAILED);
		printf("初始化进程的符号处理程序失败。\n");
		return FALSE;
	}

	// 更改当前符号调试器的选项掩码
	// 
	// 当应用程序使用库时，可以多次更改这些选项。 
	// 任何选项更改都会影响将来对符号处理程序的所有调用。

	DWORD dwOpt = SymGetOptions();
	SymSetOptions(
		dwOpt | SYMOPT_DEFERRED_LOADS |
		SYMOPT_UNDNAME | SYMOPT_CASE_INSENSITIVE);

	// UNICODE 转换
	char szFileName[MAX_PATH] = { 0 };
	UnicodeToAnsi(pkg->szDllPath, szFileName);
	size_t len = strlen(szFileName);
	szFileName[len] = '\0';
	szFileName[len - 1] = 'b';
	szFileName[len - 2] = 'd';
	szFileName[len - 3] = 'p';

	if (!PathFileExistsA(szFileName))
	{
		SetLastError(ERROR_FILE_NOT_FOUND);
		printf("找不到 PDB 文件。\n");
		return FALSE;
	}
	szFileName[len - 1] = 'l';
	szFileName[len - 2] = 'l';
	szFileName[len - 3] = 'd';
	// 符号处理程序为模块创建一个条目，如果已关闭延迟符号加载选项，
	// 则尝试加载符号。 如果启用了延迟符号加载，则模块将
	// 被标记为延迟，并且不会加载符号，直到对模块中的符号进行引用。
	// 因此，在调用 SymLoadModuleEx 后，应始终调用
	// SymGetModuleInfo64 函数。

	DWORD64 dwSymModule = SymLoadModuleEx(
		hProcess, NULL,
		szFileName, NULL,
		0, 0, NULL, 0);

	if (0 == dwSymModule)
	{
		SymCleanup(hProcess);
		SetLastError(ERROR_DELAY_LOAD_FAILED);
		printf("加载符号模块失败。\n");
		return -1;
	}
	// 模块基地址
	wprintf(L"SymModuleBaseAddress: 0x%I64X\n", dwSymModule);
	pkg->BaseOfDll = dwSymModule;

	// 查询地址信息
	DWORD64 codeAddress = pkg->BaseOfDll + pkg->OffsetDll;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)];
	PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
	symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	symbol->MaxNameLen = MAX_SYM_NAME;
	DWORD64 offset = 0;
	BOOL got_objname = SymFromAddr(hProcess,
		(DWORD64)codeAddress, &offset, symbol);
	if (!got_objname)
		return false;

	DWORD  unused;
	IMAGEHLP_LINE64 info;
	info.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
	BOOL got_fileline = SymGetLineFromAddr64(hProcess,
		(DWORD64)codeAddress, &unused, &info);
	int written = 0;
	char OutBuffer[1024] = {0};
	// FIXME: it might be useful to print out 'obj' or 'obj+offset' info too.
	if (got_fileline)
	{
		written += sprintf_s(OutBuffer + written, 1024 - written,
			" %s %s:%d", symbol->Name,
			info.FileName, info.LineNumber);
	}
	else
	{
		written += sprintf_s(OutBuffer + written, 1024 - written,
			" %s+0x%p", symbol->Name, offset);
	}
	std::cout <<codeAddress <<" "<< OutBuffer << std::endl;
	return SymCleanup(hProcess);
}

int wmain(int argc, TCHAR* argv[])
{
	// 初始换变量，为结构体分配内存
	FILE* hLogFile = NULL;
	CALLBACKPACKAGE* pkg = new CALLBACKPACKAGE;
	if (pkg == nullptr)
	{
		SetLastError(ERROR_STACK_OVERFLOW);
		printf("系统当前内存不足。\n");
		return 1;
	}

	wchar_t* address = argv[2];
	wchar_t* modulename = argv[3];
	DWORD dAdress = _wtol(address);

	// 打开指定的日志文件
	fopen_s(&hLogFile, "storage_log.txt", "a");// 信息保存路径
	if (hLogFile == NULL)
	{
		pkg->logfile = NULL;
		delete pkg;
		SetLastError(ERROR_FILE_NOT_FOUND);
		printf("无法打开指定的文件。\n");
		return 2;
	}
	// 设置结构体成员
	pkg->logfile = hLogFile;

	WCHAR szBuf[MAX_PATH] = { 0 };
	::GetModuleFileName(NULL, szBuf, MAX_PATH);
	(wcsrchr(szBuf, L'\\'))[0] = 0;
	std::wstring wPath = szBuf;
	wPath += L"\\";
	// 补充模块名
	wPath += modulename;
	
	pkg->szDllPath = wPath.c_str(); // 要查询的 DLL 路径
	pkg->OffsetDll = dAdress;
	if (!GetSymbolProc(&pkg))// 调用遍历函数
	{
		fclose(hLogFile);
		pkg->logfile = NULL;
		delete pkg;
		SetLastError(ERROR_ACCESS_DENIED);
		printf("遍历 PDB 文件信息失败。err_code: [%d]\n", GetLastError());
		return 3;
	}
	printf("操作已经完成。\n");

	// 清理环境
	fclose(hLogFile);
	pkg->logfile = NULL;
	delete pkg;

	system("pause");
	return 0;
}