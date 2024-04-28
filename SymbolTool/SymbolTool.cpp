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
		printf("���� UserContext ����Ϊ�ա�\n");
		return FALSE;
	}

	auto      pkg = (LPCALLBACKPACKAGE)UserContext;
	FILE*     hLogFile = pkg->logfile;
	DWORD64   BaseOfDll = pkg->BaseOfDll;
	fprintf(hLogFile,
		"������: %s\r\n��ַ: 0x%I64X \r\n\r\n",
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
		printf("���� lpCallBackPackage ����Ϊ�ա�\n");
		return FALSE;
	}

	CALLBACKPACKAGE* pkg = (*lpCallBackPackage);
	HANDLE hProcess = GetCurrentProcess();
	//hProcess = OpenProcess(PROCESS_ALL_ACCESS,
	//	FALSE, GetCurrentProcessId()); // ��ȡ��ǰ���̵ľ��

	/* ��ʼ�����̵ķ��Ŵ������
	// SymInitialize �������ڳ�ʼ�����̵ķ��Ŵ������
	// �ڷ��Ŵ��������������У��������ռ�������ϢʱҪʹ�õķ������
	// ͨ��������������������ʹ�÷��Ŵ������
	// ��Щ������ҪΪ���ڵ��ԵĽ��̼��ط��š�
	*/

	if (!SymInitialize(hProcess, NULL, FALSE))
	{
		CloseHandle(hProcess);
		SetLastError(ERROR_DELAY_LOAD_FAILED);
		printf("��ʼ�����̵ķ��Ŵ������ʧ�ܡ�\n");
		return FALSE;
	}

	// ���ĵ�ǰ���ŵ�������ѡ������
	// 
	// ��Ӧ�ó���ʹ�ÿ�ʱ�����Զ�θ�����Щѡ� 
	// �κ�ѡ����Ķ���Ӱ�콫���Է��Ŵ����������е��á�

	DWORD dwOpt = SymGetOptions();
	SymSetOptions(
		dwOpt | SYMOPT_DEFERRED_LOADS |
		SYMOPT_UNDNAME | SYMOPT_CASE_INSENSITIVE);

	// UNICODE ת��
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
		printf("�Ҳ��� PDB �ļ���\n");
		return FALSE;
	}
	szFileName[len - 1] = 'l';
	szFileName[len - 2] = 'l';
	szFileName[len - 3] = 'd';
	// ���Ŵ������Ϊģ�鴴��һ����Ŀ������ѹر��ӳٷ��ż���ѡ�
	// ���Լ��ط��š� ����������ӳٷ��ż��أ���ģ�齫
	// �����Ϊ�ӳ٣����Ҳ�����ط��ţ�ֱ����ģ���еķ��Ž������á�
	// ��ˣ��ڵ��� SymLoadModuleEx ��Ӧʼ�յ���
	// SymGetModuleInfo64 ������

	DWORD64 dwSymModule = SymLoadModuleEx(
		hProcess, NULL,
		szFileName, NULL,
		0, 0, NULL, 0);

	if (0 == dwSymModule)
	{
		SymCleanup(hProcess);
		SetLastError(ERROR_DELAY_LOAD_FAILED);
		printf("���ط���ģ��ʧ�ܡ�\n");
		return -1;
	}
	// ģ�����ַ
	wprintf(L"SymModuleBaseAddress: 0x%I64X\n", dwSymModule);
	pkg->BaseOfDll = dwSymModule;

	// ��ѯ��ַ��Ϣ
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
	// ��ʼ��������Ϊ�ṹ������ڴ�
	FILE* hLogFile = NULL;
	CALLBACKPACKAGE* pkg = new CALLBACKPACKAGE;
	if (pkg == nullptr)
	{
		SetLastError(ERROR_STACK_OVERFLOW);
		printf("ϵͳ��ǰ�ڴ治�㡣\n");
		return 1;
	}

	wchar_t* address = argv[2];
	wchar_t* modulename = argv[3];
	DWORD dAdress = _wtol(address);

	// ��ָ������־�ļ�
	fopen_s(&hLogFile, "storage_log.txt", "a");// ��Ϣ����·��
	if (hLogFile == NULL)
	{
		pkg->logfile = NULL;
		delete pkg;
		SetLastError(ERROR_FILE_NOT_FOUND);
		printf("�޷���ָ�����ļ���\n");
		return 2;
	}
	// ���ýṹ���Ա
	pkg->logfile = hLogFile;

	WCHAR szBuf[MAX_PATH] = { 0 };
	::GetModuleFileName(NULL, szBuf, MAX_PATH);
	(wcsrchr(szBuf, L'\\'))[0] = 0;
	std::wstring wPath = szBuf;
	wPath += L"\\";
	// ����ģ����
	wPath += modulename;
	
	pkg->szDllPath = wPath.c_str(); // Ҫ��ѯ�� DLL ·��
	pkg->OffsetDll = dAdress;
	if (!GetSymbolProc(&pkg))// ���ñ�������
	{
		fclose(hLogFile);
		pkg->logfile = NULL;
		delete pkg;
		SetLastError(ERROR_ACCESS_DENIED);
		printf("���� PDB �ļ���Ϣʧ�ܡ�err_code: [%d]\n", GetLastError());
		return 3;
	}
	printf("�����Ѿ���ɡ�\n");

	// ������
	fclose(hLogFile);
	pkg->logfile = NULL;
	delete pkg;

	system("pause");
	return 0;
}