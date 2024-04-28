//===-- backtrace_win32.cpp --------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "backtrace.h"
#include "../../options.h"
#include <stdio.h>
#include <iostream>
#include <dbghelp.h>
#include <TlHelp32.h>

#pragma comment(lib, "dbghelp.lib")
namespace 
{
	wchar_t g_printf_path[MAX_PATH] = L"crash_report.txt";
	void Printf(const TCHAR* Format, ...)
	{
		FILE* pFile;
		errno_t err = _wfopen_s(&pFile, g_printf_path, L"a");
		if (pFile)
		{
			va_list args;
			va_start(args, Format);
			int result = vfwprintf(pFile, Format, args);
			va_end(args);
			fclose(pFile);
		}

	}

	size_t Backtrace(uintptr_t *TraceBuffer, size_t Size) 
	{
		static_assert(sizeof(uintptr_t) == sizeof(void *), "uintptr_t is not void*");
		// 获取堆栈信息
		USHORT frames = CaptureStackBackTrace(0, Size, (PVOID*)TraceBuffer, NULL);
		return frames;
	}

	bool g_dbghelp_initialized = false;
	bool Symbolize(const void *Addr, char *OutBuffer, int BufferSize) 
	{
		if (!g_dbghelp_initialized)
		{
			SymSetOptions(SYMOPT_DEFERRED_LOADS |
				SYMOPT_UNDNAME |
				SYMOPT_LOAD_LINES);
			SymInitialize(GetCurrentProcess(), 0, TRUE);
			// FIXME: We don't call SymCleanup() on exit yet - should we?
			g_dbghelp_initialized = true;
		}

		// See http://msdn.microsoft.com/en-us/library/ms680578(VS.85).aspx
		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)];
		PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
		symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol->MaxNameLen = MAX_SYM_NAME;
		DWORD64 offset = 0;
		BOOL got_objname = SymFromAddr(GetCurrentProcess(),
			(DWORD64)Addr, &offset, symbol);
		if (!got_objname)
			return false;

		DWORD  unused;
		IMAGEHLP_LINE64 info;
		info.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
		BOOL got_fileline = SymGetLineFromAddr64(GetCurrentProcess(),
			(DWORD64)Addr, &unused, &info);
		int written = 0;
		OutBuffer[0] = '\0';
		// FIXME: it might be useful to print out 'obj' or 'obj+offset' info too.
		if (got_fileline) 
		{
			written += sprintf_s(OutBuffer + written, BufferSize - written,
				" %s %s:%d", symbol->Name,
				info.FileName, info.LineNumber);
		}
		else 
		{
			written += sprintf_s(OutBuffer + written, BufferSize - written,
				" %s+0x%p", symbol->Name, offset);
		}
		return true;
	}

	static void PrintBacktrace(uintptr_t *Trace, size_t TraceLength,
		gwp_asan::options::Printf_t Printf) 
	{
		if (TraceLength == 0) 
		{
			Printf(L"  <not found (does your allocator support backtracing?)>\n\n");
			return;
		}

		char SymbolBuffer[MAX_PATH] = { 0 };
		char **BacktraceSymbols = reinterpret_cast<char**>(Trace);
		for (size_t i = 0; i < TraceLength; ++i) 
		{
			if (Symbolize((void*)Trace[i], SymbolBuffer, MAX_PATH))
			{
				int len = strlen(SymbolBuffer) + 1;
				// 获取转换后的 wchar_t 类型字符串所需的长度
				int wcharLength = MultiByteToWideChar(CP_UTF8, 0, SymbolBuffer, len, NULL, 0);
				// 分配内存来存储 wchar_t 类型字符串
				wchar_t* SymbolString = new wchar_t[wcharLength];
				// 将 char 类型字符串转换为 wchar_t 类型字符串
				MultiByteToWideChar(CP_UTF8, 0, SymbolBuffer, len, SymbolString, wcharLength);

				Printf(L"#%d 0x%x %s\n", i, Trace[i], SymbolString);
			}
			else
			{
				Printf(L"#%d 0x%x\n", i, Trace[i]);
			}

		}
		Printf(L"\n");
	}

} // anonymous namespace

namespace gwp_asan 
{
	namespace options 
	{
		Backtrace_t getBacktraceFunction() { return Backtrace; }
		PrintBacktrace_t getPrintBacktraceFunction() { return PrintBacktrace; }
		Printf_t getPrintfFunction() { return Printf; }

		void SetPrintfPath(const wchar_t* path)
		{
			if (path != nullptr)
			{
				wcscpy_s(g_printf_path, MAX_PATH, path);
				wcscat_s(g_printf_path, MAX_PATH, L"_crash_report.txt");
			}
		}

	} // namespace options
} // namespace gwp_asan
