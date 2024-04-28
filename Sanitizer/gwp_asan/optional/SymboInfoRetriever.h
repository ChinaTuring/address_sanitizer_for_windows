#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <filesystem>
#include <vector>
#include "../../options.h"
#include <TlHelp32.h>
#pragma comment(lib, "dbghelp.lib")

namespace gwp_asan {
	namespace windbg{

		class SymbolInfoRetriever {
		public:
			SymbolInfoRetriever(DWORD64 codeAddress, const TCHAR* pdbDirectory)
				: m_codeAddress(codeAddress), m_pdbDirectory(pdbDirectory) {}

			bool RetrieveSymbolInfo(gwp_asan::options::Printf_t Printf) {
				//SymSetOptions(SYMOPT_DEBUG);
				HANDLE hCurrentProcess = GetCurrentProcess();
				HANDLE hProcess = nullptr;
				if (!DuplicateHandle(hCurrentProcess, hCurrentProcess, hCurrentProcess, &hProcess, 0, FALSE, DUPLICATE_SAME_ACCESS))
				{
					// DuplicateHandle failed
					int error = GetLastError();
					printf("DuplicateHandle returned error : %d\n", error);
					return FALSE;
				}
				if (!SymInitialize(hProcess, nullptr, TRUE)) {
					Printf(L"Failed to initialize symbol handler : %d\n", GetLastError());
					return false;
				}
				SymSetSearchPathW(hProcess, m_pdbDirectory.c_str());
				//Printf(L"Set Symbol SearchPath: %s \n", m_pdbDirectory.c_str());
				std::vector<MODULEENTRY32> modules = GetLoadedModules();
				bool bFind = false;
				for (const MODULEENTRY32& module : modules) {
					std::wstring pdbPath = GetPDBPathFromModule(module.szExePath);
					DWORD64 BaseOfDll = 0;
					DWORD SizeOfDll = 0;
					if (!pdbPath.empty()) {		
						if (SymLoadModuleExW(hProcess, nullptr, module.szExePath, NULL, 0, 0, nullptr, 0)) {
							
							DWORD displacement = 0;
							IMAGEHLP_SYMBOL_PACKAGE symbol;
							symbol.sym.SizeOfStruct = sizeof(IMAGEHLP_SYMBOL_PACKAGE);
							symbol.sym.MaxNameLength = MAX_SYM_NAME;
							if (SymGetSymFromAddr(hProcess, m_codeAddress, &displacement, &symbol.sym)) {

								int len = strlen(symbol.sym.Name) + 1;
								// 获取转换后的 wchar_t 类型字符串所需的长度
								int wcharLength = MultiByteToWideChar(CP_UTF8, 0, symbol.sym.Name, len, NULL, 0);

								// 分配内存来存储 wchar_t 类型字符串
								wchar_t* wcharString = new wchar_t[wcharLength];

								// 将 char 类型字符串转换为 wchar_t 类型字符串
								MultiByteToWideChar(CP_UTF8, 0, symbol.sym.Name, len, wcharString, wcharLength);

								Printf(L"Symbol found in(%s) : %s (Displacement : %d)\n",module.szModule ,wcharString, displacement);
								delete[] wcharString;
								bFind = true;
							}

						}
						else
						{
							Printf(L"load module pdb failed: %s ,error:%d\n", pdbPath.c_str(), GetLastError());
						}
					}
				}
				SymCleanup(hProcess);
				if (!bFind)
				{
					Printf(L"Failed to retrieve symbol information. address:%x, DIR:%s \n", m_codeAddress, m_pdbDirectory.c_str());
				}
				
				return false;
			}


			static std::vector<MODULEENTRY32>  GetLoadedModules() {
				std::vector<MODULEENTRY32> modules;
				HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
				if (hSnapshot != INVALID_HANDLE_VALUE) {
					MODULEENTRY32 me32;
					me32.dwSize = sizeof(MODULEENTRY32);
					if (Module32First(hSnapshot, &me32)) {
						do {
							modules.push_back(me32);
						} while (Module32Next(hSnapshot, &me32));
					}
					CloseHandle(hSnapshot);
				}
				return modules;
			}

		private:
			std::wstring GetPDBPathFromModule(const TCHAR* modulePath) {
				std::wstring dllFilename = std::wstring(modulePath);
				size_t lastDot = dllFilename.find_last_of('.');
				if (lastDot != std::wstring::npos) {
					std::wstring pdbFilename = dllFilename.substr(0,lastDot) + L".pdb";
					size_t pos = pdbFilename.find_last_of(L"\\");
					if (pos == std::wstring::npos)
					{
						return L"";
					}
					std::wstring pdbPath = m_pdbDirectory + pdbFilename.substr(pos);
					if (_waccess(pdbPath.c_str(), 0) != -1) {
						return pdbPath;
					}
				}
				return L"";
			}

		private:
			DWORD64 m_codeAddress;
			std::wstring m_pdbDirectory;
		};

	}
}