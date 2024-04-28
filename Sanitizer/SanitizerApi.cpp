#include "stdafx.h"
#include <Windows.h>
#include "include/SanitizerApi.h"
#include <stdio.h>
#include "gwp_asan/guarded_pool_allocator.h"
#include "gwp_asan/optional/backtrace.h"
#include "gwp_asan/optional/SymboInfoRetriever.h"
#include "detours.h"
#include <thread>
#include <Psapi.h>

void  (*SysFree)(void*) = free;
void* (*SysMalloc)(size_t) = malloc;
void* (*SysRealloc)(void* _Memory, size_t _NewSize) = realloc;
void* (*SysNew)(size_t size) = reinterpret_cast<void* (*)(size_t)>(operator new);
void  (*SysDelete)(void* ptr) = reinterpret_cast<void(*)(void*)>(operator delete);

gwp_asan::GuardedPoolAllocator* allocator = new gwp_asan::GuardedPoolAllocator();

DWORD gSanitizerAddressBegin = 0;
DWORD gSanitizerAddressEnd = 0;
//�����Լ���malloc ʵ�� �滻ϵͳmalloc
void* __cdecl NewMalloc(size_t _Size)
{
	gwp_asan::ThreadLocalPackedVariables* current_thread_variable = gwp_asan::GuardedPoolAllocator::ThreadLocals.Get();
	if (current_thread_variable == nullptr)
	{
		current_thread_variable = (gwp_asan::ThreadLocalPackedVariables*)SysMalloc(sizeof(gwp_asan::ThreadLocalPackedVariables));
		current_thread_variable->NextSampleCounter = 16;
		current_thread_variable->SampleTimes = 16;
		current_thread_variable->RecursiveGuard = false;
		gwp_asan::GuardedPoolAllocator::ThreadLocals.Set(current_thread_variable);
	}

	void* ptr = nullptr;
	if (gSanitizerAddressBegin != 0 && gSanitizerAddressEnd != 0)
	{
		void* stack[32];
		unsigned short frames = CaptureStackBackTrace(0, 32, stack, NULL);
		// ��ȡ���ø�hook������ģ����Ϣ
		for (int i = 0; i < frames; i++)
		{
			uintptr_t addrs = (uintptr_t)stack[i];
			if (addrs > (uintptr_t)gSanitizerAddressBegin && addrs <= gSanitizerAddressEnd)
			{
				ptr = allocator->alloc(_Size);
				break;
			}
		}
		return ptr ? ptr : SysMalloc(_Size);
	}

    ptr = allocator->alloc(_Size);
	return ptr ? ptr : SysMalloc(_Size);
}

// free �����Լ���ʵ��
void __cdecl NewFree(void* _Block)
{
	if (allocator->pointerIsMine(_Block))
	{
		allocator->dealloc(_Block);
	}
	else
	{
		SysFree(_Block);
	}
}

void* __cdecl CustomNew(std::size_t size)
{
	return NewMalloc(size);
}

void CustomDelete(void* ptr)
{
	if (allocator->pointerIsMine(ptr))
	{
		allocator->dealloc(ptr);
	}
	else
	{
		SysFree(ptr);
	}
}

//�����������������Ҫ�ر�С�ģ�������һ�������ڴ�ط����ڴ棬���γ��ޣ���ϵͳ��������
void* __cdecl NewRealloc(void* _Memory, size_t _NewSize)
{
	if (allocator->pointerIsMine(_Memory))
	{
		void* new_address = allocator->realloc(_Memory, _NewSize);
		if (!new_address)
		{
			new_address = SysMalloc(_NewSize);
			memcpy(new_address, _Memory, allocator->getSize(_Memory));
		}
		return new_address;
	}
	else
	{
		return SysRealloc(_Memory, _NewSize);
	}
}

//�¹��Ӻ���
void StartHook() 
{
	printf("StartHook\n");
	//��ʼ����
	DetourTransactionBegin();
	//�����߳���Ϣ
	DetourUpdateThread(GetCurrentThread());
	//�����صĺ������ӵ�ԭ�����ĵ�ַ��
	DetourAttach(&(PVOID&)SysMalloc, NewMalloc);
	DetourAttach(&(PVOID&)SysFree, NewFree);
	DetourAttach(&(PVOID&)SysRealloc, NewRealloc);
	DetourAttach(&(PVOID&)SysNew, CustomNew);
	DetourAttach(&(PVOID&)SysDelete, CustomDelete);
	// ��ȡԭʼ�� delete ��������ַ
	//��������
	DetourTransactionCommit();
}

//�����Ӻ���
void EndHook()
{
	//��ʼdetours����
	DetourTransactionBegin();
	//�����߳���Ϣ 
	DetourUpdateThread(GetCurrentThread());
	//�����صĺ�����ԭ�����ĵ�ַ�Ͻ��
	DetourDetach(&(PVOID&)SysMalloc, NewMalloc);
	DetourDetach(&(PVOID&)SysFree, NewFree);
	DetourAttach(&(PVOID&)SysNew, CustomNew);
	DetourAttach(&(PVOID&)SysDelete, CustomDelete);
	DetourAttach(&(PVOID&)SysRealloc, NewRealloc);
	//����detours����
	DetourTransactionCommit();
	printf("EndHook\n");
}

extern "C"  int InstallSanitizer(SanitizerOption opt)
{
	gwp_asan::options::SetPrintfPath(opt.report_path);

	gwp_asan::options::Options option;
	option.setDefaults();
	option.SampleRate = opt.sample_rate;
	option.MaxSimultaneousAllocations = opt.max_memory_allocations * 128;
	option.Backtrace = gwp_asan::options::getBacktraceFunction();
	option.PrintBacktrace = gwp_asan::options::getPrintBacktraceFunction();
	option.Printf = gwp_asan::options::getPrintfFunction();
	option.ExceptionFilter = opt.exception_filter;
	
	std::vector<MODULEENTRY32> modules = gwp_asan::windbg::SymbolInfoRetriever::GetLoadedModules();
	for (const MODULEENTRY32& module : modules)
	{
		uintptr_t moduleEndAddress = (uintptr_t)module.modBaseAddr + module.modBaseSize;
		option.Printf(L"load module %s at [0x%x - 0x%x] size %d\n", module.szModule, module.modBaseAddr, moduleEndAddress, module.modBaseSize);
		if (wcscmp(module.szModule, opt.module_name) == 0)
		{
			gSanitizerAddressBegin = (DWORD)module.modBaseAddr;
			gSanitizerAddressEnd = moduleEndAddress;
		}
	}

	return allocator->init(option);
}

// DLL ��ڵ㺯��
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call) 
	{
	case DLL_PROCESS_ATTACH:
		// DLL ������ʱִ�еĴ���
		StartHook();
		break;
	case DLL_THREAD_ATTACH:
		// �̱߳�����ʱִ�еĴ���
		
		break;
	case DLL_THREAD_DETACH:
		// �̱߳�����ʱִ�еĴ���
		break;
	case DLL_PROCESS_DETACH:
		// DLL ��ж��ʱִ�еĴ���
		break;
	}

	return TRUE;
}