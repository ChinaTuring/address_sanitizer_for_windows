//===-- guarded_pool_allocator_posix.cpp ------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#include "../guarded_pool_allocator.h"
#include <windows.h>
#include <processthreadsapi.h>
#include <stdlib.h>
#include <errno.h>

namespace gwp_asan 
{
	void* GuardedPoolAllocator::mapMemory(size_t Size) const
	{
		void *Ptr = VirtualAlloc(nullptr, Size, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
		if (Ptr == NULL) 
		{
			Printf(L"Failed to map guarded pool allocator memory, errno: %d\n", errno);
			Printf(L"  VirtualAlloc(nullptr, %d, ...) failed.\n", Size);
			exit(EXIT_FAILURE);
		}
		return Ptr;
	}
	//即使设置为1字节，也会扩展为整个page页。MSDN说了，如果设置2字节并且这两个字节分别跨越了不同的页，那么这两个页也都会被设置上
	void GuardedPoolAllocator::markReadWrite(void *Ptr, size_t Size) const
	{
		DWORD oldProtect;
		if (!VirtualProtect(Ptr, Size, PAGE_READWRITE, &oldProtect)) 
		{
			Printf(L"Failed to set guarded pool allocator memory at as RW, errno: %d\n",
				errno);
			Printf(L"  VirtualProtect(%p, %d, RW) failed.\n", Ptr, Size);
			exit(EXIT_FAILURE);
		}
	}

	void GuardedPoolAllocator::markInaccessible(void *Ptr, size_t Size) const
	{
		DWORD oldProtect;
		if (!VirtualProtect(Ptr, Size, PAGE_NOACCESS, &oldProtect)) 
		{

			Printf(L"Failed to set guarded pool allocator memory as inaccessible, "
				L"errno: %d\n",
				errno);
			Printf(L"  mmap(%p, %d, NONE, ...) failed.\n", Ptr, Size);
			exit(EXIT_FAILURE);
		}
	}

	size_t GuardedPoolAllocator::getPlatformPageSize()
	{
		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);
		return systemInfo.dwPageSize;
	}

	uint64_t GuardedPoolAllocator::getThreadID() 
	{
		return GetCurrentThreadId();
	}

} // namespace gwp_asan
