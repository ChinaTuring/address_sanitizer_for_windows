// Copyright (c) 2011, NetEase Inc. All rights reserved.
//
// Author: SONGMM
// Date: 2024/3/11
//
// This file implements some useful thread local template data structures for Windows

#include "thread_local.h"
#include <windows.h>
#include <assert.h>
namespace gwp_asan
{

// static
void ThreadLocalWindowsPlatform::AllocateSlot(SlotType &slot)
{
	slot = ::TlsAlloc();
	assert(slot != TLS_OUT_OF_INDEXES);
}

// static
void ThreadLocalWindowsPlatform::FreeSlot(SlotType &slot)
{
	if (!::TlsFree(slot))
	{
		assert(false);
	}
}

// static
void* ThreadLocalWindowsPlatform::GetValueFromSlot(SlotType &slot)
{
	return ::TlsGetValue(slot);
}

// static
void ThreadLocalWindowsPlatform::SetValueInSlot(SlotType &slot, void *value)
{
	if (!::TlsSetValue(slot, value))
	{
		assert(false);
	}
}

}  // namespace internal

