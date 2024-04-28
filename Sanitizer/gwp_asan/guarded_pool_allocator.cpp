//===-- guarded_pool_allocator.cpp ------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "guarded_pool_allocator.h"
#include "optional/backtrace.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <Windows.h>
#include <errhandlingapi.h>
#include "optional/SymboInfoRetriever.h"

using AllocationMetadata = gwp_asan::GuardedPoolAllocator::AllocationMetadata;
using Error = gwp_asan::GuardedPoolAllocator::Error;

namespace gwp_asan 
{
	namespace
	{
		// Forward declare the pointer to the singleton version of this class.
		// Instantiated during initialization, this allows the signal handler
		// to find this class in order to deduce the root cause of failures. Must not be
		// referenced by users outside this translation unit, in order to avoid
		// init-order-fiasco.
		GuardedPoolAllocator *SingletonPtr = nullptr;

		class ScopedBoolean
		{
		public:
			ScopedBoolean(bool &B) : Bool(B) { Bool = true; }
			~ScopedBoolean() { Bool = false; }

		private:
			bool &Bool;
		};

		void defaultPrintStackTrace(uintptr_t *Trace, size_t TraceLength,
			options::Printf_t Printf)
		{
			if (TraceLength == 0)
				Printf(L"  <unknown (does your allocator support backtracing?)>\n");

			for (size_t i = 0; i < TraceLength; ++i) 
			{
				Printf(L"  #%d 0x%x in <unknown>\n", i, Trace[i]);
			}
			Printf(L"\n");
		}
	} // anonymous namespace

	// Gets the singleton implementation of this class. Thread-compatible until
	// init() is called, thread-safe afterwards.
	GuardedPoolAllocator *getSingleton() { return SingletonPtr; }

	LONG WINAPI WinUnhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
	{
		// 获取异常记录
		PEXCEPTION_RECORD exceptionRecord = ExceptionInfo->ExceptionRecord;
		// 如果是访问内存异常
		if (exceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) 
		{
			// 获取引发异常时访问的内存地址
			uintptr_t faultAddr = static_cast<uintptr_t>(exceptionRecord->ExceptionInformation[1]);
			gwp_asan::getSingleton()->reportError(faultAddr);
		}

		gwp_asan::getSingleton()->dealwithException(ExceptionInfo);
		return EXCEPTION_EXECUTE_HANDLER; // 返回值决定如何处理异常，此处示例直接终止程序
	}

	void PreventSetUnhandledExceptionFilter()
	{
		void* addr = (void*)GetProcAddress(LoadLibrary(L"kernel32.dll"),
			"SetUnhandledExceptionFilter");

		if (addr)
		{
			unsigned char code[16];
			int size = 0;

			code[size++] = 0x33;
			code[size++] = 0xC0;
			code[size++] = 0xC2;
			code[size++] = 0x04;
			code[size++] = 0x00;

			DWORD dwOldFlag, dwTempFlag;
			VirtualProtect(addr, size, PAGE_READWRITE, &dwOldFlag);
			WriteProcessMemory(GetCurrentProcess(), addr, code, size, NULL);
			VirtualProtect(addr, size, dwOldFlag, &dwTempFlag);
		}
	}

	void GuardedPoolAllocator::AllocationMetadata::RecordAllocation(
		uintptr_t AllocAddr, size_t AllocSize, options::Backtrace_t Backtrace)
	{
		Addr = AllocAddr;
		Size = AllocSize;
		IsDeallocated = false;

		// TODO(victims): Ask the caller to provide the thread ID, so we don't waste
		// other thread's time getting the thread ID under lock.
		AllocationTrace.ThreadID = getThreadID();
		AllocationTrace.TraceSize = 0;
		DeallocationTrace.TraceSize = 0;
		DeallocationTrace.ThreadID = kInvalidThreadID;

		if (Backtrace)
		{
			uintptr_t UncompressedBuffer[kMaxTraceLengthToCollect];
			size_t BacktraceLength =
				Backtrace(UncompressedBuffer, kMaxTraceLengthToCollect);
			AllocationTrace.TraceSize = compression::pack(
				UncompressedBuffer, BacktraceLength, AllocationTrace.CompressedTrace,
				kStackFrameStorageBytes);
		}
	}

	void GuardedPoolAllocator::AllocationMetadata::RecordDeallocation(
		options::Backtrace_t Backtrace)
	{
		IsDeallocated = true;
		// Ensure that the unwinder is not called if the recursive flag is set,
		// otherwise non-reentrant unwinders may deadlock.
		DeallocationTrace.TraceSize = 0;
		CurrentThreadVariables(current_thread_variable); 
		if (Backtrace && !current_thread_variable->RecursiveGuard)
		{
			ScopedBoolean B(current_thread_variable->RecursiveGuard);
			uintptr_t UncompressedBuffer[kMaxTraceLengthToCollect];
			size_t BacktraceLength =
				Backtrace(UncompressedBuffer, kMaxTraceLengthToCollect);
			DeallocationTrace.TraceSize = compression::pack(
				UncompressedBuffer, BacktraceLength, DeallocationTrace.CompressedTrace,
				kStackFrameStorageBytes);
		}
		DeallocationTrace.ThreadID = getThreadID();
	}

	int GuardedPoolAllocator::init(const options::Options &Opts)
	{
		InitializeCriticalSection(&CriticalSection);
		// Note: We return from the constructor here if GWP-ASan is not available.
		// This will stop heap-allocation of class members, as well as mmap() of the
		// guarded slots.
		if (!Opts.Enabled || Opts.SampleRate == 0 ||
			Opts.MaxSimultaneousAllocations == 0)
			return -1;

		// TODO(victims): Add a death unit test for this.
		if (SingletonPtr)
		{
			(*SingletonPtr->Printf)(
				L"GWP-ASan Error: init() has already been called.\n");
			return -2;
		}

		if (Opts.SampleRate < 0)
		{
			Opts.Printf(L"GWP-ASan Error: SampleRate is < 0.\n");
			return -3;
		}

		if (Opts.SampleRate > INT32_MAX)
		{
			Opts.Printf(L"GWP-ASan Error: SampleRate is > 2^31.\n");
			return -4;
		}

		if (Opts.MaxSimultaneousAllocations < 0) 
		{
			Opts.Printf(L"GWP-ASan Error: MaxSimultaneousAllocations is < 0.\n");
			return -5;
		}

		SingletonPtr = this;

		MaxSimultaneousAllocations = Opts.MaxSimultaneousAllocations;

		PageSize = getPlatformPageSize();
		// 是否要完全右对齐
		PerfectlyRightAlign = Opts.PerfectlyRightAlign;
		Printf = Opts.Printf;
		Backtrace = Opts.Backtrace;
		ExceptionFilter = Opts.ExceptionFilter;

		if (Opts.PrintBacktrace)
			PrintBacktrace = Opts.PrintBacktrace;
		else
			PrintBacktrace = defaultPrintStackTrace;
		//
		// Get a handle to the default process heap.
		//
		size_t PoolBytesRequired =
			PageSize * (1 + MaxSimultaneousAllocations) +
			MaxSimultaneousAllocations * maximumAllocationSize();
		void *GuardedPoolMemory = mapMemory(PoolBytesRequired);

		size_t BytesRequired = MaxSimultaneousAllocations * sizeof(*Metadata);
		Metadata = reinterpret_cast<AllocationMetadata *>(mapMemory(BytesRequired));
		markReadWrite(Metadata, BytesRequired);

		// Allocate memory and set up the free pages queue.
		BytesRequired = MaxSimultaneousAllocations * sizeof(*FreeSlots);
		FreeSlots = reinterpret_cast<size_t *>(mapMemory(BytesRequired));
		markReadWrite(FreeSlots, BytesRequired);

		// Multiply the sample rate by 2 to give a good, fast approximation for (1 /
		// SampleRate) chance of sampling.
		if (Opts.SampleRate != 1)
			AdjustedSampleRate = static_cast<uint32_t>(Opts.SampleRate) * 2;
		else
			AdjustedSampleRate = 1;

		GuardedPagePool = reinterpret_cast<uintptr_t>(GuardedPoolMemory);
		GuardedPagePoolEnd =
			reinterpret_cast<uintptr_t>(GuardedPoolMemory)+PoolBytesRequired;

		Printf(L"******PagePool Adress:[0x%x,0x%x]********\n", GuardedPagePool, GuardedPagePoolEnd);
		// Ensure that signal handlers are installed as late as possible, as the class
		// is not thread-safe until init() is finished, and thus a SIGSEGV may cause a
		// race to members if received during init().
		if (Opts.InstallExceptionHandlers)
		{
			SetUnhandledExceptionFilter(WinUnhandledExceptionFilter);
			PreventSetUnhandledExceptionFilter();
		}

		return 0;
	}

	void* GuardedPoolAllocator::alloc(size_t Size)
	{
		// GuardedPagePoolEnd == 0 when GWP-ASan is disabled. If we are disabled, fall
		// back to the supporting allocator.
		if (GuardedPagePoolEnd == 0)
			return nullptr;

		ThreadLocalPackedVariables* current_thread_variables = GuardedPoolAllocator::ThreadLocals.Get();
		// Protect against recursivity.
		if (current_thread_variables->RecursiveGuard)
			return nullptr;

		ScopedBoolean SB(current_thread_variables->RecursiveGuard);

		if (Size == 0 || Size > maximumAllocationSize())
		{
			Printf(L"Alloc Size too large:%d\n", Size);
			return nullptr;
		}

		if (!shouldSample())
		{
			return nullptr;
		}

		size_t Index;
		{
			EnterCriticalSection(&CriticalSection);
			Index = reserveSlot();
			LeaveCriticalSection(&CriticalSection);
		}

		if (Index == kInvalidSlotID)
			return nullptr;

		uintptr_t Ptr = slotToAddr(Index);
		Ptr += allocationSlotOffset(Size);
		AllocationMetadata *Meta = addrToMetadata(Ptr);
		// If a slot is multiple pages in size, and the allocation takes up a single
		// page, we can improve overflow detection by leaving the unused pages as
		// unmapped.
		markReadWrite(reinterpret_cast<void *>(getPageAddr(Ptr)), Size);
		Meta->RecordAllocation(Ptr, Size, Backtrace);
		return reinterpret_cast<void *>(Ptr);
	}

	void* GuardedPoolAllocator::realloc(void* Ptr, size_t Size)
	{
		if (GuardedPagePoolEnd == 0)
			return nullptr;

		ThreadLocalPackedVariables* current_thread_variables = GuardedPoolAllocator::ThreadLocals.Get();
		// Protect against recursivity.
		if (current_thread_variables->RecursiveGuard)
			return nullptr;

		ScopedBoolean SB(current_thread_variables->RecursiveGuard);

		if (Size == 0 || Size > maximumAllocationSize())
		{
			Printf(L"Realloc Size too large:%d\n", Size);
			return nullptr;
		}

		uintptr_t UPtr = reinterpret_cast<uintptr_t>(Ptr);
		uintptr_t SlotStart = slotToAddr(addrToSlot(UPtr));
		AllocationMetadata *Meta = addrToMetadata(UPtr);
		//地址发生了变化，则是无效的删除
		if (Meta->Addr != UPtr) {
			reportError(UPtr, Error::INVALID_FREE);
			exit(EXIT_FAILURE);
		}
		uintptr_t new_address = SlotStart;
		new_address += allocationSlotOffset(Size);
		markReadWrite(reinterpret_cast<void *>(new_address), maximumAllocationSize());
		memcpy(reinterpret_cast<void *>(new_address), reinterpret_cast<void *>(Meta->Addr), Meta->Size);
		Meta->RecordAllocation(new_address, Size, Backtrace);

		return reinterpret_cast<void *>(new_address);
	}

	void GuardedPoolAllocator::dealloc(void *Ptr)
	{
		assert(pointerIsMine(Ptr) && "Pointer is not mine!");
		uintptr_t UPtr = reinterpret_cast<uintptr_t>(Ptr);
		uintptr_t SlotStart = slotToAddr(addrToSlot(UPtr));
		AllocationMetadata *Meta = addrToMetadata(UPtr);
		//地址发生了变化，则是无效的删除
		if (Meta->Addr != UPtr) 
		{
			reportError(UPtr, Error::INVALID_FREE);
			exit(EXIT_FAILURE);
		}

		// Intentionally scope the mutex here, so that other threads can access the
		// pool during the expensive markInaccessible() call.
		  {

			  if (Meta->IsDeallocated)
			  {
				  reportError(UPtr, Error::DOUBLE_FREE);
				  exit(EXIT_FAILURE);
			  }
			  // Ensure that the deallocation is recorded before marking the page as
			  // inaccessible. Otherwise, a racy use-after-free will have inconsistent
			  // metadata.
			  Meta->RecordDeallocation(Backtrace);
		  }
		  markReadWrite((void*)SlotStart, maximumAllocationSize());
		  markInaccessible(reinterpret_cast<void *>(SlotStart),
			  maximumAllocationSize());
		  // And finally, lock again to release the slot back into the pool.
		  EnterCriticalSection(&CriticalSection);
		  freeSlot(addrToSlot(UPtr));
		  LeaveCriticalSection(&CriticalSection);
	}

	size_t GuardedPoolAllocator::getSize(const void *Ptr)
	{
		assert(pointerIsMine(Ptr));
		EnterCriticalSection(&CriticalSection);
		AllocationMetadata *Meta = addrToMetadata(reinterpret_cast<uintptr_t>(Ptr));
		assert(Meta->Addr == reinterpret_cast<uintptr_t>(Ptr));
		LeaveCriticalSection(&CriticalSection);
		return Meta->Size;
	}

	size_t GuardedPoolAllocator::maximumAllocationSize() const { return PageSize; }

	AllocationMetadata *GuardedPoolAllocator::addrToMetadata(uintptr_t Ptr) const
	{
		return &Metadata[addrToSlot(Ptr)];
	}

	// 判断当前ptr落在第几个slot里面
	size_t GuardedPoolAllocator::addrToSlot(uintptr_t Ptr) const
	{
		assert(pointerIsMine(reinterpret_cast<void *>(Ptr)));
		size_t ByteOffsetFromPoolStart = Ptr - GuardedPagePool;
		return ByteOffsetFromPoolStart / (maximumAllocationSize() + PageSize);
	}

	// 获取slot 对应pool的首地址，地址 = pool_start + (n+1) * guardpage + n * slot
	uintptr_t GuardedPoolAllocator::slotToAddr(size_t N) const
	{
		return GuardedPagePool + (PageSize * (1 + N)) + (maximumAllocationSize() * N);
	}

	//内存页对齐
	uintptr_t GuardedPoolAllocator::getPageAddr(uintptr_t Ptr) const
	{
		assert(pointerIsMine(reinterpret_cast<void *>(Ptr)));
		return Ptr & ~(static_cast<uintptr_t>(PageSize)-1);
	}

	//判断是否是受保护页，由于插入的页堆是理论是系统的页大小，分配的页是系统页大小的整数倍
	bool GuardedPoolAllocator::isGuardPage(uintptr_t Ptr) const
	{
		assert(pointerIsMine(reinterpret_cast<void *>(Ptr)));
		size_t PageOffsetFromPoolStart = (Ptr - GuardedPagePool) / PageSize;
		size_t PagesPerSlot = maximumAllocationSize() / PageSize;
		return (PageOffsetFromPoolStart % (PagesPerSlot + 1)) == 0;
	}

	size_t GuardedPoolAllocator::reserveSlot()
	{
		// Avoid potential reuse of a slot before we have made at least a single
		// allocation in each slot. Helps with our use-after-free detection.
		if (NumSampledAllocations < MaxSimultaneousAllocations)
			return NumSampledAllocations++;

		if (FreeSlotsLength == 0)
			return kInvalidSlotID;
		// 自动调整搜索空间，这个操作比较遛
		size_t ReservedIndex = getRandomUnsigned32() % FreeSlotsLength;
		size_t SlotIndex = FreeSlots[ReservedIndex];
		FreeSlots[ReservedIndex] = FreeSlots[--FreeSlotsLength];
		return SlotIndex;
	}

	void GuardedPoolAllocator::freeSlot(size_t SlotIndex)
	{
		assert(FreeSlotsLength < MaxSimultaneousAllocations);
		FreeSlots[FreeSlotsLength++] = SlotIndex;
	}

	// 如果是右对齐的话，需要调整指针位置
	uintptr_t GuardedPoolAllocator::allocationSlotOffset(size_t Size) const
	{
		assert(Size > 0);

		uintptr_t Offset = maximumAllocationSize();
		// 如果不是完整的右对齐，则预留2的倍数空间
		if (!PerfectlyRightAlign)
		{
			if (Size <= 4)
				Size = 4;
			else if (Size < 8)
				Size = 8;
			else if (Size > 8 && (Size % 16) != 0)
				Size += 16 - (Size % 16);
		}

		Offset -= Size;
		return Offset;
	}

	void GuardedPoolAllocator::reportError(uintptr_t AccessPtr, Error E)
	{
		if (SingletonPtr)
			SingletonPtr->reportErrorInternal(AccessPtr, E);
	}

	void GuardedPoolAllocator::dealwithException(struct _EXCEPTION_POINTERS* exceptions)
	{
		if (ExceptionFilter)
		{
			ExceptionFilter(exceptions);
		}
	}

	size_t GuardedPoolAllocator::getNearestSlot(uintptr_t Ptr) const
	{
		if (Ptr <= GuardedPagePool + PageSize)
			return 0;
		if (Ptr > GuardedPagePoolEnd - PageSize)
			return MaxSimultaneousAllocations - 1;

		if (!isGuardPage(Ptr))
			return addrToSlot(Ptr);

		if (Ptr % PageSize <= PageSize / 2)
			return addrToSlot(Ptr - PageSize); // Round down.
		return addrToSlot(Ptr + PageSize);   // Round up.
	}

	Error GuardedPoolAllocator::diagnoseUnknownError(uintptr_t AccessPtr,
		AllocationMetadata **Meta)
	{
		// Let's try and figure out what the source of this error is.
		if (isGuardPage(AccessPtr))
		{
			size_t Slot = getNearestSlot(AccessPtr);
			AllocationMetadata *SlotMeta = addrToMetadata(slotToAddr(Slot));

			// Ensure that this slot was allocated once upon a time.
			if (!SlotMeta->Addr)
				return Error::UNKNOWN;
			*Meta = SlotMeta;

			if (SlotMeta->Addr < AccessPtr)
				return Error::BUFFER_OVERFLOW;
			return Error::BUFFER_UNDERFLOW;
		}

		// Access wasn't a guard page, check for use-after-free.
		AllocationMetadata *SlotMeta = addrToMetadata(AccessPtr);
		if (SlotMeta->IsDeallocated)
		{
			*Meta = SlotMeta;
			return Error::USE_AFTER_FREE;
		}

		// If we have reached here, the error is still unknown. There is no metadata
		// available.
		*Meta = nullptr;
		return Error::UNKNOWN;
	}

	namespace 
	{
		// Prints the provided error and metadata information.
		void printErrorType(Error E, uintptr_t AccessPtr, AllocationMetadata *Meta,
			options::Printf_t Printf, uint64_t ThreadID)
		{
			// Print using intermediate strings. Platforms like Android don't like when
			// you print multiple times to the same line, as there may be a newline
			// appended to a log file automatically per Printf(L) call.
			const wchar_t *ErrorString;
			switch (E)
			{
			case Error::UNKNOWN:
				ErrorString = L"GWP-ASan couldn't automatically determine the source of "
					L"the memory error. It was likely caused by a wild memory "
					L"access into the GWP-ASan pool. The error occurred";
				break;
			case Error::USE_AFTER_FREE:
				ErrorString = L"Use after free";
				break;
			case Error::DOUBLE_FREE:
				ErrorString = L"Double free";
				break;
			case Error::INVALID_FREE:
				ErrorString = L"Invalid (wild) free";
				break;
			case Error::BUFFER_OVERFLOW:
				ErrorString = L"Buffer overflow";
				break;
			case Error::BUFFER_UNDERFLOW:
				ErrorString = L"Buffer underflow";
				break;
			default:
				ErrorString = L"Unknow Error";
				break;
			}

			const size_t kDescriptionBufferLen = 128;
			wchar_t DescriptionBuffer[kDescriptionBufferLen];
			if (Meta) 
			{
				if (E == Error::USE_AFTER_FREE) 
				{
					swprintf_s(DescriptionBuffer, kDescriptionBufferLen,
						L"(%d byte%s into a %d-byte allocation at 0x%x)",
						AccessPtr - Meta->Addr, (AccessPtr - Meta->Addr == 1) ? L"" : L"s",
						Meta->Size, Meta->Addr);
				}
				else if (AccessPtr < Meta->Addr) 
				{
					swprintf_s(DescriptionBuffer, kDescriptionBufferLen,
						L"(%d byte%s to the left of a %d-byte allocation at 0x%x)",
						Meta->Addr - AccessPtr, (Meta->Addr - AccessPtr == 1) ? L"" : L"s",
						Meta->Size, Meta->Addr);
				}
				else if (AccessPtr > Meta->Addr)
				{
					swprintf_s(DescriptionBuffer, kDescriptionBufferLen,
						L"(%d byte%s to the right of a %d-byte allocation at 0x%x)",
						AccessPtr - Meta->Addr, (AccessPtr - Meta->Addr == 1) ? L"" : L"s",
						Meta->Size, Meta->Addr);
				}
				else 
				{
					swprintf_s(DescriptionBuffer, kDescriptionBufferLen,
						L"(a %d-byte allocation)", Meta->Size);
				}
			}

			// Possible number of digits of a 64-bit number: ceil(log10(2^64)) == 20. Add
			// a null terminator, and round to the nearest 8-byte boundary.
			const size_t kThreadBufferLen = 24;
			wchar_t ThreadBuffer[kThreadBufferLen];
			if (ThreadID == GuardedPoolAllocator::kInvalidThreadID)
				swprintf_s(ThreadBuffer, kThreadBufferLen, L"<unknown>");
			else
				swprintf_s(ThreadBuffer, kThreadBufferLen, L"%ld", ThreadID);

			Printf(L"%s at 0x%x %s by thread %s here:\n", ErrorString, AccessPtr,
				DescriptionBuffer, ThreadBuffer);
		}

		void printAllocDeallocTraces(uintptr_t AccessPtr, AllocationMetadata *Meta,
			options::Printf_t Printf,
			options::PrintBacktrace_t PrintBacktrace)
		{
			assert(Meta != nullptr && "Metadata is non-null for printAllocDeallocTraces");

			if (Meta->AllocationTrace.ThreadID == GuardedPoolAllocator::kInvalidThreadID)
				Printf(L"0x%x was allocated by thread <unknown> here:\n", Meta->Addr);
			else
				Printf(L"0x%x was allocated by thread %d here:\n", Meta->Addr,
				Meta->AllocationTrace.ThreadID);

			uintptr_t UncompressedTrace[AllocationMetadata::kMaxTraceLengthToCollect];
			size_t UncompressedLength = compression::unpack(
				Meta->AllocationTrace.CompressedTrace, Meta->AllocationTrace.TraceSize,
				UncompressedTrace, AllocationMetadata::kMaxTraceLengthToCollect);

			PrintBacktrace(UncompressedTrace, UncompressedLength, Printf);
		}

		struct ScopedEndOfReportDecorator 
		{
			ScopedEndOfReportDecorator(options::Printf_t Printf) : Printf(Printf) {}
			~ScopedEndOfReportDecorator() { Printf(L"*** End GWP-ASan report ***\n"); }
			options::Printf_t Printf;
		};
	} // anonymous namespace

	void GuardedPoolAllocator::reportErrorInternal(uintptr_t AccessPtr, Error E)
	{
		if (!pointerIsMine(reinterpret_cast<void *>(AccessPtr))) 
		{
			Printf(L"Exception Pointer [0x%x] Is not Mine\n", AccessPtr);
			return;
		}

		// Attempt to prevent races to re-use the same slot that triggered this error.
		// This does not guarantee that there are no races, because another thread can
		// take the locks during the time that the signal handler is being called.
		ThreadLocalPackedVariables* current_thread = GuardedPoolAllocator::ThreadLocals.Get();
		current_thread->RecursiveGuard = true;
		Printf(L"*** GWP-ASan detected a memory error ***\n");

		ScopedEndOfReportDecorator Decorator(Printf);

		AllocationMetadata *Meta = nullptr;

		if (E == Error::UNKNOWN) 
		{
			E = diagnoseUnknownError(AccessPtr, &Meta);
		}
		else 
		{
			size_t Slot = getNearestSlot(AccessPtr);
			Meta = addrToMetadata(slotToAddr(Slot));
			// Ensure that this slot has been previously allocated.
			if (!Meta->Addr)
				Meta = nullptr;
		}

		// Print the error information.
		uint64_t ThreadID = getThreadID();
		printErrorType(E, AccessPtr, Meta, Printf, ThreadID);
		if (Backtrace) 
		{
			const static  unsigned kMaximumStackFramesForCrashTrace = 512;
			uintptr_t Trace[kMaximumStackFramesForCrashTrace];
			size_t TraceLength = Backtrace(Trace, kMaximumStackFramesForCrashTrace);

			PrintBacktrace(Trace, TraceLength, Printf);
		}
		else 
		{
			Printf(L"  <unknown (does your allocator support backtracing?)>\n\n");
		}

		if (Meta)
			printAllocDeallocTraces(AccessPtr, Meta, Printf, PrintBacktrace);
	}

	ThreadLocalPointer<ThreadLocalPackedVariables> GuardedPoolAllocator::ThreadLocals;
} // namespace gwp_asan
