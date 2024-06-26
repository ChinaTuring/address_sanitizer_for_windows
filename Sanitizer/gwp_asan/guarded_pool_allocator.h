//===-- guarded_pool_allocator.h --------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef GWP_ASAN_GUARDED_POOL_ALLOCATOR_H_
#define GWP_ASAN_GUARDED_POOL_ALLOCATOR_H_

#include <windows.h>
#include "../options.h"
#include "random.h"
#include "stack_trace_compressor.h"
#include <stddef.h>
#include <stdint.h>
#include <mutex>
#include <thread>
#include <type_traits>
#include "thread/thread_local.h"

#define CurrentThreadVariables(x) \
ThreadLocalPackedVariables* x = GuardedPoolAllocator::ThreadLocals.Get(); \
if (x == nullptr) \
{ \
	x = new ThreadLocalPackedVariables; \
	GuardedPoolAllocator::ThreadLocals.Set(x); \
}

namespace gwp_asan {
	// This class is the primary implementation of the allocator portion of GWP-
	// ASan. It is the sole owner of the pool of sequentially allocated guarded
	// slots. It should always be treated as a singleton.

	// Functions in the public interface of this class are thread-compatible until
	// init() is called, at which point they become thread-safe (unless specified
	// otherwise).
	class GuardedPoolAllocator 
	{
	public:
		static const uint64_t kInvalidThreadID = UINT64_MAX;

		enum class Error 
		{
			UNKNOWN,
			USE_AFTER_FREE,
			DOUBLE_FREE,
			INVALID_FREE,
			BUFFER_OVERFLOW,
			BUFFER_UNDERFLOW
		};

		struct AllocationMetadata
		{
			// The number of bytes used to store a compressed stack frame. On 64-bit
			// platforms, assuming a compression ratio of 50%, this should allow us to
			// store ~64 frames per trace.
			static const size_t kStackFrameStorageBytes = 256;

			// Maximum number of stack frames to collect on allocation/deallocation. The
			// actual number of collected frames may be less than this as the stack
			// frames are compressed into a fixed memory range.
			static const  size_t kMaxTraceLengthToCollect = 128;

			// Records the given allocation metadata into this struct.
			void RecordAllocation(uintptr_t Addr, size_t Size,
				options::Backtrace_t Backtrace);

			// Record that this allocation is now deallocated.
			void RecordDeallocation(options::Backtrace_t Backtrace);

			struct CallSiteInfo 
			{
				// The compressed backtrace to the allocation/deallocation.
				uint8_t CompressedTrace[kStackFrameStorageBytes];
				// The thread ID for this trace, or kInvalidThreadID if not available.
				uint64_t ThreadID = kInvalidThreadID;
				// The size of the compressed trace (in bytes). Zero indicates that no
				// trace was collected.
				size_t TraceSize = 0;
			};

			// The address of this allocation.
			uintptr_t Addr = 0;
			// Represents the actual size of the allocation.
			size_t Size = 0;

			CallSiteInfo AllocationTrace;
			CallSiteInfo DeallocationTrace;

			// Whether this allocation has been deallocated yet.
			bool IsDeallocated = false;
		};

		// During program startup, we must ensure that memory allocations do not land
		// in this allocation pool if the allocator decides to runtime-disable
		// GWP-ASan. The constructor value-initialises the class such that if no
		// further initialisation takes place, calls to shouldSample() and
		// pointerIsMine() will return false.
	    GuardedPoolAllocator(){};
		GuardedPoolAllocator(const GuardedPoolAllocator &) = delete;
		GuardedPoolAllocator &operator=(const GuardedPoolAllocator &) = delete;

		// Note: This class is expected to be a singleton for the lifetime of the
		// program. If this object is initialized, it will leak the guarded page pool
		// and metadata allocations during destruction. We can't clean up these areas
		// as this may cause a use-after-free on shutdown.
		~GuardedPoolAllocator() = default;

		// Initialise the rest of the members of this class. Create the allocation
		// pool using the provided options. See options.inc for runtime configuration
		// options.
		int init(const options::Options &Opts);

		// Return whether the allocation should be randomly chosen for sampling.
		inline bool shouldSample() 
		{
			CurrentThreadVariables(current_thread_variable);
			// NextSampleCounter == 0 means we "should regenerate the counter".
			//                   == 1 means we "should sample this allocation".
			if (current_thread_variable->NextSampleCounter == 0)
			{
				if (--current_thread_variable->SampleTimes > 0)
				{
					return true;
				}
				else
				{
					current_thread_variable->SampleTimes = 10;
					current_thread_variable->NextSampleCounter =
						(getRandomUnsigned32() % AdjustedSampleRate) + 1;
				}

			}
			return --current_thread_variable->NextSampleCounter == 0;
		}

		// Returns whether the provided pointer is a current sampled allocation that
		// is owned by this pool.
		bool  GuardedPoolAllocator::pointerIsMine(const void *Ptr) const
		{
			uintptr_t P = reinterpret_cast<uintptr_t>(Ptr);
			return GuardedPagePool <= P && P < GuardedPagePoolEnd;
		}
		
		// Allocate memory in a guarded slot, and return a pointer to the new
		// allocation. Returns nullptr if the pool is empty, the requested size is too
		// large for this pool to handle, or the requested size is zero.
		void* alloc(size_t Size);

		void* realloc(void* Ptr, size_t Size);

		// Deallocate memory in a guarded slot. The provided pointer must have been
		// allocated using this pool. This will set the guarded slot as inaccessible.
		void dealloc(void *Ptr);

		// Returns the size of the allocation at Ptr.
		size_t getSize(const void *Ptr);

		// Returns the largest allocation that is supported by this pool. Any
		// allocations larger than this should go to the regular system allocator.
		size_t maximumAllocationSize() const;

		// Dumps an error report (including allocation and deallocation stack traces).
		// An optional error may be provided if the caller knows what the error is
		// ahead of time. This is primarily a helper function to locate the static
		// singleton pointer and call the internal version of this function. This
		// method is never thread safe, and should only be called when fatal errors
		// occur.
		static void reportError(uintptr_t AccessPtr, Error E = Error::UNKNOWN);

		// Get the current thread ID, or kInvalidThreadID if failure. Note: This
		// implementation is platform-specific.
		static uint64_t getThreadID();

		void dealwithException(struct _EXCEPTION_POINTERS* exceptions); 

	private:
		static const size_t kInvalidSlotID = SIZE_MAX;

		// These functions anonymously map memory or change the permissions of mapped
		// memory into this process in a platform-specific way. Pointer and size
		// arguments are expected to be page-aligned. These functions will never
		// return on error, instead electing to kill the calling process on failure.
		// Note that memory is initially mapped inaccessible. In order for RW
		// mappings, call mapMemory() followed by markReadWrite() on the returned
		// pointer.
		void *mapMemory(size_t Size) const;
		void markReadWrite(void *Ptr, size_t Size) const;
		void markInaccessible(void *Ptr, size_t Size) const;

		// Get the page size from the platform-specific implementation. Only needs to
		// be called once, and the result should be cached in PageSize in this class.
		static size_t getPlatformPageSize();

		// Install the SIGSEGV crash handler for printing use-after-free and heap-
		// buffer-{under|over}flow exceptions. This is platform specific as even
		// though POSIX and Windows both support registering handlers through
		// signal(), we have to use platform-specific signal handlers to obtain the
		// address that caused the SIGSEGV exception.
		//static void installSignalHandlers();

		// Returns the index of the slot that this pointer resides in. If the pointer
		// is not owned by this pool, the result is undefined.
		size_t addrToSlot(uintptr_t Ptr) const;

		// Returns the address of the N-th guarded slot.
		uintptr_t slotToAddr(size_t N) const;

		// Returns a pointer to the metadata for the owned pointer. If the pointer is
		// not owned by this pool, the result is undefined.
		AllocationMetadata *addrToMetadata(uintptr_t Ptr) const;

		// Returns the address of the page that this pointer resides in.
		uintptr_t getPageAddr(uintptr_t Ptr) const;

		// Gets the nearest slot to the provided address.
		size_t getNearestSlot(uintptr_t Ptr) const;

		// Returns whether the provided pointer is a guard page or not. The pointer
		// must be within memory owned by this pool, else the result is undefined.
		bool isGuardPage(uintptr_t Ptr) const;

		// Reserve a slot for a new guarded allocation. Returns kInvalidSlotID if no
		// slot is available to be reserved.
		size_t reserveSlot();

		// Unreserve the guarded slot.
		void freeSlot(size_t SlotIndex);

		// Returns the offset (in bytes) between the start of a guarded slot and where
		// the start of the allocation should take place. Determined using the size of
		// the allocation and the options provided at init-time.
		uintptr_t allocationSlotOffset(size_t AllocationSize) const;

		// Returns the diagnosis for an unknown error. If the diagnosis is not
		// Error::INVALID_FREE or Error::UNKNOWN, the metadata for the slot
		// responsible for the error is placed in *Meta.
		Error diagnoseUnknownError(uintptr_t AccessPtr, AllocationMetadata **Meta);

		void reportErrorInternal(uintptr_t AccessPtr, Error E);

		// Cached page size for this system in bytes.
		size_t PageSize = 0;

		// A mutex to protect the guarded slot and metadata pool for this class.
		CRITICAL_SECTION  CriticalSection;
		
		// The number of guarded slots that this pool holds.
		size_t MaxSimultaneousAllocations = 0;
		// Record the number allocations that we've sampled. We store this amount so
		// that we don't randomly choose to recycle a slot that previously had an
		// allocation before all the slots have been utilised.
		size_t NumSampledAllocations = 0;
		// Pointer to the pool of guarded slots. Note that this points to the start of
		// the pool (which is a guard page), not a pointer to the first guarded page.
		uintptr_t GuardedPagePool = UINTPTR_MAX;
		uintptr_t GuardedPagePoolEnd = 0;
		// Pointer to the allocation metadata (allocation/deallocation stack traces),
		// if any.
		AllocationMetadata *Metadata = nullptr;

		// Pointer to an array of free slot indexes.
		size_t *FreeSlots = nullptr;
		// The current length of the list of free slots.
		size_t FreeSlotsLength = 0;

		// See options.{h, inc} for more information.
		bool PerfectlyRightAlign = false;

		// Printf function supplied by the implementing allocator. We can't (in
		// general) use printf() from the cstdlib as it may malloc(), causing infinite
		// recursion.
		options::Printf_t Printf = nullptr;
		options::Backtrace_t Backtrace = nullptr;
		options::PrintBacktrace_t PrintBacktrace = nullptr;

		// filter delegate
		LPTOP_LEVEL_EXCEPTION_FILTER ExceptionFilter = nullptr;

		// The adjusted sample rate for allocation sampling. Default *must* be
		// nonzero, as dynamic initialization may call malloc (e.g. from libstdc++)
		// before GPA::init() is called. This would cause an error in shouldSample(),
		// where we would calculate modulo zero. This value is set UINT32_MAX, as when
		// GWP-ASan is disabled, we wish to never spend wasted cycles recalculating
		// the sample rate.
		uint32_t AdjustedSampleRate = UINT32_MAX;
	public:

		static ThreadLocalPointer<ThreadLocalPackedVariables> ThreadLocals;
	};
} // namespace gwp_asan

#endif // GWP_ASAN_GUARDED_POOL_ALLOCATOR_H_
