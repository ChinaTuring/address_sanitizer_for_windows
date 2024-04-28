// This file implements some useful thread local template data structures

#ifndef GWP_THREAD_THREAD_LOCAL_H_
#define GWP_THREAD_THREAD_LOCAL_H_
#include <stdint.h>

namespace gwp_asan {

	// A macro to disallow the copy constructor and operator= functions
	// This should be used in the private: declarations for a class
#define GWP_DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&);               \
  void operator=(const TypeName&)

// Pack the thread local variables into a struct to ensure that they're in
// the same cache line for performance reasons. These are the most touched
// variables in GWP-ASan.
struct ThreadLocalPackedVariables
{
	//sample times when counter is zero.
	uint32_t SampleTimes = 16;
	// Thread-local decrementing counter that indicates that a given allocation
	// should be sampled when it reaches zero.
	uint32_t NextSampleCounter = 0;
	// Guard against recursion. Unwinders often contain complex behavior that
	// may not be safe for the allocator (i.e. the unwinder calls dlopen(),
	// which calls malloc()). When recursive behaviour is detected, we will
	// automatically fall back to the supporting allocator to supply the
	// allocation.
	bool RecursiveGuard = false;
};


struct ThreadLocalWindowsPlatform
{
	typedef unsigned long SlotType;
	static void AllocateSlot(SlotType &slot);
	static void FreeSlot(SlotType &slot);
	static void* GetValueFromSlot(SlotType &slot);
	static void SetValueInSlot(SlotType &slot, void *value);
};

template<typename Type>
class ThreadLocalPointer
{
public:

	ThreadLocalPointer() : slot_()
	{
		gwp_asan::ThreadLocalWindowsPlatform::AllocateSlot(slot_);
	}

	~ThreadLocalPointer()
	{
		gwp_asan::ThreadLocalWindowsPlatform::FreeSlot(slot_);
	}

	Type* Get()
	{
		return static_cast<Type*>(gwp_asan::ThreadLocalWindowsPlatform::GetValueFromSlot(slot_));
	}

	void Set(Type *ptr)
	{
		gwp_asan::ThreadLocalWindowsPlatform::SetValueInSlot(slot_, ptr);
	}

private:
	typedef gwp_asan::ThreadLocalWindowsPlatform::SlotType SlotType;
	SlotType slot_;

	GWP_DISALLOW_COPY_AND_ASSIGN(ThreadLocalPointer);
};


} // namespace gwp_asan

#endif // GWP_THREAD_THREAD_LOCAL_H_
