#ifdef SANITIZER_DLL_EXPORT
#define SANITIZER_DLL_API __declspec(dllexport)
#else
#define SANITIZER_DLL_API __declspec(dllimport)
#endif

#include <stddef.h>
#include <stdint.h>
#include <errhandlingapi.h>

typedef struct _SanitizerOption
{
	unsigned int sample_rate;                   //采样间隔
	unsigned int  max_memory_allocations;        // 单位M
	wchar_t* report_path;					     // 报告输出位置
	wchar_t* module_name;					     // 监测模块名，可以传空
	LPTOP_LEVEL_EXCEPTION_FILTER exception_filter;  // 异常回调 函数

} SanitizerOption, *PSanitizerOption;

// 初始化内存监测器
extern "C" SANITIZER_DLL_API int InstallSanitizer(SanitizerOption opt);
