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
	unsigned int sample_rate;                   //�������
	unsigned int  max_memory_allocations;        // ��λM
	wchar_t* report_path;					     // �������λ��
	wchar_t* module_name;					     // ���ģ���������Դ���
	LPTOP_LEVEL_EXCEPTION_FILTER exception_filter;  // �쳣�ص� ����

} SanitizerOption, *PSanitizerOption;

// ��ʼ���ڴ�����
extern "C" SANITIZER_DLL_API int InstallSanitizer(SanitizerOption opt);
