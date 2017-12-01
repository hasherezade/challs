#include <stdio.h>
#include <windows.h>
#include "peconv.h"

__int64 (__fastcall *to_overwrite_mem)(__int64 a1) = NULL;

DWORD (*exported_func) (DWORD arg0, DWORD arg1, LPSTR str, DWORD arg3) = NULL;

DWORD exec_func(HMODULE loaded_pe, char *checked_str)
{
    exported_func = (DWORD (*) (DWORD, DWORD, LPSTR, DWORD)) 
        peconv::get_exported_func(loaded_pe, MAKEINTRESOURCE(1));

    if (exported_func == NULL) {
        return -1;
    }
    exported_func(0, 0, checked_str, 0);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Args: <path> <keyword>\n");
        printf("path: path to the crackme\n");
        printf("keyword: the checked keyword (same as the function name)\n");
        system("pause");
        return -1;
    }
    char *path = argv[1]; // "C:\\FlareOn2017\\payload.dll";
    char *keyword = argv[2]; //the keyword will be different in each month

    size_t v_size = 0;
    BYTE* loaded_pe = peconv::load_pe_executable(path, v_size);
    if (!loaded_pe) {
        printf("Loading module failed!\n");
        system("pause");
        return 0;
    }
    ULONGLONG func_offset = (ULONGLONG)loaded_pe + 0x5D30;
    ULONGLONG srand_offset = (ULONGLONG)loaded_pe + 0x7900;
    ULONGLONG rand_offset = (ULONGLONG)loaded_pe + 0x78D4;

    peconv::redirect_to_local64((void*)srand_offset, (ULONGLONG)&srand);
    peconv::redirect_to_local64((void*)rand_offset, (ULONGLONG)&rand);

    to_overwrite_mem = ( __int64 (__fastcall *)(__int64 ))func_offset;
    printf("Call the function:\n");
    __int64 ret = to_overwrite_mem(0);

    exec_func((HMODULE)loaded_pe, keyword);

    peconv::free_pe_buffer(loaded_pe, v_size);
    system("pause");
    return 0;
}