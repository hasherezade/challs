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
    char *path = "C:\\FlareOn2017\\payload.dll";
    if (argc >= 2) {
        path = argv[1];
    }
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

    std::vector<std::string> names_vec;
    if (peconv::get_exported_names(loaded_pe, names_vec) > 0) {
        const char *first_name = names_vec[0].c_str();
        printf("name: %s\n", first_name);
        exec_func((HMODULE)loaded_pe, const_cast<char *>(first_name));
    }

    peconv::free_pe_buffer(loaded_pe, v_size);
    system("pause");
    return 0;
}
