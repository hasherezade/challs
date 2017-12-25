#include <stdio.h>
#include <windows.h>
#include "peconv.h"

int g_index = 0;

int my_index()
{
    return g_index % 26;
}

int _stdcall my_MessageBoxA(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType)
{
    int key_part = 0;
    int key_id = 0;
    sscanf(lpText,"key[%d] = %x;", &key_id, &key_part);
    printf("%02d : %c\n", key_id, key_part);
    return 0;
}

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
    char *path = NULL;// "C:\\FlareOn2017\\payload.dll";
    if (argc < 3) {
        printf("Args: <path> <index>\n");
        printf("path: path to the crackme\n");
        printf("index: index of the chunk that you want to see\n");
        system("pause");
        return -1;
    }
    path = argv[1];
    g_index = atoi(argv[2]);

    peconv::hooking_func_resolver my_res;
    my_res.add_hook("MessageBoxA", (FARPROC) &my_MessageBoxA);

    size_t v_size = 0;
    BYTE* loaded_pe = peconv::load_pe_executable(
        path, v_size, 
        (peconv::t_function_resolver*) &my_res
        );

    if (!loaded_pe) {
        printf("Loading module failed!\n");
        system("pause");
        return 0;
    }
    ULONGLONG func_offset = (ULONGLONG)loaded_pe + 0x5D30;
    ULONGLONG srand_offset = (ULONGLONG)loaded_pe + 0x7900;
    ULONGLONG rand_offset = (ULONGLONG)loaded_pe + 0x78D4;
    ULONGLONG calc_index_offset = (ULONGLONG)loaded_pe + 0x4710;

    peconv::redirect_to_local64((void*)srand_offset, (ULONGLONG)&srand);
    peconv::redirect_to_local64((void*)rand_offset, (ULONGLONG)&rand);
    peconv::redirect_to_local64((void*)calc_index_offset, (ULONGLONG)&my_index);

    to_overwrite_mem = ( __int64 (__fastcall *)(__int64 ))func_offset;
    __int64 ret = to_overwrite_mem(0);

    std::vector<std::string> names_vec;
    if (peconv::get_exported_names(loaded_pe, names_vec) > 0) {
        const char *first_name = names_vec[0].c_str();
        exec_func((HMODULE)loaded_pe, const_cast<char *>(first_name));
    }
    peconv::free_pe_buffer(loaded_pe, v_size);
    return 0;
}
