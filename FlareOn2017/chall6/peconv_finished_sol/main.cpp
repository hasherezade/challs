#include <stdio.h>
#include <windows.h>
#include "peconv.h"

const size_t g_flagLen = 26;
char g_flag[g_flagLen + 1] = { 0 };

int my_index()
{
    static int index = 0;
    return (index++) % g_flagLen;
}

int _stdcall my_MessageBoxA(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType)
{
    BYTE key_part = 0;
    int key_id = 0;
    sscanf(lpText,"key[%d] = %x;", &key_id, &key_part);
    g_flag[key_id] = key_part;
    return 0;
}

DWORD exec_func(HMODULE loaded_pe, char *checked_str)
{
    DWORD (*exported_func) (DWORD arg0, DWORD arg1, LPSTR str, DWORD arg3) = NULL;
    exported_func = (DWORD (*) (DWORD, DWORD, LPSTR, DWORD)) 
        peconv::get_exported_func(loaded_pe, MAKEINTRESOURCE(1));

    if (exported_func == NULL) {
        return -1;
    }
    exported_func(0, 0, checked_str, 0);
    return 0;
}

bool load_next_char(const char *path)
{
    peconv::hooking_func_resolver my_res;
    my_res.add_hook("MessageBoxA", (FARPROC) &my_MessageBoxA);

    size_t v_size = 0;
    BYTE* loaded_pe = peconv::load_pe_executable(
        path, v_size, 
        (peconv::t_function_resolver*) &my_res
        );

    if (!loaded_pe) {
        printf("Loading module failed!\n");
        return false;
    }
    ULONGLONG func_offset = (ULONGLONG)loaded_pe + 0x5D30;
    ULONGLONG srand_offset = (ULONGLONG)loaded_pe + 0x7900;
    ULONGLONG rand_offset = (ULONGLONG)loaded_pe + 0x78D4;
    ULONGLONG calc_index_offset = (ULONGLONG)loaded_pe + 0x4710;

    peconv::redirect_to_local64((void*)srand_offset, (ULONGLONG)&srand);
    peconv::redirect_to_local64((void*)rand_offset, (ULONGLONG)&rand);
    peconv::redirect_to_local64((void*)calc_index_offset, (ULONGLONG)&my_index);

    __int64 (__fastcall *to_overwrite_mem)(__int64 a1) = NULL;
    to_overwrite_mem = ( __int64 (__fastcall *)(__int64 ))func_offset;
    __int64 ret = to_overwrite_mem(0);

    std::vector<std::string> names_vec;
    if (peconv::get_exported_names(loaded_pe, names_vec) > 0) {
        const char *first_name = names_vec[0].c_str();
        exec_func((HMODULE)loaded_pe, const_cast<char *>(first_name));
    }
    peconv::free_pe_buffer(loaded_pe, v_size);
    return true;
}

int main(int argc, char *argv[])
{
    char *path = NULL; //i.e. "C:\\FlareOn2017\\payload.dll"
    if (argc < 2) {
        printf("Args: <path>\n");
        printf("path: path to the crackme (FlareOn2017 chall6: payload.dll)\n");
        system("pause");
        return -1;
    }

    path = argv[1];
    for (int i = 0; i < 26; i++) {
        if (!load_next_char(path)) break;
    }
    printf("Flag:\n%s\n", g_flag);
    system("pause");
    return 0;
}
