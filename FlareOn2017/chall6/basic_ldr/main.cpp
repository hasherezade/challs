#include <stdio.h>
#include <windows.h>

DWORD (*exported_func) (DWORD arg0, DWORD arg1, LPSTR str, DWORD arg3) = NULL;

DWORD exec_func(const char *dll_path, char *checked_str)
{
    HMODULE hLib = LoadLibraryA(dll_path);
    if (hLib == NULL) {
        return -1;
    }
    exported_func = (DWORD (*) (DWORD, DWORD, LPSTR, DWORD)) 
        GetProcAddress(hLib, MAKEINTRESOURCE(1));
    
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

    if (exec_func(path, keyword) == -1) {
        printf("Loading failed\n");
    }
    system("pause");
    return 0;
}
