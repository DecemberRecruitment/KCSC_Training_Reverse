#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

typedef bool (*CheckFunction)(const char*);

int main() {
    HMODULE hDll = LoadLibrary("KCSC.dll");
    if (hDll == NULL) {
        printf("Failed to load KCSC.dll\n");
        return 1;
    }

    CheckFunction check_func = (CheckFunction)GetProcAddress(hDll, "HelloWorld");
    if (check_func == NULL) {
        printf("Failed to locate function 'HelloWorld'\n");
        FreeLibrary(hDll);
        return 1;
    }

    char input[100];
    printf("Flag: ");
    gets(input);

    int result = check_func(input);
    if (result) printf("Correct :>\n");
    else printf("Wrong :<\n");

    FreeLibrary(hDll);
    return 0;
}
