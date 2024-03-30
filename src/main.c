#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>

#include <windows.h>

#include "injector.h"

int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("Usage: <path_to_inject> <exe_to_inject>\n");
        return 1;
    }
    if (inject_in_exe(argv[1], argv[2]) < 0) {
        printf("Error injecting in exe\n");
        return 1;
    }
    return 0;
}
