#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include <windows.h>

uint32_t pe_header_checksum(uint32_t *base, size_t size) {
    uint8_t           *ptr;
    uint32_t          sum = 0;
    size_t            i;

    ptr = (uint8_t *)&((PIMAGE_NT_HEADERS)((uint8_t *)base +
                                ((PIMAGE_DOS_HEADER)base)->e_lfanew))
        ->OptionalHeader.CheckSum;
    
    for (i = 0; i < (size/4); i++) {
        if (i == (((uintptr_t)ptr - (uintptr_t)base)/4))
            continue;
        sum += __builtin_uadd_overflow(base[i],sum,&sum);
    }
    if (size%4)
        sum += base[i];
    
    sum = (sum&0xffff) + (sum>>16);
    sum += (sum>>16);
    sum &= 0xffff;
    return (uint32_t)(sum+size);
}

unsigned long find_rva(unsigned long rva, PIMAGE_SECTION_HEADER section,
                       unsigned short nb_of_section) {
    for (int i = 0; i < nb_of_section; i++) {
        if (rva >= section[i].VirtualAddress &&
            rva < section[i].VirtualAddress + section[i].Misc.VirtualSize)
            return rva - section[i].VirtualAddress + section[i].PointerToRawData;
    }
    return 0;
}

uint8_t *read_file(char *f, size_t *out_size) {
    FILE    *fp;
    uint8_t *ret;
    size_t  buf_size;

    // en r+b pour verif droit d'ecriture
    fp = fopen(f, "r+b");
    if (fp == NULL)
        return NULL;
    fseek(fp, 0, SEEK_END);
    buf_size = ftell(fp);
    rewind(fp);
    ret = malloc(buf_size);
    if (ret == NULL)
        return fclose(fp), NULL;
    fread(ret, 1, buf_size, fp);
    fclose(fp);

    *out_size = buf_size;
    return ret;
}
