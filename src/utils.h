#ifndef UTILS_H__
# define UTILS_H__

#include <stdint.h>
#include <stddef.h>

#include <windows.h>

uint32_t pe_header_checksum(uint32_t *base, size_t size);
unsigned long find_rva(unsigned long rva, PIMAGE_SECTION_HEADER section,
                       unsigned short nb_of_section);
uint8_t *read_file(char *f, size_t *out_size);

#endif /* utils.h */
