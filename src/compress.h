#ifndef COMPRESS_H__
# define COMPRESS_H__

#include <stdint.h>
#include <stddef.h>

uint8_t *compress_buf(uint8_t *buf, size_t bufisze, size_t *out_size);

#endif /* compress.h */