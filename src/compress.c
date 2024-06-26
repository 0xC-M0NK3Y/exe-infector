#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define __cache_aligned(name) __attribute__((aligned(64))) name

/*******************************************************************************
 * POLAR Coder
 ******************************************************************************/
#define POLAR_SYMBOLS   512 /* should be even */
#define POLAR_MAXLEN    15  /* should be less than 16, so we can pack two length values into a byte */

#define M_round_down(x)     while((x)&(-(x)^(x))) { (x) &= (-(x)^(x)); }
#define M_round_up(x)       while((x)&(-(x)^(x))) { (x) &= (-(x)^(x)); } (x) <<= 1;
#define M_int_swap(x, y)    {int (_)=(x); (x)=(y); (y)=(_);}

int polar_make_leng_table(const int* freq_table, int* leng_table) {
    int symbols[POLAR_SYMBOLS];
    int i;
    int s;
    int total;
    int shift = 0;

    memcpy(leng_table, freq_table, POLAR_SYMBOLS * sizeof(int));

MakeTablePass:
    /* sort symbols */
    for(i = 0; i < POLAR_SYMBOLS; i++) {
        symbols[i] = i;
    }
    for(i = 0; i < POLAR_SYMBOLS; i++) { /* simple gnome sort */
        if(i > 0 && leng_table[symbols[i - 1]] < leng_table[symbols[i]]) {
            M_int_swap(symbols[i - 1], symbols[i]);
            i -= 2;
        }
    }

    /* calculate total frequency */
    total = 0;
    for(i = 0; i < POLAR_SYMBOLS; i++) {
        total += leng_table[i];
    }

    /* run */
    M_round_up(total);
    s = 0;
    for(i = 0; i < POLAR_SYMBOLS; i++) {
        M_round_down(leng_table[i]);
        s += leng_table[i];
    }
    while(s < total) {
        for(i = 0; i < POLAR_SYMBOLS; i++) {
            if(s + leng_table[symbols[i]] <= total) {
                s += leng_table[symbols[i]];
                leng_table[symbols[i]] *= 2;
            }
        }
    }

    /* get code length */
    for(i = 0; i < POLAR_SYMBOLS; i++) {
        s = 2;
        if(leng_table[i] > 0) {
            while((total / leng_table[i]) >> s != 0) {
                s += 1;
            }
            leng_table[i] = s - 1;
        } else {
            leng_table[i] = 0;
        }

        /* code length too long -- scale and rebuild table */
        if(leng_table[i] > POLAR_MAXLEN) {
            shift += 1;
            for(i = 0; i < POLAR_SYMBOLS; i++) {
                if((leng_table[i] = freq_table[i] >> shift) == 0 && freq_table[i] > 0) {
                    leng_table[i] = 1;
                }
            }
            goto MakeTablePass;
        }
    }
    return 0;
}

int polar_make_code_table(const int* leng_table, int* code_table) {
    int i;
    int s;
    int t1;
    int t2;
    int code = 0;

    memset(code_table, 0, POLAR_SYMBOLS * sizeof(int));

    /* make code for each symbol */
    for(s = 1; s <= POLAR_MAXLEN; s++) {
        for(i = 0; i < POLAR_SYMBOLS; i++) {
            if(leng_table[i] == s) {
                code_table[i] = code;
                code += 1;
            }
        }
        code *= 2;
    }

    /* reverse each code */
    for(i = 0; i < POLAR_SYMBOLS; i++) {
        t1 = 0;
        t2 = leng_table[i] - 1;
        while(t1 < t2) {
            code_table[i] ^= (1 & (code_table[i] >> t1)) << t2;
            code_table[i] ^= (1 & (code_table[i] >> t2)) << t1;
            code_table[i] ^= (1 & (code_table[i] >> t1)) << t2;
            t1++;
            t2--;
        }
    }
    return 0;
}

int polar_make_decode_table(const int* leng_table, const int* code_table, int* decode_table) {
    int i;
    int c;

    for(c = 0; c < POLAR_SYMBOLS; c++) {
        if(leng_table[c] > 0) {
            for(i = 0; i + code_table[c] < 65536; i += (1 << leng_table[c])) {
                decode_table[i + code_table[c]] = c;
            }
        }
    }
    return 0;
}

/*******************************************************************************
 * ROLZ
 ******************************************************************************/
#define ROLZ_BUCKET_SIZE    65536
#define MATCH_IDX_SIZE      15  /* make element of rolz_table[] 64 Bytes */
#define MATCH_LEN_MIN       2
#define MATCH_LEN_MAX       17  /* MATCH_LEN_MAX < MATCH_LEN_MIN + (POLAR_SYMBOLS-257) / MATCH_IDX_SIZE */

static unsigned short lastword = 0;
static unsigned short context = 0;

static const unsigned char __cache_aligned(mod15_table)[] = { /* MATCH_IDX_SIZE=15 */
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
};
#define M_rolz_item(x, n) rolz_table[(x)].m_item[mod15_table[rolz_table[(x)].m_head + (n)]]

/* last-char table */
static unsigned char lastchar[65536];

/* rolz table */
static struct {
    unsigned int m_item[MATCH_IDX_SIZE];
    unsigned int m_head;
} __cache_aligned(rolz_table)[ROLZ_BUCKET_SIZE];

static inline void rolz_update_context(unsigned char* buf, int pos, int cache) {
    int new_head;

    /* update rolz table */
    new_head = mod15_table[rolz_table[context].m_head + MATCH_IDX_SIZE - 1];
    rolz_table[context].m_head = new_head;
    rolz_table[context].m_item[new_head] = cache ?
        pos | (buf[pos] << 24) :
        pos;

    /* update last-char table */
    lastchar[lastword] = buf[pos];

    /* update context */
    context = lastword * 13131 + buf[pos];
    lastword <<= 8;
    lastword |= buf[pos];
    return;
}

int rolz_encode(unsigned char* ibuf, unsigned short* obuf, int ilen) {
    int olen = 0;
    int pos = 0;
    int i;
    int j;
    int match_idx;
    int match_len;
    unsigned int  item;
    unsigned char item_chr;
    unsigned int  item_pos;

    memset(rolz_table, 0, sizeof(rolz_table));

    while(pos < ilen) {
        match_len = MATCH_LEN_MIN - 1;
        match_idx = -1;
        if(pos + MATCH_LEN_MAX < ilen) { /* find match */
            for(i = 0; i < MATCH_IDX_SIZE; i++) {
                if((item = M_rolz_item(context, i)) == 0) {
                    break;
                }
                item_chr = item >> 24;
                item_pos = item & 0xffffff;

                if(item_chr == ibuf[pos]) {
                    for(j = 1; j < MATCH_LEN_MAX; j++) {
                        if(ibuf[pos + j] != ibuf[item_pos + j]) {
                            break;
                        }
                    }

                    if(j > match_len) {
                        match_len = j;
                        match_idx = i;
                        if(match_len == MATCH_LEN_MAX) { /* no need to find longer match */
                            break;
                        }
                    }
                }
            }
        }

        if(match_len < MATCH_LEN_MIN) { /* encode */
            if(lastchar[lastword] != ibuf[pos]) { /* last-char match? */
                obuf[olen++] = ibuf[pos];
            } else {
                obuf[olen++] = 511;
            }
            rolz_update_context(ibuf, pos++, 1);

        } else {
            obuf[olen++] = 256 + (match_len - MATCH_LEN_MIN) * MATCH_IDX_SIZE + match_idx;
            while((match_len--) > 0) {
                rolz_update_context(ibuf, pos++, 1);
            }
        }

    }
    return olen;
}

int rolz_decode(unsigned short* ibuf, unsigned char* obuf, int ilen) {
    int olen = 0;
    int pos = 0;
    int match_idx;
    int match_len;
    int match_offset;

    for(pos = 0; pos < ilen; pos++) {
        if(ibuf[pos] == 511) { /* last-char match */
            obuf[olen] = lastchar[lastword];
            rolz_update_context(obuf, olen++, 0);

        } else if(ibuf[pos] < 256) { /* process a literal byte */
            obuf[olen] = ibuf[pos];
            rolz_update_context(obuf, olen++, 0);

        } else { /* process a match */
            match_idx = (ibuf[pos] - 256) % MATCH_IDX_SIZE;
            match_len = (ibuf[pos] - 256) / MATCH_IDX_SIZE + MATCH_LEN_MIN;
            match_offset = olen - M_rolz_item(context, match_idx);

            while((match_len--) > 0) {
                obuf[olen] = obuf[olen - match_offset];
                rolz_update_context(obuf, olen++, 0);
            }
        }
    }
    return olen;
}

#define BLOCK_SIZE_IN  16777216
#define BLOCK_SIZE_OUT 18000000

#include <stdint.h>

uint8_t *compress_buf(uint8_t *buf, size_t bufisze, size_t *out_size) {
    static unsigned char  ibuf[BLOCK_SIZE_IN];
    static unsigned short rbuf[BLOCK_SIZE_IN];
    static unsigned char  obuf[BLOCK_SIZE_OUT];
    uint8_t *ret = NULL;
    uint8_t *p = NULL;
    size_t  ret_size = 0;
    size_t  offset = 0;
    int ilen;
    int rlen;
    int olen;
    int i;
    int freq_table[POLAR_SYMBOLS];
    int leng_table[POLAR_SYMBOLS];
    int code_table[POLAR_SYMBOLS];
    int code_buf;
    int code_len;

    *out_size = 0;

    while (offset < bufisze) {
        memcpy(ibuf, &buf[offset], (sizeof(ibuf)>bufisze)?bufisze:sizeof(ibuf));
        ilen = (sizeof(ibuf)>bufisze)?bufisze:sizeof(ibuf);
        offset += ilen;
        rlen = rolz_encode(ibuf, rbuf, ilen);
        olen = 0;

        memset(freq_table, 0, sizeof(freq_table));
        code_buf = 0;
        code_len = 0;

        for(i = 0; i < rlen; i++) {
            freq_table[rbuf[i]] += 1;
        }
        polar_make_leng_table(freq_table, leng_table);
        polar_make_code_table(leng_table, code_table);

        /* write length table */
        for(i = 0; i < POLAR_SYMBOLS; i += 2) {
            obuf[olen++] = leng_table[i] * 16 + leng_table[i + 1];
        }

        /* encode */
        for(i = 0; i < rlen; i++) {
            code_buf += code_table[rbuf[i]] << code_len;
            code_len += leng_table[rbuf[i]];
            while(code_len > 8) {
                obuf[olen++] = code_buf % 256;
                code_buf /= 256;
                code_len -= 8;
            }
        }
        if(code_len > 0) {
            obuf[olen++] = code_buf;
            code_buf = 0;
            code_len = 0;
        }
        p = realloc(ret, ret_size + sizeof(rlen) + sizeof(olen) + olen);
        if (p == 0)
            return free(ret), NULL;
        ret = p;
        memcpy(&ret[ret_size], &rlen, sizeof(rlen));
        ret_size += sizeof(rlen);
        memcpy(&ret[ret_size], &olen, sizeof(olen));
        ret_size += sizeof(olen);
        memcpy(&ret[ret_size], obuf, olen);
        ret_size += olen;
        *out_size = ret_size;
    }
    return ret;
}
