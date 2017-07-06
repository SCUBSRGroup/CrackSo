/*
 * Copyright (C) 2008, 2009 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* 这些是原始的头文件 */
// #include <dlfcn.h>
// #include <errno.h>
// #include <fcntl.h>
// #include <linux/auxvec.h>
// #include <pthread.h>
// #include <stdbool.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/atomics.h>
// #include <sys/mman.h>
// #include <sys/stat.h>
// #include <unistd.h>

// // Private C library headers.
// #include <private/bionic_tls.h>
// #include <private/logd.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <errno.h>

#include "linker_debug.h"
#include "linker_environ.h"
#include "linker_format.h"
#include "linker_phdr.h"
#include "linker.h"
#include "xdlfcn.h"
#include "crc.h"
#include "options.h"


struct elfinfo_t {
	unsigned done;
	unsigned dynamic_offset;          /* PT_DYNAMIC段的文件/内存偏移 */
	unsigned dynamic_size;            /* PT_DYNAMIC段的长度 */

	unsigned dt_hash_offset;          /* DT_HASH节的文件/内存偏移 */
	unsigned dt_symtab_offset;        /* DT_SYMTAB节的文件/内存偏移 */
	unsigned dt_strtab_offset;        /* DT_STRTAB节的文件/内存偏移 */
};

struct elfinfo_t g_infos;
struct options_t* g_opts = NULL;

#define ALLOW_SYMBOLS_FROM_MAIN 1
#define SO_MAX 128

/* Assume average path length of 64 and max 8 paths */
#define LDPATH_BUFSIZE 512
#define LDPATH_MAX 8

#define LDPRELOAD_BUFSIZE 512
#define LDPRELOAD_MAX 8

/* >>> IMPORTANT NOTE - READ ME BEFORE MODIFYING <<<
 *
 * Do NOT use malloc() and friends or pthread_*() code here.
 * Don't use printf() either; it's caused mysterious memory
 * corruption in the past.
 * The linker runs before we bring up libc and it's easiest
 * to make sure it does not depend on any complex libc features
 *
 * open issues / todo:
 *
 * - are we doing everything we should for ARM_COPY relocations?
 * - cleaner error reporting
 * - after linking, set as much stuff as possible to READONLY
 *   and NOEXEC
 * - linker hardcodes PAGE_SIZE and PAGE_MASK because the kernel
 *   headers provide versions that are negative...
 * - allocate space for soinfo structs dynamically instead of
 *   having a hard limit (SO_MAX)
 */

/********************************************************************************/
#if defined(ANDROID_ARM_LINKER)
//                     0000000 00011111 111112 22222222 2333333 333344444444445555555
//                     0123456 78901234 567890 12345678 9012345 678901234567890123456
#define ANDROID_LIBDL_STRTAB											\
	"dlopen\0dlclose\0dlsym\0dlerror\0dladdr\0dl_unwind_find_exidx\0"

#elif defined(ANDROID_X86_LINKER) || defined(ANDROID_MIPS_LINKER)
//                     0000000 00011111 111112 22222222 2333333 3333444444444455
//                     0123456 78901234 567890 12345678 9012345 6789012345678901
#define ANDROID_LIBDL_STRTAB										\
	"dlopen\0dlclose\0dlsym\0dlerror\0dladdr\0dl_iterate_phdr\0"
#else
#error Unsupported architecture. Only ARM, MIPS, and x86 are presently supported.
#endif

#ifdef ANDROID_ARM_LINKER

/* For a given PC, find the .so that it belongs to.
 * Returns the base address of the .ARM.exidx section
 * for that .so, and the number of 8-byte entries
 * in that section (via *pcount).
 *
 * Intended to be called by libc's __gnu_Unwind_Find_exidx().
 *
 * This function is exposed via dlfcn.c and libdl.so.
 */
_Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int *pcount);
#elif defined(ANDROID_X86_LINKER) || defined(ANDROID_MIPS_LINKER)
int
_Unwind_Ptr dl_iterate_phdr(int (*cb)(dl_phdr_info *info, size_t size, void *data),
							void *data);
#endif

#define MAX_LIBDL_SYMTAB      0x10
static Elf32_Sym libdl_symtab[MAX_LIBDL_SYMTAB]; // = {
//       // total length of libdl_info.strtab, including trailing 0
//       // This is actually the the STH_UNDEF entry. Technically, it's
//       // supposed to have st_name == 0, but instead, it points to an index
//       // in the strtab with a \0 to make iterating through the symtab easier.
//     { st_name: sizeof(ANDROID_LIBDL_STRTAB) - 1,
//     },
//     { st_name: 0,   // starting index of the name in libdl_info.strtab
//       st_value: (Elf32_Addr) &dlopen,
//       st_info: STB_GLOBAL << 4,
//       st_shndx: 1,
//     },
//     { st_name: 7,
//       st_value: (Elf32_Addr) &dlclose,
//       st_info: STB_GLOBAL << 4,
//       st_shndx: 1,
//     },
//     { st_name: 15,
//       st_value: (Elf32_Addr) &dlsym,
//       st_info: STB_GLOBAL << 4,
//       st_shndx: 1,
//     },
//     { st_name: 21,
//       st_value: (Elf32_Addr) &dlerror,
//       st_info: STB_GLOBAL << 4,
//       st_shndx: 1,
//     },
//     { st_name: 29,
//       st_value: (Elf32_Addr) &dladdr,
//       st_info: STB_GLOBAL << 4,
//       st_shndx: 1,
//     },
// #ifdef ANDROID_ARM_LINKER
//     { st_name: 36,
//       st_value: (Elf32_Addr) &dl_unwind_find_exidx,
//       st_info: STB_GLOBAL << 4,
//       st_shndx: 1,
//     },
// #elif defined(ANDROID_X86_LINKER) || defined(ANDROID_MIPS_LINKER)
//     { st_name: 36,
//       st_value: (Elf32_Addr) &dl_iterate_phdr,
//       st_info: STB_GLOBAL << 4,
//       st_shndx: 1,
//     },
// #endif
// };

typedef uint16_t Elf32_Section;
static void fill_libdl_symtab_entry(Elf32_Sym* obj, Elf32_Word name, Elf32_Addr val, unsigned char info, Elf32_Section shndx) {
	obj->st_name = name;
	obj->st_value = val;
	obj->st_info = info;
	obj->st_shndx = shndx;
}
	
void fill_libdl_symtab() {
	// total length of libdl_info.strtab, including trailing 0
	// This is actually the the STH_UNDEF entry. Technically, it's
	// supposed to have st_name == 0, but instead, it points to an index
	// in the strtab with a \0 to make iterating through the symtab easier.
	fill_libdl_symtab_entry(&libdl_symtab[0], sizeof(ANDROID_LIBDL_STRTAB) - 1, 0, 0, 0);
	fill_libdl_symtab_entry(&libdl_symtab[1], 0, (Elf32_Addr) &dlopen, STB_GLOBAL << 4, 1);
	fill_libdl_symtab_entry(&libdl_symtab[2], 7, (Elf32_Addr) &dlclose, STB_GLOBAL << 4, 1);
	fill_libdl_symtab_entry(&libdl_symtab[3], 15, (Elf32_Addr) &dlsym, STB_GLOBAL << 4, 1);
	fill_libdl_symtab_entry(&libdl_symtab[4], 21, (Elf32_Addr) &dlerror, STB_GLOBAL << 4, 1);
	fill_libdl_symtab_entry(&libdl_symtab[5], 29, (Elf32_Addr) &dladdr, STB_GLOBAL << 4, 1);
#if defined(ANDROID_ARM_LINKER)
	fill_libdl_symtab_entry(&libdl_symtab[6], 36, (Elf32_Addr) &dl_unwind_find_exidx, STB_GLOBAL << 4, 1);
#elif defined(ANDROID_X86_LINKER) || defined(ANDROID_MIPS_LINKER)
	fill_libdl_symtab_entry(&libdl_symtab[6], 36, (Elf32_Addr) &dl_iterate_phdr, STB_GLOBAL << 4, 1);
#endif
}

/* Fake out a hash table with a single bucket.
 * A search of the hash table will look through
 * libdl_symtab starting with index [1], then
 * use libdl_chains to find the next index to
 * look at.  libdl_chains should be set up to
 * walk through every element in libdl_symtab,
 * and then end with 0 (sentinel value).
 *
 * I.e., libdl_chains should look like
 * { 0, 2, 3, ... N, 0 } where N is the number
 * of actual symbols, or nelems(libdl_symtab)-1
 * (since the first element of libdl_symtab is not
 * a real symbol).
 *
 * (see _elf_lookup())
 *
 * Note that adding any new symbols here requires
 * stubbing them out in libdl.
 */
static unsigned libdl_buckets[1] = { 1 };
static unsigned libdl_chains[7] = { 0, 2, 3, 4, 5, 6, 0 };

soinfo libdl_info;
// soinfo libdl_info = {
//     name: "libdl.so",
//     flags: FLAG_LINKED,

//     strtab: ANDROID_LIBDL_STRTAB,
//     symtab: libdl_symtab,

//     nbucket: 1,
//     nchain: 7,
//     bucket: libdl_buckets,
//     chain: libdl_chains,
// };

/* 填充libdl_info结构 */
static void fill_libdl_info() {
	strcpy(libdl_info.name, "libdl.so");
	libdl_info.flags = FLAG_LINKED;
	libdl_info.strtab = ANDROID_LIBDL_STRTAB;
	libdl_info.symtab = libdl_symtab;
	libdl_info.nbucket = 1;
	libdl_info.nchain = 7;
	libdl_info.bucket = libdl_buckets;
	libdl_info.chain = libdl_chains;
	libdl_info.constructors_called = 1;
	libdl_info.refcount = 1;                  /* dlclose时,不对此进行释放 */
}
/********************************************************************************/

unsigned umin(unsigned a, unsigned b) {
	return (a < b) ? a : b;
}

unsigned umax(unsigned a, unsigned b) {
	return (a >= b) ? a : b;
}

unsigned up4(unsigned x) {
	return ~3u & (3 + x);
}

unsigned upx(unsigned x) {
	unsigned page_size = 1 << 12;
	unsigned page_mask = page_size - 1;
	return ~(page_mask) & (page_mask + x);
}

/* 加载SO，很重要的函数 */
static int soinfo_link_image(soinfo *si);

static int socount = 0;                   /* 已经加载SO库的数量 */
static soinfo sopool[SO_MAX];             /* SO库的缓存 */
static soinfo *freelist = NULL;
static soinfo *solist = &libdl_info;      /* 已加载的库队列 */
static soinfo *sonext = &libdl_info;      /* 已加载的库队列节点指针 */
#if ALLOW_SYMBOLS_FROM_MAIN
static soinfo *somain; /* main process, always the one after libdl_info */
#endif


static char ldpaths_buf[LDPATH_BUFSIZE];
static const char *ldpaths[LDPATH_MAX + 1];

/* 预先加载 */
static char ldpreloads_buf[LDPRELOAD_BUFSIZE];
static const char *ldpreload_names[LDPRELOAD_MAX + 1];   /* 预加载库名称 */
static soinfo *preloads[LDPRELOAD_MAX + 1];              /* 预加载库数组 */

/* 链接器调试 */
int debug_verbosity;                                     /* 详细调试信息 */
static int pid;                                          /* 进程ID */

/* This boolean is set if the program being loaded is setuid */
static bool program_is_setuid;

/* 重定位类型 */
enum RelocationKind {
    kRelocAbsolute = 0,
    kRelocRelative,
    kRelocCopy,
    kRelocSymbol,
    kRelocMax
};

/* 如果开启的状态统计 */
#if STATS
struct linker_stats_t {
    int count[kRelocMax];
};

static linker_stats_t linker_stats;

static void count_relocation(RelocationKind kind) {
    ++linker_stats.count[kind];
}
#else
static void count_relocation(RelocationKind) {
}
#endif

#if COUNT_PAGES
static unsigned bitmask[4096];
#define MARK(offset)													\
    do {																\
        bitmask[((offset) >> 12) >> 3] |= (1 << (((offset) >> 12) & 7)); \
    } while(0)
#else
#define MARK(x) do {} while (0)
#endif

// You shouldn't try to call memory-allocating functions in the dynamic linker.
// Guard against the most obvious ones.
/*
  #define DISALLOW_ALLOCATION(return_type, name, ...)					\
  return_type name __VA_ARGS__                                                \
  {                                                                           \
  const char* msg = "ERROR: " #name " called from the dynamic linker!\n"; \
  __libc_android_log_write(ANDROID_LOG_FATAL, "linker", msg);            \
  write(2, msg, sizeof(msg));                                             \
  abort();                                                                \
  }
  #define UNUSED __attribute__((unused))
  DISALLOW_ALLOCATION(void*, malloc, (size_t u UNUSED));
  DISALLOW_ALLOCATION(void, free, (void* u UNUSED));
  DISALLOW_ALLOCATION(void*, realloc, (void* u1 UNUSED, size_t u2 UNUSED));
  DISALLOW_ALLOCATION(void*, calloc, (size_t u1 UNUSED, size_t u2 UNUSED));
*/

static char tmp_err_buf[768];
static char __linker_dl_err_buf[768];
#define BASENAME(s) (strrchr(s, '/') != NULL ? strrchr(s, '/') + 1 : s)
#define DL_ERR(fmt, x...)												\
    do {																\
        format_buffer(__linker_dl_err_buf, sizeof(__linker_dl_err_buf), \
                      "%s(%s:%d): " fmt,								\
                      __FUNCTION__, BASENAME(__FILE__), __LINE__, ##x); \
        ERROR(fmt "\n", ##x);											\
    } while(0)

const char *linker_get_error(void)
{
    return (const char *)&__linker_dl_err_buf[0];
}

#ifdef NOTIFY_GDB
/*
 * This function is an empty stub where GDB locates a breakpoint to get notified
 * about linker activity.
 */
extern "C" void __attribute__((noinline)) __attribute__((visibility("default"))) rtld_db_dlactivity(void);

static r_debug _r_debug = {1, NULL, &rtld_db_dlactivity,
						   RT_CONSISTENT, 0};
static link_map* r_debug_tail = 0;

static pthread_mutex_t _r_debug_lock = PTHREAD_MUTEX_INITIALIZER;

/* 将链接器的信息插入到debug map中 */
static void insert_soinfo_into_debug_map(soinfo * info) {
    // Copy the necessary fields into the debug structure.
    link_map* map = &(info->linkmap);
    map->l_addr = info->base;
    map->l_name = (char*) info->name;
    map->l_ld = (uintptr_t)info->dynamic;

    /* Stick the new library at the end of the list.
     * gdb tends to care more about libc than it does
     * about leaf libraries, and ordering it this way
     * reduces the back-and-forth over the wire.
     */
    if (r_debug_tail) {
        r_debug_tail->l_next = map;
        map->l_prev = r_debug_tail;
        map->l_next = 0;
    } else {
        _r_debug.r_map = map;
        map->l_prev = 0;
        map->l_next = 0;
    }
    r_debug_tail = map;
}

static void remove_soinfo_from_debug_map(soinfo* info) {
    link_map* map = &(info->linkmap);

    if (r_debug_tail == map) {
        r_debug_tail = map->l_prev;
    }

    if (map->l_prev) {
        map->l_prev->l_next = map->l_next;
    }
    if (map->l_next) {
        map->l_next->l_prev = map->l_prev;
    }
}

/* 通知GDB，应用程序加载 */
static void notify_gdb_of_load(soinfo* info) {
    if (info->flags & FLAG_EXE) {
        // GDB already knows about the main executable
        return;
    }

    pthread_mutex_lock(&_r_debug_lock);

    _r_debug.r_state = RT_ADD;
    rtld_db_dlactivity();

    insert_soinfo_into_debug_map(info);

    _r_debug.r_state = RT_CONSISTENT;
    rtld_db_dlactivity();

    pthread_mutex_unlock(&_r_debug_lock);
}

static void notify_gdb_of_unload(soinfo* info) {
    if (info->flags & FLAG_EXE) {
        // GDB already knows about the main executable
        return;
    }

    pthread_mutex_lock(&_r_debug_lock);

    _r_debug.r_state = RT_DELETE;
    rtld_db_dlactivity();

    remove_soinfo_from_debug_map(info);

    _r_debug.r_state = RT_CONSISTENT;
    rtld_db_dlactivity();

    pthread_mutex_unlock(&_r_debug_lock);
}

extern "C" void notify_gdb_of_libraries()
{
    _r_debug.r_state = RT_ADD;
    rtld_db_dlactivity();
    _r_debug.r_state = RT_CONSISTENT;
    rtld_db_dlactivity();
}

#endif

/* 分配一个SO结构,并插入链中 */
static soinfo *soinfo_alloc(const char *name)
{
    if (strlen(name) >= SOINFO_NAME_LEN) {
        DL_ERR("library name \"%s\" too long", name);
        return NULL;
    }

    /* The freelist is populated when we call soinfo_free(), which in turn is
       done only by dlclose(), which is not likely to be used.
    */
    if (!freelist) {
		/* 加载库数量达到最大 */
        if (socount == SO_MAX) {
            DL_ERR("too many libraries when loading \"%s\"", name);
            return NULL;
        }
        freelist = sopool + socount++;
        freelist->next = NULL;
    }

	/* 从这里可以看出添加到soinfo链表,并不影响第一个链接节点 */
    soinfo* si = freelist;
    freelist = freelist->next;

    /* Make sure we get a clean block of soinfo */
    memset(si, 0, sizeof(soinfo));
    strlcpy((char*) si->name, name, sizeof(si->name));
    sonext->next = si;
    si->next = NULL;
    si->refcount = 0;
    sonext = si;

    TRACE("%5d name %s: allocated soinfo @ %p\n", pid, name, si);
    return si;
}

static soinfo *soinfo_add(soinfo* isi)
{
	const char* name = isi->name;
    /* The freelist is populated when we call soinfo_free(), which in turn is
       done only by dlclose(), which is not likely to be used.
    */
    if (!freelist) {
		/* 加载库数量达到最大 */
        if (socount == SO_MAX) {
            DL_ERR("too many libraries when loading \"%s\"", name);
            return NULL;
        }
        freelist = sopool + socount++;
        freelist->next = NULL;
    }

    soinfo* si = freelist;
    freelist = freelist->next;

    /* Make sure we get a clean block of soinfo */
    memset(si, 0, sizeof(soinfo));
	memcpy(si, isi, sizeof(soinfo));
    sonext->next = si;
    si->next = NULL;
    si->refcount = 0;
    sonext = si;

    TRACE("%5d name %s: allocated soinfo @ %p\n", pid, name, si);
    return si;
}

/* 释放SI结构 */
static void soinfo_free(soinfo* si)
{
    if (si == NULL) {
        return;
    }

    soinfo *prev = NULL, *trav;

    TRACE("%5d name %s: freeing soinfo @ %p\n", pid, si->name, si);

	/* 从链表中移除 */
    for(trav = solist; trav != NULL; trav = trav->next){
        if (trav == si)
            break;
        prev = trav;
    }
    if (trav == NULL) {
        /* si was not ni solist */
        DL_ERR("name \"%s\" is not in solist!", si->name);
        return;
    }

    /* prev will never be NULL, because the first entry in solist is
       always the static libdl_info.
    */
    prev->next = si->next;
    if (si == sonext) sonext = prev;
    si->next = freelist;
    freelist = si;
}

#ifdef ANDROID_ARM_LINKER

/* For a given PC, find the .so that it belongs to.
 * Returns the base address of the .ARM.exidx section
 * for that .so, and the number of 8-byte entries
 * in that section (via *pcount).
 *
 * Intended to be called by libc's __gnu_Unwind_Find_exidx().
 *
 * This function is exposed via dlfcn.c and libdl.so.
 */
_Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int *pcount)
{
    soinfo *si;
    unsigned addr = (unsigned)pc;

    for (si = solist; si != 0; si = si->next){
        if ((addr >= si->base) && (addr < (si->base + si->size))) {
            *pcount = si->ARM_exidx_count;
            return (_Unwind_Ptr)si->ARM_exidx;
        }
    }
	*pcount = 0;
    return NULL;
}

#elif defined(ANDROID_X86_LINKER) || defined(ANDROID_MIPS_LINKER)

/* Here, we only have to provide a callback to iterate across all the
 * loaded libraries. gcc_eh does the rest. */
int
dl_iterate_phdr(int (*cb)(dl_phdr_info *info, size_t size, void *data),
                void *data)
{
    int rv = 0;
    for (soinfo* si = solist; si != NULL; si = si->next) {
        dl_phdr_info dl_info;
        dl_info.dlpi_addr = si->linkmap.l_addr;
        dl_info.dlpi_name = si->linkmap.l_name;
        dl_info.dlpi_phdr = si->phdr;
        dl_info.dlpi_phnum = si->phnum;
        rv = cb(&dl_info, sizeof(dl_phdr_info), data);
        if (rv != 0) {
            break;
        }
    }
    return rv;
}

#endif

/* si : 要搜索库的库结构指针
 * hash : 要搜索符号的HASH值
 * name : 要找符号的字符串
 * 
 * 找STB_GLOBAL与STB_WEAK的符号，并且不能无定义
 * 也就是说搜索本SO模块下的变量。
 */
static Elf32_Sym *soinfo_elf_lookup(soinfo *si, unsigned hash, const char *name)
{
    Elf32_Sym *s;
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    unsigned n;

    TRACE_TYPE(LOOKUP, "%5d SEARCH %s in %s@0x%08x %08x %d\n", pid,
               name, si->name, si->base, hash, hash % si->nbucket);
    n = hash % si->nbucket;

    for(n = si->bucket[hash % si->nbucket]; n != 0; n = si->chain[n]){
        s = symtab + n;
        if(strcmp(strtab + s->st_name, name)) continue;

		/* only concern ourselves with global and weak symbol definitions */
		/* 这里搜寻到是弱符号与全局变量，如果非未定义则返回 */
        switch(ELF32_ST_BIND(s->st_info)){
        case STB_GLOBAL:
        case STB_WEAK:
			/* 如果是没有找到定义则忽略，以后加载会重新寻找的 */
            if(s->st_shndx == SHN_UNDEF)
                continue;

            TRACE_TYPE(LOOKUP, "%5d FOUND %s in %s (%08x) %d\n", pid,
                       name, si->name, s->st_value, s->st_size);
            return s;
        }
    }

    return NULL;
}

/* HASH值计算 */
static unsigned elfhash(const char *_name)
{
    const unsigned char *name = (const unsigned char *) _name;
    unsigned h = 0, g;

    while(*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

/* si : 当的库结构指针
 * name : 当前要重定位的符号名称
 * offset : 输出
 * needed : 依赖库队列
 * ignore_local : 忽略
 */
static Elf32_Sym *
soinfo_do_lookup(soinfo *si, const char *name, Elf32_Addr *offset,
                 soinfo *needed[], bool ignore_local)
{
    unsigned elf_hash = elfhash(name);
    Elf32_Sym *s = NULL;
    soinfo *lsi = si;
    int i;

	/* ignore_local 表示 不在自身文件中寻找符号，此符号是外来文件引入的 */
    if (!ignore_local) {
        /* Look for symbols in the local scope (the object who is
         * searching). This happens with C++ templates on i386 for some
         * reason.
         *
         * Notes on weak symbols:
         * The ELF specs are ambiguous about treatment of weak definitions in
         * dynamic linking.  Some systems return the first definition found
         * and some the first non-weak definition.   This is system dependent.
         * Here we return the first definition found for simplicity.  */

        s = soinfo_elf_lookup(si, elf_hash, name);
        if(s != NULL)
            goto done;
    }

    /* Next, look for it in the preloads list */
	/* 从预加载库队列中查找 */
    for(i = 0; preloads[i] != NULL; i++) {
        lsi = preloads[i];
        s = soinfo_elf_lookup(lsi, elf_hash, name);
        if(s != NULL)
            goto done;
    }

	/* 从依赖库中搜索 */
    for(i = 0; needed[i] != NULL; i++) {
        lsi = needed[i];
        DEBUG("%5d %s: looking up %s in %s\n",
              pid, si->name, name, lsi->name);
        s = soinfo_elf_lookup(lsi, elf_hash, name);
        if (s != NULL)
            goto done;
    }

#if ALLOW_SYMBOLS_FROM_MAIN
    /* If we are resolving relocations while dlopen()ing a library, it's OK for
     * the library to resolve a symbol that's defined in the executable itself,
     * although this is rare and is generally a bad idea.
     */
	/* 如果我们要重定位在dlopening一个库时,它可以被解析，当它在它自己的可执行程序中定义 */
    if (somain) {
        lsi = somain;
        DEBUG("%5d %s: looking up %s in executable %s\n",
              pid, si->name, name, lsi->name);
        s = soinfo_elf_lookup(lsi, elf_hash, name);
    }
#endif

 done:
    if(s != NULL) {
        TRACE_TYPE(LOOKUP, "%5d si %s sym %s s->st_value = 0x%08x, "
                   "found in %s, base = 0x%08x, load bias = 0x%08x\n",
                   pid, si->name, name, s->st_value,
                   lsi->name, lsi->base, lsi->load_bias);
        *offset = lsi->load_bias;
        return s;
    }

    return NULL;
}

/* This is used by dl_sym().  It performs symbol lookup only within the
   specified soinfo object and not in any of its dependencies.
*/
Elf32_Sym *soinfo_lookup(soinfo *si, const char *name)
{
    return soinfo_elf_lookup(si, elfhash(name), name);
}

/* This is used by dl_sym().  It performs a global symbol lookup.
 * 由dl_sym()进行调用.
 */
Elf32_Sym *lookup(const char *name, soinfo **found, soinfo *start)
{
    unsigned elf_hash = elfhash(name);
    Elf32_Sym *s = NULL;
    soinfo *si;

    if(start == NULL) {
        start = solist;
    }

    for(si = start; (s == NULL) && (si != NULL); si = si->next)
		{
			if(si->flags & FLAG_ERROR)
				continue;
			s = soinfo_elf_lookup(si, elf_hash, name);
			if (s != NULL) {
				*found = si;
				break;
			}
		}

    if(s != NULL) {
        TRACE_TYPE(LOOKUP, "%5d %s s->st_value = 0x%08x, "
                   "si->base = 0x%08x\n", pid, name, s->st_value, si->base);
        return s;
    }

    return NULL;
}

/* 确定一个地址否在在一个库中 */
soinfo *find_containing_library(const void *addr)
{
    soinfo *si;

    for(si = solist; si != NULL; si = si->next)
		{
			if((unsigned)addr >= si->base && (unsigned)addr - si->base < si->size) {
				return si;
			}
		}

    return NULL;
}

/* 确定一个内存地址是否是是在一个库文件中 */
Elf32_Sym *soinfo_find_symbol(soinfo* si, const void *addr)
{
    unsigned int i;
    unsigned soaddr = (unsigned)addr - si->base;

    /* Search the library's symbol table for any defined symbol which
     * contains this address */
    for(i=0; i<si->nchain; i++) {
        Elf32_Sym *sym = &si->symtab[i];

        if(sym->st_shndx != SHN_UNDEF &&
           soaddr >= sym->st_value &&
           soaddr < sym->st_value + sym->st_size) {
            return sym;
        }
    }

    return NULL;
}

#if 0
static void dump(soinfo *si)
{
    Elf32_Sym *s = si->symtab;
    unsigned n;

    for(n = 0; n < si->nchain; n++) {
        TRACE("%5d %04d> %08x: %02x %04x %08x %08x %s\n", pid, n, s,
			  s->st_info, s->st_shndx, s->st_value, s->st_size,
			  si->strtab + s->st_name);
        s++;
    }
}
#endif

static const char * const sopaths[] = {
    "/vendor/lib",
    "/system/lib",
	"./",
    0
};

/* 使用open打开这个句柄 */
static int _open_lib(const char* name) {
    // TODO: why not just call open?
    struct stat sb;
    if (stat(name, &sb) == -1 || !S_ISREG(sb.st_mode)) {
        return -1;
    }
    return TEMP_FAILURE_RETRY(open(name, O_RDONLY));
}

/* 打开库文件 */
static int open_library(const char *name)
{
    int fd;
    char buf[512];
    const char * const*path;
    int n;

    TRACE("[ %5d opening %s ]\n", pid, name);

    if(name == 0) return -1;
    if(strlen(name) > 256) return -1;

    if ((name[0] == '/') && ((fd = _open_lib(name)) >= 0))
        return fd;

	/* 使用ldpaths中的路径进行打开 */
    for (path = ldpaths; *path; path++) {
        n = format_buffer(buf, sizeof(buf), "%s/%s", *path, name);
        if (n < 0 || n >= (int)sizeof(buf)) {
            WARN("Ignoring very long library path: %s/%s\n", *path, name);
            continue;
        }
        if ((fd = _open_lib(buf)) >= 0)
            return fd;
    }

	/* 使用自身的路径打开 */
    for (path = sopaths; *path; path++) {
        n = format_buffer(buf, sizeof(buf), "%s/%s", *path, name);
        if (n < 0 || n >= (int)sizeof(buf)) {
            WARN("Ignoring very long library path: %s/%s\n", *path, name);
            continue;
        }
        if ((fd = _open_lib(buf)) >= 0)
            return fd;
    }

    return -1;
}

// Returns 'true' if the library is prelinked or on failure so we error out
// either way. We no longer support prelinking.
/* 返回TRUE则表明是一个预先加载库 */
static bool is_prelinked(int fd, const char* name)
{
    struct prelink_info_t {
        long mmap_addr;
        char tag[4]; // "PRE ".
    };

    off_t sz = lseek(fd, -sizeof(prelink_info_t), SEEK_END);
    if (sz < 0) {
        DL_ERR("lseek failed: %s", strerror(errno));
        return true;
    }

    prelink_info_t info;
    int rc = TEMP_FAILURE_RETRY(read(fd, &info, sizeof(info)));
    if (rc != sizeof(info)) {
        DL_ERR("could not read prelink_info_t structure for \"%s\":", name, strerror(errno));
        return true;
    }

    if (memcmp(info.tag, "PRE ", 4) == 0) {
        DL_ERR("prelinked libraries no longer supported: %s", name);
        return true;
    }
    return false;
}

/* 验证elf文件头
 *      Verifies the content of an ELF header.
 *
 * Args:
 *
 * Returns:
 *       0 on success
 *      -1 if no valid ELF object is found @ base.
 */
static int
verify_elf_header(const Elf32_Ehdr* hdr)
{
    if (hdr->e_ident[EI_MAG0] != ELFMAG0) return -1;
    if (hdr->e_ident[EI_MAG1] != ELFMAG1) return -1;
    if (hdr->e_ident[EI_MAG2] != ELFMAG2) return -1;
    if (hdr->e_ident[EI_MAG3] != ELFMAG3) return -1;
    if (hdr->e_type != ET_DYN) return -1;

    /* TODO: Should we verify anything else in the header? */
#ifdef ANDROID_ARM_LINKER
    if (hdr->e_machine != EM_ARM) return -1;
#elif defined(ANDROID_X86_LINKER)
    if (hdr->e_machine != EM_386) return -1;
#elif defined(ANDROID_MIPS_LINKER)
    if (hdr->e_machine != EM_MIPS) return -1;
#endif
    return 0;
}

/* 文件句柄结构 */
struct scoped_fd {
    ~scoped_fd() {
        if (fd != -1) {
            close(fd);
        }
    }
    int fd;
};

/* so指针结构 */
struct soinfo_ptr {
    soinfo_ptr(const char* name) {
        const char* bname = strrchr(name, '/');          /* 只取文件名 */
        ptr = soinfo_alloc(bname ? bname + 1 : name);
    }
    ~soinfo_ptr() {
        soinfo_free(ptr);
    }
    soinfo* release() {
        soinfo* result = ptr;
        ptr = NULL;
        return result;
    }
    soinfo* ptr;
};

// TODO: rewrite linker_phdr.h to use a class, then lose this.
struct phdr_ptr {
    phdr_ptr() : phdr_mmap(NULL) {}
    ~phdr_ptr() {
        if (phdr_mmap != NULL) {
            phdr_table_unload(phdr_mmap, phdr_size);
        }
    }
    void* phdr_mmap;
    Elf32_Addr phdr_size;
};

/* 加载库文件 */
static soinfo* load_library(const char* name)
{
    /* 打开文件 */
    scoped_fd fd;
    fd.fd = open_library(name);
    if (fd.fd == -1) {
        DL_ERR("library \"%s\" not found", name);
        return NULL;
    }

    /* 读取一个ELF头 */
    Elf32_Ehdr header[1];
    int ret = TEMP_FAILURE_RETRY(read(fd.fd, (void*)header, sizeof(header)));
    if (ret < 0) {
        DL_ERR("can't read file \"%s\": %s", name, strerror(errno));
        return NULL;
    }
    if (ret != (int)sizeof(header)) {
        DL_ERR("too small to be an ELF executable: %s", name);
        return NULL;
    }
	/* 验证ELF头 */
    if (verify_elf_header(header) < 0) {
        DL_ERR("not a valid ELF executable: %s", name);
        return NULL;
    }

	/* 读取程序段头表 */
    const Elf32_Phdr* phdr_table;
    phdr_ptr phdr_holder;
	/* 映射到程序段头表 */
    ret = phdr_table_load(fd.fd, header->e_phoff, header->e_phnum,
                          &phdr_holder.phdr_mmap, &phdr_holder.phdr_size, &phdr_table);
    if (ret < 0) {
        DL_ERR("can't load program header table: %s: %s", name, strerror(errno));
        return NULL;
    }
	/* 获取段数量 */
    size_t phdr_count = header->e_phnum;

    /* 获取可加载段总长度 */
    Elf32_Addr ext_sz = phdr_table_get_load_size(phdr_table, phdr_count);
    TRACE("[ %5d - '%s' wants sz=0x%08x ]\n", pid, name, ext_sz);
    if (ext_sz == 0) {
        DL_ERR("no loadable segments in file: %s", name);
        return NULL;
    }

	/* 如果是在预加载库中的文件则直接返回，我们不支持 */
    if (is_prelinked(fd.fd, name)) {
        return NULL;
    }

	/* 解析地址空间为所有的可加载段 */
    void* load_start = NULL;
    Elf32_Addr load_size = 0;
    Elf32_Addr load_bias = 0;
    ret = phdr_table_reserve_memory(phdr_table,
                                    phdr_count,
                                    &load_start,
                                    &load_size,
                                    &load_bias);
	/* load_bias 为 load_start - 第一个可加载段的内存偏移 */
    if (ret < 0) {
        DL_ERR("can't reserve %d bytes in address space for \"%s\": %s",
               ext_sz, name, strerror(errno));
        return NULL;
    }

    TRACE("[ %5d allocated memory for %s @ %p (0x%08x) ]\n",
          pid, name, load_start, load_size);

    /* Map all the segments in our address space with default protections */
	/* 映射所有的段在我们的地址空间使用默认的保护属性 */
    ret = phdr_table_load_segments(phdr_table,
                                   phdr_count,
                                   load_bias,
                                   fd.fd);
    if (ret < 0) {
        DL_ERR("can't map loadable segments for \"%s\": %s",
               name, strerror(errno));
        return NULL;
    }

    soinfo_ptr si(name);
    if (si.ptr == NULL) {
        return NULL;
    }

    si.ptr->base = (Elf32_Addr) load_start;
    si.ptr->size = load_size;
    si.ptr->load_bias = load_bias;
    si.ptr->flags = 0;
    si.ptr->entry = 0;
    si.ptr->dynamic = (unsigned *)-1;
    si.ptr->phnum = phdr_count;
    si.ptr->phdr = phdr_table_get_loaded_phdr(phdr_table, phdr_count, load_bias);
    if (si.ptr->phdr == NULL) {
        DL_ERR("can't find loaded PHDR for \"%s\"", name);
        return NULL;
    }

    return si.release();
}

static soinfo *
init_library(soinfo *si)
{
    /* At this point we know that whatever is loaded @ base is a valid ELF
     * shared library whose segments are properly mapped in. */
    TRACE("[ %5d init_library base=0x%08x sz=0x%08x name='%s') ]\n",
          pid, si->base, si->size, si->name);

    if(soinfo_link_image(si)) {
        munmap((void *)si->base, si->size);
        return NULL;
    }

    return si;
}

/* 通过名称从已加载库中寻找SO句柄 */
static soinfo *find_loaded_library(const char *name)
{
    soinfo *si;
    const char *bname;

    // TODO: don't use basename only for determining libraries
    // http://code.google.com/p/android/issues/detail?id=6670

    bname = strrchr(name, '/');
    bname = bname ? bname + 1 : name;

    for(si = solist; si != NULL; si = si->next){
        if(!strcmp(bname, si->name)) {
            return si;
        }
    }
    return NULL;
}

//static void call_array(unsigned *ctor, int count, int reverse);
/* 根据名称找so库 */
soinfo *find_library(const char *name)
{
    soinfo *si;

#if ALLOW_SYMBOLS_FROM_MAIN
    if (name == NULL)
        return somain;
#else
    if (name == NULL)
        return NULL;
#endif

	/* 寻找已加载的库 */
    si = find_loaded_library(name);
    if (si != NULL) {
		/* 打印出错并推出 */
        if(si->flags & FLAG_ERROR) {
            DL_ERR("\"%s\" failed to load previously", name);
            return NULL;
        }
		/* 链接器自身 */
        if(si->flags & FLAG_LINKED) return si;
        DL_ERR("OOPS: recursive link to \"%s\"", si->name);
        return NULL;
    }

	/* 已经加载的库没有找到则加载 */
    TRACE("[ %5d '%s' has not been loaded yet.  Locating...]\n", pid, name);
    si = load_library(name);
    if(si == NULL)
        return NULL;

	// #ifdef TEST_TDOG_CALL
	// 	/* 测试tdog */
	// 	test_tdog_call(si);
	// #endif

    return init_library(si);
}

static void call_destructors(soinfo *si);

/* SO库卸载 */
int soinfo_unload(soinfo* si) {
    if (si->refcount == 1) {
		/* 到最后一次引用，就调用一次析构函数 */
        TRACE("%5d unloading '%s'\n", pid, si->name);
        call_destructors(si);

		/* 遍历它的动态信息段 */
        for (unsigned* d = si->dynamic; *d; d += 2) {
			/* 如果存在依赖库 */
            if(d[0] == DT_NEEDED){
				/* 找到依赖库并卸载 */
                soinfo *lsi = find_loaded_library(si->strtab + d[1]);
                if (lsi) {
                    TRACE("%5d %s needs to unload %s\n", pid,
                          si->name, lsi->name);
                    soinfo_unload(lsi);
                } else {
                    // TODO: should we return -1 in this case?
                    DL_ERR("\"%s\": could not unload dependent library",
                           si->name);
                }
            }
        }

		/* 释放内存，通知GDB，释放SI结构内存 */
        munmap((char *)si->base, si->size);
#ifdef NOTIFY_GDB
        notify_gdb_of_unload(si);
#endif
        soinfo_free(si);
        si->refcount = 0;
    } else {
		/* 仅减引用次数 */
        si->refcount--;
        PRINT("%5d not unloading '%s', decrementing refcount to %d\n",
              pid, si->name, si->refcount);
    }
    return 0;
}

/* TODO: don't use unsigned for addrs below. It works, but is not
 * ideal. They should probably be either uint32_t, Elf32_Addr, or unsigned
 * long.
 *
 * si : 当前SO的信息结构
 * rel : 重定位表
 * count : 重定位表项数
 * needed : 依赖库队列 
 */
static int soinfo_relocate(soinfo *si, Elf32_Rel *rel, unsigned count,
                           soinfo *needed[])
{
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    Elf32_Sym *s;
    Elf32_Addr offset;
    Elf32_Rel *start = rel;

	/* 遍历重定位项 */
    for (size_t idx = 0; idx < count; ++idx, ++rel) {
		/* 从r_info中读取重定位的类型与符号对应的符号表下标 */
        unsigned type = ELF32_R_TYPE(rel->r_info); /* 重定位的类型 */
        unsigned sym = ELF32_R_SYM(rel->r_info);   /* 符号索引 */
		/* 获取到要重定位的内存地址 */
        unsigned reloc = (unsigned)(rel->r_offset + si->load_bias);
        unsigned sym_addr = 0;
        char *sym_name = NULL;

        DEBUG("%5d Processing '%s' relocation at index %d\n", pid,
              si->name, idx);
        if (type == 0) { // R_*_NONE
            continue;
        }
        if(sym != 0) {
			/* 获取到符号 */
            sym_name = const_cast<char*>(strtab + symtab[sym].st_name);
            bool ignore_local = false;
#if defined(ANDROID_ARM_LINKER)
			/* ARM专用
			 * R_ASM_COPY 代表 从其余库文件中直接复制指到此
			 */
            ignore_local = (type == R_ARM_COPY);
#endif
			/* 查找符号加载地址
			 * 从依赖
			 * 遇到 R_ARM_COPY的重定位项，则表示
			 * 是在其他库中定义，或者是一个弱符号
			 */
            s = soinfo_do_lookup(si, sym_name, &offset, needed, ignore_local);
            if(s == NULL) {
                /* We only allow an undefined symbol if this is a weak
                   reference..   */
				/* 我们只允许一个未定义的符号是一个弱符号 */
                s = &symtab[sym];
                if (ELF32_ST_BIND(s->st_info) != STB_WEAK) {
                    DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, si->name);
                    return -1;
                }

                /* IHI0044C AAELF 4.5.1.1:

                   Libraries are not searched to resolve weak references.
                   It is not an error for a weak reference to remain
                   unsatisfied.

                   During linking, the value of an undefined weak reference is:
                   - Zero if the relocation type is absolute
                   - The address of the place if the relocation is pc-relative
                   - The address of nominal base address if the relocation
				   type is base-relative.
				*/

				/* 以下是针对弱符号的处理 */
                switch (type) {
#if defined(ANDROID_ARM_LINKER)
					/* 不关心以下重定位项 */
                case R_ARM_JUMP_SLOT:
                case R_ARM_GLOB_DAT:
                case R_ARM_ABS32:
                case R_ARM_RELATIVE:    /* Don't care. */
#elif defined(ANDROID_X86_LINKER)
                case R_386_JMP_SLOT:
                case R_386_GLOB_DAT:
                case R_386_32:
                case R_386_RELATIVE:    /* Dont' care. */
#endif /* ANDROID_*_LINKER */
                    /* sym_addr was initialized to be zero above or relocation
                       code below does not care about value of sym_addr.
                       No need to do anything.  */
                    break;

#if defined(ANDROID_X86_LINKER)
                case R_386_PC32:
                    sym_addr = reloc;
                    break;
#endif /* ANDROID_X86_LINKER */

#if defined(ANDROID_ARM_LINKER)
					/* 传递控制，如果弱符号没有在run-time中找到，则不能确实的复制它 */
                case R_ARM_COPY:
                    /* Fall through.  Can't really copy if weak symbol is
                       not found in run-time.  */
#endif /* ANDROID_ARM_LINKER */
                default:
                    DL_ERR("unknown weak reloc type %d @ %p (%d)",
						   type, rel, (int) (rel - start));
                    return -1;
                }
            } else {
                /* We got a definition.  */
				/* 我们获取一个定义 */
				// #if 0
				//                 if((base == 0) && (si->base != 0)){
				//                         /* linking from libraries to main image is bad */
				//                     DL_ERR("cannot locate \"%s\"...",
				//                            strtab + symtab[sym].st_name);
				//                     return -1;
				//                 }
				// #endif
				/* 确定符号地址 
				 * offset 保存了当前符号所在库的内存加载地址
				 * s->st_value 表示了当前符号在它所在库相对于加载地址的偏移
				 */
                sym_addr = (unsigned)(s->st_value + offset);
            }
			/* 统计重定位项 */
            count_relocation(kRelocSymbol);
        } else {
            s = NULL;
        }

		/* TODO: This is ugly. Split up the relocations by arch into
		 * different files.
		 */
        switch(type){
#if defined(ANDROID_ARM_LINKER)
        case R_ARM_JUMP_SLOT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO JMP_SLOT %08x <- %08x %s\n", pid,
                       reloc, sym_addr, sym_name);
            *((unsigned*)reloc) = sym_addr;
            break;
        case R_ARM_GLOB_DAT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO GLOB_DAT %08x <- %08x %s\n", pid,
                       reloc, sym_addr, sym_name);
            *((unsigned*)reloc) = sym_addr;
            break;
        case R_ARM_ABS32:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO ABS %08x <- %08x %s\n", pid,
                       reloc, sym_addr, sym_name);
            *((unsigned*)reloc) += sym_addr;
            break;
        case R_ARM_REL32:
            count_relocation(kRelocRelative);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO REL32 %08x <- %08x - %08x %s\n", pid,
                       reloc, sym_addr, rel->r_offset, sym_name);
            *((unsigned*)reloc) += sym_addr - rel->r_offset;
            break;
#elif defined(ANDROID_X86_LINKER)
        case R_386_JMP_SLOT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO JMP_SLOT %08x <- %08x %s\n", pid,
                       reloc, sym_addr, sym_name);
            *((unsigned*)reloc) = sym_addr;
            break;
        case R_386_GLOB_DAT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO GLOB_DAT %08x <- %08x %s\n", pid,
                       reloc, sym_addr, sym_name);
            *((unsigned*)reloc) = sym_addr;
            break;
#elif defined(ANDROID_MIPS_LINKER)
		case R_MIPS_JUMP_SLOT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO JMP_SLOT %08x <- %08x %s\n", pid,
                       reloc, sym_addr, sym_name);
            *((unsigned*)reloc) = sym_addr;
            break;
		case R_MIPS_REL32:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO REL32 %08x <- %08x %s\n", pid,
                       reloc, sym_addr, (sym_name) ? sym_name : "*SECTIONHDR*");
            if (s) {
                *((unsigned*)reloc) += sym_addr;
            } else {
                *((unsigned*)reloc) += si->base;
            }
            break;
#endif /* ANDROID_*_LINKER */

#if defined(ANDROID_ARM_LINKER)
        case R_ARM_RELATIVE:
#elif defined(ANDROID_X86_LINKER)
        case R_386_RELATIVE:
#endif /* ANDROID_*_LINKER */
            count_relocation(kRelocRelative);
            MARK(rel->r_offset);
			/* 如果是修订的相对偏移，不可能找到符号的,这里就是进行基地址重定位 */
            if (sym) {
                DL_ERR("odd RELATIVE form...", pid);
                return -1;
            }
            TRACE_TYPE(RELO, "%5d RELO RELATIVE %08x <- +%08x\n", pid,
                       reloc, si->base);
            *((unsigned*)reloc) += si->base;
            break;

#if defined(ANDROID_X86_LINKER)
        case R_386_32:
            count_relocation(kRelocRelative);
            MARK(rel->r_offset);

            TRACE_TYPE(RELO, "%5d RELO R_386_32 %08x <- +%08x %s\n", pid,
                       reloc, sym_addr, sym_name);
            *((unsigned *)reloc) += (unsigned)sym_addr;
            break;

        case R_386_PC32:
            count_relocation(kRelocRelative);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO R_386_PC32 %08x <- "
                       "+%08x (%08x - %08x) %s\n", pid, reloc,
                       (sym_addr - reloc), sym_addr, reloc, sym_name);
            *((unsigned *)reloc) += (unsigned)(sym_addr - reloc);
            break;
#endif /* ANDROID_X86_LINKER */

#ifdef ANDROID_ARM_LINKER
        case R_ARM_COPY:
            if ((si->flags & FLAG_EXE) == 0) {
				/* FLAG_EXE 被设置到 ET_DYN与ET_EXEC文件中。
				 * 这里我们仅不允许ET_DYN可执行有这个重定位项
				 *
				 * R_ARM_COPY也许仅会出现在可执行文件中(ET_EXEC)
				 */
                /*
                 * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044d/IHI0044D_aaelf.pdf
                 *
                 * Section 4.7.1.10 "Dynamic relocations"
                 * R_ARM_COPY may only appear in executable objects where e_type is
                 * set to ET_EXEC.
                 *
                 * TODO: FLAG_EXE is set for both ET_DYN and ET_EXEC executables.
                 * We should explicitly disallow ET_DYN executables from having
                 * R_ARM_COPY relocations.
                 */
                DL_ERR("%s R_ARM_COPY relocations only supported for ET_EXEC", si->name);
                return -1;
            }
            count_relocation(kRelocCopy);
            MARK(rel->r_offset);
            TRACE_TYPE(RELO, "%5d RELO %08x <- %d @ %08x %s\n", pid,
                       reloc, s->st_size, sym_addr, sym_name);
            if (reloc == sym_addr) {
                DL_ERR("Internal linker error detected. reloc == symaddr");
                return -1;
            }
			/* 直接进行复制 */
            memcpy((void*)reloc, (void*)sym_addr, s->st_size);
            break;
#endif /* ANDROID_ARM_LINKER */

        default:
            DL_ERR("unknown reloc type %d @ %p (%d)",
                   type, rel, (int) (rel - start));
            return -1;
        }
    }
    return 0;
}

#ifdef ANDROID_MIPS_LINKER
static int mips_relocate_got(soinfo* si, soinfo* needed[]) {
    unsigned *got;
    unsigned local_gotno, gotsym, symtabno;
    Elf32_Sym *symtab, *sym;
    unsigned g;

    got = si->plt_got;
    local_gotno = si->mips_local_gotno;
    gotsym = si->mips_gotsym;
    symtabno = si->mips_symtabno;
    symtab = si->symtab;

    /*
     * got[0] is address of lazy resolver function
     * got[1] may be used for a GNU extension
     * set it to a recognizable address in case someone calls it
     * (should be _rtld_bind_start)
     * FIXME: maybe this should be in a separate routine
     */

    if ((si->flags & FLAG_LINKER) == 0) {
        g = 0;
        got[g++] = 0xdeadbeef;
        if (got[g] & 0x80000000) {
            got[g++] = 0xdeadfeed;
        }
        /*
         * Relocate the local GOT entries need to be relocated
         */
        for (; g < local_gotno; g++) {
            got[g] += si->load_bias;
        }
    }

    /* Now for the global GOT entries */
    sym = symtab + gotsym;
    got = si->plt_got + local_gotno;
    for (g = gotsym; g < symtabno; g++, sym++, got++) {
        const char *sym_name;
        unsigned base;
        Elf32_Sym *s;

        /* This is an undefined reference... try to locate it */
        sym_name = si->strtab + sym->st_name;
        s = soinfo_do_lookup(si, sym_name, &base, needed, false);
        if (s == NULL) {
            /* We only allow an undefined symbol if this is a weak
               reference..   */
            s = &symtab[g];
            if (ELF32_ST_BIND(s->st_info) != STB_WEAK) {
                DL_ERR("cannot locate \"%s\"...", sym_name);
                return -1;
            }
            *got = 0;
        }
        else {
            /* FIXME: is this sufficient?
             * For reference see NetBSD link loader
             * http://cvsweb.netbsd.org/bsdweb.cgi/src/libexec/ld.elf_so/arch/mips/mips_reloc.c?rev=1.53&content-type=text/x-cvsweb-markup
             */
			*got = base + s->st_value;
        }
    }
    return 0;
}
#endif

/* Please read the "Initialization and Termination functions" functions.
 * of the linker design note in bionic/linker/README.TXT to understand
 * what the following code is doing.
 *
 * The important things to remember are:
 *
 *   DT_PREINIT_ARRAY must be called first for executables, and should
 *   not appear in shared libraries.
 *
 *   DT_INIT should be called before DT_INIT_ARRAY if both are present
 *
 *   DT_FINI should be called after DT_FINI_ARRAY if both are present
 *
 *   DT_FINI_ARRAY must be parsed in reverse order.
 */

static void call_array(unsigned *ctor, int count, int reverse)
{
    int n, inc = 1;

    if (reverse) {
        ctor += (count-1);
        inc   = -1;
    }

    for(n = count; n > 0; n--) {
        TRACE("[ %5d Looking at %s *0x%08x == 0x%08x ]\n", pid,
              reverse ? "dtor" : "ctor",
              (unsigned)ctor, (unsigned)*ctor);
        void (*func)() = (void (*)()) *ctor;
        ctor += inc;/* 下一个函数 */
        if(((int) func == 0) || ((int) func == -1)) continue;
        TRACE("[ %5d Calling func @ 0x%08x ]\n", pid, (unsigned)func);
        func();/* 调用 */
    }
}

/* 调用预初始化库的构造函数 */
static void soinfo_call_preinit_constructors(soinfo *si)
{
	TRACE("[ %5d Calling preinit_array @ 0x%08x [%d] for '%s' ]\n",
		  pid, (unsigned)si->preinit_array, si->preinit_array_count,
		  si->name);
	call_array(si->preinit_array, si->preinit_array_count, 0);
	TRACE("[ %5d Done calling preinit_array for '%s' ]\n", pid, si->name);
}

/* 调用构造函数 */
void soinfo_call_constructors(soinfo *si)
{
    if (si->constructors_called)
        return;

    // Set this before actually calling the constructors, otherwise it doesn't
    // protect against recursive constructor calls. One simple example of
    // constructor recursion is the libc debug malloc, which is implemented in
    // libc_malloc_debug_leak.so:
    // 1. The program depends on libc, so libc's constructor is called here.
    // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
    // 3. dlopen() calls soinfo_call_constructors() with the newly created
    //    soinfo for libc_malloc_debug_leak.so.
    // 4. The debug so depends on libc, so soinfo_call_constructors() is
    //    called again with the libc soinfo. If it doesn't trigger the early-
    //    out above, the libc constructor will be called again (recursively!).
    si->constructors_called = 1;

	/* 共享文件不能有preinit_array表 */
    if (!(si->flags & FLAG_EXE) && si->preinit_array) {
		DL_ERR("shared library \"%s\" has a preinit_array table @ 0x%08x. "
			   "This is INVALID.", si->name, (unsigned) si->preinit_array);
    }

    if (si->dynamic) {
        unsigned *d;
        for(d = si->dynamic; *d; d += 2) {
            if(d[0] == DT_NEEDED){
                soinfo* lsi = find_loaded_library(si->strtab + d[1]);
                if (!lsi) {
                    DL_ERR("\"%s\": could not initialize dependent library",
                           si->name);
                } else {
					/* 调用依赖库的构造函数 */
					soinfo_call_constructors(lsi);
                }
            }
        }
    }

	if (g_opts->call_dt_init) {
		/* 调用初始化函数 */
		if (si->init_func) {
			TRACE("[ %5d Calling init_func @ 0x%08x for '%s' ]\n", pid,
				  (unsigned)si->init_func, si->name);
			si->init_func();
			TRACE("[ %5d Done calling init_func for '%s' ]\n", pid, si->name);
		}
	}

	if (g_opts->call_dt_init_array) {
		/* 初始化队列 */
		if (si->init_array) {
			TRACE("[ %5d Calling init_array @ 0x%08x [%d] for '%s' ]\n", pid,
				  (unsigned)si->init_array, si->init_array_count, si->name);
			call_array(si->init_array, si->init_array_count, 0);
			TRACE("[ %5d Done calling init_array for '%s' ]\n", pid, si->name);
		}
	}

}

/* 由dlopen调用 */
void soinfo_call_constructors_from_dlopen(soinfo *si) {
    if (si->constructors_called)
        return;

    // Set this before actually calling the constructors, otherwise it doesn't
    // protect against recursive constructor calls. One simple example of
    // constructor recursion is the libc debug malloc, which is implemented in
    // libc_malloc_debug_leak.so:
    // 1. The program depends on libc, so libc's constructor is called here.
    // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
    // 3. dlopen() calls soinfo_call_constructors() with the newly created
    //    soinfo for libc_malloc_debug_leak.so.
    // 4. The debug so depends on libc, so soinfo_call_constructors() is
    //    called again with the libc soinfo. If it doesn't trigger the early-
    //    out above, the libc constructor will be called again (recursively!).
    si->constructors_called = 1;

	/* 共享文件不能有preinit_array表 */
    if (!(si->flags & FLAG_EXE) && si->preinit_array) {
		DL_ERR("shared library \"%s\" has a preinit_array table @ 0x%08x. "
			   "This is INVALID.", si->name, (unsigned) si->preinit_array);
    }

    // if (si->dynamic) {
    //     unsigned *d;
    //     for(d = si->dynamic; *d; d += 2) {
    //         if(d[0] == DT_NEEDED){
    //             soinfo* lsi = find_loaded_library(si->strtab + d[1]);
    //             if (!lsi) {
    //                 DL_ERR("\"%s\": could not initialize dependent library",
    //                        si->name);
    //             } else {
	// 				/* 调用依赖库的构造函数 */
	// 				soinfo_call_constructors(lsi);
    //             }
    //         }
    //     }
    // }

	if (g_opts->call_dt_init) {
		/* 调用初始化函数 */
		if (si->init_func) {
			TRACE("[ %5d Calling init_func @ 0x%08x for '%s' ]\n", pid,
				  (unsigned)si->init_func, si->name);
			si->init_func();
			TRACE("[ %5d Done calling init_func for '%s' ]\n", pid, si->name);
		}
	}

	if (g_opts->call_dt_init_array) {
		/* 初始化队列 */
		if (si->init_array) {
			TRACE("[ %5d Calling init_array @ 0x%08x [%d] for '%s' ]\n", pid,
				  (unsigned)si->init_array, si->init_array_count, si->name);
			call_array(si->init_array, si->init_array_count, 0);
			TRACE("[ %5d Done calling init_array for '%s' ]\n", pid, si->name);
		}
	}

}

/* 调用析构函数 */
static void call_destructors(soinfo *si)
{
	if (g_opts->call_dt_finit) {
		if (si->fini_array) {
			TRACE("[ %5d Calling fini_array @ 0x%08x [%d] for '%s' ]\n", pid,
				  (unsigned)si->fini_array, si->fini_array_count, si->name);
			call_array(si->fini_array, si->fini_array_count, 1);
			TRACE("[ %5d Done calling fini_array for '%s' ]\n", pid, si->name);
		}
	}

	if (g_opts->call_dt_finit_array) {
		if (si->fini_func) {
			TRACE("[ %5d Calling fini_func @ 0x%08x for '%s' ]\n", pid,
				  (unsigned)si->fini_func, si->name);
			si->fini_func();
			TRACE("[ %5d Done calling fini_func for '%s' ]\n", pid, si->name);
		}
	}
}

/* Force any of the closed stdin, stdout and stderr to be associated with
   /dev/null. */
/* 定位stdin,stdout与stderr到/dev/null */
static int nullify_closed_stdio (void)
{
    int dev_null, i, status;
    int return_value = 0;

    dev_null = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR));
    if (dev_null < 0) {
        DL_ERR("cannot open /dev/null: %s", strerror(errno));
        return -1;
    }
    TRACE("[ %5d Opened /dev/null file-descriptor=%d]\n", pid, dev_null);

    /* If any of the stdio file descriptors is valid and not associated
       with /dev/null, dup /dev/null to it.  */
    for (i = 0; i < 3; i++) {
        /* If it is /dev/null already, we are done. */
        if (i == dev_null) {
            continue;
        }

        TRACE("[ %5d Nullifying stdio file descriptor %d]\n", pid, i);
        status = TEMP_FAILURE_RETRY(fcntl(i, F_GETFL));

        /* If file is opened, we are good. */
        if (status != -1) {
            continue;
        }

        /* The only error we allow is that the file descriptor does not
           exist, in which case we dup /dev/null to it. */
        if (errno != EBADF) {
            DL_ERR("fcntl failed: %s", strerror(errno));
            return_value = -1;
            continue;
        }

        /* Try dupping /dev/null to this stdio file descriptor and
           repeat if there is a signal.  Note that any errors in closing
           the stdio descriptor are lost.  */
        status = TEMP_FAILURE_RETRY(dup2(dev_null, i));
        if (status < 0) {
            DL_ERR("dup2 failed: %s", strerror(errno));
            return_value = -1;
            continue;
        }
    }

    /* If /dev/null is not one of the stdio file descriptors, close it. */
    if (dev_null > 2) {
        TRACE("[ %5d Closing /dev/null file-descriptor=%d]\n", pid, dev_null);
        status = TEMP_FAILURE_RETRY(close(dev_null));
        if (status == -1) {
            DL_ERR("close failed: %s", strerror(errno));
            return_value = -1;
        }
    }

    return return_value;
}

/* 进行影像链接 */
static int soinfo_link_image(soinfo *si)
{
    unsigned *d;
    /* "base" might wrap around UINT32_MAX. */
    Elf32_Addr base = si->load_bias;
    const Elf32_Phdr *phdr = si->phdr;
    int phnum = si->phnum;
    int relocating_linker = (si->flags & FLAG_LINKER) != 0;  /* 是否要重定位链接器 */
    soinfo **needed, **pneeded;
    size_t dynamic_count;                                    /* 动态项数量 */

	/* 在linker被重定位之前我们不能调试任何东西 */
    if (!relocating_linker) {
        INFO("[ %5d linking %s ]\n", pid, si->name);
        DEBUG("%5d si->base = 0x%08x si->flags = 0x%08x\n", pid,
			  si->base, si->flags);
    }

	/* 展开动态段 */
    phdr_table_get_dynamic_section(phdr, phnum, base, &si->dynamic,
                                   &dynamic_count);
    if (si->dynamic == NULL) {
		/* 如果不是重定位链接器则报错 */
        if (!relocating_linker) {
            DL_ERR("missing PT_DYNAMIC?!");
        }
		/* 直接跳到错误 */
        goto fail;
    } else {
		/* 检查重定位是为针对linker */
        if (!relocating_linker) {
            DEBUG("%5d dynamic = %p\n", pid, si->dynamic);
        }
    }

	/* 记录 */
	if (g_infos.done == 0) {
		unsigned dynamic_size = dynamic_count * 8;
		unsigned dynamic_offset = (unsigned)si->dynamic - (unsigned)base;
		g_infos.dynamic_offset = dynamic_offset;
		g_infos.dynamic_size = dynamic_size;
	}

#ifdef ANDROID_ARM_LINKER
	/* ARM体系的linker, .ARM.exidx节,可有可无 */
    (void) phdr_table_get_arm_exidx(phdr, phnum, base,
                                    &si->ARM_exidx, &si->ARM_exidx_count);
#endif

	/* 从动态节中提取有用的信息 */
    for(d = si->dynamic; *d; d++){
        DEBUG("%5d d = %p, d[0] = 0x%08x d[1] = 0x%08x\n", pid, d, d[0], d[1]);
        switch(*d++){
        case DT_HASH:
			/* HASH表 */
			if (g_infos.done == 0)
				g_infos.dt_hash_offset = *d;
            si->nbucket = ((unsigned *) (base + *d))[0];
            si->nchain = ((unsigned *) (base + *d))[1];
            si->bucket = (unsigned *) (base + *d + 8);
            si->chain = (unsigned *) (base + *d + 8 + si->nbucket * 4);
            break;
        case DT_STRTAB:
			/* 字符串表 */
			if (g_infos.done == 0)
				g_infos.dt_strtab_offset = *d;
            si->strtab = (const char *) (base + *d);
            break;
        case DT_SYMTAB:
			/* 符号表 */
			if (g_infos.done == 0)
				g_infos.dt_symtab_offset = *d;
            si->symtab = (Elf32_Sym *) (base + *d);
            break;
        case DT_PLTREL:
			/* 延迟重定位 */
            if(*d != DT_REL) {
                DL_ERR("DT_RELA not supported");
                goto fail;
            }
            break;
        case DT_JMPREL:
			/* 延迟重定位 */
            si->plt_rel = (Elf32_Rel*) (base + *d);
            break;
        case DT_PLTRELSZ:
			/* 延迟重定位项 */
            si->plt_rel_count = *d / 8;
            break;
        case DT_REL:
			/* 重定位表 */
            si->rel = (Elf32_Rel*) (base + *d);
            break;
        case DT_RELSZ:
			/* 重定位项 */
            si->rel_count = *d / 8;
            break;
        case DT_PLTGOT:
            /* Save this in case we decide to do lazy binding. We don't yet. */
            si->plt_got = (unsigned *)(base + *d);
            break;
        case DT_DEBUG:
			/* _r_debug地址 GDB专用 */
#if !defined(ANDROID_MIPS_LINKER)
			/* 这里是为ARM使用的 */
#ifdef NOTIFY_GDB
            // Set the DT_DEBUG entry to the address of _r_debug for GDB
            *d = (int) &_r_debug;
#endif
#endif
            break;
		case DT_RELA:
			/* 带偏移的重定位项 */
            DL_ERR("DT_RELA not supported");
            goto fail;
        case DT_INIT:
			/* 入口点 */
            si->init_func = (void (*)(void))(base + *d);
            DEBUG("%5d %s constructors (init func) found at %p\n",
                  pid, si->name, si->init_func);
            break;
        case DT_FINI:
			/* 析构函数 */
            si->fini_func = (void (*)(void))(base + *d);
            DEBUG("%5d %s destructors (fini func) found at %p\n",
                  pid, si->name, si->fini_func);
            break;
        case DT_INIT_ARRAY:
			/* 初始化函数队列 */
            si->init_array = (unsigned *)(base + *d);
            DEBUG("%5d %s constructors (init_array) found at %p\n",
                  pid, si->name, si->init_array);
            break;
        case DT_INIT_ARRAYSZ:
			/* 初始化函数队列数量 */
            si->init_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
            break;
        case DT_FINI_ARRAY:
			/* 析构函数队列 */
            si->fini_array = (unsigned *)(base + *d);
            DEBUG("%5d %s destructors (fini_array) found at %p\n",
                  pid, si->name, si->fini_array);
            break;
        case DT_FINI_ARRAYSZ:
			/* 析构函数数量 */
            si->fini_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
            break;
        case DT_PREINIT_ARRAY:
            si->preinit_array = (unsigned *)(base + *d);
            DEBUG("%5d %s constructors (preinit_array) found at %p\n",
                  pid, si->name, si->preinit_array);
            break;
        case DT_PREINIT_ARRAYSZ:
            si->preinit_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
            break;
        case DT_TEXTREL:
			/* 当没有PIC选项时，直接作用于代码节的重定位表 */
            si->has_text_relocations = true;
            break;
#if defined(ANDROID_MIPS_LINKER)
			/* 这里是MIPS专用，跳过 */
        case DT_NEEDED:
        case DT_STRSZ:
        case DT_SYMENT:
        case DT_RELENT:
			break;
        case DT_MIPS_RLD_MAP:
            // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
            {
				r_debug** dp = (r_debug**) *d;
				*dp = &_r_debug;
            }
            break;
        case DT_MIPS_RLD_VERSION:
        case DT_MIPS_FLAGS:
        case DT_MIPS_BASE_ADDRESS:
        case DT_MIPS_UNREFEXTNO:
        case DT_MIPS_RWPLT:
            break;

        case DT_MIPS_PLTGOT:
#if 0
            /* not yet... */
            si->mips_pltgot = (unsigned *)(si->base + *d);
#endif
            break;

        case DT_MIPS_SYMTABNO:
            si->mips_symtabno = *d;
            break;

        case DT_MIPS_LOCAL_GOTNO:
            si->mips_local_gotno = *d;
            break;

        case DT_MIPS_GOTSYM:
            si->mips_gotsym = *d;
            break;

        default:
            DEBUG("%5d Unused DT entry: type 0x%08x arg 0x%08x\n",
                  pid, d[-1], d[0]);
            break;
#endif
        }
    }

    DEBUG("%5d si->base = 0x%08x, si->strtab = %p, si->symtab = %p\n",
		  pid, si->base, si->strtab, si->symtab);

	/* 如果符号表与字符串表缺失，则失败 */
    if((si->strtab == 0) || (si->symtab == 0)) {
        DL_ERR("missing essential tables");
        goto fail;
    }

    /* if this is the main executable, then load all of the preloads now */
	/* 如果是一个main可执行程序，现在加载所有的预先加载库 */
	if (g_opts->load_pre_libs) {
		if(si->flags & FLAG_EXE) {
			int i;
			memset(preloads, 0, sizeof(preloads));
			for(i = 0; ldpreload_names[i] != NULL; i++) {
				soinfo *lsi = find_library(ldpreload_names[i]);
				if(lsi == 0) {
					strlcpy(tmp_err_buf, linker_get_error(), sizeof(tmp_err_buf));
					DL_ERR("could not load library \"%s\" needed by \"%s\"; caused by %s", ldpreload_names[i], si->name, tmp_err_buf);
					goto fail;
				}
				lsi->refcount++;     /* 增加引用 */
				preloads[i] = lsi;
			}
		}/* end if */
	} else {
		if(si->flags & FLAG_EXE) {
			memset(preloads, 0, sizeof(preloads));
		}/* end if */
	}

	/* dynamic_count是一个上对齐的需要库的数量
	 * DT_NEEDED也是动态段中的一项，所以dynamic_count
	 * 肯定比依赖库的大小要大
	 */
	if (g_opts->load_needed_libs) {
		pneeded = needed = (soinfo**) alloca((1 + dynamic_count) * sizeof(soinfo*));

		/* 遍历动态节 */
		for(d = si->dynamic; *d; d += 2) {
			/* 加载依赖库 */
			if(d[0] == DT_NEEDED){
				DEBUG("%5d %s needs %s\n", pid, si->name, si->strtab + d[1]);
				soinfo *lsi = find_library(si->strtab + d[1]);
				if(lsi == 0) {
					strlcpy(tmp_err_buf, linker_get_error(), sizeof(tmp_err_buf));
					DL_ERR("could not load library \"%s\" needed by \"%s\"; caused by %s",
						   si->strtab + d[1], si->name, tmp_err_buf);
					goto fail;
				}
				*pneeded++ = lsi;
				lsi->refcount++;
			}
		}/* end for */
		*pneeded = NULL;
	} else {
		pneeded = needed = (soinfo**) alloca((1 + dynamic_count) * sizeof(soinfo*));
		*pneeded = NULL;
	}

	/* 不经过重定位 */
	if (g_opts->not_relocal == true) {
		goto done_relocal;
	}

	/* linker自身并无此选项 */
    if (si->has_text_relocations) {
		/* 对自身代码进行重定位，没有开启PIC选项编译 
		 * 先把代码段设置为可写，允许我们进行重定位
		 */
        /* Unprotect the segments, i.e. make them writable, to allow
         * text relocations to work properly. We will later call
         * phdr_table_protect_segments() after all of them are applied
         * and all constructors are run.
         */
        if (phdr_table_unprotect_segments(si->phdr, si->phnum, si->load_bias) < 0) {
            DL_ERR("can't unprotect loadable segments for \"%s\": %s",
                   si->name, strerror(errno));
            goto fail;
        }
    }

	/* 延迟引用重定位 */
    if(si->plt_rel) {
        DEBUG("[ %5d relocating %s plt ]\n", pid, si->name );
        if(soinfo_relocate(si, si->plt_rel, si->plt_rel_count, needed))
            goto fail;
    }
	/* 进行标准的重定位 */
    if(si->rel) {
        DEBUG("[ %5d relocating %s ]\n", pid, si->name );
        if(soinfo_relocate(si, si->rel, si->rel_count, needed))
            goto fail;
    }

#ifdef ANDROID_MIPS_LINKER
	/* 对MIPS的支持 */
    if(mips_relocate_got(si, needed)) {
        goto fail;
    }
#endif

    if (si->has_text_relocations) {
		/* 对自身进行重定位 */
        /* All relocations are done, we can protect our segments back to
         * read-only. */
		/* 重新修改会只读属性 */
        if (phdr_table_protect_segments(si->phdr, si->phnum, si->load_bias) < 0) {
            DL_ERR("can't protect segments for \"%s\": %s",
                   si->name, strerror(errno));
            goto fail;
        }
    }

	/* 已经完成重定位 */
 done_relocal:

	/* 这里标志已经完成链接 */
    si->flags |= FLAG_LINKED;
    DEBUG("[ %5d finished linking %s ]\n", pid, si->name);

    /* We can also turn on GNU RELRO protection */
	/* 将PT_GNU_RELRO段设置为只读 */
    if (phdr_table_protect_gnu_relro(si->phdr, si->phnum, si->load_bias) < 0) {
        DL_ERR("can't enable GNU RELRO protection for \"%s\": %s",
               si->name, strerror(errno));
        goto fail;
    }

    /* If this is a SET?ID program, dup /dev/null to opened stdin,
       stdout and stderr to close a security hole described in:

	   ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-02:23.stdio.asc

	*/
	/* 如果是一个SET？ID程序,则将stdin重定位到/dev/null设备,并且
	 * 将stdout与stderr定位到一个关闭的安全描述
	 */
    if (program_is_setuid) {
        nullify_closed_stdio();
    }

#ifdef NOTIFY_GDB
	/* 通知GDB调试器 */
    notify_gdb_of_load(si);
#endif

	/* 设置完成 */
	if (g_infos.done == 0) g_infos.done = 1;
    return 0;

 fail:
    ERROR("failed to link %s\n", si->name);
    si->flags |= FLAG_ERROR;
    return -1;
}

/* 分析路径 */
static void parse_path(const char* path, const char* delimiters,
                       const char** array, char* buf, size_t buf_size, size_t max_count)
{
    if (path == NULL) {
        return;
    }

    size_t len = strlcpy(buf, path, buf_size);

    size_t i = 0;
    char* buf_p = buf;
    while (i < max_count && (array[i] = strsep(&buf_p, delimiters))) {
        if (*array[i] != '\0') {
            ++i;
        }
    }

    // Forget the last path if we had to truncate; this occurs if the 2nd to
    // last char isn't '\0' (i.e. wasn't originally a delimiter).
    if (i > 0 && len >= buf_size && buf[buf_size - 2] != '\0') {
        array[i - 1] = NULL;
    } else {
        array[i] = NULL;
    }
}

/* 分析LD_LIBRARY_PATH环境变量 */
static void parse_LD_LIBRARY_PATH(const char* path) {
    parse_path(path, ":", ldpaths,
               ldpaths_buf, sizeof(ldpaths_buf), LDPATH_MAX);
}

/* 分析LD_PRELOAD环境变量 */
static void parse_LD_PRELOAD(const char* path) {
    // We have historically supported ':' as well as ' ' in LD_PRELOAD.
    parse_path(path, " :", ldpreload_names,
               ldpreloads_buf, sizeof(ldpreloads_buf), LDPRELOAD_MAX);
}

/*
 * This code is called after the linker has linked itself and
 * fixed it's own GOT. It is safe to make references to externs
 * and other non-local data at this point.
 */
/* elfdata : 要加载库的内存映射
 * linker_data : 链接器的基地址
 */
// static unsigned __linker_init_post_relocation(unsigned **elfdata, unsigned linker_base UNUSED)
// {
//     static soinfo linker_soinfo UNUSED;
	
//     int argc = (int) *elfdata;
//     char **argv = (char**) (elfdata + 1);
//     unsigned *vecs = (unsigned*) (argv + argc + 1);
//     unsigned *v;
//     soinfo *si;
//     int i UNUSED;
//     const char *ldpath_env = NULL;
//     const char *ldpreload_env = NULL;

//     /* NOTE: we store the elfdata pointer on a special location
//      *       of the temporary TLS area in order to pass it to
//      *       the C Library's runtime initializer.
//      *
//      *       The initializer must clear the slot and reset the TLS
//      *       to point to a different location to ensure that no other
//      *       shared library constructor can access it.
//      */
// 	/* TLS初始化
// 	 */
//     //__libc_init_tls(elfdata);

//     pid = getpid();

// #if TIMING
//     struct timeval t0, t1;
//     gettimeofday(&t0, 0);
// #endif

//     /* Initialize environment functions, and get to the ELF aux vectors table */
// 	/* 初始化环境函数，获取ELF辅助向量表 */
//     vecs = linker_env_init(vecs);

//     /* Check auxv for AT_SECURE first to see if program is setuid, setgid,
//        has file caps, or caused a SELinux/AppArmor domain transition. */
// 	/* 首先检查AT_SECURE的auxv遍历，如果程序被设置到setuid,setgid */
//     for (v = vecs; v[0]; v += 2) {
//         if (v[0] == AT_SECURE) {
//             /* kernel told us whether to enable secure mode */
// 			/* 内核通知是否开启安全模式 */
//             program_is_setuid = v[1];
//             goto sanitize;
//         }
//     }

//     /* Kernel did not provide AT_SECURE - fall back on legacy test. */
// 	/* 内核不提供AT_SECURE - 传递到传统模式测试 */
//     program_is_setuid = (getuid() != geteuid()) || (getgid() != getegid());

//  sanitize:
//     /* Sanitize environment if we're loading a setuid program */
// 	/* 如果我们读取到一个setuid程序清洁环境 */
//     if (program_is_setuid) {
//         linker_env_secure();
//     }

// #ifdef NOTIFY_GDB
// 	/* 调试器初始化 */
//     debugger_init();
// #endif

//     /* Get a few environment variables */
//     {
// #if LINKER_DEBUG == 1
// 		/* 调试链接器 */
//         const char* env;
//         env = linker_env_get("DEBUG"); /* XXX: TODO: Change to LD_DEBUG */
//         if (env)
//             debug_verbosity = atoi(env);
// #endif

//         /* Normally, these are cleaned by linker_env_secure, but the test
//          * against program_is_setuid doesn't cost us anything */
// 		/* 正常状况下，如果非setuid程序则获取
// 		 * LD_LIBRARY_PATH
// 		 * LD_PRELOAD
// 		 */
//         if (!program_is_setuid) {
//             ldpath_env = linker_env_get("LD_LIBRARY_PATH");
//             ldpreload_env = linker_env_get("LD_PRELOAD");
//         }
//     }

//     INFO("[ android linker & debugger ]\n");
//     DEBUG("%5d elfdata @ 0x%08x\n", pid, (unsigned)elfdata);

// 	/* 分配一个sinfo结构的内存 */
//     si = soinfo_alloc(argv[0]);
//     if(si == 0) {
//         exit(-1);
//     }

//     /* bootstrap the link map, the main exe always needs to be first */
// 	/* link_map是针对调试器使用的 */
//     si->flags |= FLAG_EXE;
// #ifdef NOTIFY_GDB
//     link_map* map = &(si->linkmap);

//     map->l_addr = 0;
//     map->l_name = argv[0];
//     map->l_prev = NULL;
//     map->l_next = NULL;

//     _r_debug.r_map = map;
//     r_debug_tail = map;

// 	/* gdb expects the linker to be in the debug shared object list.
// 	 * Without this, gdb has trouble locating the linker's ".text"
// 	 * and ".plt" sections. Gdb could also potentially use this to
// 	 * relocate the offset of our exported 'rtld_db_dlactivity' symbol.
// 	 * Don't use soinfo_alloc(), because the linker shouldn't
// 	 * be on the soinfo list.
// 	 */
// #endif

// #ifdef NOTIFY_GDB
// 	/* 设定linker的信息 */
//     strlcpy((char*) linker_soinfo.name, "/system/bin/linker", sizeof linker_soinfo.name);
//     linker_soinfo.flags = 0;
//     linker_soinfo.base = linker_base;
//     /*
//      * Set the dynamic field in the link map otherwise gdb will complain with
//      * the following:
//      *   warning: .dynamic section for "/system/bin/linker" is not at the
//      *   expected address (wrong library or version mismatch?)
//      */
//     Elf32_Ehdr *elf_hdr = (Elf32_Ehdr *) linker_base;
//     Elf32_Phdr *phdr =
//         (Elf32_Phdr *)((unsigned char *) linker_base + elf_hdr->e_phoff);
//     phdr_table_get_dynamic_section(phdr, elf_hdr->e_phnum, linker_base,
//                                    &linker_soinfo.dynamic, NULL);

//     insert_soinfo_into_debug_map(&linker_soinfo);
// #endif

//     /* extract information passed from the kernel */
// 	/* 提取从内核传递过来的信息 */
//     while(vecs[0] != 0){
// 		/* 程序头地址，程序头数量，入口点 */
//         switch(vecs[0]){
//         case AT_PHDR:
//             si->phdr = (Elf32_Phdr*) vecs[1];
//             break;
//         case AT_PHNUM:
//             si->phnum = (int) vecs[1];
//             break;
//         case AT_ENTRY:
//             si->entry = vecs[1];
//             break;
//         }
//         vecs += 2;
//     }

//     /* Compute the value of si->base. We can't rely on the fact that
//      * the first entry is the PHDR because this will not be true
//      * for certain executables (e.g. some in the NDK unit test suite)
//      */
//     int nn;
//     si->base = 0;
//     si->size = phdr_table_get_load_size(si->phdr, si->phnum);
//     si->load_bias = 0;
//     for ( nn = 0; nn < si->phnum; nn++ ) {
// 		/* 如果是头类型 */
//         if (si->phdr[nn].p_type == PT_PHDR) {
// 			/* 略过ELF头 */
//             si->load_bias = (Elf32_Addr)si->phdr - si->phdr[nn].p_vaddr;
//             si->base = (Elf32_Addr) si->phdr - si->phdr[nn].p_offset;
//             break;
//         }
//     }
//     si->dynamic = (unsigned *)-1;
//     si->refcount = 1;

//     // Use LD_LIBRARY_PATH and LD_PRELOAD (but only if we aren't setuid/setgid).
// 	/* 在非setuid程序的情况下使用LD_LIBRARY_PATH与LD_PRELOAD */
//     parse_LD_LIBRARY_PATH(ldpath_env);
//     parse_LD_PRELOAD(ldpreload_env);

// #ifdef USE_ORIG_LINK
// 	/* 加载这个SO文件 */
//     if(soinfo_link_image(si)) {
//         char errmsg[] = "CANNOT LINK EXECUTABLE\n";
//         write(2, __linker_dl_err_buf, strlen(__linker_dl_err_buf));
//         write(2, errmsg, sizeof(errmsg));
//         exit(-1);
//     }

// 	/* 进行构造函数 */
//     soinfo_call_preinit_constructors(si);

// 	/* 遍历所有预加载库并且调用他们的构造函数 */
//     for(i = 0; preloads[i] != NULL; i++) {
//         soinfo_call_constructors(preloads[i]);
//     }

// 	/* 调用当前库的构造函数 */
//     soinfo_call_constructors(si);
// #endif

// #if ALLOW_SYMBOLS_FROM_MAIN
//     /* Set somain after we've loaded all the libraries in order to prevent
//      * linking of symbols back to the main image, which is not set up at that
//      * point yet.
//      */
//     somain = si;
// #endif

// 	/* 以下这些是调试辅助信息了 */

// #if TIMING
//     gettimeofday(&t1,NULL);
//     PRINT("LINKER TIME: %s: %d microseconds\n", argv[0], (int) (
// 																(((long long)t1.tv_sec * 1000000LL) + (long long)t1.tv_usec) -
// 																(((long long)t0.tv_sec * 1000000LL) + (long long)t0.tv_usec)
// 																));
// #endif
// #if STATS
//     PRINT("RELO STATS: %s: %d abs, %d rel, %d copy, %d symbol\n", argv[0],
// 		  linker_stats.count[kRelocAbsolute],
// 		  linker_stats.count[kRelocRelative],
// 		  linker_stats.count[kRelocCopy],
// 		  linker_stats.count[kRelocSymbol]);
// #endif
// #if COUNT_PAGES
//     {
//         unsigned n;
//         unsigned i;
//         unsigned count = 0;
//         for(n = 0; n < 4096; n++){
//             if(bitmask[n]){
//                 unsigned x = bitmask[n];
//                 for(i = 0; i < 8; i++){
//                     if(x & 1) count++;
//                     x >>= 1;
//                 }
//             }
//         }
//         PRINT("PAGES MODIFIED: %s: %d (%dKB)\n", argv[0], count, count * 4);
//     }
// #endif

// #if TIMING || STATS || COUNT_PAGES
//     fflush(stdout);
// #endif

//     TRACE("[ %5d Ready to execute '%s' @ 0x%08x ]\n", pid, si->name,
//           si->entry);
//     return si->entry;
// }

/* 在内核传递给我们的数据中。寻找 AT_BASE的值
 */
static unsigned find_linker_base(unsigned **elfdata) {
	/* 获取命令个数
	 * 命令字符串
	 * 环境变量
	 */
    int argc = (int) *elfdata;
    char **argv = (char**) (elfdata + 1);
    unsigned *vecs = (unsigned*) (argv + argc + 1);
    while (vecs[0] != 0) {
        vecs++;
    }

	/* 环境块结束有两个NULL标记 */
    vecs++;

	/* 以下是一个数组，前4个字节表示类型，后4个字节表示值 */
    while(vecs[0]) {
        if (vecs[0] == AT_BASE) {
            return vecs[1];
        }
        vecs += 2;
    }

    return 0; // should never happen
}

/* Compute the load-bias of an existing executable. This shall only
 * be used to compute the load bias of an executable or shared library
 * that was loaded by the kernel itself.
 *
 * Input:
 *    elf    -> address of ELF header, assumed to be at the start of the file.
 * Return:
 *    load bias, i.e. add the value of any p_vaddr in the file to get
 *    the corresponding address in memory.
 */
/* 返回第一个可加载段的文件偏移 - 内存地址 之间的值
 */
static Elf32_Addr
get_elf_exec_load_bias(const Elf32_Ehdr* elf)
{
    Elf32_Addr        offset     = elf->e_phoff;
	unsigned          base       = (unsigned)elf;
    const Elf32_Phdr* phdr_table = reinterpret_cast<const Elf32_Phdr*>(base + offset);
    const Elf32_Phdr* phdr_end   = phdr_table + elf->e_phnum;
    const Elf32_Phdr* phdr;

    for (phdr = phdr_table; phdr < phdr_end; phdr++) {
        if (phdr->p_type == PT_LOAD) {
            return (Elf32_Addr)elf + phdr->p_offset - phdr->p_vaddr;
        }
    }
    return 0;
}

#if 0
/* 获取PT_DYNAMIC的内容 */
static int fill_pt_dynamic(soinfo* si) {
    unsigned *d;
    /* "base" might wrap around UINT32_MAX. */
    Elf32_Addr base = si->load_bias;
    const Elf32_Phdr *phdr = si->phdr;
    int phnum = si->phnum;
    size_t dynamic_count;                                    /* 动态项数量 */

	INFO("[ %5d linking %s ]\n", pid, si->name);
	DEBUG("%5d si->base = 0x%08x si->flags = 0x%08x\n", pid,
		  si->base, si->flags);

	/* 展开动态段 */
    phdr_table_get_dynamic_section(phdr, phnum, base, &si->dynamic,
                                   &dynamic_count);
    if (si->dynamic == NULL) {
		DL_ERR("missing PT_DYNAMIC?!");
		goto fail;
    } else {
		DEBUG("%5d dynamic = %p\n", pid, si->dynamic);
	}

#ifdef ANDROID_ARM_LINKER
	/* ARM体系的linker, .ARM.exidx节,可有可无 */
    (void) phdr_table_get_arm_exidx(phdr, phnum, base,
                                    &si->ARM_exidx, &si->ARM_exidx_count);
#endif

	/* 从动态节中提取有用的信息 */
    for(d = si->dynamic; *d; d++){
        DEBUG("%5d d = %p, d[0] = 0x%08x d[1] = 0x%08x\n", pid, d, d[0], d[1]);
        switch(*d++){
		case DT_NEEDED:
			DEBUG("%5d d = %p, needed library = %s\n", pid, d, si->strtab + d[1]);
			break;
        case DT_HASH:
			/* HASH表 */
            si->nbucket = ((unsigned *) (base + *d))[0];
            si->nchain = ((unsigned *) (base + *d))[1];
            si->bucket = (unsigned *) (base + *d + 8);
            si->chain = (unsigned *) (base + *d + 8 + si->nbucket * 4);
            break;
        case DT_STRTAB:
			/* 字符串表 */
            si->strtab = (const char *) (base + *d);
            break;
        case DT_SYMTAB:
			/* 符号表 */
            si->symtab = (Elf32_Sym *) (base + *d);
            break;
        case DT_PLTREL:
			/* 延迟重定位 */
            if(*d != DT_REL) {
                DL_ERR("DT_RELA not supported");
                goto fail;
            }
            break;
        case DT_JMPREL:
			/* 延迟重定位 */
            si->plt_rel = (Elf32_Rel*) (base + *d);
            break;
        case DT_PLTRELSZ:
			/* 延迟重定位项 */
            si->plt_rel_count = *d / 8;
            break;
        case DT_REL:
			/* 重定位表 */
            si->rel = (Elf32_Rel*) (base + *d);
            break;
        case DT_RELSZ:
			/* 重定位项 */
            si->rel_count = *d / 8;
            break;
        case DT_PLTGOT:
            /* Save this in case we decide to do lazy binding. We don't yet. */
            si->plt_got = (unsigned *)(base + *d);
            break;
        case DT_DEBUG:
			/* _r_debug地址 GDB专用 */
#if !defined(ANDROID_MIPS_LINKER)
			/* 这里是为ARM使用的 */
#ifdef NOTIFY_GDB
            // Set the DT_DEBUG entry to the address of _r_debug for GDB
            *d = (int) &_r_debug;
#endif
#endif
            break;
		case DT_RELA:
			/* 带偏移的重定位项 */
            DL_ERR("DT_RELA not supported");
            goto fail;
        case DT_INIT:
			/* 入口点 */
            si->init_func = (void (*)(void))(base + *d);
            DEBUG("%5d %s constructors (init func) found at %p\n",
                  pid, si->name, si->init_func);
            break;
        case DT_FINI:
			/* 析构函数 */
            si->fini_func = (void (*)(void))(base + *d);
            DEBUG("%5d %s destructors (fini func) found at %p\n",
                  pid, si->name, si->fini_func);
            break;
        case DT_INIT_ARRAY:
			/* 初始化函数队列 */
            si->init_array = (unsigned *)(base + *d);
            DEBUG("%5d %s constructors (init_array) found at %p\n",
                  pid, si->name, si->init_array);
            break;
        case DT_INIT_ARRAYSZ:
			/* 初始化函数队列数量 */
            si->init_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
            break;
        case DT_FINI_ARRAY:
			/* 析构函数队列 */
            si->fini_array = (unsigned *)(base + *d);
            DEBUG("%5d %s destructors (fini_array) found at %p\n",
                  pid, si->name, si->fini_array);
            break;
        case DT_FINI_ARRAYSZ:
			/* 析构函数数量 */
            si->fini_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
            break;
        case DT_PREINIT_ARRAY:
            si->preinit_array = (unsigned *)(base + *d);
            DEBUG("%5d %s constructors (preinit_array) found at %p\n",
                  pid, si->name, si->preinit_array);
            break;
        case DT_PREINIT_ARRAYSZ:
            si->preinit_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
            break;
        case DT_TEXTREL:
			/* 当没有PIC选项时，直接作用于代码节的重定位表 */
            si->has_text_relocations = true;
            break;
#if defined(ANDROID_MIPS_LINKER)
			/* 这里是MIPS专用，跳过 */
        case DT_NEEDED:
        case DT_STRSZ:
        case DT_SYMENT:
        case DT_RELENT:
			break;
        case DT_MIPS_RLD_MAP:
            // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
            {
				r_debug** dp = (r_debug**) *d;
				*dp = &_r_debug;
            }
            break;
        case DT_MIPS_RLD_VERSION:
        case DT_MIPS_FLAGS:
        case DT_MIPS_BASE_ADDRESS:
        case DT_MIPS_UNREFEXTNO:
        case DT_MIPS_RWPLT:
            break;

        case DT_MIPS_PLTGOT:
#if 0
            /* not yet... */
            si->mips_pltgot = (unsigned *)(si->base + *d);
#endif
            break;

        case DT_MIPS_SYMTABNO:
            si->mips_symtabno = *d;
            break;

        case DT_MIPS_LOCAL_GOTNO:
            si->mips_local_gotno = *d;
            break;

        case DT_MIPS_GOTSYM:
            si->mips_gotsym = *d;
            break;

        default:
            DEBUG("%5d Unused DT entry: type 0x%08x arg 0x%08x\n",
                  pid, d[-1], d[0]);
            break;
#endif
        }
    }

    DEBUG("%5d si->base = 0x%08x, si->strtab = %p, si->symtab = %p\n",
		  pid, si->base, si->strtab, si->symtab);

	/* 如果符号表与字符串表缺失，则失败 */
    if((si->strtab == 0) || (si->symtab == 0)) {
        DL_ERR("missing essential tables");
        goto fail;
    }

	return 0;

 fail:
    ERROR("failed to fill PT_DYNAMIC info %s\n", si->name);
    si->flags |= FLAG_ERROR;
    return -1;
}

static int fill_env(unsigned **elfdata, soinfo* isi) {
	int argc = (int) *elfdata;
    char **argv = (char**) (elfdata + 1);
    unsigned *vecs = (unsigned*) (argv + argc + 1);
    unsigned *v;
    soinfo *si;
    int i UNUSED;
    const char *ldpath_env = NULL;
    const char *ldpreload_env = NULL;
	unsigned linker_base UNUSED = isi->base;

#ifdef NODEBUG
    /* NOTE: we store the elfdata pointer on a special location
     *       of the temporary TLS area in order to pass it to
     *       the C Library's runtime initializer.
     *
     *       The initializer must clear the slot and reset the TLS
     *       to point to a different location to ensure that no other
     *       shared library constructor can access it.
     */
	/* TLS初始化
	 */
    __libc_init_tls(elfdata);
#endif

	pid = getpid();

#if TIMING
    struct timeval t0, t1;
    gettimeofday(&t0, 0);
#endif

    /* Initialize environment functions, and get to the ELF aux vectors table */
	/* 初始化环境函数，获取ELF辅助向量表 */
    vecs = linker_env_init(vecs);

    /* Check auxv for AT_SECURE first to see if program is setuid, setgid,
       has file caps, or caused a SELinux/AppArmor domain transition. */
	/* 首先检查AT_SECURE的auxv遍历，如果程序被设置到setuid,setgid */
    for (v = vecs; v[0]; v += 2) {
        if (v[0] == AT_SECURE) {
            /* kernel told us whether to enable secure mode */
			/* 内核通知是否开启安全模式 */
            program_is_setuid = v[1];
            goto sanitize;
        }
    }

    /* Kernel did not provide AT_SECURE - fall back on legacy test. */
	/* 内核不提供AT_SECURE - 传递到传统模式测试 */
    program_is_setuid = (getuid() != geteuid()) || (getgid() != getegid());

 sanitize:
    /* Sanitize environment if we're loading a setuid program */
	/* 如果我们读取到一个setuid程序清洁环境 */
    if (program_is_setuid) {
        linker_env_secure();
    }

#ifdef NOTIFY_GDB
	/* 调试器初始化 */
    debugger_init();
#endif

    /* Get a few environment variables */
    {
#if LINKER_DEBUG == 1
		/* 调试链接器 */
        // const char* env;
        // env = linker_env_get("DEBUG"); /* XXX: TODO: Change to LD_DEBUG */
        // if (env)
        //     debug_verbosity = atoi(env);
#endif

        /* Normally, these are cleaned by linker_env_secure, but the test
         * against program_is_setuid doesn't cost us anything */
		/* 正常状况下，如果非setuid程序则获取
		 * LD_LIBRARY_PATH
		 * LD_PRELOAD
		 */
        if (!program_is_setuid) {
            ldpath_env = linker_env_get("LD_LIBRARY_PATH");
            ldpreload_env = linker_env_get("LD_PRELOAD");
        }
    }

    INFO("[ android linker & debugger ]\n");
    DEBUG("%5d elfdata @ 0x%08x\n", pid, (unsigned)elfdata);

	/* 分配一个sinfo结构的内存 */
    si = soinfo_add(isi);
    if(si == 0) {
        exit(-1);
    }

    /* bootstrap the link map, the main exe always needs to be first */
	/* link_map是针对调试器使用的 */
    si->flags |= FLAG_EXE;
#ifdef NOTIFY_GDB
    link_map* map = &(si->linkmap);

    map->l_addr = 0;
    map->l_name = argv[0];
    map->l_prev = NULL;
    map->l_next = NULL;

    _r_debug.r_map = map;
    r_debug_tail = map;

	/* gdb expects the linker to be in the debug shared object list.
	 * Without this, gdb has trouble locating the linker's ".text"
	 * and ".plt" sections. Gdb could also potentially use this to
	 * relocate the offset of our exported 'rtld_db_dlactivity' symbol.
	 * Don't use soinfo_alloc(), because the linker shouldn't
	 * be on the soinfo list.
	 */
#endif

#ifdef NOTIFY_GDB
	soinfo linker_soinfo;
	/* 设定linker的信息 */
    strlcpy((char*) linker_soinfo.name, "/system/bin/linker", sizeof linker_soinfo.name);
    linker_soinfo.flags = 0;
    linker_soinfo.base = linker_base;
    /*
     * Set the dynamic field in the link map otherwise gdb will complain with
     * the following:
     *   warning: .dynamic section for "/system/bin/linker" is not at the
     *   expected address (wrong library or version mismatch?)
     */
    Elf32_Ehdr *elf_hdr = (Elf32_Ehdr *) linker_base;
    Elf32_Phdr *phdr =
        (Elf32_Phdr *)((unsigned char *) linker_base + elf_hdr->e_phoff);
    phdr_table_get_dynamic_section(phdr, elf_hdr->e_phnum, linker_base,
                                   &linker_soinfo.dynamic, NULL);

    insert_soinfo_into_debug_map(&linker_soinfo);
#endif

    /* extract information passed from the kernel */
	/* 提取从内核传递过来的信息 */
    while(vecs[0] != 0){
		/* 程序头地址，程序头数量，入口点 */
        switch(vecs[0]){
			// case AT_PHDR:
			//     si->phdr = (Elf32_Phdr*) vecs[1];
			//     break;
			// case AT_PHNUM:
			//     si->phnum = (int) vecs[1];
			//     break;
        case AT_ENTRY:
            si->entry = vecs[1];
            break;
        }
        vecs += 2;
    }

    /* Compute the value of si->base. We can't rely on the fact that
     * the first entry is the PHDR because this will not be true
     * for certain executables (e.g. some in the NDK unit test suite)
     */
    int nn;
    // si->base = 0;
    // si->size = phdr_table_get_load_size(si->phdr, si->phnum);
    // si->load_bias = 0;
    for ( nn = 0; nn < si->phnum; nn++ ) {
		/* 如果是头类型 */
        if (si->phdr[nn].p_type == PT_PHDR) {
			/* 略过ELF头 */
            si->load_bias = (Elf32_Addr)si->phdr - si->phdr[nn].p_vaddr;
            si->base = (Elf32_Addr) si->phdr - si->phdr[nn].p_offset;
            break;
        }
    }
    //si->dynamic = (unsigned *)-1;
    si->refcount = 1;

    // Use LD_LIBRARY_PATH and LD_PRELOAD (but only if we aren't setuid/setgid).
	/* 在非setuid程序的情况下使用LD_LIBRARY_PATH与LD_PRELOAD */
    parse_LD_LIBRARY_PATH(ldpath_env);
    parse_LD_PRELOAD(ldpreload_env);

#if ALLOW_SYMBOLS_FROM_MAIN
    /* Set somain after we've loaded all the libraries in order to prevent
     * linking of symbols back to the main image, which is not set up at that
     * point yet.
     */
    somain = si;
#endif

	/* 以下这些是调试辅助信息了 */

#if TIMING
    gettimeofday(&t1,NULL);
    PRINT("LINKER TIME: %s: %d microseconds\n", argv[0], (int) (
																(((long long)t1.tv_sec * 1000000LL) + (long long)t1.tv_usec) -
																(((long long)t0.tv_sec * 1000000LL) + (long long)t0.tv_usec)
																));
#endif
#if STATS
    PRINT("RELO STATS: %s: %d abs, %d rel, %d copy, %d symbol\n", argv[0],
		  linker_stats.count[kRelocAbsolute],
		  linker_stats.count[kRelocRelative],
		  linker_stats.count[kRelocCopy],
		  linker_stats.count[kRelocSymbol]);
#endif
#if COUNT_PAGES
    {
        unsigned n;
        unsigned i;
        unsigned count = 0;
        for(n = 0; n < 4096; n++){
            if(bitmask[n]){
                unsigned x = bitmask[n];
                for(i = 0; i < 8; i++){
                    if(x & 1) count++;
                    x >>= 1;
                }
            }
        }
        PRINT("PAGES MODIFIED: %s: %d (%dKB)\n", argv[0], count, count * 4);
    }
#endif

#if TIMING || STATS || COUNT_PAGES
    fflush(stdout);
#endif

    TRACE("[ %5d Ready to execute '%s' @ 0x%08x ]\n", pid, si->name,
          si->entry);
    return si->entry;
}
#endif

/*
 * This is the entry point for the linker, called from begin.S. This
 * method is responsible for fixing the linker's own relocations, and
 * then calling __linker_init_post_relocation().
 *
 * Because this method is called before the linker has fixed it's own
 * relocations, any attempt to reference an extern variable, extern
 * function, or other GOT reference will generate a segfault.
 */
/* 这个函数是linker的入口函数,被begin.S调用.这个函数对linker自身进行重定位，然后调用
 * __linker_init_post_relocation()函数.
 *
 * 应为这个函数被调用在linker修订自身重定位之前，在这个函数中，任何引用全局变量，函数，或者
 * 对齐GOT表的其余数据进行引用将产生一个 段错误 (segfault)
 */
unsigned __linker_init(unsigned **elfdata) {
	unsigned linker_entry = 0;
    unsigned linker_addr = find_linker_base(elfdata);     /* 找到linker的基地址 */
    Elf32_Ehdr *elf_hdr = (Elf32_Ehdr *) linker_addr;
    Elf32_Phdr *phdr UNUSED = reinterpret_cast<Elf32_Phdr*>(linker_addr + elf_hdr->e_phoff);

	/* 这里linker_so其实没有什么用途，仅是为了记录而已 */
    // soinfo linker_so;
    // memset(&linker_so, 0, sizeof(soinfo));

	// strcpy(linker_so.name, "linker");
    // linker_so.base = linker_addr;
    // linker_so.size = phdr_table_get_load_size(phdr, elf_hdr->e_phnum);
    // linker_so.load_bias = get_elf_exec_load_bias(elf_hdr);
    // linker_so.dynamic = (unsigned *) -1;
    // linker_so.phdr = phdr;
    // linker_so.phnum = elf_hdr->e_phnum;
    // linker_so.flags |= FLAG_LINKER;

	// fill_pt_dynamic(&linker_so);
	// linker_entry = fill_env(elfdata, &linker_so);

	// linker_so.constructors_called = 1;      /* 已经调用了 */
    // linker_so.flags |= FLAG_LINKED;     	/* 这里标志已经完成链接 */
    // if (soinfo_link_image(&linker_so)) {
    //     // It would be nice to print an error message, but if the linker
    //     // can't link itself, there's no guarantee that we'll be able to
    //     // call write() (because it involves a GOT reference).
    //     //
    //     // This situation should never occur unless the linker itself
    //     // is corrupt.
    //     exit(-1);
    // }

    // We have successfully fixed our own relocations. It's safe to run
    // the main part of the linker now.
	/* 现在我们以及功能成功完成我们自身的重定位.现在可以安全的运行linker了 */
    //return __linker_init_post_relocation(elfdata, linker_addr);
	return linker_entry;
}

void fix_entry(unsigned char* buf, soinfo* lib) {
	unsigned* d = lib->dynamic;
	while (*d) {
		if (*d == DT_INIT) {
			unsigned offset = (unsigned)(d+1) - lib->base;
			*(unsigned*)(void*)(buf + offset) = 0;
			break;
		}
		d += 2;
	}
}

int dump_file(soinfo* lib) {
	FILE* fp = fopen(g_opts->dump_file, "w");
	if (NULL ==fp) {
	}

	/* 修改整个映射为可读属性 */
	int ret = mprotect((void*)lib->base, 
					   lib->size, 
					   7);/* 全部权限打开 */
	printf("--------------------------------------------------\n");
	printf("base = 0x%x\n", lib->base);
	printf("size = 0x%x\n", lib->size);
	printf("entry = 0x%x\n", lib->entry);
	printf("program header count = %d\n", lib->phnum);
	printf("--------------------------------------------------\n");
			
	unsigned dump_size = lib->size;
	unsigned buf_size = dump_size + 0x10;
	unsigned char* buf = new unsigned char [buf_size];
	if (NULL == buf) {}
	memcpy(buf, (void*)lib->base, lib->size);

	/* 定位到程序头,将所有程序段的内存地址修订 */
	Elf32_Ehdr* elfhdr = (Elf32_Ehdr*)(void*)buf;
	elfhdr->e_shnum = 0;
	elfhdr->e_shoff = 0;
	elfhdr->e_shstrndx = 0;

	unsigned phoff = elfhdr->e_phoff;
	Elf32_Phdr* phdr = (Elf32_Phdr*)(void*)(buf + phoff);
	for (int i = 0; i < lib->phnum; i++, phdr++) {
		unsigned v = phdr->p_vaddr;
		phdr->p_offset = v;
		unsigned s = phdr->p_memsz;
		phdr->p_filesz = s;
	}

	/* 是否清除DT_INIT入口点 */
	if (g_opts->clear_entry)
		fix_entry(buf, lib);

	/* 写入 */
	ret = fwrite((void*)buf, 1, dump_size, fp);

	if (buf) delete [] buf;
	fflush(fp);
	fclose(fp);
	printf("Dump Successful\n");
	return 0;
}

Elf32_Phdr* elf_get_1th_PT_LOAD(unsigned char* fmap) {
	Elf32_Ehdr* hdr = (Elf32_Ehdr*)(void*)(fmap);
	Elf32_Phdr* phdr = (Elf32_Phdr*)(void*)(fmap + hdr->e_phoff);
	int phnum = hdr->e_phnum;

	int j = phnum;
	for (; --j >= 0; ++phdr)
		if (PT_LOAD == phdr->p_type) {
			return phdr;
		}
	return NULL;
}

unsigned elf_get_offset_from_address(unsigned char* fmap, unsigned const addr) {
	Elf32_Ehdr* hdr = (Elf32_Ehdr*)(void*)(fmap);
	Elf32_Phdr* phdr = (Elf32_Phdr*)(void*)(fmap + hdr->e_phoff);
	int phnum = hdr->e_phnum;

	int j = phnum;
	for (; --j >= 0; ++phdr)
		if (PT_LOAD == phdr->p_type) {
			unsigned const t = addr - phdr->p_vaddr;
			if (t < phdr->p_filesz) {
				return t + phdr->p_offset;
			}
		}
	return 0;
}

unsigned get_text_code(unsigned char* fmap, 
					   unsigned* xct_va,
					   unsigned* xct_offset) {
	Elf32_Ehdr* hdr = (Elf32_Ehdr*)(void*)(fmap);
	unsigned soff = hdr->e_shoff;
	int snum = hdr->e_shnum;
	Elf32_Shdr* shdr = (Elf32_Shdr*)(void*)(fmap + soff);
	bool find_exe_sec = false;
	
	*xct_va = *xct_offset = 0;

	for (int j = snum; --j >= 0; ++shdr) {
		/* 遇到可执行节 */
		if (SHF_EXECINSTR & shdr->sh_flags) {
			/* 这里寻找最后一个可执行节,跳过.plt节 */
			find_exe_sec = true;
			*xct_va = umax(*xct_va, shdr->sh_addr);
		}
	}
		
	/* 检查验证xct_va */
	if (!find_exe_sec)
		return 0;

	*xct_offset = elf_get_offset_from_address(fmap, *xct_va);

	Elf32_Phdr* pload = elf_get_1th_PT_LOAD(fmap);
	if (pload == NULL) return 0;

	unsigned size = pload->p_filesz - *xct_offset;

	return size;
}

void checkcode_by_x(unsigned char* fmap, const char* str, 
					unsigned x, unsigned s) {
	unsigned xct_offset = 0;
	/* 提取代码段的crc值 */
	unsigned text_size = s;
	unsigned char* text = fmap + x;
	unsigned crc = crc32(text, text_size);

	printf("%s:0x%X <%x:%x>\n", str, crc, xct_offset, text_size);
}

void checkcode(char* fname, const char* str, unsigned x, unsigned s) {
	unsigned xct_va = 0, xct_offset = 0;
	FILE* fp = fopen(fname, "rb");
	if (fp == NULL) {
		printf("can not open file:%s\n", fname);
		return;
	}

	fseek(fp, 0, SEEK_END);
	unsigned fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	unsigned char* fmap = new unsigned char [fsize+0x10];
	if (fmap == NULL) return;
	memset(fmap, 0, fsize+0x10);
	fread(fmap, 1, fsize, fp);

	/* 提取代码段的crc值 */
	unsigned text_size = 0;
	unsigned char* text = NULL;
	if ((x == 0) || (s == 0)) {
		text_size = get_text_code(fmap, &xct_va, &xct_offset);
	} else {
		text_size = s;
		xct_offset = x;
	}
	text = fmap + xct_offset;
	unsigned crc = crc32(text, text_size);

	printf("%s:0x%X <%x:%x>\n", str, crc, xct_offset, text_size);

	if (fmap) delete [] fmap;
	if (fp) fclose(fp);
}

int make_sectables(char* fname) {
	//unsigned size = 0;
	//Elf32_Shdr shdr;
	FILE* fp = fopen(fname, "wr");
	if (NULL == fp) {
		return -1;
	}

	fseek(fp, 0, SEEK_END);

	/* .dynamic节 */
	
	/* 节名表节 */
	/* 符号节 */
	/* 字符串节 */

	fflush(fp);
	fclose(fp);
	return 0;
}

int main(int argc, char* argv[]) {
	/* 处理命令行 */
	g_opts = handle_arguments(argc, argv);
	if (!g_opts) {
		/* 失败 */
		usage();
		return -1;
	}

	/* 设定调试级别 */
	debug_verbosity = g_opts->debuglevel;

	/* 处理命令行 */
	if (g_opts->help) {
		show_help();
		return 0;
	} else if (g_opts->version) {
		show_version();
		return 0;
	}

	/* 加载库文件 */
	if (g_opts->load) {

		/* 清空全局信息结构 */
		memset(&g_infos, 0, sizeof(g_infos));

		/* 填充符号表与libdl_info结构 */
		fill_libdl_symtab();
		fill_libdl_info();

		// unsigned ret = __linker_init((unsigned **)(argv-1));
		// if (ret == 0) return ret;

		char* fname = g_opts->target_file;
		soinfo* lib = (soinfo*)dlopen(fname, 0);
		if (lib == NULL) {
			return -1;
		}

		//void* handle = dlsym(lib, "prepare_key");
		//if (handle) {
		//	printf("%x\n", *(unsigned*)handle);
		//}

		/* 从lib中dump出文件 */
		if (g_opts->dump) {
			if (dump_file(lib) != 0) {
				return -1;
			}

			/* 制作节表 */
			// if (g_opts->make_sectabs) {
			// 	if (make_sectables(g_opts->dump_file) != 0) {
			// 		return -1;
			// 	}
			// }			
		} else {
			/* 打印代码CRC */
			if (g_opts->check) {
				checkcode_by_x((unsigned char*)(lib->base),
							   "code text crc32",
							   g_opts->xct_offset,
							   g_opts->xct_size);
			}
		}
		dlclose(lib);
	} else {
		/* 未加载的功能  */
		if (g_opts->check) {
			checkcode(g_opts->target_file, "code text crc32", 
					  g_opts->xct_offset, 
					  g_opts->xct_size);
		}
	}
	return 0;
}
