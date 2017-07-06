/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "xdlfcn.h"
#include <pthread.h>
#include <stdio.h>
#include "linker.h"
#include "linker_format.h"

/* This file hijacks the symbols stubbed out in libdl.so. */

#define DL_SUCCESS                    0
#define DL_ERR_CANNOT_LOAD_LIBRARY    1
#define DL_ERR_INVALID_LIBRARY_HANDLE 2
#define DL_ERR_BAD_SYMBOL_NAME        3
#define DL_ERR_SYMBOL_NOT_FOUND       4
#define DL_ERR_SYMBOL_NOT_GLOBAL      5

static char dl_err_buf[1024];
static const char *dl_err_str;

static const char *dl_errors[] = {
	"Success",
    "Cannot load library",
    "Invalid library handle",
    "Invalid symbol name",
    "Symbol not found",
    "Symbol is not global",
};

#define likely(expr)   __builtin_expect (expr, 1)
#define unlikely(expr) __builtin_expect (expr, 0)

pthread_mutex_t dl_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER;

static void set_dlerror(int err)
{
    format_buffer(dl_err_buf, sizeof(dl_err_buf), "%s: %s", dl_errors[err],
             linker_get_error());
    dl_err_str = (const char *)&dl_err_buf[0];
};

void *dlopen(const char *filename, int flag UNUSED)
{
    soinfo *ret;

    pthread_mutex_lock(&dl_lock);
	/* 寻找库，并加载 */
    ret = find_library(filename);
    if (unlikely(ret == NULL)) {
        set_dlerror(DL_ERR_CANNOT_LOAD_LIBRARY);
    } else {
		/* 调用构造函数 */
        soinfo_call_constructors_from_dlopen(ret);
        ret->refcount++;
    }
    pthread_mutex_unlock(&dl_lock);
    return ret;
}

const char *dlerror(void)
{
    const char *tmp = dl_err_str;
    dl_err_str = NULL;
    return (const char *)tmp;
}

void *dlsym(void *handle, const char *symbol)
{
    soinfo *found;
    Elf32_Sym *sym;
    unsigned bind;

    pthread_mutex_lock(&dl_lock);

    if(unlikely(handle == 0)) {
        set_dlerror(DL_ERR_INVALID_LIBRARY_HANDLE);
        goto err;
    }
    if(unlikely(symbol == 0)) {
        set_dlerror(DL_ERR_BAD_SYMBOL_NAME);
        goto err;
    }

    if(handle == RTLD_DEFAULT) {
        sym = lookup(symbol, &found, NULL);
    } else if(handle == RTLD_NEXT) {
        void *ret_addr = __builtin_return_address(0);
        soinfo *si = find_containing_library(ret_addr);

        sym = NULL;
        if(si && si->next) {
            sym = lookup(symbol, &found, si->next);
        }
    } else {
        found = (soinfo*)handle;
        sym = soinfo_lookup(found, symbol);
    }

    if(likely(sym != 0)) {
        bind = ELF32_ST_BIND(sym->st_info);

        if(likely((bind == STB_GLOBAL) && (sym->st_shndx != 0))) {
            unsigned ret = sym->st_value + found->base;
            pthread_mutex_unlock(&dl_lock);
            return (void*)ret;
        }

        set_dlerror(DL_ERR_SYMBOL_NOT_GLOBAL);
    }
    else
        set_dlerror(DL_ERR_SYMBOL_NOT_FOUND);

err:
    pthread_mutex_unlock(&dl_lock);
    return 0;
}

int dladdr(const void *addr, Dl_info* info)
{
    int ret = 0;

    pthread_mutex_lock(&dl_lock);

    /* Determine if this address can be found in any library currently mapped */
    soinfo *si = find_containing_library(addr);

    if(si) {
        memset(info, 0, sizeof(Dl_info));

        info->dli_fname = si->name;
        info->dli_fbase = (void*)si->base;

        /* Determine if any symbol in the library contains the specified address */
        Elf32_Sym *sym = soinfo_find_symbol(si, addr);

        if(sym != NULL) {
            info->dli_sname = si->strtab + sym->st_name;
            info->dli_saddr = (void*)(si->base + sym->st_value);
        }

        ret = 1;
    }

    pthread_mutex_unlock(&dl_lock);

    return ret;
}

int dlclose(void* handle) {
    pthread_mutex_lock(&dl_lock);
    int result = soinfo_unload((soinfo*)handle);
    pthread_mutex_unlock(&dl_lock);
    return result;
}
