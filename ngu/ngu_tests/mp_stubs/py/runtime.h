#pragma once

// Minimal MicroPython declarations needed to compile the production random.c
// in the deterministic host test. None of these wrappers are exercised there.
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define STATIC static
#define MP_BUFFER_READ 1
#define MP_ERROR_TEXT(text) text

typedef uintptr_t mp_obj_t;
typedef uintptr_t mp_rom_obj_t;

typedef struct {
    const void *type;
} mp_obj_base_t;

typedef struct {
    mp_obj_base_t base;
    void *globals;
} mp_obj_module_t;

typedef struct {
    int unused;
} mp_obj_dict_t;

typedef struct {
    mp_rom_obj_t key;
    mp_rom_obj_t value;
} mp_rom_map_elem_t;

typedef union {
    mp_obj_t (*fun0)(void);
    mp_obj_t (*fun1)(mp_obj_t);
} mp_obj_fun_builtin_fixed_t;

typedef struct {
    void *buf;
    size_t len;
} mp_buffer_info_t;

typedef struct {
    size_t alloc;
    size_t len;
    char *buf;
    bool fixed_buf;
} vstr_t;

extern const int mp_type_bytes;
extern const int mp_type_module;

#define mp_const_none ((mp_obj_t)0)
#define MP_QSTR___name__ 1
#define MP_QSTR_random 2
#define MP_QSTR_bytes 3
#define MP_QSTR_uint32 4
#define MP_QSTR_uniform 5
#define MP_QSTR_reseed 6
#define MP_ROM_QSTR(qstr) ((mp_rom_obj_t)(qstr))
#define MP_ROM_PTR(ptr) ((mp_rom_obj_t)(uintptr_t)(ptr))

#define MP_DEFINE_CONST_FUN_OBJ_0(name, function) \
    const mp_obj_fun_builtin_fixed_t name = { .fun0 = function }
#define MP_DEFINE_CONST_FUN_OBJ_1(name, function) \
    const mp_obj_fun_builtin_fixed_t name = { .fun1 = function }
#define MP_DEFINE_CONST_DICT(name, table) \
    const mp_obj_dict_t name = { 0 }

mp_obj_t mp_obj_new_int_from_uint(uint32_t value);
int mp_obj_get_int_truncated(mp_obj_t object);
void mp_raise_OSError(int error) __attribute__((noreturn));
void mp_raise_ValueError(const char *message) __attribute__((noreturn));
void vstr_init_len(vstr_t *vstr, size_t len);
mp_obj_t mp_obj_new_str_from_vstr(const void *type, vstr_t *vstr);
void mp_get_buffer_raise(mp_obj_t object, mp_buffer_info_t *buffer, int flags);
