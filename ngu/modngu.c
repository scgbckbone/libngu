//
// mod NgU
//
#include "py/obj.h"
#include "py/runtime.h"
#include "py/builtin.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if MICROPY_ENABLE_DYNRUNTIME
#error "Static Only"
#endif

// All submodules here.
extern const mp_obj_module_t mp_module_hash;
extern const mp_obj_module_t mp_module_secp256k1;
extern const mp_obj_module_t mp_module_rnd;
extern const mp_obj_module_t mp_module_codecs;
extern const mp_obj_module_t mp_module_hdnode;
extern const mp_obj_module_t mp_module_hmac;
#if MICROPY_SSL_MBEDTLS
extern const mp_obj_module_t mp_module_ec;
extern const mp_obj_module_t mp_module_cert;
#endif
#if NGU_INCL_AES
extern const mp_obj_module_t mp_module_aes;
#endif

STATIC const mp_rom_map_elem_t mp_module_ngu_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ngu) },

    // Constants
    //{ MP_ROM_QSTR(MP_QSTR_ABCD_123), MP_ROM_INT(34) },

    { MP_ROM_QSTR(MP_QSTR_hdnode), MP_ROM_PTR(&mp_module_hdnode) },
    { MP_ROM_QSTR(MP_QSTR_hash), MP_ROM_PTR(&mp_module_hash) },
    { MP_ROM_QSTR(MP_QSTR_secp256k1), MP_ROM_PTR(&mp_module_secp256k1) },
    { MP_ROM_QSTR(MP_QSTR_rnd), MP_ROM_PTR(&mp_module_rnd) },
    { MP_ROM_QSTR(MP_QSTR_codecs), MP_ROM_PTR(&mp_module_codecs) },
    { MP_ROM_QSTR(MP_QSTR_hmac), MP_ROM_PTR(&mp_module_hmac) },
#if MICROPY_SSL_MBEDTLS
    { MP_ROM_QSTR(MP_QSTR_ec), MP_ROM_PTR(&mp_module_ec) },
    { MP_ROM_QSTR(MP_QSTR_cert), MP_ROM_PTR(&mp_module_cert) },
#endif
#if NGU_INCL_AES
    { MP_ROM_QSTR(MP_QSTR_aes), MP_ROM_PTR(&mp_module_aes) },
#endif
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ngu_globals, mp_module_ngu_globals_table);

const mp_obj_module_t mp_module_ngu = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_ngu_globals,
};

MP_REGISTER_MODULE(MP_QSTR_ngu, mp_module_ngu);


