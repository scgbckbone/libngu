//
// secp256k1 anti-exfil signing helpers
//
#include "py/runtime.h"
#include <string.h>

#include "k1.h"

static const uint8_t antiexfil_tweak_tag[] = {
    'N', 'G', 'u', '/', 'A', 'n', 't', 'i', 'E', 'x', 'f', 'i', 'l',
    '/', 't', 'w', 'e', 'a', 'k'
};

static const uint8_t secp256k1_order[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

static void require_buf_len(mp_obj_t obj, mp_buffer_info_t *buf, size_t len, const char *msg)
{
    mp_get_buffer_raise(obj, buf, MP_BUFFER_READ);
    if(buf->len != len) {
        mp_raise_ValueError(msg);
    }
}

static void get_seckey(mp_obj_t privkey_in, uint8_t seckey[32])
{
    if(mp_obj_get_type(privkey_in) == &s_keypair_type) {
        mp_obj_keypair_t *keypair = MP_OBJ_TO_PTR(privkey_in);
        secp256k1_keypair_sec(lib_ctx, seckey, &keypair->keypair);
    } else {
        mp_buffer_info_t privkey;
        require_buf_len(privkey_in, &privkey, 32, MP_ERROR_TEXT("privkey len != 32"));
        memcpy(seckey, privkey.buf, 32);
    }
}

static int bytes32_ge(const uint8_t *a, const uint8_t *b)
{
    int i;

    for (i = 0; i < 32; i++) {
        if (a[i] > b[i]) {
            return 1;
        }
        if (a[i] < b[i]) {
            return 0;
        }
    }
    return 1;
}

static void bytes32_sub(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
    int i;
    unsigned int borrow = 0;

    for (i = 31; i >= 0; i--) {
        unsigned int ai = a[i];
        unsigned int bi = b[i] + borrow;
        if (ai < bi) {
            r[i] = (uint8_t)(ai + 0x100 - bi);
            borrow = 1;
        } else {
            r[i] = (uint8_t)(ai - bi);
            borrow = 0;
        }
    }
}

static void ecdsa_r_from_x(uint8_t r[32], const uint8_t x[32])
{
    if (bytes32_ge(x, secp256k1_order)) {
        bytes32_sub(r, x, secp256k1_order);
    } else {
        memcpy(r, x, 32);
    }
}

static int antiexfil_nonce_schnorr(
    uint8_t *nonce32,
    const uint8_t *msg,
    size_t msglen,
    const uint8_t *key32,
    const uint8_t *xonly_pk32,
    const uint8_t *algo,
    size_t algolen,
    void *data)
{
    (void)msg;
    (void)msglen;
    (void)key32;
    (void)xonly_pk32;
    (void)algo;
    (void)algolen;
    memcpy(nonce32, (uint8_t*)data, 32);
    return 1;
}

static int antiexfil_nonce_ecdsa(
    uint8_t *nonce32,
    const uint8_t *msg32,
    const uint8_t *key32,
    const uint8_t *algo16,
    void *data,
    unsigned int counter)
{
    (void)msg32;
    (void)key32;
    (void)algo16;
    (void)counter;
    memcpy(nonce32, (uint8_t*)data, 32);
    return 1;
}

static int antiexfil_tweak_schnorr(
    uint8_t tweak[32],
    const uint8_t Q32[32],
    const uint8_t msg32[32],
    const uint8_t rho32[32])
{
    uint8_t buf[96];

    memcpy(buf, Q32, 32);
    memcpy(buf + 32, msg32, 32);
    memcpy(buf + 64, rho32, 32);
    return secp256k1_tagged_sha256(
        lib_ctx, tweak, antiexfil_tweak_tag, sizeof(antiexfil_tweak_tag),
        buf, sizeof(buf));
}

static int antiexfil_tweak_ecdsa(
    uint8_t tweak[32],
    const uint8_t Q33[33],
    const uint8_t msg32[32],
    const uint8_t rho32[32])
{
    uint8_t buf[97];

    memcpy(buf, Q33, 33);
    memcpy(buf + 33, msg32, 32);
    memcpy(buf + 65, rho32, 32);
    return secp256k1_tagged_sha256(
        lib_ctx, tweak, antiexfil_tweak_tag, sizeof(antiexfil_tweak_tag),
        buf, sizeof(buf));
}

static int antiexfil_reconstruct_schnorr_R(
    uint8_t R32[32],
    const uint8_t Q32[32],
    const uint8_t msg32[32],
    const uint8_t rho32[32])
{
    secp256k1_xonly_pubkey Q;
    secp256k1_xonly_pubkey R_xonly;
    secp256k1_pubkey R;
    uint8_t tweak[32];
    int ok;

    ok = secp256k1_xonly_pubkey_parse(lib_ctx, &Q, Q32);
    if (!ok) {
        return 0;
    }
    ok = antiexfil_tweak_schnorr(tweak, Q32, msg32, rho32);
    if (!ok) {
        return 0;
    }
    ok = secp256k1_xonly_pubkey_tweak_add(lib_ctx, &R, &Q, tweak);
    if (!ok) {
        return 0;
    }
    ok = secp256k1_xonly_pubkey_from_pubkey(lib_ctx, &R_xonly, NULL, &R);
    if (!ok) {
        return 0;
    }
    return secp256k1_xonly_pubkey_serialize(lib_ctx, R32, &R_xonly);
}

static int antiexfil_reconstruct_ecdsa_r(
    uint8_t r32[32],
    const uint8_t Q33[33],
    const uint8_t msg32[32],
    const uint8_t rho32[32])
{
    secp256k1_pubkey Q;
    secp256k1_pubkey R;
    secp256k1_xonly_pubkey R_xonly;
    uint8_t tweak[32];
    uint8_t R32[32];
    int ok;

    ok = secp256k1_ec_pubkey_parse(lib_ctx, &Q, Q33, 33);
    if (!ok) {
        return 0;
    }
    ok = antiexfil_tweak_ecdsa(tweak, Q33, msg32, rho32);
    if (!ok) {
        return 0;
    }
    R = Q;
    ok = secp256k1_ec_pubkey_tweak_add(lib_ctx, &R, tweak);
    if (!ok) {
        return 0;
    }
    ok = secp256k1_xonly_pubkey_from_pubkey(lib_ctx, &R_xonly, NULL, &R);
    if (!ok) {
        return 0;
    }
    ok = secp256k1_xonly_pubkey_serialize(lib_ctx, R32, &R_xonly);
    if (!ok) {
        return 0;
    }
    ecdsa_r_from_x(r32, R32);
    return 1;
}

STATIC mp_obj_t s_antiexfil_sign_schnorr(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    sec_setup_ctx();

    mp_buffer_info_t digest;
    mp_buffer_info_t q_in;
    mp_buffer_info_t rho;
    uint8_t seckey[32];
    uint8_t q[32];
    uint8_t Q32[32];
    uint8_t tweak[32];
    uint8_t k[32];
    secp256k1_pubkey Q_pub;
    secp256k1_xonly_pubkey Q_xonly;
    secp256k1_keypair keypair;
    int parity = 0;
    int ok;

    get_seckey(args[0], seckey);
    require_buf_len(args[1], &digest, 32, MP_ERROR_TEXT("md len != 32"));
    require_buf_len(args[2], &q_in, 32, MP_ERROR_TEXT("q len != 32"));
    require_buf_len(args[3], &rho, 32, MP_ERROR_TEXT("rho len != 32"));

    ok = secp256k1_keypair_create(lib_ctx, &keypair, seckey);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid secret"));
    }

    memcpy(q, q_in.buf, 32);
    ok = secp256k1_ec_pubkey_create(lib_ctx, &Q_pub, q);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid q"));
    }
    ok = secp256k1_xonly_pubkey_from_pubkey(lib_ctx, &Q_xonly, &parity, &Q_pub);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_xonly_pubkey_from_pubkey"));
    }
    ok = secp256k1_xonly_pubkey_serialize(lib_ctx, Q32, &Q_xonly);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_xonly_pubkey_serialize"));
    }
    if (parity) {
        ok = secp256k1_ec_seckey_negate(lib_ctx, q);
        if (!ok) {
            mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ec_seckey_negate"));
        }
    }

    ok = antiexfil_tweak_schnorr(tweak, Q32, digest.buf, rho.buf);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("anti-exfil tweak"));
    }
    memcpy(k, q, 32);
    ok = secp256k1_ec_seckey_tweak_add(lib_ctx, k, tweak);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("anti-exfil nonce"));
    }

    vstr_t sig;
    vstr_init_len(&sig, 64);
    secp256k1_schnorrsig_extraparams xp = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    xp.noncefp = antiexfil_nonce_schnorr;
    xp.ndata = k;
    ok = secp256k1_schnorrsig_sign_custom(
        lib_ctx, (uint8_t *)sig.buf, digest.buf, digest.len, &keypair, &xp);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_schnorrsig_sign_custom"));
    }

    mp_obj_t res[2];
    res[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &sig);
    res[1] = mp_obj_new_bytes(Q32, 32);
    return mp_obj_new_tuple(2, res);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    s_antiexfil_sign_schnorr_obj, 4, 4, s_antiexfil_sign_schnorr);

STATIC mp_obj_t s_antiexfil_verify_schnorr(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    sec_setup_ctx();

    mp_buffer_info_t sig;
    mp_buffer_info_t digest;
    mp_buffer_info_t Q32;
    mp_buffer_info_t rho;
    uint8_t R32[32];

    require_buf_len(args[0], &sig, 64, MP_ERROR_TEXT("compact sig len != 64"));
    require_buf_len(args[1], &digest, 32, MP_ERROR_TEXT("md len != 32"));
    if(mp_obj_get_type(args[2]) != &s_xonly_pubkey_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("xonly pubkey type"));
    }
    require_buf_len(args[3], &Q32, 32, MP_ERROR_TEXT("Q len != 32"));
    require_buf_len(args[4], &rho, 32, MP_ERROR_TEXT("rho len != 32"));

    if (!antiexfil_reconstruct_schnorr_R(R32, Q32.buf, digest.buf, rho.buf)) {
        return mp_const_false;
    }
    if (memcmp(R32, sig.buf, 32) != 0) {
        return mp_const_false;
    }

    mp_obj_xonly_pubkey_t *xonly_pub = MP_OBJ_TO_PTR(args[2]);
    int ok = secp256k1_schnorrsig_verify(
        lib_ctx, sig.buf, digest.buf, digest.len, &xonly_pub->pubkey);
    return mp_obj_new_bool(ok == 1);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    s_antiexfil_verify_schnorr_obj, 5, 5, s_antiexfil_verify_schnorr);

STATIC mp_obj_t s_antiexfil_sign(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    sec_setup_ctx();

    mp_buffer_info_t digest;
    mp_buffer_info_t q_in;
    mp_buffer_info_t rho;
    uint8_t seckey[32];
    uint8_t q[32];
    uint8_t Q33[33];
    uint8_t tweak[32];
    uint8_t k[32];
    secp256k1_pubkey Q_pub;
    size_t Q33_len = sizeof(Q33);
    int ok;

    get_seckey(args[0], seckey);
    require_buf_len(args[1], &digest, 32, MP_ERROR_TEXT("md len != 32"));
    require_buf_len(args[2], &q_in, 32, MP_ERROR_TEXT("q len != 32"));
    require_buf_len(args[3], &rho, 32, MP_ERROR_TEXT("rho len != 32"));

    memcpy(q, q_in.buf, 32);
    ok = secp256k1_ec_pubkey_create(lib_ctx, &Q_pub, q);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid q"));
    }
    ok = secp256k1_ec_pubkey_serialize(
        lib_ctx, Q33, &Q33_len, &Q_pub, SECP256K1_EC_COMPRESSED);
    if (!ok || Q33_len != sizeof(Q33)) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ec_pubkey_serialize"));
    }

    ok = antiexfil_tweak_ecdsa(tweak, Q33, digest.buf, rho.buf);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("anti-exfil tweak"));
    }
    memcpy(k, q, 32);
    ok = secp256k1_ec_seckey_tweak_add(lib_ctx, k, tweak);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("anti-exfil nonce"));
    }

    mp_obj_sig_t *sig = m_new_obj(mp_obj_sig_t);
    sig->base.type = &s_sig_type;
    ok = secp256k1_ecdsa_sign_recoverable(
        lib_ctx, &sig->sig, digest.buf, seckey, antiexfil_nonce_ecdsa, k);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ecdsa_sign_recoverable"));
    }

    mp_obj_t res[2];
    res[0] = MP_OBJ_FROM_PTR(sig);
    res[1] = mp_obj_new_bytes(Q33, 33);
    return mp_obj_new_tuple(2, res);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    s_antiexfil_sign_obj, 4, 4, s_antiexfil_sign);

STATIC mp_obj_t s_antiexfil_verify(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    sec_setup_ctx();

    mp_buffer_info_t digest;
    mp_buffer_info_t Q33;
    mp_buffer_info_t rho;
    uint8_t expect_r[32];
    uint8_t sig64[64];
    int recid = 0;

    if(mp_obj_get_type(args[0]) != &s_sig_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("sig type"));
    }
    require_buf_len(args[1], &digest, 32, MP_ERROR_TEXT("md len != 32"));
    if(mp_obj_get_type(args[2]) != &s_pubkey_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("pubkey type"));
    }
    require_buf_len(args[3], &Q33, 33, MP_ERROR_TEXT("Q len != 33"));
    require_buf_len(args[4], &rho, 32, MP_ERROR_TEXT("rho len != 32"));

    if (!antiexfil_reconstruct_ecdsa_r(expect_r, Q33.buf, digest.buf, rho.buf)) {
        return mp_const_false;
    }

    mp_obj_sig_t *sig = MP_OBJ_TO_PTR(args[0]);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(
        lib_ctx, sig64, &recid, &sig->sig);
    if (memcmp(expect_r, sig64, 32) != 0) {
        return mp_const_false;
    }

    secp256k1_ecdsa_signature normal_sig;
    secp256k1_ecdsa_recoverable_signature_convert(lib_ctx, &normal_sig, &sig->sig);

    mp_obj_pubkey_t *pubkey = MP_OBJ_TO_PTR(args[2]);
    int ok = secp256k1_ecdsa_verify(lib_ctx, &normal_sig, digest.buf, &pubkey->pubkey);
    return mp_obj_new_bool(ok == 1);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    s_antiexfil_verify_obj, 5, 5, s_antiexfil_verify);

STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_antiexfil) },

    { MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&s_antiexfil_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&s_antiexfil_verify_obj) },
    { MP_ROM_QSTR(MP_QSTR_sign_schnorr), MP_ROM_PTR(&s_antiexfil_sign_schnorr_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify_schnorr), MP_ROM_PTR(&s_antiexfil_verify_schnorr_obj) },
};

STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_antiexfil = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
