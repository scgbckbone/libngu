// Two-round anti-exfil signing. Secret nonces never cross the Python boundary.
#include "k1.h"
#include <limits.h>
#include "cifra/ext/handy.h"
#include <string.h>

static void require_buf_len(mp_obj_t obj, mp_buffer_info_t *buf, size_t len)
{
    mp_get_buffer_raise(obj, buf, MP_BUFFER_READ);
    if (buf->len != len) mp_raise_ValueError(MP_ERROR_TEXT("anti-exfil buffer length"));
}

static int host_hash(uint8_t out[32], const uint8_t rho[32], int schnorr)
{
    const char *tag = schnorr ? "s2c/schnorr/data" : "s2c/ecdsa/data";
    return secp256k1_tagged_sha256(lib_ctx, out, (const uint8_t *)tag, strlen(tag), rho, 32);
}

static int nonce_tweak(uint8_t out[32], const uint8_t *Q, const uint8_t rho[32], int schnorr)
{
    const char *tag = schnorr ? "s2c/schnorr/point" : "s2c/ecdsa/point";
    size_t qlen = schnorr ? 32 : 33;
    uint8_t buf[65];
    memcpy(buf, Q, qlen);
    memcpy(buf + qlen, rho, 32);
    // The secp tweak APIs reject hashes >= n; do not reduce the hash here.
    return secp256k1_tagged_sha256(lib_ctx, out, (const uint8_t *)tag, strlen(tag), buf, qlen + 32);
}

static int derive_ecdsa(uint8_t q[32], const uint8_t sk[32], const uint8_t md[32], const uint8_t hc[32])
{
    // Match secp256k1-zkp's anti-exfil commitment derivation, including
    // RFC6979 bits2octets reduction of the digest and its retry sequence.
    for (unsigned int counter = 0; ; ++counter) {
        if (!secp256k1_nonce_function_rfc6979(q, md, sk, NULL, (void *)hc, counter))
            return 0;
        if (secp256k1_ec_seckey_verify(lib_ctx, q)) return 1;
        if (counter == UINT_MAX) return 0;
    }
}

#if NGU_INCL_SCHNORR
static int derive_schnorr(uint8_t q[32], const uint8_t sk[32], const uint8_t md[32], const uint8_t hc[32])
{
    secp256k1_pubkey pub;
    secp256k1_xonly_pubkey xpub;
    uint8_t d[32], pk[32];
    int parity, ok;
    memcpy(d, sk, 32);
    ok = secp256k1_ec_pubkey_create(lib_ctx, &pub, d)
        && secp256k1_xonly_pubkey_from_pubkey(lib_ctx, &xpub, &parity, &pub)
        && secp256k1_xonly_pubkey_serialize(lib_ctx, pk, &xpub);
    if (ok && parity) ok = secp256k1_ec_seckey_negate(lib_ctx, d);
    if (ok) {
        static const uint8_t algo[] = "BIP0340/nonce";
        ok = secp256k1_nonce_function_bip340(q, md, 32, d, pk, algo, sizeof(algo)-1, (void *)hc);
        ngu_secp256k1_scalar_reduce(q, q);
        ok = ok && secp256k1_ec_seckey_verify(lib_ctx, q);
    }
    mem_clean(d, sizeof d);
    return ok;
}

static int forced_schnorr(uint8_t *nonce, const uint8_t *msg, size_t msglen,
        const uint8_t *key, const uint8_t *pk, const uint8_t *algo, size_t algolen, void *data)
{
    (void)msg; (void)msglen; (void)key; (void)pk; (void)algo; (void)algolen;
    memcpy(nonce, data, 32);
    return 1;
}
#endif

static int forced_ecdsa(uint8_t *nonce, const uint8_t *msg, const uint8_t *key,
        const uint8_t *algo, void *data, unsigned int counter)
{
    (void)msg; (void)key; (void)algo;
    if (counter) return 0;  // Never retry/grind after publishing Q.
    memcpy(nonce, data, 32);
    return 1;
}

// Input checking and signature-object allocation precede secret copies. Then
// helpers return errors, allowing cleanup before any Python exception or
// allocation of the public return values.
static mp_obj_t ae_run(const mp_obj_t *args, int signing, int schnorr)
{
    sec_setup_ctx();
    mp_buffer_info_t md, hc, rho, raw;
    require_buf_len(args[1], &md, 32);
    require_buf_len(args[2], &hc, 32);
    if (signing) require_buf_len(args[3], &rho, 32);
    int is_keypair = mp_obj_get_type(args[0]) == &s_keypair_type;
    if (!is_keypair) require_buf_len(args[0], &raw, 32);

    uint8_t check[32];
    if (signing && (!host_hash(check, rho.buf, schnorr) || memcmp(check, hc.buf, 32))) {
        mp_raise_ValueError(MP_ERROR_TEXT("host entropy mismatch"));
    }

    mp_obj_sig_t *sig = NULL;
    if (signing && !schnorr) {
        sig = m_new_obj(mp_obj_sig_t);
        sig->base.type = &s_sig_type;
    }
    uint8_t sk[32], q[32], k[32], Q[33], tweak[32], sig64[64];
    secp256k1_keypair keypair;
    secp256k1_pubkey pub;
    int ok;
    if (is_keypair) {
        mp_obj_keypair_t *kp = MP_OBJ_TO_PTR(args[0]);
        ok = secp256k1_keypair_sec(lib_ctx, sk, &kp->keypair);
    } else {
        memcpy(sk, raw.buf, 32);
        ok = 1;
    }
    ok = ok && secp256k1_ec_seckey_verify(lib_ctx, sk);
    size_t qlen = schnorr ? 32 : 33;
    if (!ok) goto cleanup;
#if NGU_INCL_SCHNORR
    if (schnorr) ok = derive_schnorr(q, sk, md.buf, hc.buf);
    else
#endif
        ok = derive_ecdsa(q, sk, md.buf, hc.buf);
    if (!ok) goto cleanup;
    ok = secp256k1_ec_pubkey_create(lib_ctx, &pub, q);
    if (!ok) goto cleanup;
    if (schnorr) {
        secp256k1_xonly_pubkey xpub;
        int parity;
        ok = secp256k1_xonly_pubkey_from_pubkey(lib_ctx, &xpub, &parity, &pub)
            && secp256k1_xonly_pubkey_serialize(lib_ctx, Q, &xpub);
        if (ok && parity) ok = secp256k1_ec_seckey_negate(lib_ctx, q);
    } else {
        ok = secp256k1_ec_pubkey_serialize(lib_ctx, Q, &qlen, &pub, SECP256K1_EC_COMPRESSED);
    }
    if (!ok || !signing) goto cleanup;
    ok = nonce_tweak(tweak, Q, rho.buf, schnorr);
    if (!ok) goto cleanup;
    memcpy(k, q, 32);
    ok = secp256k1_ec_seckey_tweak_add(lib_ctx, k, tweak); // Abort if k == 0.
    if (!ok) goto cleanup;
#if NGU_INCL_SCHNORR
    if (schnorr) {
        secp256k1_schnorrsig_extraparams xp = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
        xp.noncefp = forced_schnorr;
        xp.ndata = k;
        ok = secp256k1_keypair_create(lib_ctx, &keypair, sk)
            && secp256k1_schnorrsig_sign_custom(lib_ctx, sig64, md.buf, 32, &keypair, &xp);
    } else
#endif
        ok = secp256k1_ecdsa_sign_recoverable(lib_ctx, &sig->sig, md.buf, sk, forced_ecdsa, k);
cleanup:
    mem_clean(sk, sizeof sk);
    mem_clean(q, sizeof q);
    mem_clean(k, sizeof k);
    mem_clean(&keypair, sizeof keypair);
    if (!ok) mp_raise_ValueError(MP_ERROR_TEXT("anti-exfil signing failed"));
    mp_obj_t commitment = mp_obj_new_bytes(Q, qlen);
    if (!signing) return commitment;
    mp_obj_t result[2] = {schnorr ? mp_obj_new_bytes(sig64, 64) : MP_OBJ_FROM_PTR(sig), commitment};
    return mp_obj_new_tuple(2, result);
}

static mp_obj_t ae_commit(mp_obj_t sk, mp_obj_t md, mp_obj_t hc)
{
    const mp_obj_t args[] = {sk, md, hc};
    return ae_run(args, 0, 0);
}
static MP_DEFINE_CONST_FUN_OBJ_3(ae_commit_obj, ae_commit);
static mp_obj_t ae_sign(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    return ae_run(args, 1, 0);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(ae_sign_obj, 4, 4, ae_sign);
#if NGU_INCL_SCHNORR
static mp_obj_t ae_commit_schnorr(mp_obj_t sk, mp_obj_t md, mp_obj_t hc)
{
    const mp_obj_t args[] = {sk, md, hc};
    return ae_run(args, 0, 1);
}
static MP_DEFINE_CONST_FUN_OBJ_3(ae_commit_schnorr_obj, ae_commit_schnorr);
static mp_obj_t ae_sign_schnorr(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    return ae_run(args, 1, 1);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(ae_sign_schnorr_obj, 4, 4, ae_sign_schnorr);
#endif

static mp_obj_t ae_verify(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    sec_setup_ctx();
    if (mp_obj_get_type(args[0]) != &s_sig_type || mp_obj_get_type(args[2]) != &s_pubkey_type)
        mp_raise_TypeError(MP_ERROR_TEXT("signature/pubkey type"));
    mp_buffer_info_t md, Q, rho;
    require_buf_len(args[1], &md, 32);
    require_buf_len(args[3], &Q, 33);
    require_buf_len(args[4], &rho, 32);
    secp256k1_pubkey R;
    uint8_t tweak[32], encoded[33], r[32], compact[64];
    size_t len = sizeof encoded;
    int recid;
    if (!secp256k1_ec_pubkey_parse(lib_ctx, &R, Q.buf, 33)
        || !nonce_tweak(tweak, Q.buf, rho.buf, 0)
        || !secp256k1_ec_pubkey_tweak_add(lib_ctx, &R, tweak)
        || !secp256k1_ec_pubkey_serialize(lib_ctx, encoded, &len, &R, SECP256K1_EC_COMPRESSED))
        return mp_const_false;
    ngu_secp256k1_scalar_reduce(r, encoded + 1);
    mp_obj_sig_t *sig = MP_OBJ_TO_PTR(args[0]);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(lib_ctx, compact, &recid, &sig->sig);
    if (memcmp(r, compact, 32)) return mp_const_false;
    secp256k1_ecdsa_signature normal;
    secp256k1_ecdsa_recoverable_signature_convert(lib_ctx, &normal, &sig->sig);
    mp_obj_pubkey_t *pk = MP_OBJ_TO_PTR(args[2]);
    return mp_obj_new_bool(secp256k1_ecdsa_verify(lib_ctx, &normal, md.buf, &pk->pubkey));
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(ae_verify_obj, 5, 5, ae_verify);

#if NGU_INCL_SCHNORR
static mp_obj_t ae_verify_schnorr(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    sec_setup_ctx();
    if (mp_obj_get_type(args[2]) != &s_xonly_pubkey_type)
        mp_raise_TypeError(MP_ERROR_TEXT("xonly pubkey type"));
    mp_buffer_info_t sig, md, Q, rho;
    require_buf_len(args[0], &sig, 64);
    require_buf_len(args[1], &md, 32);
    require_buf_len(args[3], &Q, 32);
    require_buf_len(args[4], &rho, 32);
    secp256k1_xonly_pubkey point, rx;
    secp256k1_pubkey R;
    uint8_t tweak[32], x[32];
    if (!secp256k1_xonly_pubkey_parse(lib_ctx, &point, Q.buf)
        || !nonce_tweak(tweak, Q.buf, rho.buf, 1)
        || !secp256k1_xonly_pubkey_tweak_add(lib_ctx, &R, &point, tweak)
        || !secp256k1_xonly_pubkey_from_pubkey(lib_ctx, &rx, NULL, &R)
        || !secp256k1_xonly_pubkey_serialize(lib_ctx, x, &rx)) return mp_const_false;
    if (memcmp(x, sig.buf, 32)) return mp_const_false;
    mp_obj_xonly_pubkey_t *pk = MP_OBJ_TO_PTR(args[2]);
    return mp_obj_new_bool(secp256k1_schnorrsig_verify(lib_ctx, sig.buf, md.buf, 32, &pk->pubkey));
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(ae_verify_schnorr_obj, 5, 5, ae_verify_schnorr);
#endif

static const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_antiexfil) },
    { MP_ROM_QSTR(MP_QSTR_commit), MP_ROM_PTR(&ae_commit_obj) },
    { MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&ae_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&ae_verify_obj) },
#if NGU_INCL_SCHNORR
    { MP_ROM_QSTR(MP_QSTR_commit_schnorr), MP_ROM_PTR(&ae_commit_schnorr_obj) },
    { MP_ROM_QSTR(MP_QSTR_sign_schnorr), MP_ROM_PTR(&ae_sign_schnorr_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify_schnorr), MP_ROM_PTR(&ae_verify_schnorr_obj) },
#endif
};
static MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);
const mp_obj_module_t mp_module_antiexfil = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
