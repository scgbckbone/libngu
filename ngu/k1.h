#pragma once

#include "py/obj.h"
#include "sec_shared.h"

typedef struct  {
    mp_obj_base_t base;
    secp256k1_pubkey    pubkey;         // not allocated
} mp_obj_pubkey_t;

typedef struct  {
    mp_obj_base_t base;
    secp256k1_xonly_pubkey    pubkey;         // not allocated
    int    parity;
} mp_obj_xonly_pubkey_t;

typedef struct  {
    mp_obj_base_t base;
    secp256k1_ecdsa_recoverable_signature   sig;
} mp_obj_sig_t;

typedef struct  {
    mp_obj_base_t base;
    secp256k1_keypair   keypair;
} mp_obj_keypair_t;

extern const mp_obj_type_t s_pubkey_type;
extern const mp_obj_type_t s_xonly_pubkey_type;
extern const mp_obj_type_t s_sig_type;
extern const mp_obj_type_t s_keypair_type;

void sec_setup_ctx(void);
