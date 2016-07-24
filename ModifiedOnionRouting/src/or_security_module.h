/*
 * FILE:	or_security_module.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_SECURITY_MODULE_H__
#define __OR_SECURITY_MODULE_H__

#include "or_types.h"

extern void or_init_security(void);
extern OrUint64 or_get_random_at_most(OrUint64 max);
extern void or_unpack_hash_string(OrUint8 packedStn[OR_HASH_STRING_LENGTH_IN_BYTES],
                                     OrUint8 *unpackedStrn);
extern OrBool or_pack_hash_string(OrUint8 unpackedStrn[OR_HASH_STRING_LENGTH + 1],
                                       OrUint8 *packedStrn);
extern OrBool or_get_key_pair(void);
extern void or_produce_secret(OrKeyPair *asKp, OrKeyPair *bsKp, OrUint8 *secret);
extern void or_get_sha256_mac(OrUint8 *data, OrUint16 dataLen, OrUint8 *linkKey, OrUint8 *mac);
extern void or_get_hash_string(OrUint8 *hashStr);
extern void or_encrypt_onion_layer(OrUint8 *onionLayr, OrUint8 *dhSecret);
extern void or_decrypt_onion_layer(const OrOnion *onion, OrUint8 *decptdOnionLayr, OrUint8 *linkKey);
extern void or_decrypt_hdr(const OrUint8 *data, OrUint16 dataL, OrUint8 *hdr, OrUint8 *linkKey);
extern void or_encrypt_hdr(OrUint8 *frame, OrUint8 *linkKey);
extern void or_crypt_challenge(OrUint8 *frame, OrUint8 *linkKey);
extern OrBool or_decrypt_challenge_n_get_link_key(OrUint8 *data, OrUint8 dataL, OrUint8 *linkKey);

#ifdef OR_KEY_TEST
extern void or_key_test(void);
#endif

#endif /* __OR_SECURITY_MODULE_H__ */
