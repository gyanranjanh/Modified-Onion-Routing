/*
 * FILE:	or_security_module.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_log.h"
#include "or_common.h"
#include "or_security_module.h"
#include "or_util.h"
#include "sha2.h"

/*--------------------------Type Defn--------------------------------------*/
typedef SHA256_CTX OR_SHA256_CTX; 
/*--------------------------Macro Defn--------------------------------------*/
#define or_SHA256_Init   SHA256_Init
#define or_SHA256_Update SHA256_Update
#define or_SHA256_End    SHA256_End
#define BUFLEN 16384
#define OR_OPTIMIZE_PV_KEY(pv) \
do { \
    while(*pv > 0x5) \
    { \
        *pv /= 2; \
    } \
}while(0)



/*--------------------------Static Fn Declaration---------------------------*/
static void or_generate_hash_string(void);
static void or_make_public_private_key_pair(OrUint64 pv, OrUint64 *pu);
static void or_produce_one_unit_secret(OrUint8 bPu, OrUint8 aPv, OrUint8 *ss);

/*--------------------------Static Fn Defn---------------------------*/

static void or_generate_hash_string()
{
    OrUint8 buf[OR_HASH_STRING_LENGTH_IN_BYTES] = {0}, i = 0;
    OrCharString hashStrn[OR_HASH_STRING_LENGTH + 1] = {0};

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>", __FUNCTION__, __LINE__);

    for(i = 0; i < OR_HASH_STRING_LENGTH_IN_BYTES; i++)
    {
        do
        {
            srand((unsigned)clock());
            buf[i] = or_get_random_at_most(0xFF) & 0xFF;
        } while((buf[i] == 0) || !(buf[i] & 0xF0));
        printf("%x", buf[i]);
    }

    printf("\n");

    or_unpack_hash_string(buf, hashStrn);

    /* Copy the generated string into context */
    or_mem_copy(orContext.hashString, hashStrn, OR_HASH_STRING_LENGTH);
}

static void or_make_public_private_key_pair(OrUint64 pv, OrUint64 *pu)
{
    OrUint64 prime      = orContext.keyPairPrime;
    OrUint64 prime_root = orContext.keyPairPrimitiveRoot;
    OrUint64 a_pu       = 0; /* Alice's Public Key */
    OrUint64 b_pu       = 0; /* Bob's Public Key */
    OrUint64 sa         = 0; /* Alice's shared secret */
    OrUint64 sb         = 0; /* Bob's shared secret */
    OrUint64 a_pv = 0, b_pv = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    a_pv = pv;

    /* Look for one octet public key only */
    do {
        //srand((unsigned)clock());
        //a_pv = or_get_random_at_most(10);

        srand((unsigned)clock());
        b_pv = or_get_random_at_most(10);

        /* a's public key */
        a_pu = (OrUint64) pow(prime_root, a_pv);
        //a_pu = prime_root ^ a_pv;
        a_pu  %= prime;

        /* b's public key */
        b_pu = (OrUint64) pow(prime_root, b_pv);
        //b_pu = prime_root ^ b_pv;
        b_pu %= prime;

        sa = (OrUint64) pow(b_pu, a_pv);
        //sa = b_pu ^ a_pv;
        sa %= prime;
        
        sb = (OrUint64) pow(a_pu , b_pv);
        sb %= prime;
    }while((a_pu & 0xffffffffffffff00) || (sa != sb));

    OR_LOG(OR_LOG_LEVEL_DEBUG, "sa : 0x%x\ta_pv : 0x%x\ta_pu : 0x%x",
                                                            sa, a_pv, a_pu);
    OR_LOG(OR_LOG_LEVEL_DEBUG, "sb : 0x%x\tb_pv : 0x%x\tb_pu : 0x%x", 
                                                            sb, b_pv, b_pu);

    /* Let's use Alice's Public/Private key for our use for now */

    *pu = a_pu;
}

static void or_produce_one_unit_secret(OrUint8 bPu, OrUint8 aPv, OrUint8 *ss)
{
    OrUint64 prime      = orContext.keyPairPrime;
    OrUint64 prime_root = orContext.keyPairPrimitiveRoot;
    OrUint64 sa         = 0;  /* Alice's shared secret */
    OrUint64 b_pu       = 0x0000000000000000 | bPu;
    OrUint64 a_pv       = 0x0000000000000000 | aPv;

    //OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    UNUSED(prime_root);

    /* a's secret key */
    sa = (OrUint64) pow(b_pu, a_pv);
    sa %= prime;

    *ss = sa & 0x00000000000000ff;
}

/*--------------------------Global Fn Defn---------------------------*/
void or_init_security()
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d) >", __FUNCTION__, __LINE__);

    orContext.keyPairPrime         = 23;
    orContext.keyPairPrimitiveRoot =  5;
}

/* Assumes 0 <= max <= RAND_MAX */
/* Returns in the half-open interval [0, max] */
OrUint64 or_get_random_at_most(OrUint64 max) 
{
    OrUint64
    /* max <= RAND_MAX < ULONG_MAX, so this is okay.*/
    num_bins = (OrUint64) max + 1,
    num_rand = (OrUint64) RAND_MAX + 1,
    bin_size = num_rand / num_bins,
    defect   = num_rand % num_bins,
    x;

    do 
    {
        x = random();
    } while (num_rand - defect <= (unsigned long)x); /* This is carefully written not to overflow */

    /* Truncated division is intentional */
    return x/bin_size;
}

void or_unpack_hash_string(OrUint8 packedStn[OR_HASH_STRING_LENGTH_IN_BYTES],
                                     OrUint8 *unpackedStrn)
{
    OrUint8 i =0, j = 0;
    OrUint8 x[OR_HASH_STRING_LENGTH], *p = packedStn;

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>", __FUNCTION__, __LINE__);

    for(i = 0; i < OR_HASH_STRING_LENGTH_IN_BYTES; i++)
    {
        j = 2*i;

        x[j] = ((p[i] & 0xf0) >> 4) & 0xff;
        x[j + 1] = p[i] & 0x0f;

       (x[j] <= 9) ? (x[j] += '0') : (x[j] += ('a' - 0xa));
       (x[j + 1] <= 9) ? (x[j + 1] += '0') : (x[j + 1] += ('a' -  0xa));
    }

    or_mem_copy(unpackedStrn, x, OR_HASH_STRING_LENGTH);
    unpackedStrn[OR_HASH_STRING_LENGTH] = '\0';

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Unpacked hash string "
                               "(as a string) ",
                               __FUNCTION__, __LINE__);


    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> %s",
                                        __FUNCTION__, __LINE__, unpackedStrn);
}

OrBool or_pack_hash_string(OrUint8 unpackedStrn[OR_HASH_STRING_LENGTH + 1],
                                    OrUint8 *packedStrn)
{
    OrUint8 i =0, j = 0;
    OrUint8 *x = unpackedStrn, p[OR_HASH_STRING_LENGTH_IN_BYTES] = {0}, q;
    OrBool result = TRUE;

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> %s", __FUNCTION__, __LINE__, x);

    for(i = 0; (i < OR_HASH_STRING_LENGTH) && result; i++)
    {
        j = i/2;

        if(!(i % 2))
        {
            ((48 <= x[i]) &&(x[i] <= 57)) ? (p[j] = ((x[i] - '0') << 4) & 0xf0) 
            : (((97 <= x[i]) &&(x[i] <= 102)) ? (p[j] = ((x[i] - ('a' - 0xa)) << 4) & 0xf0)
                            : (result = FALSE));
        }
        else
        {
            ((48 <= x[i]) &&(x[i] <= 57)) ? (p[j] |= (((x[i] - '0')) & 0x0f)) 
             : (((97 <= x[i]) &&(x[i] <= 102)) ? (p[j] |= ((x[i] - ('a' - 0xa)) & 0x0f))
                            : (result = FALSE));
        }
    }

    if(result == TRUE)
    {
        or_mem_copy(packedStrn, p, (OR_HASH_STRING_LENGTH_IN_BYTES));
        for(i = 0; i < (OR_HASH_STRING_LENGTH_IN_BYTES); i++)
        {
            printf("%x", packedStrn[i]);
        }
        printf("\n");
    }
    else
    {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> pack hashstring failed",
                                                        __FUNCTION__, __LINE__);
    }

    return result;
}

OrBool or_get_key_pair()
{
    OrUint8 buf[BUFLEN] = {0}, i = 0;
    OR_SHA256_CTX  ctx256;
    OrUint64 pu = 0;
    OrBool result = TRUE;

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>", __FUNCTION__, __LINE__);

    /* generate hash string */
    or_generate_hash_string();

    /* Initialise context */
    or_SHA256_Init(&ctx256);

    /* Update with key */
    or_SHA256_Update(&ctx256, orContext.hashString, OR_HASH_STRING_LENGTH);

    /* Produce results */
    or_SHA256_End(&ctx256, buf);

    printf("hashed key string %s\n", buf);

    /* Copy result as private keys */
    or_mem_copy(orContext.keyPair.privateKey, buf, OR_PUBLIC_PRIVATE_KEY_LENGTH);

    //or_pack_hash_string(buf, orContext.keyPair.privateKey);

    printf("Private key = %s %x\n", orContext.keyPair.privateKey, 
                                    orContext.keyPair.privateKey[0]);

    for(i = 0; i < OR_PUBLIC_PRIVATE_KEY_LENGTH && result; i++)
    {
        if((48 <= orContext.keyPair.privateKey[i])
              && (orContext.keyPair.privateKey[i] <= 57))
        {
            orContext.keyPair.privateKey[i] -= '0';
            OR_OPTIMIZE_PV_KEY(&orContext.keyPair.privateKey[i]);
            /* Get 64 bit public key. The following fn will return one
             * octet public key only although the computation must be 
             * 64 bit */
            or_make_public_private_key_pair(orContext.keyPair.privateKey[i], &pu);
            /* Fill the next octet of the final 32 byte (256bit) key */
            orContext.keyPair.publicKey[i] = pu & 0xff;
        }
        else if((97 <= orContext.keyPair.privateKey[i])
            && (orContext.keyPair.privateKey[i] <= 102))
        {
            orContext.keyPair.privateKey[i] -= ('a' - 0xa);
            OR_OPTIMIZE_PV_KEY(&orContext.keyPair.privateKey[i]);
            /* Get 64 bit public key. The following fn will return one
             * octet public key only although the computation must be 
             * 64 bit */
            or_make_public_private_key_pair(orContext.keyPair.privateKey[i], &pu);
            /* Fill the next octet of the final 32 byte (256bit) key */
            orContext.keyPair.publicKey[i] = pu & 0xff;
        }
        else
        {
            result = FALSE;
        }
    }

    if(result == TRUE)
    {
        for(i = 0; i < OR_PUBLIC_PRIVATE_KEY_LENGTH; i++)
        {
            printf("%x", orContext.keyPair.publicKey[i]);
        }
    }

    /* Unpack public key to publish */
    or_mem_zero(buf, BUFLEN);
    or_unpack_hash_string(orContext.keyPair.publicKey, buf);

    /* Save published key */
    or_mem_zero(orContext.publishedPublicKey, 
                        sizeof(orContext.publishedPublicKey));
    or_mem_copy(orContext.publishedPublicKey, buf, 
                                    2*OR_PUBLIC_PRIVATE_KEY_LENGTH);

    printf("Public key to be published %s\n", buf);

    /* Unpack Private key just for keeping record */
    or_mem_zero(buf, BUFLEN);
    or_unpack_hash_string(orContext.keyPair.privateKey, buf);

    printf("Prvate key for record keeping %s\n", buf);

    return result;
}

void or_produce_secret(OrKeyPair *asKp,
                       OrKeyPair *bsKp,
                       OrUint8 *secret)
{
    OrUint8 i = 0;

    for(i = 0; i < OR_PUBLIC_PRIVATE_KEY_LENGTH; i++)
    {
        or_produce_one_unit_secret(bsKp->publicKey[i],
                                asKp->privateKey[i], &secret[i]);
    }
}

void or_get_sha256_mac(OrUint8 *data,
                       OrUint16 dataLen,
                       OrUint8 *linkKey,
                       OrUint8 *mac)
{
    OR_SHA256_CTX  ctx256;
    OrUint8 buf[BUFLEN];

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_mem_copy(buf, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 64);

    /* Initialise context */
    or_SHA256_Init(&ctx256);

    /* Update with key */
    or_SHA256_Update(&ctx256, linkKey, OR_DH_SECRET_LENGTH);
    /* Update with data */
    or_SHA256_Update(&ctx256, (OrUint8 *)data, dataLen);

    /* Produce results */
    or_SHA256_End(&ctx256, buf);

    or_mem_zero(mac, OR_MAC_SIZE);
    or_mem_copy(mac, buf, OR_MAC_SIZE);

    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> Produced HMAC %s", buf);
    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> MAC %s", mac);
}

void or_get_hash_string(OrUint8 *hashStr)
{
    OrUint8 k = 0;
    OrUint8 buf[OR_HASH_STRING_LENGTH_IN_BYTES] = {0}, i = 0;
    OrCharString hashStrn[OR_HASH_STRING_LENGTH + 1] = {0};

    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_mem_set(hashStrn, 0xFF, OR_HASH_STRING_LENGTH + 1);

    for(i = 0; i < OR_HASH_STRING_LENGTH_IN_BYTES; i++)
    {
        do
        {
            srand((unsigned)clock());
            buf[i] = or_get_random_at_most(0xFF) & 0xFF;
        } while((buf[i] == 0) || !(buf[i] & 0xF0));
    }

    or_unpack_hash_string(buf, hashStrn);

    or_mem_copy(hashStr, hashStrn, OR_FORW_BACK_KEY_LENGTH);

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                               "Retuned hash string "
                               "(each byte as hex values): ",
                                    __FUNCTION__, __LINE__);

    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\t");
    for(; k < OR_FORW_BACK_KEY_LENGTH; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_ERROR, "%x ", hashStr[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");
}

void or_encrypt_onion_layer(OrUint8 *onionLayr,
                            OrUint8 *dhSecret)
{
#ifndef OR_DISABLE_LINK_ENCRYPTION
    OrUint8 *key = dhSecret;
    OrUint8 m = 0, n = 0, k = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_LOG(OR_LOG_LEVEL_DEBUG, "DH secret: ");
    for(k = 0; k < OR_DH_SECRET_LENGTH; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", dhSecret[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");

    OR_LOG(OR_LOG_LEVEL_DEBUG, "Onion Layer bfr encryption: ");
    for(k = 0; k < OR_ONION_LAYER_LEN; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", onionLayr[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");


    OR_ASSERT((onionLayr == NULL), 
        "or_encrypt_onion_layer> onionLayr is NULL\n");

    m = OR_ONION_LAYER_LEN / OR_DH_SECRET_LENGTH;
    n = OR_ONION_LAYER_LEN % OR_DH_SECRET_LENGTH;

    OR_XOR_KEY_N_TIMES(onionLayr, key, m);
    OR_XOR_KEY_N_BYTES(onionLayr + m * OR_DH_SECRET_LENGTH, key, n);

    OR_LOG(OR_LOG_LEVEL_DEBUG, "Onion Layer after encryption: ");
    for(k = 0; k < OR_ONION_LAYER_LEN; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", onionLayr[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");
#endif
}

void or_decrypt_onion_layer(const OrOnion *onion,
                            OrUint8 *decptdOnionLayr,
                            OrUint8 *linkKey)
{
#ifndef OR_DISABLE_LINK_ENCRYPTION
    OrUint8 *key = linkKey;
    OrUint8 m = 0, n = 0, k = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "DH secret: \n");
    for(k = 0; k < OR_DH_SECRET_LENGTH; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", linkKey[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");

    OR_ASSERT(((onion == NULL) || (onion->orOnion == NULL)
        ||(onion->orLen < OR_ONION_LAYER_LEN)), 
        "or_router_decrypt_onion_layer> Insuffcient onion layer data\n");
    OR_ASSERT((decptdOnionLayr == NULL), 
        "or_router_decrypt_onion_layer> decptdOnionLayr is NULL\n");

    or_mem_copy(decptdOnionLayr, onion->orOnion, OR_ONION_LAYER_LEN);

    OR_LOG(OR_LOG_LEVEL_DEBUG, "Onion Layer bfr decryption: ");
    for(k = 0; k < OR_ONION_LAYER_LEN; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", decptdOnionLayr[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");

    m = OR_ONION_LAYER_LEN / OR_DH_SECRET_LENGTH;
    n = OR_ONION_LAYER_LEN % OR_DH_SECRET_LENGTH;

    OR_XOR_KEY_N_TIMES(decptdOnionLayr, key, m);
    OR_XOR_KEY_N_BYTES(decptdOnionLayr + m * OR_DH_SECRET_LENGTH, key, n);

    OR_LOG(OR_LOG_LEVEL_DEBUG, "Onion Layer after decryption: ");
    for(k = 0; k < OR_ONION_LAYER_LEN; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", decptdOnionLayr[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");
#else
    or_mem_copy(decptdOnionLayr, onion->orOnion, OR_ONION_LAYER_LEN);
#endif
}

void or_decrypt_hdr(const OrUint8 *data,
                          OrUint16 dataL,
                          OrUint8 *hdr,
                          OrUint8 *linkKey)
{
#ifndef OR_DISABLE_LINK_ENCRYPTION
    OrUint8 *key = linkKey;
    OrUint8 m = 0, n = 0, k = 0;

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "DH secret: \n");
    for(k = 0; k < OR_DH_SECRET_LENGTH; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", linkKey[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");

    OR_ASSERT(((data == NULL) || (dataL < OR_PKT_HDR_LEN)),
          "or_decrypt_hdr> Invalid incloming data\n");

    or_mem_copy(hdr, (void *)data, OR_PKT_HDR_LEN);

    m = OR_PKT_HDR_LEN / OR_DH_SECRET_LENGTH;
    n = OR_PKT_HDR_LEN % OR_DH_SECRET_LENGTH;

    OR_XOR_KEY_N_TIMES(hdr, key, m);
    OR_XOR_KEY_N_BYTES(hdr + m * OR_DH_SECRET_LENGTH, key, n);
#else
    or_mem_copy(hdr, (void *)data, OR_PKT_HDR_LEN);
#endif
}

void or_encrypt_hdr(OrUint8 *frame, OrUint8 *linkKey)
{
#ifndef OR_DISABLE_LINK_ENCRYPTION
    OrUint8 *key = linkKey;
    OrUint8 m = 0, n = 0, k = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "DH secret: \n");
    for(k = 0; k < OR_DH_SECRET_LENGTH; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", linkKey[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");

    OR_ASSERT((frame == NULL) ,
                            "or_encrypt_hdr> Invalid data\n");

    m = OR_PKT_HDR_LEN / OR_DH_SECRET_LENGTH;
    n = OR_PKT_HDR_LEN % OR_DH_SECRET_LENGTH;

    OR_XOR_KEY_N_TIMES(frame, key, m);
    OR_XOR_KEY_N_BYTES(frame + m * OR_DH_SECRET_LENGTH, key, n);
#endif
}

void or_crypt_challenge(OrUint8 *frame, OrUint8 *linkKey)
{
#ifndef OR_DISABLE_LINK_ENCRYPTION
    OrUint8 *key = linkKey;
    OrUint8 m = 0, n = 0, k = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "DH secret: \n");
    for(k = 0; k < OR_DH_SECRET_LENGTH; k++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", linkKey[k]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");

    OR_ASSERT((frame == NULL) ,
                            "or_encrypt_hdr> Invalid data\n");

    m = OR_CHALLENGE_LEN / OR_DH_SECRET_LENGTH;
    n = OR_CHALLENGE_LEN % OR_DH_SECRET_LENGTH;

    OR_XOR_KEY_N_TIMES(frame, key, m);
    OR_XOR_KEY_N_BYTES(frame + m * OR_DH_SECRET_LENGTH, key, n);
#endif
}

OrBool or_decrypt_challenge_n_get_link_key(OrUint8 *data,
                                           OrUint8 dataL,
                                           OrUint8 *linkKey)
{
#ifndef OR_DISABLE_LINK_ENCRYPTION
    OrUint8 chlngBuf[OR_CHALLENGE_LEN], k;
    OrNeighborTable *nbrTble = &orContext.neigborTable;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    if(dataL > OR_CHALLENGE_LEN) {
        for(k = 0; k < nbrTble->noOfEntriesInNeighborTable; k++) {
            or_mem_copy(chlngBuf, data, OR_CHALLENGE_LEN);
            or_crypt_challenge(chlngBuf, nbrTble->orNeighbor[k].orDhSecret);
            if(!strncmp(chlngBuf, OR_CHALLENGE_TEXT, OR_CHALLENGE_LEN)) {
                or_mem_copy(linkKey,
                    nbrTble->orNeighbor[k].orDhSecret, OR_DH_SECRET_LENGTH);
                result = TRUE;
                break;
            }
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                            __FUNCTION__, __LINE__, result);

    return result;
#else
    or_mem_set(linkKey, 0x00, OR_DH_SECRET_LENGTH);
    return TRUE;
#endif
}

#ifdef OR_KEY_TEST
typedef struct
{
    OrUint8 secret[OR_PUBLIC_PRIVATE_KEY_LENGTH];
    OrKeyPair kp;
    OrUint8 exPublicKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH];
    OrUint8 exPrivateKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH];
}testKeyPair;

testKeyPair asTestKeyPair = {
    {0},
    {{0}, {0}},
    "0a0a0a040a0a0a040a0a0a140a1404140a050a05140a140402050a050a050405",
    "0303030403030304030303050305040503010301050305040201030103010401"
    };

testKeyPair bsTestKeyPair = {
    {0},
    {{0}, {0}},
    "0a0a140a0a0a14020a0414020a0a0a140a0a0a0a0a14020a140a020a14050a0a",
    "0303050303030502030405020303030503030303030502030503020305010303"
    };

void or_key_test()
{
    OrUint8 orBuf[OR_HASH_STRING_LENGTH + 1] = {0}, i = 0;
    OrBool result = TRUE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_mem_copy(orBuf, asTestKeyPair.exPublicKey, 2*OR_PUBLIC_PRIVATE_KEY_LENGTH);
    /* Pack key pairs */
    or_pack_hash_string(orBuf, asTestKeyPair.kp.publicKey);

    or_mem_zero(orBuf, OR_HASH_STRING_LENGTH + 1);
    or_mem_copy(orBuf, asTestKeyPair.exPrivateKey, 2*OR_PUBLIC_PRIVATE_KEY_LENGTH);
    /* Pack key pairs */
    or_pack_hash_string(orBuf, asTestKeyPair.kp.privateKey);

    or_mem_zero(orBuf, OR_HASH_STRING_LENGTH + 1);
    or_mem_copy(orBuf, bsTestKeyPair.exPublicKey, 2*OR_PUBLIC_PRIVATE_KEY_LENGTH);
    /* Pack key pairs */
    or_pack_hash_string(orBuf, bsTestKeyPair.kp.publicKey);

    or_mem_zero(orBuf, OR_HASH_STRING_LENGTH + 1);
    or_mem_copy(orBuf, bsTestKeyPair.exPrivateKey, 2*OR_PUBLIC_PRIVATE_KEY_LENGTH);
    /* Pack key pairs */
    or_pack_hash_string(orBuf, bsTestKeyPair.kp.privateKey);

    /* Now produce shared secret */
    or_produce_secret(&asTestKeyPair.kp, &bsTestKeyPair.kp, asTestKeyPair.secret);
    or_produce_secret(&bsTestKeyPair.kp, &asTestKeyPair.kp, bsTestKeyPair.secret);

    /* Validate */
    for(i = 0; i < OR_PUBLIC_PRIVATE_KEY_LENGTH; i++)
    {
        if(asTestKeyPair.secret[i] != bsTestKeyPair.secret[i])
        {
            result = FALSE;
        }
        printf("<%s Line: %d>a's secret[%d] 0x%x\tb's secret[%d] 0x%x\n",
                __FUNCTION__, __LINE__,
                i, asTestKeyPair.secret[i], i, bsTestKeyPair.secret[i]);
    }

    if(!result)
    {
        printf("secret match failed\n");
    }
    else
    {
        printf("secret matched\n");
    }
}
#endif
