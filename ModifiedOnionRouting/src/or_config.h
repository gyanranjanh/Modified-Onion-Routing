/*
 * FILE:	or_config.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_CONFIG_H__
#define __OR_CONFIG_H__

//#define OR_CLIENT_SERVER_TEST
//#define OR_KEY_TEST
//#define OR_DISABLE_LINK_ENCRYPTION
#define OR_TEST_MODE

#define ORCS_NOT_READY
#define OR_BASE_TCP_SERVER_PORT        (3000)
#define OR_CONFIG_MAX_NO_OF_NEIGHBOR   (3)
#define OR_MSS                         (760)
#define OR_MAC_SIZE                    (8) /* Can't exceed 32 as sha256 */
#define OR_HASH_STRING_LENGTH_IN_BYTES (32) /* Don't change this for now */
#define OR_HASH_STRING_LENGTH          (2*OR_HASH_STRING_LENGTH_IN_BYTES)
#define OR_PUBLIC_PRIVATE_KEY_LENGTH   (OR_HASH_STRING_LENGTH_IN_BYTES)
#define OR_DH_SECRET_LENGTH            (OR_PUBLIC_PRIVATE_KEY_LENGTH)
#define OR_MAX_NO_TIMERS               (100)
#define OR_ONION_PROXY_MAX_SESSION     (10)
#define OR_TYPICAL_EXP_TIME            (1*24*60*60)
#define OR_FORW_BACK_KEY_LENGTH        (16)
#define OR_INVALID_MEMBER_ID           (0xff)
#define OR_ALLOWED_CKT_SETUP_TIME_IN_SCD (30) 

#define OR_MIX_PARAM_N                  (3)  /* N is the pool size */
#define OR_MIX_PARAM_S                  (2)  /* s is the threshold size */

#define OR_HANDHSAKE_MSG           "I am ur anonymous friend. Accept Greetings."
#define OR_EXPECTED_HANDHSHAKE_RSP "Hello anonymous friend. Greetings accepted."

#ifdef ORCS_NOT_READY
#define SENDER_SECRET_HASH_STRING "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
#endif

#endif /* __OR_CONFIG_H_ */
