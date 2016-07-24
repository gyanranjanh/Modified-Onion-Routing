/*
 * FILE:	or_types.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_TYPES_H__
#define __OR_TYPES_H__

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
//#include <jiffies.h>
//#include <linux/sched.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <inttypes.h>
#include <semaphore.h> 
#include "or_config.h"

/*------------------------------------Macro Defn------------------------*/
#undef  FALSE
#define FALSE (0)

#undef  TRUE
#define TRUE (1)

#define OR_TIME_ONE_SEC_IN_USEC (1000000)
#define OR_TIME_ONE_US_IN_NSEC  (1000)

#define OR_IP_ADDRESS_LENGTH (16)

#define OR_INVALID_SESSION_ID (0xFF)
#define OR_PAD_BYTE           (0xFF)
#define OR_CHALLENGE_TEXT     "challenge"

/* PKT Param and field macros */
#define OR_CHALLENGE_LEN      (0x09)
#define OR_CID_FLD_LEN        (0x04)
#define OR_CMD_FLD_LEN        (0x01)
#define OR_TYPE_FLD_LEN       (0x01)
#define OR_PAYLD_LEN_FLD_LEN  (0x02)
#define OR_PAYLD_FLD_LEN      (OR_MSS)
#define OR_MAC_FLD_LEN        (OR_MAC_SIZE)
#define OR_PKT_LEN            (OR_CHALLENGE_LEN + OR_CID_FLD_LEN + OR_CMD_FLD_LEN + OR_TYPE_FLD_LEN \
                               + OR_PAYLD_LEN_FLD_LEN + OR_PAYLD_FLD_LEN + OR_MAC_FLD_LEN)
#define OR_PKT_HDR_LEN        (OR_CID_FLD_LEN + OR_CMD_FLD_LEN + OR_TYPE_FLD_LEN \
                               + OR_PAYLD_LEN_FLD_LEN)


#define OR_BACK_F_LEN         (1)
#define OR_FORW_F_LEN         (1)
#define OR_MEMBER_ID_LEN      (2)
#define OR_EXP_TIME_LEN       (4)
#define OR_ONION_LAYER_LEN    (OR_CHALLENGE_LEN + OR_BACK_F_LEN + OR_FORW_F_LEN \
                               + OR_MEMBER_ID_LEN + 2*OR_FORW_BACK_KEY_LENGTH + OR_EXP_TIME_LEN)

/*------------------------------------Type Defn------------------------*/

/* Basic types */
typedef size_t  OrSize;         /* Return type of sizeof */
typedef ssize_t OrSsize;        /* Retuen type of getline() etc. */


/* Unsigned fixed width types */
typedef uint8_t OrUint8;
typedef uint16_t OrUint16;
typedef uint32_t OrUint32;

/* Signed fixed width types */
typedef int8_t OrInt8;
typedef int16_t OrInt16;
typedef int32_t OrInt32;
typedef int  OrInt;

/* Boolean */
typedef OrUint8 OrBool;

/* 64-bit integers */
#if __x86_64__
typedef uint64_t OrUint64;
typedef int64_t OrInt64;
#else
typedef uint32_t OrUint64;
typedef int32_t OrInt64;
#endif

/* String types */
typedef char OrCharString;

/* OS type */
typedef pthread_t OrThread;
typedef pthread_mutex_t* OrMutexHandle;
typedef sem_t OrSemaHandle;
#define CREATE_THREAD pthread_create
#define DESTORY_THREAD pthread_cancel
#define EXIT_THREAD(p) pthread_exit(p)

/* file type */
typedef FILE OrFile;


typedef enum {
    OR_SENDER   = 0x00,
    OR_RECEIVER = 0x01,
    OR_ROUTER   = 0x02,
    OR_INVALID  = 0xFF,
} OrRole;

typedef enum {
    OR_END_DEVICE_T     = 0x00,
    OR_ROUTER_T         = 0x01,
    OR_INVALID_DEVICE_T = 0x02,
} OrDeviceType;

typedef enum {
    OR_HOST_NAME = 0x00,
    OR_HOST_IP   = 0x01,
} OrHostIdType;

/* System time, in microseconds */
typedef OrUint32  OrTime;
typedef useconds_t OrTimeUs;
typedef time_t OrTimeS;
typedef OrUint32  OrTimer;

/* Time of day in UTC, for OrTimeUtc() */
typedef struct {
    OrUint32 sec;
    OrUint16 msec;
} OrTimeUtc;

typedef struct
{
    OrUint8 publicKey[OR_PUBLIC_PRIVATE_KEY_LENGTH];
    OrUint8 privateKey[OR_PUBLIC_PRIVATE_KEY_LENGTH];
} OrKeyPair;

typedef struct
{
    OrUint16     memberId;
    OrDeviceType deviceType;
    OrUint16     port;
    OrCharString ip[OR_IP_ADDRESS_LENGTH];
    OrUint8      publishedPublicKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH + 1];
    OrUint8      orDhSecret[OR_DH_SECRET_LENGTH];
} OrNeighbor;

typedef struct
{
    OrUint32   noOfEntriesInNeighborTable;
    OrNeighbor orNeighbor[OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1];
} OrNeighborTable;

typedef struct
{
    OrRole          role;                  /* Device role */
    OrUint16        port;                  /* Port where the server will listen */
    OrUint32        memberId;              /* Member id - to be assigned by ORCS */
    OrUint8         keyPairPrime;          /* p - prime to generate key pair */
    OrUint8         keyPairPrimitiveRoot;  /* g - primitive root modulo p */
    OrKeyPair       keyPair;               /* Self Key Pair */
    OrUint8         publishedPublicKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH + 1]; /* Published Key */
#ifdef ORCS_NOT_READY
    OrNeighborTable neigborTable; /* Neigbor table */
#else
    OrNeighborTable *neigborTable;
#endif
    OrUint8         hashString[OR_HASH_STRING_LENGTH]; /* 256 bit hash string */
    OrMutexHandle  orLock;
} OrContext;

#ifdef ORCS_NOT_READY
typedef struct
{
    OrUint16 port;
    OrUint8  publishedPublicKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH + 1];
    OrUint8  recordPrivateKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH + 1];
} OrKeyPairTable;
#endif

/*-------------------Protocol Specific Defines-----------------------*/

#define OR_VERSION 0x01

typedef enum
{
    OR_PROTO_SERIAL    = 0x00,
    OR_PROTO_RLOGIN    = 0x01,
    OR_PROTO_HTTP      = 0x02,
    OR_PROTO_SMTP      = 0x03,
    OR_PROTO_UNDEFINED = 0xFF,
}OrProtocol;

typedef enum {
    OR_CREATE_CMD  = 0x01,
    OR_DATA_CMD    = 0x02,
    OR_DESTROY_CMD = 0x03,
    OR_PADDING_CMD = 0x04,
}OrCmd;

typedef enum {
    OR_SIMPLE_ENCRYPTION = 0x00,
    OR_DES_OFB           = 0x01,
    OR_RC4               = 0x02,
}OrFwdBkwdCrypto;

typedef enum
{
    OR_PAYLOAD_DELAY_TOLERANT_T   = 0x00,
    OR_PAYLOAD_DELAY_INTOLERANT_T = 0x01,
}OrPayloadType;

typedef enum {
    OR_CRYPTO_DIR_FWD = 0x01,
    OR_CRYPTO_DIR_BCK = 0x02,
}OrCryptoDir;

typedef struct {
    OrUint8 *data;
    OrUint16 dataL;
}OrCktData;

typedef struct OrOutgoingCktDataT_ {
    OrUint8 *data;
    OrUint16 dataL;
    struct OrOutgoingCktDataT_ *next;
}OrOutgoingCktData;

typedef struct OrCktSpecificDataT_ OrCktSpecificData;

typedef struct OrDlyTolerantDataT_ {
    OrUint8 *data;
    OrUint16 dataL;
    OrBool    fire;
    struct OrCktSpecificDataT_ *rfnceToCktData;
    struct OrDlyTolerantDataT_ *next;
    struct OrDlyTolerantDataT_ *mixnext;
}OrDlyTolerantData;

typedef OrCktData OrIncomingData;
typedef OrCktData OrOutGoingData;

typedef OrHostIdType OrAddrFormat;
typedef void (*OrAppDataInd)(void *sessn, OrUint8 *data, OrUint16 dataL);
typedef void (*OrAppProxyDataInd)(OrUint8 sessionId, OrUint8 *data, OrUint16 dataL);
typedef void (*OrRcvDataInd) (OrUint8 memberId, OrUint8 sesnData, const OrIncomingData *icmgData);

typedef struct
{
    OrUint16     port;
    OrCharString ip[OR_IP_ADDRESS_LENGTH];
}OrDestAddress;

typedef struct {
    OrUint32        memberId;
    OrNeighborTable *neighborTable;
} OrMemberNeighborTablePair;

typedef struct OrMemberNeighborTablePairPoolT_{
    OrMemberNeighborTablePair memberNbrTablePair;
    struct OrMemberNeighborTablePairPoolT_ *next;
} OrMemberNeighborTablePairPool;

typedef struct {
    OrFwdBkwdCrypto     backF;
    OrFwdBkwdCrypto     forwF;
    OrUint16     nextmemberId;
    OrUint8      orBackFkey[OR_FORW_BACK_KEY_LENGTH];
    OrUint8      orForwFkey[OR_FORW_BACK_KEY_LENGTH];
    OrUint32          expTime;
}OrLyerInfo;

typedef struct OrNodeInfoT_{
    OrUint16    memberId;
    OrUint8     orDhSecret[OR_DH_SECRET_LENGTH];
    OrLyerInfo  layerInfo;
    struct OrNodeInfoT_ *next;
}OrNodeInfo;

typedef struct {
    OrUint8       memberId;
    OrDestAddress destAddr;    /* the destination to which the address is */
    OrDestAddress nextHopAddr; /* next hop address */
    OrUint8       linkKey[OR_DH_SECRET_LENGTH];
    OrUint8      routeLen;
    OrNodeInfo  *routeHead;
} OrRoute;

typedef struct
{
    OrDestAddress dest;
    OrUint8  sessionId;
    OrUint8      proto;
}OrSessionTriplet;

typedef struct OrSessionEntry_
{
    OrAppDataInd      appDataInd;
    OrSessionTriplet sesnTriplet;
    struct OrSessionEntry_ *next;
}OrSessionEntry;

typedef struct
{
    OrUint8  *orOnion;
    OrUint16    orLen;
    OrUint8   mac[OR_MAC_SIZE];
}OrOnion;

typedef struct OrOnionListNodeT_{
    OrOnion onion;
    OrTimer orTimer;
    OrThread orTimerThd;
    struct OrOnionListNodeT_ *next;
}OrOnionListNode;

typedef OrOnionListNode OrOnionList;

typedef struct OrSesnDataT_
{
    OrUint8  orPkt[OR_PKT_LEN];
    OrUint16 orPktL;
    struct OrSesnDataT_ *next ;
}OrSesnData;

typedef struct OrOnionProxySessionEntry_
{
    OrUint32                      memberId;
    OrSessionTriplet    orSesnProxyTriplet;
    OrPayloadType              payLoadType;
    OrAppProxyDataInd         appDataIndFn;
    OrRoute                          route;
    OrOnion                          onion;
    OrUint8                           vcId;
    OrInt                         clientFd;
    OrThread         orOnionProxyRcvThread;
    OrThread         orOnionProxySndThread;
    OrMutexHandle    orOnionPxySndRcvLock;
    OrMutexHandle      orOnionPxySndQLock;
    OrSemaHandle         orOnionPxySndSema;
    OrSesnData                *orSesnDataH;
    struct OrOnionProxySessionEntry_ *next;
}OrOnionProxySessionEntry;

typedef struct
{
    OrUint8          cid;
    OrCmd            cmd;
    OrPayloadType pLoadT;
    OrUint8       *pLoad;
    OrUint16       pLoadL;
    OrUint8       linkKey[OR_DH_SECRET_LENGTH];
    OrUint8 mac[OR_MAC_SIZE];
}OrIncmingDataTuple;

#endif /*__OR_TYPES_H__*/