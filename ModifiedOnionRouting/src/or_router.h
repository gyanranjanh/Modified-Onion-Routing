/*
 * FILE:	or_router.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_ROUTER_H__
#define __OR_ROUTER_H__

#include "or_types.h"

typedef struct OrCktSpecificDataT_{
    OrUint8                      vcId;
    OrInt                          fd;
    OrPayloadType             pldType;
    OrOnion                     onion;
    OrLyerInfo              layerInfo;
    OrUint8               nextHopVcId;
    OrInt                   nextHopFd;
    OrThread        orRouterRcvThread;
    OrThread        orRouterSndThread;
    OrMutexHandle orRouterSndRcvLock;
    OrSemaHandle      orRouterSndSema;
    OrOutgoingCktData *orOutGngDataQh;
    OrDlyTolerantData *orDlyTolrntDataQh;
    OrMutexHandle       orOutGngQLock;
    OrMutexHandle  orDlyTolerantQLock;
    OrUint8           linkKey[OR_DH_SECRET_LENGTH];
    OrUint8    nextHopLinkKey[OR_DH_SECRET_LENGTH];
    struct OrCktSpecificDataT_  *next;
}OrCktSpecificData;

typedef struct OrCktSpecificData OrCktDataPool;

extern void or_router_init(void);
extern void or_router_handler(OrInt fd, const OrUint8 *data, OrUint16 length);
extern void or_router_deinit(void);

#endif /* __OR_ROUTER_H__ */