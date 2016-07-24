/*
 * FILE:	or_exit_funnel.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_EXIT_FUNNEL_H__
#define __OR_EXIT_FUNNEL_H__

#include "or_types.h"

#define OR_MAX_RCVR_SESNS        (10)
#define OR_RCVR_INVALID_SESN_ID (0xff)

typedef struct {
    OrUint8                    sesnId;
    OrUint8                      vcId;
    OrInt                          fd;
    OrPayloadType             pldType;
    OrOnion                     onion;
    OrLyerInfo              layerInfo;
    OrUint8                 linkKey[OR_DH_SECRET_LENGTH];
}OrRcvCktSpcfcData;

typedef struct OrRegdRcvrT_{
    OrUint8                                 memberId;
    OrRcvDataInd                          rcvDataInd;
    OrUint8                                   nSesns;
    OrRcvCktSpcfcData  rcvCktData[OR_MAX_RCVR_SESNS];
    struct OrRegdRcvrT_                        *next;
}OrRegdRcvr;

typedef OrRegdRcvr OrRegdRcvrPool;

typedef struct OrPendingVcNodeT_{
    OrRcvCktSpcfcData        cktData;
    struct OrPendingVcNodeT_ *next;
}OrPendingVcNode;

typedef struct OrPendingVcNode OrPendingVcList;


extern void or_exit_funnel_init(void);
extern void or_exit_funnel_handler(OrInt fd, const OrUint8 *data, OrUint16 length);
extern void or_exit_funnel_register_receiver(OrUint8 memberId, OrRcvDataInd rcvDataInd);
extern OrBool or_exit_funnel_reply_req(OrUint8 memberId, OrUint8 sesnId,
                                                            OrOutGoingData *outGngData);
extern void or_exit_funnel_deinit(void);

#endif /* __OR_EXIT_FUNNEL_H__ */
