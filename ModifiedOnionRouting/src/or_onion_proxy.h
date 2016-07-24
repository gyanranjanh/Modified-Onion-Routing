/*
 * FILE:	or_onion_proxy.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_ONION_PROXY_H__
#define __OR_ONION_PROXY_H__

#include "or_types.h"

extern void or_onion_proxy_init(void);
extern OrBool or_onion_proxy_data_req(OrUint32 memberId, OrUint8 sessionId,
                               OrUint8 *data, OrUint16 dataLength);
extern OrBool or_onion_proxy_create_or_session_req(OrUint32 memberId, OrDestAddress dest,
                            OrProtocol proto, OrAppProxyDataInd appDataIndFn, OrUint8 *sessionId);
extern OrBool or_onion_proxy_destroy_or_session_req(OrUint32 memberId, OrUint8 sessionId);
extern void or_onion_proxy_update_neighbor_table_for_member(OrUint32 memberId, OrNeighborTable *neighborTable);
extern void or_onion_proxy_deinit(void);

#ifdef OR_TEST_MODE
extern void or_replay_onion(void);
extern OrBool or_onion_proxy_dummy_msg_req(OrUint32 memberId, OrUint8 sessionId);
#endif

#endif /* __OR_ONION_PROXY_H__ */
