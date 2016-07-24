/*
 * FILE:	or_application_proxy.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */
#ifndef __OR_APPLICATION_PROXY_H__
#define __OR_APPLICATION_PROXY_H__

#include "or_types.h"

extern void or_app_proxy_init(void);
extern OrBool or_app_proxy_send_data(OrDestAddress dest, OrProtocol   proto,
                              OrUint8 *data, OrUint16 dataL, OrAppDataInd appDataInd);
extern void or_app_proxy_data_ind(OrUint8 sessionId, OrUint8 *data, OrUint16 dataL);
extern void or_app_proxy_deinit(void);

#ifdef OR_TEST_MODE
OrBool or_app_proxy_send_dummy_msg(OrDestAddress dest);
#endif

#endif /* __OR_APPLICATION_PROXY_H__ */
