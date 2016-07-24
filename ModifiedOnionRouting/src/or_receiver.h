/*
 * FILE:	or_receiver.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_RECEIVER_H__
#define __OR_RECEIVER_H__

#include "or_types.h"

void or_receiver_init(void);
void or_receiver_handler(OrUint8 *data, OrUint16 length);
OrBool or_receiver_send_rsp_req(OrUint8 sesnId, OrOutGoingData *oData);
void or_receiver_deinit(void);

#endif /* __OR_RECEIVER_H__ */

