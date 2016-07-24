/*
 * FILE:	or_time.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_TIME_H__
#define __OR_TIME_H__
#include "or_types.h"

#define OR_INVALID_TIMER 0xffffffff

typedef enum {
    OR_TIME_IN_SEC_T  = 0x01,
    OR_TIME_IN_USEC_T = 0x02,
}OrTimerType;

typedef struct OrTimerNodeT_{
    OrTimer timerId;
    OrUint64 timeout;
    struct OrTimerNodeT_ *next;
}OrTimerNode;

typedef OrTimerNode* OrTimerList;

extern void or_timer_module_init();
extern void or_time_utc_get(OrTimeUtc *tod, OrTime *low, OrTime *high);
extern OrTimer or_time_init_timer(OrUint64 time, OrTimerType tType);
extern OrBool or_is_timeout(OrTimer timer, OrBool *isTimeOut);
extern void or_timer_module_deinit();

#endif /* __OR_TIME_H__ */