/*
 * FILE:	or_time.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_time.h"
#include "or_common.h"
#include "or_log.h"

/*------------------------------Local Variables------------------------------*/
OR_CREATE_Q(OrTimer, timeQ);
OrTimerList timerList = NULL;

/*------------------------------Public Fn Defn-------------------------------*/

void or_timer_module_init() {
    OrUint16 itr;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_INIT_Q(timeQ);

    /* Add timer ids to the Q */
    for(itr = 1; itr <= OR_MAX_NO_TIMERS; itr++) {
        OR_Q_PUT(timeQ, itr);
    }
}

/*----------------------------------------------------------------------------*
 *  NAME
 *      or_time_utc_get
 *
 *  DESCRIPTION
 *      Get the current system wallclock timestamp in UTC.
 *      Specifically, if tod is non-NULL, the contents will be set to the
 *      number of seconds (plus any fraction of a second in milliseconds)
 *      since January 1st 1970.  If low is non-NULL, the contents will be
 *      set to the low 32 bit part of the current system time in microseconds.
 *      If high is non-NULL, the contents will be set to the high 32 bit
 *      part of the current system time.
 *
 *  NOTE
 *      NULL pointers may be provided for both low and high parameters.
 *
 *  RETURNS
 *      void
 *
*----------------------------------------------------------------------------*/
void or_time_utc_get(OrTimeUtc *tod, OrTime *low, OrTime *high) {
    struct timespec ts;
    OrUint64      time;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    clock_gettime(CLOCK_MONOTONIC, &ts);
    time = (OrUint64) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

    if (high != NULL)
    {
        *high = (OrTime) ((time >> 32) & 0xFFFFFFFF);
    }

    if (low != NULL)
    {
        *low = (OrTime) (time & 0xFFFFFFFF);
    }

    if (tod != NULL)
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        tod->sec  = tv.tv_sec;
        tod->msec = tv.tv_usec / 1000;
    }
}

OrTimer or_time_init_timer(OrUint64 time, OrTimerType tType) {
    OrTimer timerId        = OR_INVALID_TIMER;
    OrTimerNode *timerNode = NULL;
    OrUint64       timeout = 0;
    struct timespec ts;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

    timerNode = (OrTimerNode *) or_mem_alloc(sizeof(OrTimerNode));

    if(timerNode != NULL) {
        OrUint64 orJiffies = ts.tv_sec * OR_TIME_ONE_SEC_IN_USEC
                                    + ts.tv_nsec / OR_TIME_ONE_US_IN_NSEC;
        if(tType == OR_TIME_IN_SEC_T) {
            timeout = orJiffies + time * OR_TIME_ONE_SEC_IN_USEC;  /* timeout saved in (us) */
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> jiffies : %lu "
                           "assigned time is: %lu", 
                            __FUNCTION__, __LINE__,
                            orJiffies, _timeout);
        }
        else if(tType == OR_TIME_IN_USEC_T) {
            timeout = orJiffies + time;                            /* timeout saved in (us) */
        }

        timerNode->timeout = timeout;
        timerNode->next    = NULL;
        if(!OR_IS_Q_EMPTY(timeQ)) {
            OR_Q_GET(timeQ, timerNode->timerId);
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> assigned timer id is : %u", 
                                        __FUNCTION__, __LINE__,
                                        timerNode->timerId);

            /* add timer to list */
            or_util_add_to_list(timerList, OrTimerNode,timerNode);
            timerId = timerNode->timerId;
        }
        else {
            or_mem_free(timerNode);
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> timer unavailable", 
                                                            __FUNCTION__, __LINE__);
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> memory allocation failed", 
                                                            __FUNCTION__, __LINE__);
    }

    return timerId;
}

OrBool or_is_timeout(OrTimer timer, OrBool *isTimeOut) {
    OrTimerNode *timerNode = NULL;
    OrBool          result = FALSE;
    struct             timespec ts;

    /* OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__); */

    *isTimeOut = FALSE;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

    or_util_find_node_in_list(timerList, OrTimerNode, timerId, timer, timerNode);

    if(timerNode == NULL) {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> timer not found", __FUNCTION__, __LINE__);
    }
    else {
        OrUint64 orJiffies = ts.tv_sec * OR_TIME_ONE_SEC_IN_USEC 
                                    + ts.tv_nsec / OR_TIME_ONE_US_IN_NSEC;

        if (orJiffies < timerNode->timeout) {
            /* OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> timer %u is still alive",
                                        __FUNCTION__, __LINE__, timer); */
            /* OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> jiffies : %lu"
                           "assigned time is %lu", 
                            __FUNCTION__, __LINE__,
                            orJiffies, timerNode->timeout); */
        } else {
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> jiffies : %lu "
                           "assigned time is %lu", 
                            __FUNCTION__, __LINE__,
                            orJiffies, timerNode->timeout);
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> timer %u has timed out",
                                        __FUNCTION__, __LINE__, timer);
            *isTimeOut = TRUE;
        }
        result = TRUE;
    }

    return result;
}

void or_timer_module_deinit() {
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_util_destroy_list(timerList, OrTimerNode);
    OR_Q_DESTROY(timeQ);
}

