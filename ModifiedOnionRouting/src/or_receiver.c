/*
 * FILE:	or_receiver.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_receiver.h"
#include "or_common.h"
#include "or_log.h"

#define OR_RSP_BUF_LEN  1520
OrUint8 rspbuf[OR_RSP_BUF_LEN];
OrOutGoingData outD;

/*-----------------------Local Fn Defn--------------------------*/
static void or_rcv_data_ind(OrUint8 memberId,
                            OrUint8 sesnId,
                            const OrIncomingData *icmgData)
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    icmgData->data[icmgData->dataL] = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG , "\n<%s (Line: %d)> "
                                "member (%u) received "
                                "msg through OR: !!!%s!!!\n"
                                , __FUNCTION__, __LINE__,
                                memberId, icmgData->data);

    /* Echo data for time being */
    outD.data  = rspbuf;
    or_mem_set(rspbuf, 0x00, OR_RSP_BUF_LEN);
    if(!strcmp(icmgData->data, OR_HANDHSAKE_MSG)) {
        strcpy(rspbuf, OR_EXPECTED_HANDHSHAKE_RSP);
    }
    else {
        strcpy(rspbuf, "Thanks! Got ur msg.");
    }
    outD.dataL = strlen(rspbuf);
    or_receiver_send_rsp_req(sesnId, &outD);
}

/*-----------------------Global Fn Defn-------------------------*/
void or_receiver_init()
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_exit_funnel_init();
    or_exit_funnel_register_receiver(orContext.memberId, or_rcv_data_ind);
}

void or_receiver_handler(OrUint8 *data, OrUint16 length)
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

}

OrBool or_receiver_send_rsp_req(OrUint8 sesnId, 
                           OrOutGoingData *oData)
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_exit_funnel_reply_req(orContext.memberId, sesnId, oData);
}

void or_receiver_deinit()
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_exit_funnel_deinit();
}
